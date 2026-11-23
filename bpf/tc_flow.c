// SPDX-License-Identifier: GPL-2.0-only
/*
 * tc_flow.c — Kavach flow tracking at TC (v0.2–v0.3).
 *
 * egress : remember the *reply* 5-tuple of every locally-originated flow (O(1) return path);
 *          on a stale-generation hit, re-evaluate egress policy with the socket's identity so a
 *          newly denied established flow is cut (design review P0-3).
 * ingress: cached verdict on hit; NEW flows only (TCP SYN, first UDP/ICMP) go through the ingress
 *          rule scan; mid-stream TCP with no state passes unless the policy is strict (FR-TC-3).
 *
 * Always passed regardless of policy (keeps the host reachable/healthy): ICMP errors and
 * non-echo ICMP, ICMPv6 other than echo-request (ND/RA/PMTU), DHCPv4/v6 client replies,
 * non-first fragments.
 *
 * Requirements: FR-TC-1..4, FR-HS-4.
 */
#include "kavach_eval.h"

#define ICMP_ECHO 8
#define ICMPV6_ECHO_REQUEST 128

static __always_inline void kv_flow_touch(struct kv_flow_val *v, __u32 len)
{
	__sync_fetch_and_add(&v->pkts, 1);
	__sync_fetch_and_add(&v->bytes, len);
	v->last_seen_ns = bpf_ktime_get_boot_ns();
}

/* Identity mask of the local socket for the current slot (egress only). */
static __always_inline __u64 kv_skb_mask(struct __sk_buff *skb, const struct kv_snapshot *s,
					 __u64 *identity_out)
{
	struct bpf_sock *bsk = skb->sk;
	if (!bsk)
		return 0;
	bsk = bpf_sk_fullsock(bsk);
	if (!bsk)
		return 0;
	struct kv_identity *id = bpf_sk_storage_get(&sk_ident, bsk, 0, 0);
	if (!id)
		return 0;
	if (id->generation == s->gen)
		return id->mask;

	/* Recompute for the new policy (selector numbering may have changed). */
	const struct kv_policy *pol = s->pol;
	__u64 exe_m = pol->hdr.wild_exe == ~0ULL ? 0 : kv_exe_mask(&id->exe, s->slot);
	__u64 uid_m = pol->hdr.wild_uid == ~0ULL ? 0 : kv_uid_mask(id->uid, s->slot);
	__u64 cg_m = 0;
	if (pol->hdr.wild_cgroup != ~0ULL) {
		/* Same as the LSM's kv_current_cg_mask, over the socket's cgroup path. */
		bool wl = pol->hdr.flags & KV_POL_F_WORKLOAD, self_hit = false, hit = false;
		__u64 wl_m = wl ? kv_wl_mask(id->cgroup_id, s->slot, &self_hit) : 0;
		cg_m = kv_cgroup_mask(id->cgroup_id, s->slot);
#pragma unroll
		for (int level = 1; level <= KV_CGROUP_LEVELS; level++) {
			__u64 a = bpf_skb_ancestor_cgroup_id(skb, level);
			if (!a || a == id->cgroup_id)
				break;
			cg_m |= kv_cgroup_mask(a, s->slot);
			if (wl && !self_hit) {
				__u64 w = kv_wl_mask(a, s->slot, &hit);
				if (hit)
					wl_m = w;
			}
		}
		cg_m |= wl_m;
	}
	__u64 m = kv_combine_mask(pol, exe_m, uid_m, cg_m);
	id->mask = m;
	id->generation = s->gen;
	*identity_out = m;
	return m;
}

static __always_inline void kv_emit_ingress(struct __sk_buff *skb, const struct kv_pkt *p,
					    const struct kv_decision *d, __u32 gen)
{
	__u32 zero = 0;
	struct kv_xdp_config *cfg = bpf_map_lookup_elem(&xdp_cfg, &zero);
	if (!cfg || !cfg->sample_rate)
		return;
	if (cfg->sample_rate > 1 && (bpf_get_prandom_u32() % cfg->sample_rate) != 0)
		return;
	struct kv_event *e = kv_event_reserve();
	if (!e)
		return;
	e->kind = KV_EVENT_KIND_INGRESS_VERDICT;
	e->verdict = d->verdict;
	e->reason = d->verdict == KV_VERDICT_DROP ? KV_STAT_INGRESS_DROP : KV_STAT_INGRESS_ALLOW;
	e->ifindex = skb->ifindex;
	e->key = p->key;
	e->rule_id = d->rule_id;
	e->generation = gen;
	bpf_ringbuf_submit(e, 0);
}

SEC("classifier")
int kavach_tc_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct kv_pkt p = {};
	struct kv_flow_key rk;
	struct kv_snapshot s;
	int have_policy;

	if (kv_parse(data, data_end, &p) != KV_PARSE_OK || !p.l4)
		return TC_ACT_OK;

	have_policy = kv_snapshot_get(&s) == 0;
	kv_flow_reverse(&p.key, &rk);

	struct kv_flow_val *v = bpf_map_lookup_elem(&flow_cache, &rk);
	if (!v) {
		struct kv_flow_val nv = {
			.flags = KV_FLOW_F_REPLY,
			.verdict = KV_VERDICT_ALLOW,
			.generation = have_policy ? s.gen : 0,
			.last_seen_ns = bpf_ktime_get_boot_ns(),
			.pkts = 1,
			.bytes = skb->len,
		};
		if (have_policy) {
			__u64 ident = 0;
			nv.identity = kv_skb_mask(skb, &s, &ident);
		}
		bpf_map_update_elem(&flow_cache, &rk, &nv, BPF_ANY);
		kv_count(KV_STAT_FLOW_CACHE_MISS);
		return TC_ACT_OK;
	}

	if (have_policy && v->generation != s.gen && (v->flags & KV_FLOW_F_REPLY)) {
		/* Policy changed since this flow was admitted: judge it again (FR-HS-4). */
		struct kv_decision d;
		__u64 ident = 0;
		__u64 mask = kv_skb_mask(skb, &s, &ident);
		if (!(s.pol->hdr.flags & KV_POL_F_NO_LOOPBACK_BYPASS) && kv_is_loopback(p.key.dst)) {
			d.verdict = KV_VERDICT_ALLOW;
			d.rule_id = 0;
		} else {
			kv_evaluate(&s, KV_DIR_EGRESS, mask, p.key.dst, bpf_ntohs(p.key.dport),
				    p.key.proto, &d);
		}
		v->verdict = d.verdict == KV_VERDICT_DROP ? KV_VERDICT_DROP : KV_VERDICT_ALLOW;
		v->rule_id = d.rule_id;
		v->identity = mask;
		v->generation = s.gen;
		kv_count(KV_STAT_FLOW_CACHE_STALE);
	} else {
		kv_count(KV_STAT_FLOW_CACHE_HIT);
	}

	kv_flow_touch(v, skb->len);
	if (v->verdict == KV_VERDICT_DROP) {
		kv_count(KV_STAT_EGRESS_DROP);
		return TC_ACT_SHOT;
	}
	return TC_ACT_OK;
}

static __always_inline int kv_always_pass(const struct kv_pkt *p)
{
	if (!p->l4)
		return 1; /* non-first fragment: no ports to judge */
	if (p->key.proto == IPPROTO_ICMP)
		return p->icmp_type != ICMP_ECHO;
	if (p->key.proto == IPPROTO_ICMPV6)
		return p->icmp_type != ICMPV6_ECHO_REQUEST;
	if (p->key.proto == IPPROTO_UDP) {
		__u16 sp = bpf_ntohs(p->key.sport), dp = bpf_ntohs(p->key.dport);
		if ((sp == 67 && dp == 68) || (sp == 547 && dp == 546))
			return 1; /* DHCP / DHCPv6 replies to this client */
	}
	return 0;
}

SEC("classifier")
int kavach_tc_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct kv_pkt p = {};
	struct kv_snapshot s;

	if (kv_parse(data, data_end, &p) != KV_PARSE_OK)
		return TC_ACT_OK;

	struct kv_flow_val *v = bpf_map_lookup_elem(&flow_cache, &p.key);
	if (v && (v->flags & KV_FLOW_F_REPLY)) {
		/* Return traffic of a flow we originated (verdict re-judged at egress). */
		kv_flow_touch(v, skb->len);
		kv_count(KV_STAT_FLOW_CACHE_HIT);
		return v->verdict == KV_VERDICT_DROP ? TC_ACT_SHOT : TC_ACT_OK;
	}

	if (kv_snapshot_get(&s))
		return TC_ACT_OK; /* no policy: observe only */

	if (v && v->generation == s.gen) {
		kv_flow_touch(v, skb->len);
		kv_count(KV_STAT_FLOW_CACHE_HIT);
		if (v->verdict == KV_VERDICT_DROP) {
			kv_count(KV_STAT_INGRESS_DROP);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}

	if (kv_always_pass(&p))
		return TC_ACT_OK;

	/* True miss on mid-stream TCP: state was evicted or predates Kavach (FR-TC-3).
	 * A stale hit (v != NULL) is always re-evaluated instead. */
	if (!v && p.key.proto == IPPROTO_TCP &&
	    !((p.tcp_flags & KV_TCP_SYN) && !(p.tcp_flags & KV_TCP_ACK))) {
		if (s.pol->hdr.flags & KV_POL_F_STRICT_INGRESS) {
			kv_count(KV_STAT_INGRESS_DROP);
			return TC_ACT_SHOT;
		}
		return TC_ACT_OK;
	}

	if (!(s.pol->hdr.flags & KV_POL_F_NO_LOOPBACK_BYPASS) && kv_is_loopback(p.key.src))
		return TC_ACT_OK;

	struct kv_decision d;
	/* v0.3: the local service identity is not known at TC ingress, so mask = 0 and only
	 * identity-agnostic ingress rules (sel == 0) can match. */
	kv_evaluate(&s, KV_DIR_INGRESS, 0, p.key.src, bpf_ntohs(p.key.dport), p.key.proto, &d);
	kv_count(v ? KV_STAT_FLOW_CACHE_STALE : KV_STAT_FLOW_CACHE_MISS);

	struct kv_flow_val nv = {
		.rule_id = d.rule_id,
		.generation = s.gen,
		.verdict = d.verdict == KV_VERDICT_DROP ? KV_VERDICT_DROP : KV_VERDICT_ALLOW,
		.flags = KV_FLOW_F_INGRESS,
		.last_seen_ns = bpf_ktime_get_boot_ns(),
		.pkts = 1,
		.bytes = skb->len,
	};
	bpf_map_update_elem(&flow_cache, &p.key, &nv, BPF_ANY);

	if (d.verdict == KV_VERDICT_DROP) {
		kv_count(KV_STAT_INGRESS_DROP);
		kv_emit_ingress(skb, &p, &d, s.gen);
		return TC_ACT_SHOT;
	}
	kv_count(KV_STAT_INGRESS_ALLOW);
	if (d.verdict == KV_VERDICT_LOG)
		kv_emit_ingress(skb, &p, &d, s.gen);
	return TC_ACT_OK;
}
