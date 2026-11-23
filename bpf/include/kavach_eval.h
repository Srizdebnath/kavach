/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Policy evaluation shared by the LSM and TC programs. The Rust reference implementation in
 * crates/kavach-core/src/eval.rs MUST implement exactly the same semantics; the differential test
 * suite feeds identical tables and flows to both and asserts equal verdicts.
 *
 * Protocol (FR-HS-2): read policy_gen ONCE, derive slot = gen & 1, and use that slot for every
 * lookup (policy, class masks, address sets) for the rest of the invocation.
 */
#ifndef KAVACH_EVAL_H
#define KAVACH_EVAL_H

#include "kavach_bpf.h"

struct kv_snapshot {
	struct kv_policy *pol;
	__u32 gen;
	__u32 slot;
};

/* Returns 0 and fills @s when a valid policy is active, -1 otherwise (caller allows). */
static __always_inline int kv_snapshot_get(struct kv_snapshot *s)
{
	__u32 zero = 0;
	__u32 *genp = bpf_map_lookup_elem(&policy_gen, &zero);
	if (!genp)
		return -1;
	s->gen = READ_ONCE(*genp);
	s->slot = s->gen & 1;
	s->pol = bpf_map_lookup_elem(&policy_slots, &s->slot);
	if (!s->pol || !(s->pol->hdr.flags & KV_POL_F_VALID)) {
		kv_count(KV_STAT_POLICY_NO_SLOT);
		return -1;
	}
	return 0;
}

/* Selector mask contributed by an executable: present in exe_class = trusted (the LSM deletes
 * entries on taint). A zero key (kernel thread, untrusted filesystem, open writers) has none. */
static __always_inline __u64 kv_exe_mask(const struct kv_exe_key *k, __u32 slot)
{
	if (!k->inode)
		return 0;
	struct kv_exe_class *c = bpf_map_lookup_elem(&exe_class, k);
	if (!c) {
		kv_count(KV_STAT_EXE_UNCLASSIFIED);
		return 0;
	}
	return c->mask[slot & 1];
}

static __always_inline __u64 kv_uid_mask(__u32 uid, __u32 slot)
{
	struct kv_class_val *c = bpf_map_lookup_elem(&uid_class, &uid);
	return c ? c->mask[slot & 1] : 0;
}

static __always_inline __u64 kv_cgroup_mask(__u64 cgid, __u32 slot)
{
	struct kv_class_val *c = bpf_map_lookup_elem(&cgroup_class, &cgid);
	return c ? c->mask[slot & 1] : 0;
}

/* Workload lookup; *hit tells an entry with mask 0 (resolved, no match) from no entry. */
static __always_inline __u64 kv_wl_mask(__u64 cgid, __u32 slot, bool *hit)
{
	struct kv_class_val *c = bpf_map_lookup_elem(&wl_class, &cgid);
	*hit = c != NULL;
	return c ? c->mask[slot & 1] : 0;
}

/*
 * m = (exe | wild_exe) & (uid | wild_uid) & (cgroup | wild_cgroup)
 * cg_mask is the OR over the cgroup and its ancestors (subtree semantics), computed by caller.
 */
static __always_inline __u64 kv_combine_mask(const struct kv_policy *pol, __u64 exe_m, __u64 uid_m,
					     __u64 cg_m)
{
	return (exe_m | pol->hdr.wild_exe) & (uid_m | pol->hdr.wild_uid) &
	       (cg_m | pol->hdr.wild_cgroup) & pol->hdr.sel_used;
}

static __always_inline __u64 kv_remote_sets(__u32 slot, const __u32 *addr)
{
	struct kv_addr_key k = { .prefixlen = 32 + 128, .slot = slot };
	__builtin_memcpy(k.addr, addr, sizeof(k.addr));
	__u64 *v = bpf_map_lookup_elem(&addr_sets, &k);
	return v ? *v : 0;
}

struct kv_eval_ctx {
	struct kv_policy *pol;
	__u64 mask;
	__u64 sets;
	__u64 now;
	__u16 port; /* host order */
	__u8 proto;
	__u8 dir;
	__s32 match;
};

static long kv_eval_cb(__u64 i, void *data)
{
	struct kv_eval_ctx *c = data;
	struct kv_rule *r = &c->pol->rules[i & (KV_MAX_RULES - 1)];

	if (r->dir != c->dir)
		return 0;
	if (r->sel && !(r->sel & c->mask))
		return 0;
	if (r->proto && r->proto != c->proto)
		return 0;
	if (c->port < r->port_lo || c->port > r->port_hi)
		return 0;
	if (r->remote_set) {
		__u32 bit = r->remote_set - 1;
		if (bit >= 64 || !((c->sets >> bit) & 1))
			return 0;
	}
	if (r->not_after_ns && c->now >= r->not_after_ns)
		return 0;
	c->match = (__s32)i;
	return 1; /* first match wins */
}

struct kv_decision {
	__u32 rule_id;
	__u8 verdict; /* final: Allow / Drop / Log (Punt already resolved through fail mode) */
	__u8 punted;
};

static __always_inline void kv_evaluate(const struct kv_snapshot *s, __u8 dir, __u64 mask,
					const __u32 *remote, __u16 port_host, __u8 proto,
					struct kv_decision *d)
{
	struct kv_eval_ctx c = {
		.pol = s->pol,
		.mask = mask,
		.sets = kv_remote_sets(s->slot, remote),
		.now = bpf_ktime_get_boot_ns(),
		.port = port_host,
		.proto = proto,
		.dir = dir,
		.match = -1,
	};
	__u32 n = s->pol->hdr.n_rules;
	if (n > KV_MAX_RULES)
		n = KV_MAX_RULES;
	bpf_loop(n, kv_eval_cb, &c, 0);

	d->punted = 0;
	if (c.match >= 0) {
		struct kv_rule *r = &s->pol->rules[c.match & (KV_MAX_RULES - 1)];
		d->rule_id = r->id;
		d->verdict = r->verdict;
		if (d->verdict == KV_VERDICT_PUNT) {
			/* v0.3: no L7 consumer yet, so the rule's fail mode decides (SR-8). */
			d->punted = 1;
			d->verdict = r->fail == KV_FAIL_CLOSED ? KV_VERDICT_DROP : KV_VERDICT_LOG;
		}
	} else {
		d->rule_id = 0;
		d->verdict = dir == KV_DIR_EGRESS ? s->pol->hdr.default_egress
						  : s->pol->hdr.default_ingress;
	}
}

#endif /* KAVACH_EVAL_H */
