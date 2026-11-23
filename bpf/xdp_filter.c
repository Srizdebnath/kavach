// SPDX-License-Identifier: GPL-2.0-only
/*
 * xdp_filter.c — Kavach v0.1 fast path.
 *
 * Runs at the driver hook before an sk_buff exists:
 *   parse → blocklist (LPM) → per-source token bucket → XDP_DROP | XDP_PASS
 *   [opt-in, KV_XDP_F_AFXDP] gateway-selected (proto, dport) → XDP_REDIRECT to an AF_XDP socket
 *
 * Requirements: FR-XDP-1..8. Zero allocations, bounded work, verifier-checked.
 * Included by kavach.bpf.c (single object so maps are shared).
 */
#include "kavach_bpf.h"

static __always_inline void xdp_emit_drop(struct xdp_md *ctx, const struct kv_pkt *p,
					  __u32 reason, __u32 rule, const struct kv_xdp_config *cfg)
{
	if (!cfg->sample_rate)
		return;
	if (cfg->sample_rate > 1 && (bpf_get_prandom_u32() % cfg->sample_rate) != 0)
		return;
	struct kv_event *e = kv_event_reserve();
	if (!e)
		return;
	e->kind = KV_EVENT_KIND_XDP_DROP;
	e->verdict = KV_VERDICT_DROP;
	e->reason = reason;
	e->ifindex = ctx->ingress_ifindex;
	e->key = p->key;
	e->rule_id = rule;
	bpf_ringbuf_submit(e, 0);
}

/*
 * GCRA (generic cell rate algorithm) — equivalent to a token bucket but with ONE u64 of state,
 * so it can be shared by all CPUs and updated with compare-and-swap (no per-CPU skew, no
 * RSS-dependent limits). emission_ns = 1e9/pps, tau_ns = emission_ns * (burst - 1).
 * IPv6 sources are keyed per /64. Returns 1 if the packet conforms.
 */
static __always_inline int xdp_rate_ok(const struct kv_pkt *p, const struct kv_xdp_config *cfg,
				       __u64 now)
{
	struct kv_src_key sk;

	__builtin_memcpy(sk.addr, p->key.src, sizeof(sk.addr));
	if (p->key.family == KV_AF_INET6)
		__builtin_memset(sk.addr + 8, 0, 8);

	struct kv_rate_state *st = bpf_map_lookup_elem(&rate_buckets, &sk);
	if (!st) {
		struct kv_rate_state fresh = { .tat_ns = now + cfg->emission_ns };
		bpf_map_update_elem(&rate_buckets, &sk, &fresh, BPF_NOEXIST);
		return 1;
	}

#pragma unroll
	for (int i = 0; i < 3; i++) {
		__u64 old = READ_ONCE(st->tat_ns);
		__u64 tat = old > now ? old : now;
		if (tat - now > cfg->tau_ns) {
			__sync_fetch_and_add(&st->drops, 1);
			return 0;
		}
		if (__sync_val_compare_and_swap(&st->tat_ns, old, tat + cfg->emission_ns) == old)
			return 1;
	}
	return 1; /* heavy contention on one key: conform rather than spin */
}

static __always_inline void xsk_count(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&xsk_stats, &idx);
	if (v)
		*v += 1;
}

/*
 * Opt-in AF_XDP gateway step. Returns XDP_REDIRECT only for a TCP/UDP frame (with a parsed L4
 * header) to a gateway-selected (proto, dport) whose RX queue has a live watchdog deadline and
 * a bound socket; every other frame gets XDP_PASS, exactly as without the backend. The
 * redirect itself falls back to XDP_PASS (flags argument) when the queue has no socket.
 */
static __always_inline int xdp_gateway_redirect(struct xdp_md *ctx, const struct kv_pkt *p,
						__u64 now)
{
	if (!p->l4 || (p->key.proto != IPPROTO_TCP && p->key.proto != IPPROTO_UDP))
		return XDP_PASS;
	__u32 pk = ((__u32)p->key.proto << 16) | bpf_ntohs(p->key.dport);
	if (!bpf_map_lookup_elem(&xsk_ports, &pk))
		return XDP_PASS;
	__u32 q = ctx->rx_queue_index;
	__u64 *alive = bpf_map_lookup_elem(&xsk_alive, &q);
	if (!alive || READ_ONCE(*alive) <= now) {
		xsk_count(KV_XSK_STAT_STALE);
		return XDP_PASS;
	}
	long act = bpf_redirect_map(&xsk_sockets, q, XDP_PASS);
	if (act != XDP_REDIRECT) {
		xsk_count(KV_XSK_STAT_NO_SOCKET);
		return XDP_PASS;
	}
	xsk_count(KV_XSK_STAT_REDIRECT);
	return XDP_REDIRECT;
}

SEC("xdp")
int kavach_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct kv_pkt p = {};
	__u32 zero = 0;

	if (kv_parse(data, data_end, &p) != KV_PARSE_OK) {
		kv_count(KV_STAT_XDP_UNPARSED);
		return XDP_PASS;
	}

	struct kv_xdp_config *cfg = bpf_map_lookup_elem(&xdp_cfg, &zero);
	if (!cfg) {
		kv_count(KV_STAT_XDP_PASS);
		return XDP_PASS;
	}
	__u64 now = bpf_ktime_get_boot_ns();

	if (cfg->flags & KV_XDP_F_BLOCKLIST) {
		struct kv_block_key bk = { .prefixlen = 128 };
		__builtin_memcpy(bk.addr, p.key.src, sizeof(bk.addr));
		struct kv_block_val *bv = bpf_map_lookup_elem(&blocklist, &bk);
		if (bv && (bv->expires_ns == 0 || bv->expires_ns > now)) {
			kv_count(KV_STAT_XDP_DROP_BLOCKLIST);
			xdp_emit_drop(ctx, &p, KV_STAT_XDP_DROP_BLOCKLIST, bv->reason, cfg);
			return XDP_DROP;
		}
	}

	if ((cfg->flags & KV_XDP_F_RATELIMIT) && !xdp_rate_ok(&p, cfg, now)) {
		kv_count(KV_STAT_XDP_DROP_RATE);
		xdp_emit_drop(ctx, &p, KV_STAT_XDP_DROP_RATE, 0, cfg);
		return XDP_DROP;
	}

	/* Last step: blocklist and rate limit above still apply to gateway flows. */
	if ((cfg->flags & KV_XDP_F_AFXDP) && xdp_gateway_redirect(ctx, &p, now) == XDP_REDIRECT)
		return XDP_REDIRECT;

	kv_count(KV_STAT_XDP_PASS);
	return XDP_PASS;
}
