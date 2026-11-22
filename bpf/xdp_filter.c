// SPDX-License-Identifier: GPL-2.0-only
/*
 * xdp_filter.c — Kavach v0.1 fast path.
 *
 * Runs at the driver hook before an sk_buff exists:
 *   parse → blocklist (LPM) → per-source token bucket → XDP_DROP | XDP_PASS
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
 * Token bucket in fixed point: tokens are scaled by KV_TOKEN_SCALE, one packet costs
 * KV_TOKEN_SCALE, refill is elapsed_ns * pps (elapsed capped at 10 s so the product stays far
 * below 2^64 for pps <= 10^8). Per-CPU value, so no atomics are needed.
 * Returns 1 if the packet conforms.
 */
static __always_inline int xdp_rate_ok(const struct kv_pkt *p, const struct kv_xdp_config *cfg,
				       __u64 now)
{
	struct kv_src_key sk;
	__u64 cap = cfg->burst * KV_TOKEN_SCALE;

	__builtin_memcpy(sk.addr, p->key.src, sizeof(sk.addr));
	struct kv_token_bucket *tb = bpf_map_lookup_elem(&rate_buckets, &sk);
	if (!tb) {
		struct kv_token_bucket fresh = {
			.tokens = cap > KV_TOKEN_SCALE ? cap - KV_TOKEN_SCALE : 0,
			.last_ns = now,
		};
		bpf_map_update_elem(&rate_buckets, &sk, &fresh, BPF_ANY);
		return cap >= KV_TOKEN_SCALE;
	}

	__u64 elapsed = now - tb->last_ns;
	if (elapsed > 10ULL * 1000000000ULL)
		elapsed = 10ULL * 1000000000ULL;
	__u64 pps = cfg->pps_per_cpu;
	if (pps > 100000000ULL)
		pps = 100000000ULL;
	__u64 tokens = tb->tokens + elapsed * pps;
	if (tokens > cap)
		tokens = cap;
	tb->last_ns = now;
	if (tokens < KV_TOKEN_SCALE) {
		tb->tokens = tokens;
		return 0;
	}
	tb->tokens = tokens - KV_TOKEN_SCALE;
	return 1;
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

	kv_count(KV_STAT_XDP_PASS);
	return XDP_PASS;
}
