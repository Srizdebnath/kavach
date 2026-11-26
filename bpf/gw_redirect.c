// SPDX-License-Identifier: GPL-2.0-only
/*
 * gw_redirect.c — Kavach v0.4 punt data path: punted TCP connects go to the L7 gateway.
 *
 *   lsm/socket_connect (lsm_egress.c)  rule verdict Punt + gateway alive → allow, sk_punt PENDING
 *   cgroup/connect4|6                   PENDING and same destination → rewrite to the gateway
 *                                       listener, mark REDIRECTED (one-shot)
 *   sockops TCP_CONNECT_CB              client port now bound → orig_dst[client 4-tuple] = record
 *   sockops STATE_CB (TCP_CLOSE)        delete orig_dst[client 4-tuple]
 *   cgroup/getpeername4|6               REDIRECTED → report the original destination
 *
 * The LSM runs before the cgroup connect hook in every connect() (security_socket_connect, then
 * sk_prot->pre_connect), so the decision and its identity stay in one place (the LSM) and this
 * file only acts on it. Everything here returns "allow": it never refuses a connect itself.
 * Attached to the root cgroup v2 by kavachd only while `[gateway] enabled = true`.
 */
#include "kavach_eval.h"

#define KV_SOCK_ADDR_ALLOW 1

/* Is the PENDING record for exactly this connect (same destination, same policy)? */
static __always_inline bool kv_punt_for(const struct kv_punt_record *pr, const __u32 *dst,
					__u16 port_net)
{
	__u32 zero = 0;
	__u32 *gen = bpf_map_lookup_elem(&policy_gen, &zero);
	if (!gen || READ_ONCE(*gen) != pr->generation)
		return false;
	return pr->dport == port_net && pr->dst[0] == dst[0] && pr->dst[1] == dst[1] &&
	       pr->dst[2] == dst[2] && pr->dst[3] == dst[3];
}

/* The record to act on for this connect, or NULL. Any other record is voided: a connect the
 * LSM did not just punt must never inherit an older redirect. */
static __always_inline struct kv_punt_record *kv_punt_take(struct bpf_sock_addr *ctx,
							   const __u32 *dst)
{
	struct bpf_sock *sk = ctx->sk;
	if (!sk || ctx->protocol != IPPROTO_TCP)
		return NULL;
	struct kv_punt_record *pr = bpf_sk_storage_get(&sk_punt, sk, 0, 0);
	if (!pr)
		return NULL;
	__u8 pending = pr->flags & KV_PUNT_F_PENDING;
	pr->flags = 0;
	if (!pending)
		return NULL;
	if (!kv_punt_for(pr, dst, (__u16)ctx->user_port)) {
		kv_gw_count(KV_GW_STAT_STALE);
		return NULL;
	}
	return pr;
}

SEC("cgroup/connect4")
int kavach_gw_connect4(struct bpf_sock_addr *ctx)
{
	__u32 dst[4];
	kv_map_v4(dst, ctx->user_ip4);
	struct kv_punt_record *pr = kv_punt_take(ctx, dst);
	if (!pr)
		return KV_SOCK_ADDR_ALLOW;
	/* An AF_INET socket's target is always the IPv4 listener (lsm_egress.c kv_gw_take). */
	ctx->user_ip4 = pr->target[3];
	ctx->user_port = pr->target_port;
	pr->flags = KV_PUNT_F_REDIRECTED;
	return KV_SOCK_ADDR_ALLOW;
}

SEC("cgroup/connect6")
int kavach_gw_connect6(struct bpf_sock_addr *ctx)
{
	__u32 dst[4];
	dst[0] = ctx->user_ip6[0];
	dst[1] = ctx->user_ip6[1];
	dst[2] = ctx->user_ip6[2];
	dst[3] = ctx->user_ip6[3];
	struct kv_punt_record *pr = kv_punt_take(ctx, dst);
	if (!pr)
		return KV_SOCK_ADDR_ALLOW;
	/* listen6, or ::ffff:listen4 (dual-stack sockets only; checked by the LSM). */
	ctx->user_ip6[0] = pr->target[0];
	ctx->user_ip6[1] = pr->target[1];
	ctx->user_ip6[2] = pr->target[2];
	ctx->user_ip6[3] = pr->target[3];
	ctx->user_port = pr->target_port;
	pr->flags = KV_PUNT_F_REDIRECTED;
	return KV_SOCK_ADDR_ALLOW;
}

static __always_inline struct kv_punt_record *kv_redirected(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	if (!sk || ctx->protocol != IPPROTO_TCP)
		return NULL;
	struct kv_punt_record *pr = bpf_sk_storage_get(&sk_punt, sk, 0, 0);
	if (!pr || !(pr->flags & KV_PUNT_F_REDIRECTED))
		return NULL;
	return pr;
}

/* The client keeps seeing the destination it asked for. */
SEC("cgroup/getpeername4")
int kavach_gw_getpeername4(struct bpf_sock_addr *ctx)
{
	struct kv_punt_record *pr = kv_redirected(ctx);
	if (pr) {
		ctx->user_ip4 = pr->dst[3];
		ctx->user_port = pr->dport;
	}
	return KV_SOCK_ADDR_ALLOW;
}

SEC("cgroup/getpeername6")
int kavach_gw_getpeername6(struct bpf_sock_addr *ctx)
{
	struct kv_punt_record *pr = kv_redirected(ctx);
	if (pr) {
		ctx->user_ip6[0] = pr->dst[0];
		ctx->user_ip6[1] = pr->dst[1];
		ctx->user_ip6[2] = pr->dst[2];
		ctx->user_ip6[3] = pr->dst[3];
		ctx->user_port = pr->dport;
	}
	return KV_SOCK_ADDR_ALLOW;
}

/*
 * The client's half of the 4-tuple, as the gateway will see it as `peer`. A target that is
 * IPv4-mapped means the connection runs over IPv4 (an AF_INET socket, or a dual-stack AF_INET6
 * socket connecting to ::ffff:a.b.c.d): its source is skc_rcv_saddr, which local_ip4 reads and
 * tcp_v4_connect has set before tcp_connect() calls us. local_port is host order.
 */
static __always_inline void kv_orig_key_of(struct bpf_sock_ops *skops,
					   const struct kv_punt_record *pr, struct kv_orig_key *k)
{
	if (pr->target[0] == 0 && pr->target[1] == 0 && pr->target[2] == bpf_htonl(0x0000ffff)) {
		kv_map_v4(k->client, skops->local_ip4);
	} else {
		k->client[0] = skops->local_ip6[0];
		k->client[1] = skops->local_ip6[1];
		k->client[2] = skops->local_ip6[2];
		k->client[3] = skops->local_ip6[3];
	}
	k->client_port = bpf_htons((__u16)skops->local_port);
	__builtin_memcpy(k->gateway, pr->target, sizeof(k->gateway));
	k->gateway_port = pr->target_port;
}

SEC("sockops")
int kavach_gw_sockops(struct bpf_sock_ops *skops)
{
	__u32 op = skops->op;
	if (op != BPF_SOCK_OPS_TCP_CONNECT_CB && op != BPF_SOCK_OPS_STATE_CB)
		return 1;
	struct bpf_sock *sk = skops->sk;
	if (!sk)
		return 1;
	struct kv_punt_record *pr = bpf_sk_storage_get(&sk_punt, sk, 0, 0);
	if (!pr || !(pr->flags & KV_PUNT_F_REDIRECTED))
		return 1;

	struct kv_orig_key k = {};
	kv_orig_key_of(skops, pr, &k);
	if (op == BPF_SOCK_OPS_TCP_CONNECT_CB) {
		/* Before the SYN leaves: the gateway can never accept before the entry exists. */
		if (bpf_map_update_elem(&orig_dst, &k, pr, BPF_ANY))
			kv_gw_count(KV_GW_STAT_ORIG_FAIL);
		/* State callbacks only for redirected sockets: no cost for anything else. */
		bpf_sock_ops_cb_flags_set(skops,
					  skops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
		return 1;
	}
	/* STATE_CB: args[1] is the new state. tcp_set_state() calls us before unhashing, so the
	 * local port is still the one the key was built with. */
	if (skops->args[1] == BPF_TCP_CLOSE && bpf_map_delete_elem(&orig_dst, &k) == 0)
		kv_gw_count(KV_GW_STAT_ORIG_CLOSED);
	return 1;
}
