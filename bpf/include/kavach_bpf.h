/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared definitions for every Kavach eBPF program: map declarations, packet parsing and small
 * helpers. All programs are compiled as ONE object (bpf/kavach.bpf.c), so every map below exists
 * exactly once and is shared by XDP, TC and LSM programs.
 */
#ifndef KAVACH_BPF_H
#define KAVACH_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "kavach_abi.h"

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define EPERM 1
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define FMODE_WRITE 0x2
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
/* uapi #defines that are not part of BTF */
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ICMPV6 58
#define IPPROTO_DSTOPTS 60

#define KV_BLOCKLIST_MAX 262144
#define KV_RATE_MAX 65536
#define KV_FLOW_MAX 262144
#define KV_IDENT_MAX 65536
#define KV_CLASS_MAX 65536
#define KV_ADDRSET_MAX 16384

/* --------------------------------------------------------------------------------------------
 * Maps
 * ------------------------------------------------------------------------------------------ */

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, KV_BLOCKLIST_MAX);
	__type(key, struct kv_block_key);
	__type(value, struct kv_block_val);
} blocklist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, KV_RATE_MAX);
	__type(key, struct kv_src_key);
	__type(value, struct kv_token_bucket);
} rate_buckets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kv_xdp_config);
} xdp_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, KV_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, KV_FLOW_MAX);
	__type(key, struct kv_flow_key);
	__type(value, struct kv_flow_val);
} flow_cache SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, KV_IDENT_MAX);
	__type(key, __u64);
	__type(value, struct kv_identity);
} identity_by_cookie SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, KV_CLASS_MAX);
	__type(key, struct kv_exe_key);
	__type(value, __u64);
} exe_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, KV_CLASS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} uid_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, KV_CLASS_MAX);
	__type(key, __u64);
	__type(value, __u64);
} cgroup_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, KV_SLOTS);
	__type(key, __u32);
	__type(value, struct kv_policy_header);
} policy_slots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, KV_SLOTS * KV_MAX_RULES);
	__type(key, __u32);
	__type(value, struct kv_rule);
} policy_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, KV_ADDRSET_MAX);
	__type(key, struct kv_addr_set_key);
	__type(value, __u8);
} addr_sets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} policy_gen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* --------------------------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------------------------ */

static __always_inline void kv_count(__u32 reason)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &reason);
	if (v)
		*v += 1;
}

/* Write an IPv4 address (network order) into a 16-byte IPv4-mapped slot. */
static __always_inline void kv_map_v4(__u32 *dst, __u32 v4)
{
	dst[0] = 0;
	dst[1] = 0;
	dst[2] = bpf_htonl(0x0000ffff);
	dst[3] = v4;
}

static __always_inline void kv_copy_v6(__u32 *dst, const struct in6_addr *a)
{
	dst[0] = a->in6_u.u6_addr32[0];
	dst[1] = a->in6_u.u6_addr32[1];
	dst[2] = a->in6_u.u6_addr32[2];
	dst[3] = a->in6_u.u6_addr32[3];
}

static __always_inline int kv_is_loopback(const __u32 *a)
{
	/* ::1 */
	if (a[0] == 0 && a[1] == 0 && a[2] == 0 && a[3] == bpf_htonl(1))
		return 1;
	/* ::ffff:127.0.0.0/8 */
	if (a[0] == 0 && a[1] == 0 && a[2] == bpf_htonl(0x0000ffff) &&
	    (bpf_ntohl(a[3]) >> 24) == 127)
		return 1;
	return 0;
}

static __always_inline struct kv_event *kv_event_reserve(void)
{
	struct kv_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		kv_count(KV_STAT_EVENTS_LOST);
		return NULL;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_boot_ns();
	return e;
}

/* --------------------------------------------------------------------------------------------
 * Packet parsing (XDP and TC share it: both give us data/data_end)
 * ------------------------------------------------------------------------------------------ */

struct kv_pkt {
	struct kv_flow_key key;
	__u8 tcp_flags;  /* raw TCP flags byte, 0 if not TCP */
	__u8 icmp_type;  /* ICMP / ICMPv6 type, 0 otherwise */
	__u8 l4;         /* 1 if the L4 header was parsed (not a non-first fragment) */
	__u8 _pad;
};

#define KV_TCP_FIN 0x01
#define KV_TCP_SYN 0x02
#define KV_TCP_RST 0x04
#define KV_TCP_ACK 0x10

#define KV_PARSE_OK 0
#define KV_PARSE_SKIP 1 /* not IP, or truncated: let the stack decide */

static __always_inline int kv_parse_l4(void *cur, void *data_end, struct kv_pkt *p)
{
	if (p->key.proto == IPPROTO_TCP) {
		struct tcphdr *th = cur;
		if ((void *)(th + 1) > data_end)
			return KV_PARSE_SKIP;
		p->key.sport = th->source;
		p->key.dport = th->dest;
		p->tcp_flags = ((__u8 *)th)[13];
		p->l4 = 1;
	} else if (p->key.proto == IPPROTO_UDP) {
		struct udphdr *uh = cur;
		if ((void *)(uh + 1) > data_end)
			return KV_PARSE_SKIP;
		p->key.sport = uh->source;
		p->key.dport = uh->dest;
		p->l4 = 1;
	} else if (p->key.proto == IPPROTO_ICMP || p->key.proto == IPPROTO_ICMPV6) {
		/* type(1) code(1) csum(2) id(2) seq(2): use echo id as both "ports". */
		__u8 *ih = cur;
		if ((void *)(ih + 8) > data_end)
			return KV_PARSE_SKIP;
		p->icmp_type = ih[0];
		p->key.sport = *(__u16 *)(ih + 4);
		p->key.dport = p->key.sport;
		p->l4 = 1;
	}
	return KV_PARSE_OK;
}

static __always_inline int kv_parse(void *data, void *data_end, struct kv_pkt *p)
{
	struct ethhdr *eth = data;
	void *cur;
	__u16 proto;

	if ((void *)(eth + 1) > data_end)
		return KV_PARSE_SKIP;
	proto = eth->h_proto;
	cur = eth + 1;

	/* Up to two VLAN tags (802.1Q / 802.1ad QinQ). */
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) && proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr {
			__be16 tci;
			__be16 proto;
		} *vh = cur;
		if ((void *)(vh + 1) > data_end)
			return KV_PARSE_SKIP;
		proto = vh->proto;
		cur = vh + 1;
	}

	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = cur;
		if ((void *)(ip + 1) > data_end)
			return KV_PARSE_SKIP;
		__u32 ihl = ip->ihl * 4;
		if (ihl < sizeof(*ip))
			return KV_PARSE_SKIP;
		p->key.family = KV_AF_INET;
		p->key.proto = ip->protocol;
		kv_map_v4(p->key.src, ip->saddr);
		kv_map_v4(p->key.dst, ip->daddr);
		/* Non-first fragments carry no L4 header. */
		if (ip->frag_off & bpf_htons(IP_OFFSET))
			return KV_PARSE_OK;
		cur = (void *)ip + ihl;
		if (cur > data_end)
			return KV_PARSE_SKIP;
		return kv_parse_l4(cur, data_end, p);
	}

	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = cur;
		if ((void *)(ip6 + 1) > data_end)
			return KV_PARSE_SKIP;
		p->key.family = KV_AF_INET6;
		kv_copy_v6(p->key.src, &ip6->saddr);
		kv_copy_v6(p->key.dst, &ip6->daddr);
		__u8 nexthdr = ip6->nexthdr;
		cur = ip6 + 1;
		/* Walk up to 4 extension headers. */
#pragma unroll
		for (int i = 0; i < 4; i++) {
			if (nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING ||
			    nexthdr == IPPROTO_DSTOPTS) {
				struct ipv6_opt_hdr *oh = cur;
				if ((void *)(oh + 1) > data_end)
					return KV_PARSE_SKIP;
				nexthdr = oh->nexthdr;
				cur = cur + (oh->hdrlen + 1) * 8;
			} else if (nexthdr == IPPROTO_FRAGMENT) {
				struct frag_hdr *fh = cur;
				if ((void *)(fh + 1) > data_end)
					return KV_PARSE_SKIP;
				nexthdr = fh->nexthdr;
				cur = fh + 1;
				if (fh->frag_off & bpf_htons(0xFFF8)) {
					p->key.proto = nexthdr;
					return KV_PARSE_OK; /* non-first fragment */
				}
			} else {
				break;
			}
		}
		p->key.proto = nexthdr;
		if (cur > data_end)
			return KV_PARSE_SKIP;
		return kv_parse_l4(cur, data_end, p);
	}

	return KV_PARSE_SKIP;
}

static __always_inline void kv_flow_reverse(const struct kv_flow_key *in, struct kv_flow_key *out)
{
	out->family = in->family;
	out->proto = in->proto;
	out->_pad[0] = 0;
	out->_pad[1] = 0;
	out->sport = in->dport;
	out->dport = in->sport;
#pragma unroll
	for (int i = 0; i < 4; i++) {
		out->src[i] = in->dst[i];
		out->dst[i] = in->src[i];
	}
}

#endif /* KAVACH_BPF_H */
