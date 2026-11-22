// SPDX-License-Identifier: GPL-2.0-only
/*
 * lsm_egress.c — Kavach v0.2 identity-aware egress (BPF-LSM).
 *
 *   socket_connect / socket_sendmsg  → who (exe, uid, cgroup subtree) → rule scan → 0 | -EPERM
 *   bprm_committed_creds             → Exec event so kavachd can hash + classify the binary
 *   file_open (write) / path_truncate → bump exe_dirty: a modified binary loses its identity
 *
 * Requirements: FR-ID-1..6, FR-EG-1..5. LSM hooks get a trailing `ret` (result of earlier LSMs):
 * a non-zero value is always passed through.
 */
#include "kavach_eval.h"

#define S_IFMT 00170000
#define S_IFREG 0100000
#define S_IXUGO 00111
#define AF_UNSPEC 0

/* --- identity ------------------------------------------------------------------------------ */

static __always_inline void kv_inode_key(struct inode *ino, struct kv_exe_key *k)
{
	k->dev = BPF_CORE_READ(ino, i_sb, s_dev);
	k->generation = BPF_CORE_READ(ino, i_generation);
	k->ino = BPF_CORE_READ(ino, i_ino);
}

static __always_inline void kv_current_exe(struct kv_exe_key *k)
{
	struct task_struct *t = bpf_get_current_task_btf();
	/* mm (and so exe_file) is NULL for kernel threads: the key stays zero = unclassified. */
	struct inode *ino = BPF_CORE_READ(t, mm, exe_file, f_inode);
	if (ino)
		kv_inode_key(ino, k);
}

static __always_inline __u64 kv_current_cg_mask(__u64 cgid, __u32 slot)
{
	__u64 m = kv_cgroup_mask(cgid, slot);
#pragma unroll
	for (int level = 1; level <= KV_CGROUP_LEVELS; level++) {
		__u64 id = bpf_get_current_ancestor_cgroup_id(level);
		if (!id || id == cgid)
			break;
		m |= kv_cgroup_mask(id, slot);
	}
	return m;
}

/* --- sockaddr ------------------------------------------------------------------------------ */

#define KV_SA_OK 0
#define KV_SA_IGNORE 1 /* AF_UNSPEC (UDP disconnect), AF_UNIX, ... : not ours to judge */

static __always_inline int kv_sockaddr(struct sockaddr *addr, int addrlen, __u32 *remote,
				       __u16 *port, __u8 *family)
{
	__u16 fam = 0;

	if (!addr || addrlen < (int)sizeof(fam))
		return KV_SA_IGNORE;
	bpf_probe_read_kernel(&fam, sizeof(fam), &addr->sa_family);
	if (fam == AF_INET) {
		struct sockaddr_in sin;
		if (addrlen < (int)sizeof(sin))
			return KV_SA_IGNORE; /* the kernel will reject it with -EINVAL */
		bpf_probe_read_kernel(&sin, sizeof(sin), addr);
		kv_map_v4(remote, sin.sin_addr.s_addr);
		*port = bpf_ntohs(sin.sin_port);
		*family = KV_AF_INET;
		return KV_SA_OK;
	}
	if (fam == AF_INET6) {
		struct sockaddr_in6 sin6;
		if (addrlen < 24) /* SIN6_LEN_RFC2133 */
			return KV_SA_IGNORE;
		bpf_probe_read_kernel(&sin6, sizeof(sin6), addr);
		/* IPv4-mapped destinations on dual-stack sockets normalise to the same bytes as
		 * AF_INET, so one rule covers both. */
		kv_copy_v6(remote, &sin6.sin6_addr);
		*port = bpf_ntohs(sin6.sin6_port);
		*family = KV_AF_INET6;
		return KV_SA_OK;
	}
	return KV_SA_IGNORE;
}

/* --- egress decision ----------------------------------------------------------------------- */

static __always_inline void kv_emit_egress(const struct kv_identity *id, const __u32 *remote,
					   __u16 port, __u8 family, __u8 proto,
					   const struct kv_decision *d, __u32 gen)
{
	struct kv_event *e = kv_event_reserve();
	if (!e)
		return;
	e->kind = KV_EVENT_KIND_EGRESS_VERDICT;
	e->verdict = d->verdict;
	e->reason = d->verdict == KV_VERDICT_DROP ? KV_STAT_EGRESS_DROP : KV_STAT_EGRESS_LOG;
	e->key.family = family;
	e->key.proto = proto;
	e->key.dport = bpf_htons(port);
	__builtin_memcpy(e->key.dst, remote, 16);
	e->pid = id->pid;
	e->uid = id->uid;
	e->cgroup_id = id->cgroup_id;
	e->identity = id->mask;
	e->rule_id = d->rule_id;
	e->generation = gen;
	__builtin_memcpy(e->comm, id->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

static __always_inline int kv_egress(struct socket *sock, struct sockaddr *addr, int addrlen)
{
	__u32 remote[4] = {};
	__u16 port = 0;
	__u8 family = 0;
	struct kv_snapshot s;

	if (kv_sockaddr(addr, addrlen, remote, &port, &family) != KV_SA_OK)
		return 0;

	struct sock *sk = sock->sk;
	if (!sk)
		return 0;
	__u8 proto = (__u8)BPF_CORE_READ(sk, sk_protocol);
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP &&
	    proto != IPPROTO_ICMPV6)
		return 0;

	if (kv_snapshot_get(&s))
		return 0; /* no policy loaded yet */

	if (!(s.pol->hdr.flags & KV_POL_F_NO_LOOPBACK_BYPASS) && kv_is_loopback(remote))
		return 0;

	/* Who is talking? (FR-ID-1) */
	struct kv_identity id = {};
	__u64 ugid = bpf_get_current_uid_gid();
	id.uid = (__u32)ugid;
	id.gid = ugid >> 32;
	id.pid = bpf_get_current_pid_tgid() >> 32;
	id.cgroup_id = bpf_get_current_cgroup_id();
	bpf_get_current_comm(id.comm, sizeof(id.comm));
	kv_current_exe(&id.exe);

	struct kv_policy *pol = s.pol;
	__u64 exe_m = pol->hdr.wild_exe == ~0ULL ? 0 : kv_exe_mask(&id.exe, s.slot);
	__u64 uid_m = pol->hdr.wild_uid == ~0ULL ? 0 : kv_uid_mask(id.uid, s.slot);
	__u64 cg_m = pol->hdr.wild_cgroup == ~0ULL ? 0 : kv_current_cg_mask(id.cgroup_id, s.slot);
	id.mask = kv_combine_mask(pol, exe_m, uid_m, cg_m);
	id.generation = s.gen;

	struct kv_decision d;
	kv_evaluate(&s, KV_DIR_EGRESS, id.mask, remote, port, proto, &d);

	/* Remember the owner for TC and user space (freed with the socket). */
	struct kv_identity *slot_id =
		bpf_sk_storage_get(&sk_ident, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (slot_id)
		*slot_id = id;

	switch (d.verdict) {
	case KV_VERDICT_DROP:
		kv_count(KV_STAT_EGRESS_DROP);
		kv_emit_egress(&id, remote, port, family, proto, &d, s.gen);
		return -EPERM;
	case KV_VERDICT_LOG:
		kv_count(KV_STAT_EGRESS_LOG);
		kv_emit_egress(&id, remote, port, family, proto, &d, s.gen);
		return 0;
	default:
		kv_count(KV_STAT_EGRESS_ALLOW);
		return 0;
	}
}

SEC("lsm/socket_connect")
int BPF_PROG(kavach_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	if (ret)
		return ret;
	return kv_egress(sock, address, addrlen);
}

/*
 * Unconnected UDP (sendto / sendmsg with a name) and TCP Fast Open (MSG_FASTOPEN carries the
 * destination without a connect()). Connected sockets (no msg_name) were judged at connect time.
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(kavach_sendmsg, struct socket *sock, struct msghdr *msg, int size, int ret)
{
	if (ret)
		return ret;
	struct sockaddr *name = BPF_CORE_READ(msg, msg_name);
	int namelen = BPF_CORE_READ(msg, msg_namelen);
	if (!name || namelen <= 0)
		return 0;
	return kv_egress(sock, name, namelen);
}

/* --- executable lifecycle ------------------------------------------------------------------ */

static __always_inline void kv_emit_exe(__u8 kind, const struct kv_exe_key *k)
{
	struct kv_event *e = kv_event_reserve();
	if (!e)
		return;
	e->kind = kind;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->identity = k->ino;
	e->rule_id = k->dev;
	e->generation = k->generation;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

/* A new program image is running: ask kavachd to classify it if we do not know it (FR-ID-2). */
SEC("lsm/bprm_committed_creds")
int BPF_PROG(kavach_exec, struct linux_binprm *bprm)
{
	struct kv_exe_key k = {};
	struct inode *ino = BPF_CORE_READ(bprm, file, f_inode);
	if (!ino)
		return 0;
	kv_inode_key(ino, &k);

	struct kv_exe_class *c = bpf_map_lookup_elem(&exe_class, &k);
	if (c) {
		__u64 *dirty = bpf_map_lookup_elem(&exe_dirty, &k);
		if ((dirty ? *dirty : 0) == c->seq_at_hash)
			return 0; /* known and unmodified */
	}
	kv_emit_exe(KV_EVENT_KIND_EXEC, &k);
	return 0;
}

static __always_inline void kv_taint(struct inode *ino)
{
	umode_t mode = BPF_CORE_READ(ino, i_mode);
	if ((mode & S_IFMT) != S_IFREG || !(mode & S_IXUGO))
		return;

	struct kv_exe_key k = {};
	kv_inode_key(ino, &k);
	__u64 *d = bpf_map_lookup_elem(&exe_dirty, &k);
	if (d) {
		__sync_fetch_and_add(d, 1);
	} else {
		__u64 one = 1;
		if (bpf_map_update_elem(&exe_dirty, &k, &one, BPF_NOEXIST)) {
			d = bpf_map_lookup_elem(&exe_dirty, &k);
			if (d)
				__sync_fetch_and_add(d, 1);
		}
	}
	if (bpf_map_lookup_elem(&exe_class, &k))
		kv_emit_exe(KV_EVENT_KIND_EXE_TAINTED, &k);
}

/* FR-ID-3: opening a classified executable for write revokes its identity. */
SEC("lsm/file_open")
int BPF_PROG(kavach_file_open, struct file *file, int ret)
{
	if (ret)
		return ret;
	struct inode *ino = BPF_CORE_READ(file, f_inode);
	if (!ino)
		return 0;
	if (BPF_CORE_READ(file, f_mode) & FMODE_WRITE) {
		kv_taint(ino);
		return 0;
	}
	/* Read-open by kavachd: report the kernel key of this inode (pre-classification). */
	__u32 zero = 0;
	__u32 *self = bpf_map_lookup_elem(&self_tgid, &zero);
	if (self && *self && *self == (__u32)(bpf_get_current_pid_tgid() >> 32)) {
		struct kv_exe_key k = {};
		kv_inode_key(ino, &k);
		kv_emit_exe(KV_EVENT_KIND_KEY_REPORT, &k);
	}
	return 0;
}

/* truncate(2) modifies a file without opening it. */
SEC("lsm/path_truncate")
int BPF_PROG(kavach_truncate, const struct path *path, int ret)
{
	if (ret)
		return ret;
	struct inode *ino = BPF_CORE_READ(path, dentry, d_inode);
	if (ino)
		kv_taint(ino);
	return 0;
}

/*
 * Startup scan: kavachd runs this task iterator once so processes that were already running
 * before Kavach started get classified too (user space cannot compute the kernel's ExeKey).
 */
SEC("iter/task")
int kavach_task_scan(struct bpf_iter__task *ctx)
{
	struct task_struct *task = ctx->task;
	if (!task)
		return 0;
	if (BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid))
		return 0; /* one event per process, not per thread */
	struct inode *ino = BPF_CORE_READ(task, mm, exe_file, f_inode);
	if (!ino)
		return 0; /* kernel thread */

	struct kv_exe_key k = {};
	kv_inode_key(ino, &k);
	struct kv_exe_class *c = bpf_map_lookup_elem(&exe_class, &k);
	if (c) {
		__u64 *dirty = bpf_map_lookup_elem(&exe_dirty, &k);
		if ((dirty ? *dirty : 0) == c->seq_at_hash)
			return 0;
	}
	struct kv_event *e = kv_event_reserve();
	if (!e)
		return 0;
	e->kind = KV_EVENT_KIND_EXEC;
	e->pid = BPF_CORE_READ(task, tgid);
	e->identity = k.ino;
	e->rule_id = k.dev;
	e->generation = k.generation;
	BPF_CORE_READ_STR_INTO(&e->comm, task, comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
