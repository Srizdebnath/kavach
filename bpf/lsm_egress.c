// SPDX-License-Identifier: GPL-2.0-only
/*
 * lsm_egress.c — Kavach v0.2 identity-aware egress (BPF-LSM).
 *
 *   socket_connect / socket_sendmsg  → who (exe, uid, cgroup subtree) → rule scan → 0 | -EPERM
 *   bprm_committed_creds             → Exec event so kavachd can hash + classify the binary
 *   file_open (write) / path_truncate / file_truncate → delete exe_class (tamper revocation)
 *   inode_free_security               → delete exe_class (a recycled inode never inherits one)
 *   file_open (kavachd, armed key_req) → placeholder + KeyReport (classification protocol)
 *
 * Requirements: FR-ID-1..6, FR-EG-1..5. LSM hooks get a trailing `ret` (result of earlier LSMs):
 * a non-zero value is always passed through.
 */
#include "kavach_eval.h"

#define S_IFMT 00170000
#define S_IFREG 0100000
#define AF_UNSPEC 0

/* --- identity ------------------------------------------------------------------------------ */

static __always_inline void kv_inode_key(struct inode *ino, struct kv_exe_key *k)
{
	k->inode = (__u64)(unsigned long)ino;
	k->ino = BPF_CORE_READ(ino, i_ino);
	k->dev = BPF_CORE_READ(ino, i_sb, s_dev);
	k->generation = BPF_CORE_READ(ino, i_generation);
}

/* Exe-kind events carry the key in identity / rule_id / generation / key.dst[0..2]. */
static __always_inline void kv_event_exe_key(struct kv_event *e, const struct kv_exe_key *k)
{
	e->identity = k->ino;
	e->rule_id = (__u32)k->inode;
	e->generation = (__u32)(k->inode >> 32);
	e->key.dst[0] = k->dev;
	e->key.dst[1] = k->generation;
}

/* Block devices served by a user-space process (nbd, ublk): the bytes under a mounted,
 * "trusted" filesystem can change at will. Loop devices are judged by kavachd, which can check
 * who owns the image (crates/kavachd/src/backing.rs), and so are dm/md stacks. */
static __always_inline bool kv_user_backed_bdev(struct super_block *sb)
{
	struct block_device *bdev = BPF_CORE_READ(sb, s_bdev);
	if (!bdev)
		return false;
	struct gendisk *disk = BPF_CORE_READ(bdev, bd_disk);
	if (!disk)
		return false;
	char n[6] = {};
	bpf_core_read_str(n, sizeof(n), &disk->disk_name);
	if (n[0] == 'n' && n[1] == 'b' && n[2] == 'd')
		return true;
	if (n[0] == 'u' && n[1] == 'b' && n[2] == 'l' && n[3] == 'k')
		return true;
	return false;
}

#define KV_SB_KERNMOUNT (1 << 22)
#define KV_EXT4_MAGIC 0xEF53
#define KV_XFS_MAGIC 0x58465342
#define KV_BTRFS_MAGIC 0x9123683E
#define KV_TMPFS_MAGIC 0x01021994
#define KV_F2FS_MAGIC 0xF2F52010
#define KV_SQUASHFS_MAGIC 0x73717368
#define KV_EROFS_MAGIC 0xE0F5E1E2
#define KV_OVERLAYFS_MAGIC 0x794C7630

/*
 * Can a hash of this file be trusted to stay true? Only on local filesystems where every
 * content change goes through a write-open or truncate we hook. Not: kernel-internal mounts
 * (memfd/shm: written without file_open, i_writecount stays 0), FUSE (the server can serve
 * different bytes to different readers), network filesystems (remote writers), overlayfs
 * (rootless users can rewrite the lower/upper file behind the overlay inode).
 */
static __always_inline bool kv_trusted_file(struct file *f)
{
	if (BPF_CORE_READ(f, f_path.mnt, mnt_flags) & MNT_INTERNAL)
		return false;
	struct super_block *sb = BPF_CORE_READ(f, f_inode, i_sb);
	if (BPF_CORE_READ(sb, s_flags) & KV_SB_KERNMOUNT)
		return false;
	if (kv_user_backed_bdev(sb))
		return false;
	switch (BPF_CORE_READ(sb, s_magic)) {
	case KV_EXT4_MAGIC:
	case KV_XFS_MAGIC:
	case KV_BTRFS_MAGIC:
	case KV_TMPFS_MAGIC:
	case KV_F2FS_MAGIC:
	case KV_SQUASHFS_MAGIC:
	case KV_EROFS_MAGIC:
		return true;
	default:
		return false;
	}
}

static __always_inline bool kv_is_overlay(struct file *f)
{
	return BPF_CORE_READ(f, f_inode, i_sb, s_magic) == KV_OVERLAYFS_MAGIC;
}

struct kv_vma_ctx {
	struct file *file;
};

static long kv_vma_file(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
	struct kv_vma_ctx *c = data;
	c->file = BPF_CORE_READ(vma, vm_file);
	return 0;
}

/*
 * Overlay executables (containers): the identity is the *real* file overlay maps the code from.
 * ovl_mmap installs the backing (upper or lower-data) file in the VMA, so the VMA holding the
 * code segment names the real ext4/xfs/... inode. Writes to that file (e.g. a rootless user
 * editing a layer directly) taint exactly that inode, and a copy-up creates a new one.
 */
static __always_inline struct file *kv_real_exe(struct task_struct *t, struct file *exe)
{
	if (!kv_is_overlay(exe))
		return exe;
	struct kv_vma_ctx c = {};
	__u64 code = BPF_CORE_READ(t, mm, start_code);
	if (!code || bpf_find_vma(t, code, kv_vma_file, &c, 0))
		return NULL; /* mmap lock contended or no mapping: unclassified (fail closed) */
	if (!c.file || kv_is_overlay(c.file))
		return NULL;
	return c.file;
}

static __always_inline void kv_current_exe(struct kv_exe_key *k)
{
	struct task_struct *t = bpf_get_current_task_btf();
	/* mm (and so exe_file) is NULL for kernel threads: the key stays zero = unclassified. */
	struct file *exe = BPF_CORE_READ(t, mm, exe_file);
	if (!exe)
		return;
	exe = kv_real_exe(t, exe);
	if (!exe || !kv_trusted_file(exe))
		return;
	struct inode *ino = BPF_CORE_READ(exe, f_inode);
	/* A binary someone holds open for write may already differ from what was hashed. */
	if (!ino || BPF_CORE_READ(ino, i_writecount.counter) > 0)
		return;
	kv_inode_key(ino, k);
}

/* Committed (not a placeholder) classification for this key? */
static __always_inline bool kv_exe_known(const struct kv_exe_key *k)
{
	struct kv_exe_class *c = bpf_map_lookup_elem(&exe_class, k);
	return c && (c->flags & KV_EXE_F_COMMITTED);
}

/* cgroup subtree classes OR'd over the path, plus (KV_POL_F_WORKLOAD) the workload class of the
 * nearest classified cgroup: the task's own, else the deepest ancestor (levels run root-down). */
static __always_inline __u64 kv_current_cg_mask(__u64 cgid, __u32 slot, bool wl)
{
	__u64 m = kv_cgroup_mask(cgid, slot);
	bool self_hit = false, hit = false;
	__u64 wl_m = wl ? kv_wl_mask(cgid, slot, &self_hit) : 0;
#pragma unroll
	for (int level = 1; level <= KV_CGROUP_LEVELS; level++) {
		__u64 id = bpf_get_current_ancestor_cgroup_id(level);
		if (!id || id == cgid)
			break;
		m |= kv_cgroup_mask(id, slot);
		if (wl && !self_hit) {
			__u64 a = kv_wl_mask(id, slot, &hit);
			if (hit)
				wl_m = a;
		}
	}
	return m | wl_m;
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
					   const struct kv_decision *d, __u32 gen,
					   __u8 reason)
{
	struct kv_event *e = kv_event_reserve();
	if (!e)
		return;
	e->kind = KV_EVENT_KIND_EGRESS_VERDICT;
	e->verdict = d->verdict;
	e->reason = reason;
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
	__u64 cg_m = pol->hdr.wild_cgroup == ~0ULL ? 0 : kv_current_cg_mask(id.cgroup_id, s.slot, pol->hdr.flags & KV_POL_F_WORKLOAD);
	id.mask = kv_combine_mask(pol, exe_m, uid_m, cg_m);
	id.generation = s.gen;

	struct kv_decision d;
	/* Strict mode: a binary we could classify but have not yet is refused until we have. */
	if ((pol->hdr.flags & KV_POL_F_UNCLASSIFIED_DENY) && pol->hdr.wild_exe != ~0ULL &&
	    id.exe.inode && !kv_exe_known(&id.exe)) {
		struct kv_decision u = { .verdict = KV_VERDICT_DROP };
		kv_count(KV_STAT_EGRESS_UNCLASSIFIED);
		kv_emit_egress(&id, remote, port, family, proto, &u, s.gen, KV_STAT_EGRESS_UNCLASSIFIED);
		return -EPERM;
	}

	kv_evaluate(&s, KV_DIR_EGRESS, id.mask, remote, port, proto, &d);

	/* Remember the owner for TC and user space (freed with the socket). */
	struct kv_identity *slot_id =
		bpf_sk_storage_get(&sk_ident, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (slot_id)
		*slot_id = id;

	switch (d.verdict) {
	case KV_VERDICT_DROP:
		kv_count(KV_STAT_EGRESS_DROP);
		kv_emit_egress(&id, remote, port, family, proto, &d, s.gen, KV_STAT_EGRESS_DROP);
		return -EPERM;
	case KV_VERDICT_LOG:
		kv_count(KV_STAT_EGRESS_LOG);
		kv_emit_egress(&id, remote, port, family, proto, &d, s.gen, KV_STAT_EGRESS_LOG);
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
	kv_event_exe_key(e, k);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

/* A new program image is running: ask kavachd to classify it if we do not know it (FR-ID-2). */
SEC("lsm/bprm_committed_creds")
int BPF_PROG(kavach_exec, struct linux_binprm *bprm)
{
	struct file *f = BPF_CORE_READ(bprm, file);
	if (!f)
		return 0;
	if (kv_is_overlay(f)) {
		/* The code is not mapped yet, so the real file is unknown here: ask kavachd, which
		 * resolves it through /proc/<pid>/exe (and skips hashing if it is already known). */
		struct kv_exe_key none = {};
		kv_emit_exe(KV_EVENT_KIND_EXEC, &none);
		return 0;
	}
	if (!kv_trusted_file(f))
		return 0; /* never classifiable: do not bother kavachd */
	struct inode *ino = BPF_CORE_READ(f, f_inode);
	if (!ino)
		return 0;
	struct kv_exe_key k = {};
	kv_inode_key(ino, &k);
	if (kv_exe_known(&k))
		return 0; /* classified and unmodified since */
	kv_emit_exe(KV_EVENT_KIND_EXEC, &k);
	return 0;
}

/*
 * Any regular file, whatever its mode: chmod -x / write / chmod +x must not keep the identity.
 * The delete is unconditional because it takes the bucket lock, which orders it against a
 * placeholder insert in kv_key_report (a lockless lookup first would not). If the delete
 * fails for any reason but "absent", the modification is refused (fail closed).
 */
static __always_inline int kv_taint(struct inode *ino)
{
	umode_t mode = BPF_CORE_READ(ino, i_mode);
	if ((mode & S_IFMT) != S_IFREG)
		return 0;

	struct kv_exe_key k = {};
	kv_inode_key(ino, &k);
	/* Compare the low 32 bits: before 6.4, bpf_map_ops returned int, so the helper's 64-bit
	 * result is NOT sign-extended there (-ENOENT reads as 0xfffffffe and every first write to
	 * an unclassified file would be refused). */
	int err = (int)bpf_map_delete_elem(&exe_class, &k);
	if (err == 0)
		kv_emit_exe(KV_EVENT_KIND_EXE_TAINTED, &k);
	else if (err != -ENOENT)
		return -EBUSY;
	return 0;
}

/* kavachd armed key_req and this thread is opening a file read-only: answer once. */
static __always_inline void kv_key_report(struct file *file, struct inode *ino)
{
	__u32 zero = 0;
	struct kv_key_req *req = bpf_map_lookup_elem(&key_req, &zero);
	if (!req)
		return;
	__u64 nonce = READ_ONCE(req->nonce);
	if (!nonce || req->tid != (__u32)bpf_get_current_pid_tgid())
		return;
	/* Overlay: answer for the backing file overlay opens next, inside this same open(). */
	if (kv_is_overlay(file))
		return;
	WRITE_ONCE(req->nonce, 0);

	struct kv_exe_key k = {};
	kv_inode_key(ino, &k);
	bool trusted = kv_trusted_file(file);
	long inserted = -1;
	/* Placeholder first, writers second. A writer increments i_writecount before its own
	 * file_open hook runs: either we see that count here, or its kv_taint takes the bucket
	 * lock after our insert and deletes the placeholder, so kavachd's commit fails. */
	if (trusted) {
		struct kv_exe_class ph = { .nonce = nonce };
		inserted = bpf_map_update_elem(&exe_class, &k, &ph, BPF_NOEXIST);
	}
	int writers = BPF_CORE_READ(ino, i_writecount.counter);

	struct kv_event *e = kv_event_reserve();
	if (!e) {
		if (inserted == 0) /* nobody will ever commit or abandon it */
			bpf_map_delete_elem(&exe_class, &k);
		return;
	}
	e->kind = KV_EVENT_KIND_KEY_REPORT;
	e->verdict = (writers > 0 ? KV_REPORT_WRITERS : 0) | (trusted ? 0 : KV_REPORT_UNTRUSTED_FS);
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->cgroup_id = nonce;
	kv_event_exe_key(e, &k);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

/* FR-ID-3: opening a file for write revokes its identity. */
SEC("lsm/file_open")
int BPF_PROG(kavach_file_open, struct file *file, int ret)
{
	if (ret)
		return ret;
	struct inode *ino = BPF_CORE_READ(file, f_inode);
	if (!ino)
		return 0;
	if (BPF_CORE_READ(file, f_mode) & FMODE_WRITE)
		return kv_taint(ino);
	kv_key_report(file, ino);
	return 0;
}

/* truncate(2) modifies a file without opening it. */
SEC("lsm/path_truncate")
int BPF_PROG(kavach_truncate, const struct path *path, int ret)
{
	if (ret)
		return ret;
	struct inode *ino = BPF_CORE_READ(path, dentry, d_inode);
	return ino ? kv_taint(ino) : 0;
}

/* ftruncate(2), and open(O_RDONLY | O_TRUNC), which truncates without FMODE_WRITE (6.2+). */
SEC("lsm/file_truncate")
int BPF_PROG(kavach_file_truncate, struct file *file, int ret)
{
	if (ret)
		return ret;
	struct inode *ino = BPF_CORE_READ(file, f_inode);
	return ino ? kv_taint(ino) : 0;
}

/* The inode is going away: its address may be reused, its classification must not be. */
SEC("lsm/inode_free_security")
int BPF_PROG(kavach_inode_free, struct inode *inode)
{
	struct kv_exe_key k = {};
	kv_inode_key(inode, &k);
	/* lockless check first: this runs for every inode eviction. No insert can race for a
	 * dying inode (an insert needs an open file, which pins the inode). */
	if (bpf_map_lookup_elem(&exe_class, &k))
		bpf_map_delete_elem(&exe_class, &k);
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
	struct file *exe = BPF_CORE_READ(task, mm, exe_file);
	if (!exe)
		return 0; /* kernel thread */
	if (kv_is_overlay(exe)) {
		struct kv_event *o = kv_event_reserve();
		if (!o)
			return 0;
		o->kind = KV_EVENT_KIND_EXEC; /* zero key: kavachd resolves the real file */
		o->pid = BPF_CORE_READ(task, tgid);
		BPF_CORE_READ_STR_INTO(&o->comm, task, comm);
		bpf_ringbuf_submit(o, 0);
		return 0;
	}
	if (!kv_trusted_file(exe))
		return 0; /* never classifiable */
	struct inode *ino = BPF_CORE_READ(exe, f_inode);
	if (!ino)
		return 0;

	struct kv_exe_key k = {};
	kv_inode_key(ino, &k);
	if (kv_exe_known(&k))
		return 0;
	struct kv_event *e = kv_event_reserve();
	if (!e)
		return 0;
	e->kind = KV_EVENT_KIND_EXEC;
	e->pid = BPF_CORE_READ(task, tgid);
	kv_event_exe_key(e, &k);
	BPF_CORE_READ_STR_INTO(&e->comm, task, comm);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
