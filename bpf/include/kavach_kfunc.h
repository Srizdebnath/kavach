/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ABI of the optional `kavach_evaluate` kfunc exported by kernel/kavach-ko (kavach.ko).
 *
 * Shared by the eBPF programs (through kavach_eval.h) and by the module's C shim. The Rust side
 * of the module mirrors these structs and both sides assert the same sizes and offsets.
 *
 * BPF calls take at most five arguments and the verifier only accepts kfunc memory arguments
 * that point to scalars or to structs made of scalars (no arrays of structs), so:
 *   - the policy slot is passed as `void *` plus a `__sz` size argument, and the module checks
 *     that the size is exactly sizeof(struct kv_policy);
 *   - everything else travels in one scalar request struct on the BPF stack;
 *   - the LPM lookup in `addr_sets` and the clock read stay in BPF (the module never touches BPF
 *     maps), so `sets` and `now_ns` are inputs.
 *
 * Returns 0 and fills @res, or a negative errno (the caller then uses the C evaluator).
 *
 *   int kavach_evaluate(const void *pol, __u32 pol__sz,
 *                       const struct kavach_eval_req *req, struct kavach_eval_res *res);
 */
#ifndef KAVACH_KFUNC_H
#define KAVACH_KFUNC_H

struct kavach_eval_req {
	__u64 mask;   /* selector mask of the local identity (0 for ingress) */
	__u64 sets;   /* kv_remote_sets() bitmap for the remote address, same slot */
	__u64 now_ns; /* bpf_ktime_get_boot_ns() */
	__u16 port;   /* service port, host order */
	__u8 proto;
	__u8 dir;     /* KV_DIR_EGRESS / KV_DIR_INGRESS */
	__u32 _pad;
};

struct kavach_eval_res {
	__u32 rule_id; /* 0 = default verdict */
	__u8 verdict;  /* final: Allow / Drop / Log (Punt resolved through the fail mode) */
	__u8 punted;
	__u16 _pad;
};

#define KAVACH_EVAL_REQ_SIZE 32
#define KAVACH_EVAL_RES_SIZE 8

_Static_assert(sizeof(struct kavach_eval_req) == KAVACH_EVAL_REQ_SIZE, "kavach_eval_req ABI");
_Static_assert(sizeof(struct kavach_eval_res) == KAVACH_EVAL_RES_SIZE, "kavach_eval_res ABI");

#endif /* KAVACH_KFUNC_H */
