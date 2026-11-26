// SPDX-License-Identifier: GPL-2.0-only
/*
 * kavach_kfunc.c — the `kavach_evaluate` kfunc entry point and its BTF registration.
 *
 * Thin by design: the evaluator is Rust (kavach_ko.rs -> kavach-core). This file exists because
 * a kfunc must have a BTF FUNC record in the module's BTF, and pahole (which generates module
 * BTF from DWARF) skips Rust compilation units. The ABI is bpf/include/kavach_kfunc.h.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/build_bug.h>
#include <linux/module.h>
#include <linux/stddef.h>
#include <linux/types.h>

#include "kavach_kfunc.h"

/* kavach_ko.rs */
int kavach_rs_evaluate(const void *pol, u32 pol_sz, const void *req, void *res);
int kavach_kfunc_register(void);

__bpf_kfunc_start_defs();

/**
 * kavach_evaluate - evaluate one flow against a Kavach policy slot (kavach-core semantics)
 * @pol:     value of the `policy_slots` map for the caller's snapshot slot
 * @pol__sz: sizeof(struct kv_policy) as the BPF object was compiled (checked)
 * @req:     flow and precomputed lookups (struct kavach_eval_req)
 * @res:     decision (struct kavach_eval_res), written on success only
 *
 * Return: 0, -EINVAL on an ABI size mismatch, -ENOENT if the slot is not valid.
 * Never sleeps, never allocates, bounded by KV_MAX_RULES iterations.
 */
__bpf_kfunc int kavach_evaluate(const void *pol, u32 pol__sz, const struct kavach_eval_req *req,
				struct kavach_eval_res *res)
{
	return kavach_rs_evaluate(pol, pol__sz, req, res);
}

__bpf_kfunc_end_defs();

/*
 * No KF_* flags: every argument is plain memory (`void *` + `__sz`, or a pointer to a struct of
 * scalars), which the verifier bounds-checks by size for any kfunc. KF_TRUSTED_ARGS /
 * KF_RCU only constrain pointers to BTF kernel objects, and the kfunc neither acquires nor
 * releases anything, nor sleeps (so not KF_SLEEPABLE: callable from LSM and TC alike).
 */
BTF_KFUNCS_START(kavach_kfunc_ids)
BTF_ID_FLAGS(func, kavach_evaluate)
BTF_KFUNCS_END(kavach_kfunc_ids)

static const struct btf_kfunc_id_set kavach_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &kavach_kfunc_ids,
};

int kavach_kfunc_register(void)
{
	int ret;

	/* Mirrors of the Rust const asserts (kavach_ko.rs). */
	BUILD_BUG_ON(sizeof(struct kavach_eval_req) != 32);
	BUILD_BUG_ON(sizeof(struct kavach_eval_res) != 8);
	BUILD_BUG_ON(offsetof(struct kavach_eval_req, port) != 24);
	BUILD_BUG_ON(offsetof(struct kavach_eval_req, dir) != 27);
	BUILD_BUG_ON(offsetof(struct kavach_eval_res, verdict) != 4);
	BUILD_BUG_ON(offsetof(struct kavach_eval_res, gateway) != 6);

	/* lsm/socket_connect, lsm/socket_sendmsg (BTF_KFUNC_HOOK_LSM). Only LSM and TC programs
	 * call kv_evaluate (bpf/lsm_egress.c, bpf/tc_flow.c); a program of any other type that
	 * referenced the kfunc would be rejected by the verifier once the module is loaded. */
	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &kavach_kfunc_set);
	if (ret)
		return ret;
	/* classifier programs (tc_flow.c). */
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &kavach_kfunc_set);
}
