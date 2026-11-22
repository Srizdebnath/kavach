# kavach.ko — Rust-for-Linux module (v0.4, planned)

**Goal:** run the *same* `kavach-core` evaluator in the kernel that `kavachctl explain` runs in
user space. Today the eBPF hot path uses a C mirror (`bpf/include/kavach_eval.h`), and the
differential test keeps the two in lockstep. The module removes the duplication.

## Design
* `kavach_ko.rs` is a `kernel::Module` that registers a BTF kfunc set:
  ```c
  __bpf_kfunc int kavach_evaluate(const struct kv_policy *pol, __u32 dir, __u64 mask,
                                  const __u32 remote[4], __u16 port, __u8 proto,
                                  struct kv_decision *out);
  ```
  It is registered with `register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, …)` and
  `…(BPF_PROG_TYPE_SCHED_CLS, …)`, flagged `KF_TRUSTED_ARGS`. The body calls
  `kavach_core::evaluate` through a `Tables` implementation over the map values passed in. No
  allocation, no sleeping, bounded by `n_rules ≤ 1024`.
* The BPF programs declare it `__ksym __weak`. At load time kavachd checks
  `bpf_ksym_exists(kavach_evaluate)` and the programs call it instead of `kv_evaluate`, which
  remains as the fallback. Policy semantics are therefore identical with or without the module.
* `kavach-common` and `kavach-core` are already `#![no_std]` with no `alloc`, and CI builds them
  for a bare-metal target to keep them that way.

## Requirements
* Kernel built with `CONFIG_RUST=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y`. The development host
  runs 7.1 with `CONFIG_RUST=y`.
* Build out of tree against the running kernel's build directory:
  `make -C /lib/modules/$(uname -r)/build M=$PWD LLVM=1`.

## Verification plan
* Differential testing: the existing 400-flow test runs twice, once with the module loaded and
  once without, and the verdicts must be identical.
* syzkaller descriptions for the kfunc (SR-6).
