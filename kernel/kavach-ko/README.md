# kavach.ko — Rust-for-Linux kfunc module (v0.4)

**Goal:** run the *same* `kavach-core` evaluator in the kernel that `kavachctl explain` runs in
user space. The eBPF hot path has a C mirror (`bpf/include/kavach_eval.h`); differential tests
keep the two in lockstep, and the module lets the programs call the Rust original instead.

**Status:** the source is complete and host-tested (`host-check.sh`); building it needs a
Rust-enabled kernel tree, and loading it is only ever done inside a VM
(`.github/workflows/kavach-ko.yml`, manual trigger). kavachd loads its programs with aya, which
cannot bind module kfuncs yet, so **in production the C evaluator always runs** and kavachd logs
`policy evaluator: built-in; kavach.ko is loaded but ... unused`. libbpf-based loaders (bpftool,
the self-test) do bind it.

## Layout

| File | What |
|---|---|
| `kavach_ko.rs` | `kernel::Module`; `kavach_rs_evaluate`, the kfunc body: validates its arguments, then runs `kavach_core::evaluate` |
| `kavach_kfunc.c` | the `kavach_evaluate` symbol and its BTF kfunc set (pahole emits no BTF for Rust units, so the symbol the verifier resolves is C) |
| `vendor.sh` | Kbuild Rust has no cargo: inlines `kavach-common` (abi, addr) and `kavach-core` as modules, dropping only the bytemuck derives; fails if they ever need std/alloc/another crate |
| `Kbuild`, `Makefile` | out-of-tree build (`make` generates `kavach_vendor.rs` first) |
| `host-check.sh`, `host-check/` | compile the Rust half against a stub `kernel` crate and unit-test it against kavach-core (no kernel needed; CI lint job) |
| `selftest.py` | differential self-test in a VM: kfunc vs C evaluator through `BPF_PROG_TEST_RUN` |
| `ci.sh` | build a Rust kernel, the module, boot it under virtme-ng, run the self-tests; syzkaller |
| `syz/` | syzkaller descriptions + `syz-manager` config template (SRS SR-6) |

## The kfunc

ABI: `bpf/include/kavach_kfunc.h` (both sides assert sizes and offsets).

```c
__bpf_kfunc int kavach_evaluate(const void *pol, u32 pol__sz,
                                const struct kavach_eval_req *req, struct kavach_eval_res *res);
```

* `pol` is the caller's `policy_slots` value, `pol__sz` must equal `sizeof(struct kv_policy)`
  (a BPF object built against another ABI gets `-EINVAL`). The verifier bounds-checks `pol` by
  `pol__sz` and `req`/`res` by their struct sizes; the module additionally rejects NULL and
  misaligned pointers (`-EINVAL`) before forming references, and an invalid slot (`-ENOENT`).
  On error `res` is untouched.
* `req` carries what the module cannot look up itself (it never touches BPF maps): the selector
  mask, the `addr_sets` bitmap, `bpf_ktime_get_boot_ns()`, port, protocol, direction.
* `res` returns rule id, final verdict (Allow/Drop/Log: Punt resolved through the rule's fail
  mode), `punted`, and the punting rule's `gateway` index for the L7 redirect.
* Registered for `BPF_PROG_TYPE_LSM` and `BPF_PROG_TYPE_SCHED_CLS` (the only callers of
  `kv_evaluate`) with **no `KF_*` flags**: all arguments are plain memory, which the verifier
  checks by size for any kfunc; `KF_TRUSTED_ARGS`/`KF_RCU` only concern pointers to kernel
  objects, nothing is acquired or released, and it never sleeps. No allocation; bounded by
  `KV_MAX_RULES` iterations.
* The programs declare it `__ksym __weak` and test `bpf_ksym_exists()`. Without the module the
  symbol resolves to 0 and the verifier drops the call as dead code, so the object loads on
  every 6.1+ kernel; a non-zero return also falls back to the C mirror. Either way the result
  goes through the same fail-closed clamp (out-of-range or unresolved Punt -> Drop).

## Building

Needs a kernel tree built with `CONFIG_RUST=y` and `CONFIG_DEBUG_INFO_BTF_MODULES=y`, the
compiler family it was built with (`LLVM=1` for clang kernels), *exactly* its `rustc`
(`CONFIG_RUSTC_VERSION_TEXT`), bindgen and pahole:

```sh
make -C kernel/kavach-ko KDIR=/path/to/linux [LLVM=1]
```

Distribution kernels with `CONFIG_RUST=y` (e.g. Arch) only work if their headers package ships
the Rust metadata *and* matches the running kernel exactly; on the development host
`/lib/modules/$(uname -r)/build` does not exist (headers not installed on purpose), so the
module is built in CI instead:

```sh
kernel/kavach-ko/ci.sh deps        # Ubuntu: build deps, rust-src, bindgen (CI)
kernel/kavach-ko/ci.sh kernel      # clone a stable tag, minimal virtme-ng config + Kavach options
kernel/kavach-ko/ci.sh module      # build kavach.ko, check its BTF has FUNC 'kavach_evaluate'
kernel/kavach-ko/ci.sh selftest    # boot the kernel under virtme-ng (see below)
```

## Verification

| Check | Where | Needs |
|---|---|---|
| `kernel::abi_tests` (object references `kavach_evaluate` weakly; evaluator reporting) | `cargo test` | nothing |
| `host-check.sh`: kfunc body == kavach-core on 15k random flows, argument validation, ABI sizes | CI lint job | rustc |
| `fuzz/fuzz_targets/kfunc_evaluate.rs`: arbitrary slots + requests, first-match oracle and invariants | `cargo +nightly fuzz run kfunc_evaluate` | nightly |
| `evaluator_falls_back_to_c_without_kavach_ko`: every caller passes the verifier with no kfunc call left in the translated program; kavachd reports the built-in evaluator; verdicts == kavach-core | `scripts/priv-test.sh`, CI, kernel matrix | root |
| `differential_random_policy_tables_vs_core`: C evaluator == kavach-core on raw random tables | same | root |
| `selftest.py`: with the module (TC/LSM programs contain the kfunc call) and without (they do not), identical verdicts and rule ids | `ci.sh selftest`, **VM only** | Rust kernel |
| privileged suite with the module loaded | `ci.sh selftest`, **VM only** | Rust kernel |
| syzkaller | `ci.sh syz`, **VM only** | KASAN kernel |

Never `insmod` kavach.ko on a machine you care about: `selftest.py` mounts fresh bpffs instances
and loads and unloads the module; `ci.sh` only ever does it inside the virtme-ng guest.

## Fuzzing (SRS SR-6)

`syz/kavach.txt` describes the paths into the kfunc: `BPF_MAP_CREATE`/`BPF_MAP_UPDATE_ELEM` of a
`policy_slots`-shaped map with fuzzed `struct kv_policy` tables, `BPF_PROG_LOAD` of TC and LSM
programs that call `kavach_evaluate` with verifier-valid arguments (the size argument, request
fields and map flags fuzzed), `BPF_PROG_TEST_RUN` of the TC program, and attaching the LSM one.

`ci.sh kernel --fuzz` builds a separate KASAN + KCOV kernel with kavach **built into vmlinux**
(`drivers/kavach`, generated): stock syzkaller resolves kfunc BTF ids from
`/sys/kernel/btf/vmlinux` only and encodes kfunc calls against vmlinux BTF, so a loadable
module's split-BTF id would be unreachable. `ci.sh syz MINUTES` then checks out the pinned
syzkaller revision, copies the descriptions into `sys/linux/`, builds it, creates a Debian image
(`tools/create-image.sh`, needs sudo + debootstrap), renders `syz/syz-manager.cfg.in` and fuzzes
for the given time; any crash fails the run (`syz-workdir/crashes`, uploaded as an artifact).

The descriptions and the config template were checked with that syzkaller revision
(`syz-sysgen`, program generation with `syz-mutate`, the manager config parser); the fuzz kernel
and a fuzzing run are only exercised by the manual workflow.
