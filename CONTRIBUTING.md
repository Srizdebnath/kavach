# Contributing to Kavach

## Layout
| Path | What | License |
|---|---|---|
| `bpf/` | eBPF programs in C (XDP, TC, BPF-LSM), one CO-RE object | GPL-2.0-only |
| `crates/kavach-common` | `#[repr(C)]` ABI shared with the kernel (single source of truth) | Apache-2.0 OR MIT |
| `crates/kavach-core` | `no_std` policy evaluator — same semantics as `bpf/include/kavach_eval.h` | Apache-2.0 OR MIT |
| `crates/kavach-policy` | `kavach.toml` compiler, signed bundles, diff | Apache-2.0 OR MIT |
| `crates/kavach-api` | control protocol + hash-chained audit log | Apache-2.0 OR MIT |
| `crates/kavachd`, `crates/kavachctl` | daemon and CLI | Apache-2.0 OR MIT |

## Build
```sh
# clang ≥ 15, bpftool, Rust stable
cargo xtask vmlinux        # bpf/include/vmlinux.h from /sys/kernel/btf/vmlinux
cargo xtask build-bpf      # verify the C side compiles with -Werror
cargo build --workspace
```

## Changing the kernel ABI
Edit `crates/kavach-common/src/abi.rs`, then `cargo xtask codegen`. CI runs `codegen --check`;
the generated header carries `_Static_assert`s for every size and offset. Bump `ABI_VERSION`
in `kavachd` if pinned map layouts change.

## Changing evaluation semantics
Change **both** `kavach_eval.h` and `kavach-core`. The differential test
(`differential_tc_ingress_vs_core`) fails if they disagree.

## Tests
```sh
cargo test --workspace        # unit + property tests, no privileges
scripts/priv-test.sh          # real kernel: verifier, BPF_PROG_TEST_RUN, live LSM hooks (sudo)
```
Privileged tests use private pin directories, only deny TEST-NET ranges, and engage the
kill-switch on drop.

## Commits
Conventional commits (`feat(kavachd): …`, `fix(bpf): …`), one logical change each, with the
requirement IDs from `docs/SRS.md` where relevant. `cargo fmt` and clippy must be clean.
