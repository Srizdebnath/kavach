# Contributing to Kavach

Thanks for helping. Kavach runs code in the kernel and decides what traffic leaves a host, so
we are strict about a few things (memory safety, the kernel ABI, tests) and relaxed about the
rest. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first; security bugs go through
[SECURITY.md](SECURITY.md), never public issues.

## Layout
| Path | What | License |
|---|---|---|
| `bpf/` | eBPF programs in C (XDP, TC, BPF-LSM), one CO-RE object | GPL-2.0-only |
| `kernel/kavach-ko` | planned Rust-for-Linux module (v0.4, not built yet; see its README) | GPL-2.0-only |
| `crates/kavach-common` | `#[repr(C)]` ABI shared with the kernel (single source of truth) | Apache-2.0 OR MIT |
| `crates/kavach-core` | `no_std` policy evaluator — same semantics as `bpf/include/kavach_eval.h` | Apache-2.0 OR MIT |
| `crates/kavach-parsers` | `no_std`, allocation-free parsers for attacker-controlled bytes (TLS, DNS, JA4) | Apache-2.0 OR MIT |
| `crates/kavach-policy` | `kavach.toml` compiler, signed bundles, diff | Apache-2.0 OR MIT |
| `crates/kavach-api` | control protocol + hash-chained audit log | Apache-2.0 OR MIT |
| `crates/kavachd`, `crates/kavachctl`, `crates/kavach-gateway` | daemon, CLI, L7 gateway | Apache-2.0 OR MIT |
| `fuzz/` | cargo-fuzz targets | Apache-2.0 OR MIT |
| `xtask/` | build automation (`cargo xtask …`) | Apache-2.0 OR MIT |

## The one design rule
**If it parses untrusted input, it is Rust.** C is allowed only in verifier-checked eBPF under
`bpf/`. Packet payloads, DNS, TLS, policy files, bundles and control-socket requests are all
parsed in Rust (`kavach-parsers`, `kavach-policy`, `kavach-api`). A PR that adds a C parser
for user space, or `unsafe` parsing in Rust, will be asked to change.

## Development setup
Requirements: Linux with BTF (`/sys/kernel/btf/vmlinux`), Rust stable (pinned by
`rust-toolchain.toml`), clang ≥ 15, llvm, libelf, libbpf headers and `bpftool`. On Ubuntu,
`scripts/ci-deps.sh` installs exactly what CI uses (it calls `sudo apt-get`).

```sh
cargo xtask vmlinux        # bpf/include/vmlinux.h from /sys/kernel/btf/vmlinux
cargo xtask codegen        # bpf/include/kavach_abi.h from crates/kavach-common (cbindgen)
cargo xtask build-bpf      # compile bpf/kavach.bpf.c -> target/bpf/kavach.bpf.o with -Werror
cargo build --workspace
```

## Tests
```sh
cargo fmt --all --check
cargo xtask codegen --check   # generated ABI header is up to date
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace        # unit + property tests, no privileges
scripts/priv-test.sh          # real kernel: verifier, BPF_PROG_TEST_RUN, live LSM hooks (uses sudo)
cargo deny check              # licenses and advisories
```
`scripts/priv-test.sh [filter]` builds the privileged suite as your user and only runs the test
binary as root. Privileged tests use private pin directories, only deny TEST-NET ranges, and
engage the kill-switch on drop. CI also runs Miri over `kavach-common`, `kavach-core` and
`kavach-parsers` (`cargo +nightly miri test -p …`).

## Changing the kernel ABI
1. Edit `crates/kavach-common/src/abi.rs`.
2. Regenerate the C header: `cargo xtask codegen`. Commit `bpf/include/kavach_abi.h`; CI runs
   `codegen --check`, and the header carries `_Static_assert`s for every size and offset.
3. If any pinned map layout changed, bump `ABI_VERSION` in `crates/kavachd/src/kernel.rs` and
   update `ABI_LAYOUT_FINGERPRINT` next to it. The `abi_version_tracks_the_layout` test fails
   when the layout changes without a bump. Pins live under `/sys/fs/bpf/kavach/v<ABI_VERSION>`,
   so a bump makes upgrades retire the old programs instead of reusing incompatible maps.

## Changing evaluation semantics
Change **both** `bpf/include/kavach_eval.h` and `kavach-core`. The differential test
(`differential_tc_ingress_vs_core`, privileged suite) fails if they disagree.

## Adding a parser (and its fuzz target)
1. Put it in `crates/kavach-parsers` (or the crate that owns the format): `no_std`, no
   allocation, no `unsafe`, bounded loops, returns `Result` instead of panicking.
2. Add unit tests with real captures plus proptests for round-trips and truncation.
3. Add a fuzz target in `fuzz/fuzz_targets/<name>.rs` (copy `dns_message.rs`) and register a
   matching `[[bin]]` in `fuzz/Cargo.toml`. Assert invariants inside the target, not just "does
   not crash".
4. Run it for a while before opening the PR:
   ```sh
   cargo install cargo-fuzz
   cd fuzz && cargo +nightly fuzz run <name>   # existing: tls_client_hello, dns_message,
                                               #   policy_compile, bundle_verify, control_request, quic_initial
   ```
   Commit any crash input that you fixed as a regression test.

## Commits
- [Conventional commits](https://www.conventionalcommits.org/): `feat(kavachd): …`,
  `fix(bpf): …`, `docs: …`, `ci: …`. One logical change each; reference requirement IDs from
  `docs/SRS.md` where relevant. PRs are squash-merged, so the PR title must also be a
  conventional commit.
- **Sign off every commit** (Developer Certificate of Origin, <https://developercertificate.org/>):
  `git commit -s` adds `Signed-off-by: Your Name <you@example.com>`. The `dco` check fails
  otherwise; fix with `git rebase --signoff main` and force-push your branch.

## Pull request checklist
- [ ] `cargo fmt`, clippy, `cargo test --workspace` and `cargo xtask codegen --check` pass
- [ ] `scripts/priv-test.sh` passes if you touched `bpf/` or `crates/kavachd`
- [ ] ABI change: header regenerated, `ABI_VERSION` bumped if map layouts changed
- [ ] Semantics change: both `kavach_eval.h` and `kavach-core` updated
- [ ] New parser: tests + fuzz target
- [ ] Docs (`README.md`, `docs/`) updated for user-visible changes
- [ ] Every commit signed off

## Licensing of contributions
By contributing you agree that your work is licensed under the license of the files you
change: **GPL-2.0-only** for code that runs in the kernel (`bpf/` and `kernel/`), and
**Apache-2.0 OR MIT** for the Rust crates, `xtask/` and `fuzz/`. License texts are in
`LICENSES/`. New files under `bpf/` and `kernel/` need an
`SPDX-License-Identifier: GPL-2.0-only` comment as their first line. We do not require a CLA;
the DCO sign-off is your statement that you have the right to submit.
