# KAVACH

**A kernel-native firewall for the agentic, encrypted, zero-trust era.**

C for the fast path · Rust for everything that parses · one portable core for every Unix

`eBPF / XDP fast path` · `Rust policy core` · `Identity > IP` · `Agent-aware: MCP · A2A` ·
`Policy-as-code` · `Hot-reload, no reboot` · `Memory-safe parsers`

![Kavach architecture](diagrams/kavach-architecture.png)

## Why

Firewalls in 2026 are themselves the attack surface (parser CVEs, internet-facing admin portals),
are blind to encrypted traffic, think in IP addresses while workloads change IPs every minute,
and still need maintenance windows to apply a rule. Kavach fixes this from the host up:

* **Kernel-native.** XDP drops known-bad traffic at line rate before an `sk_buff` exists. TC tracks
  flows in O(1). BPF-LSM attributes every connection to the process that opened it.
* **Identity, not IP.** Rules target `binary sha256`, user, cgroup, k8s labels, SPIFFE IDs and agent
  tokens.
* **Policy as code.** `kavach.toml` in git → validated, shadow-checked, compiled, **ed25519-signed**
  bundle → atomic A/B hot-swap in the kernel. No reboot, no reload, no half-applied policy.
* **Memory-safe where it matters.** *If it parses untrusted input, it is Rust.* C exists only in
  verifier-checked eBPF programs.
* **No admin portal.** Control is a local Unix socket with peer-credential checks. Nothing listens
  on the network.

## Status

| Release | Scope | State |
|---------|-------|-------|
| v0.1 | XDP blocklist + per-source rate limiting (C, loaded from Rust with Aya) | ✅ working, kernel-tested |
| v0.2 | Identity-aware egress via BPF-LSM: binary hash/path, uid, cgroup; tamper revocation | ✅ working, kernel-tested |
| v0.3 | `kavach.toml` policy-as-code + `kavachctl`, signed bundles, A/B hot-swap, audit log | ✅ working, kernel-tested |
| v0.4 | Agent gateway: MCP / A2A policies, `kavach.ko` Rust kfunc core | 🧪 policy core + designs |
| v0.5 | FreeBSD shim, macOS Network Extension | planned |

Verified on every push: lint, unit tests, Miri on the `no_std` crates, dependency/license
audit, and the root-only eBPF suite (XDP, TC, LSM, real traffic over a veth pair in a private
network namespace) on GitHub's runner kernel. Parsers (TLS ClientHello, JA4, DNS) are fuzzed.

## Documents

* [Software Requirements Specification](docs/SRS.md)
* [Architecture / solution design](docs/ARCHITECTURE.md)
* [Code-level architecture diagram](diagrams/kavach-code-architecture.png)

## Building

Requirements: Linux ≥ 6.1 with BTF (`/sys/kernel/btf/vmlinux`), Rust stable, `clang` ≥ 16,
`bpftool`, `libbpf` headers. For identity enforcement, `bpf` must be in `/sys/kernel/security/lsm`.

```sh
cargo xtask vmlinux      # bpf/include/vmlinux.h from your kernel's BTF
cargo xtask codegen      # bpf/include/kavach_abi.h from kavach-common
cargo build --release    # builds BPF objects (via build.rs) + kavachd + kavachctl
cargo test --workspace
```

## Licensing

* Code that runs in the kernel (`bpf/`, `kernel/`): **GPL-2.0-only**.
* User-space Rust crates: **Apache-2.0 OR MIT**.

See [`LICENSES/`](LICENSES/).
