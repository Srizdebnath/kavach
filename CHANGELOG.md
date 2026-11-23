# Changelog

All notable changes to Kavach. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/). Release milestones (v0.1 … v0.5
in the README) describe *scope*; version numbers describe *releases*.

## [0.3.1] - 2026-11-23

First release with installable, signed packages: `.deb`, `.rpm` and a static (musl) tarball
for x86_64 and aarch64, with `SHA256SUMS`, a keyless Sigstore signature and SLSA build
provenance.

### Added
- `kavachctl top`: live terminal dashboard (verdict rates, top denied identities, rules hit,
  recent events; `q` quit, `p` pause, `tab`, `s` sort).
- `kavachctl doctor`: checks kernel, BTF, BPF LSM, bpffs and cgroup v2, and prints the fix for each miss.
- Per-identity anomaly engine in kavachd (`[anomaly]`, detection only): EWMA baselines of
  connection rate, deny rate, distinct destinations and new destination ports; reported as
  `anomaly` events (`kavachctl events --kind anomaly`) and audit records.
- QUIC v1/v2 client Initial decryption in `kavach-parsers` (SNI, ALPN, JA4 `q` marker), with a
  fuzz target.
- Opt-in AF_XDP RX backend for the v0.4 gateway (`[gateway.afxdp]`, off by default):
  zero-copy → copy → SKB fallback per queue, port-selective redirect, stall watchdog.
  Preview only: redirected ports are counted and dropped until the v0.4 proxy exists.
- `interfaces = ["auto"]`: protect every interface with a default route.
- Real-kernel benchmark (`bench_report`) and a CI perf gate (`docs/bench/budget.json`).
- Release pipeline, tarball `install.sh`, `docs/INSTALL.md`.
- 23 SVG architecture and firewall-gap diagrams; README with benchmarks, test results and a setup guide.
- Community files: CONTRIBUTING, Code of Conduct, governance, security policy, issue/PR
  templates, CODEOWNERS, Dependabot, DCO check, OpenSSF Scorecard.

### Fixed
- **Uninstall left enforcement attached.** Package removal stops kavachd before running the
  kill-switch, which needed the daemon. `kavachctl kill-switch --yes` now removes every pin
  under `/sys/fs/bpf/kavach` itself when the daemon is not running.
- Upgrades across an ABI change retire the old version's programs only after the new ones enforce.
- Identity: executables in overlay (container) filesystems are keyed by their real file; no
  first-run window for hash-named binaries in strict mode; every block-device layer under a
  binary must be trusted.

## [0.3.0] - 2026-11-22

Scope v0.1–v0.3, built and kernel-tested (source only, no packages).

### Added
- v0.1: XDP LPM blocklist (IPv4/IPv6/VLAN) and per-source GCRA rate limiting (IPv6 per /64).
- v0.2: identity-aware egress via BPF-LSM (binary SHA-256 / path, user, cgroup), in-kernel
  revocation of trust on write (placeholder protocol).
- v0.3: `kavach.toml` policy-as-code, shadowed-rule detection, ed25519-signed KVB1 bundles,
  anti-rollback, A/B hot-swap, TC flow tracking with re-evaluation, hash-chained audit log,
  `kavachctl`.
- `no_std` reference engine (`kavach-core`) differentially tested against the kernel; TLS
  ClientHello, JA4 and DNS parsers; fuzz targets; Miri in CI.

[0.3.1]: https://github.com/Srizdebnath/kavach/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Srizdebnath/kavach/releases/tag/v0.3.0
