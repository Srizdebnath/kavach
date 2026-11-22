# KAVACH — Software Requirements Specification

| | |
|---|---|
| Document | SRS, revision 1.0 |
| Status | Baseline for v0.1 – v0.3, forward-looking for v0.4 – v0.5 |
| Date | 2026-11-22 |
| Source diagrams | `diagrams/kavach-architecture.png`, `diagrams/kavach-code-architecture.png` |

Requirement keywords **MUST / SHOULD / MAY** follow RFC 2119. Every requirement carries an ID
(`FR-*` functional, `NFR-*` non-functional, `SR-*` safety/security) so tests and commits can cite it.

---

## 1. Introduction

### 1.1 Purpose
Kavach is a kernel-native, identity-aware, host-distributed firewall for Linux first (then
FreeBSD, macOS, Windows). It enforces network policy at line rate using eBPF, attributes every
flow to a *workload identity* rather than an IP address, and is configured exclusively through
signed, version-controlled policy (`kavach.toml`).

### 1.2 The problems it solves (2026)
| # | Gap | Kavach response | Lives in |
|---|-----|-----------------|----------|
| G1 | The firewall itself is the target (parser CVEs, exposed admin portals) | Memory-safe Rust for every byte parser; no web UI; local UDS only; verifier-proven fast path; continuous fuzzing | kernel core + control plane |
| G2 | Encrypted traffic is opaque (TLS 1.3, ECH, QUIC) | No MITM by default. Host-native: we know which process opened the socket. Decide on identity + metadata (JA4, SNI, DNS) | policy core + identity |
| G3 | AI agents speak MCP / A2A / WebSockets | L7 agent gateway: per-agent identity, tool allowlists, rate & spend budgets, kill-switch | agent gateway (v0.4) |
| G4 | East-west traffic is invisible | Every host enforces; deny-by-default micro-segmentation; central policy, local verdicts in µs | every host |
| G5 | IPs are not identity | Rules target binary sha256, user, cgroup, k8s label, SPIFFE ID, agent token | identity broker + LSM |
| G6 | Rule sprawl & misconfig | Policy-as-code, dry-run + diff, mandatory-able TTLs, shadowed-rule detector, `explain` | compiler + kavachctl |
| G7 | Exploited within hours | Atomic hot-reload, virtual patching in minutes, signed auto-update with rollback | BPF maps + kavachd |
| G8 | Kernel modules can crash the box | Tiny C surface, verified eBPF hot path, audited `unsafe`, watchdog, clean unload | whole kernel plane |

### 1.3 Scope of this baseline
* **v0.1** XDP blocklist + per-source rate limiting (C, loaded from Rust with Aya).
* **v0.2** Identity-aware egress via BPF-LSM + cgroup identity.
* **v0.3** `kavach.toml` policy-as-code, signed bundles, A/B hot-swap, `kavachctl`.
* **v0.4** (specified, not built) agent gateway: MCP / A2A / WebSocket policy; `kavach.ko` Rust kfunc core.
* **v0.5** (specified, not built) FreeBSD pfil shim, macOS Network Extension.

### 1.4 Definitions
| Term | Meaning |
|------|---------|
| Flow | 5-tuple (family, proto, src, sport, dst, dport) in one direction |
| Identity | A workload class a flow is attributed to: (binary, user, cgroup, labels, agent) selector match |
| Selector | A `who = {...}` conjunction in policy, compiled to one bit of a 64-bit identity mask |
| Verdict | `Allow`, `Drop`, `Log` (allow + event), `Punt` (defer to user space / L7) |
| Bundle | Compiled, ed25519-signed binary policy image consumed by kavachd |
| Slot | One of two in-kernel policy tables (A/B); `policy_gen` selects the active one |
| Punt | A flow handed to user space (gateway) for a decision that is then cached in-kernel |

### 1.5 Actors
* **Operator** — writes `kavach.toml`, runs `kavachctl` locally.
* **CI / policy pipeline** — validates, compiles, signs bundles.
* **kavachd** — per-host daemon (root, CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN for LSM attach).
* **Workloads** — processes, containers, agents whose traffic is governed.
* **SIEM** — consumes the hash-chained audit log.

---

## 2. Overall description

### 2.1 Product perspective — three planes
1. **User space (Rust, control plane):** kavachd, identity broker, anomaly engine, kavachctl + TUI,
   policy compiler, audit log, agent gateway.
2. **Kernel space (C eBPF + later Rust kfunc):** XDP fast path → TC/netfilter hooks → policy core →
   LSM socket hooks → verdict. Shared state lives only in BPF maps.
3. **Platform shims:** Linux (first target), FreeBSD, OpenBSD (pf companion), macOS (NE), Windows (WFP).

The kernel ↔ user boundary is crossed only through BPF maps, ring buffers, and ed25519-signed bundles.

### 2.2 Design rule
> **If it parses untrusted input, it is Rust.** C is permitted only for verifier-checked eBPF
> programs and thin kernel glue (netfilter/pfil registration).

### 2.3 Operating environment
* Linux ≥ 6.1 LTS, `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_BPF_JIT`.
* `CONFIG_BPF_LSM=y` with `bpf` in the active LSM list for identity enforcement (v0.2). If absent,
  kavachd MUST degrade to cgroup/connect hooks and report the reduced capability.
* TC attach: `tcx` on ≥ 6.6, legacy clsact qdisc on 6.1 – 6.5.
* x86_64 and aarch64.

### 2.4 Constraints
* C1: Hot path performs **zero allocations** and **bounded loops** only.
* C2: No listening TCP/UDP port for administration. Control API = Unix domain socket (0600, root).
* C3: Policy is data, never code: bundles cannot carry executable content.
* C4: GPL-2.0 for all code loaded into the kernel; Apache-2.0 OR MIT for user-space crates.

### 2.5 Assumptions
* The root user on the host is trusted (Kavach is not a rootkit defence).
* Clock is roughly synchronised (TTL enforcement tolerates ±5 min skew).

---

## 3. Functional requirements

### 3.1 XDP fast path (v0.1)
| ID | Requirement |
|----|-------------|
| FR-XDP-1 | The system MUST drop packets whose source address matches an IPv4 or IPv6 blocklist CIDR using longest-prefix matching (`LPM_TRIE`). |
| FR-XDP-2 | The system MUST enforce a per-source rate limit (GCRA: pps + burst) configurable at runtime without reload. IPv6 sources MUST share one budget per /64. |
| FR-XDP-3 | Rate-limit state MUST live in an LRU hash (one shared, atomically updated state per source) so a spoofed-source flood evicts cold entries instead of exhausting the map, and the rate is exact regardless of RSS. |
| FR-XDP-4 | Header parsing MUST be bounds-checked (Ethernet, single + double 802.1Q VLAN, IPv4 with options, IPv6 with up to 4 extension headers, TCP/UDP/ICMP). Unparseable frames are `XDP_PASS` (the kernel stack decides). |
| FR-XDP-5 | Per-reason drop counters MUST be exported via a per-CPU array (`stats`). |
| FR-XDP-6 | Sampled drop events (1/N, configurable) MUST be emitted to the `events` ring buffer. |
| FR-XDP-7 | The XDP program MUST attach in native mode when supported and fall back to generic (SKB) mode, reporting which mode is active. |
| FR-XDP-8 | Blocklist entries MAY carry an expiry; kavachd MUST purge expired entries. |

### 3.2 Identity (v0.2)
| ID | Requirement |
|----|-------------|
| FR-ID-1 | Every outbound connection MUST be attributed to: pid/tgid, uid/gid, cgroup id, executable (the live kernel inode, on trusted local filesystems), and `comm`. |
| FR-ID-2 | kavachd MUST map executables to SHA-256 digests and publish `exe → selector-mask` classifications to the kernel. |
| FR-ID-3 | Opening an executable for write or truncating it MUST invalidate its classification in-kernel, including a modification that races the hash (sequence-pair protocol). |
| FR-ID-4 | kavachd MUST map uids and cgroup ids (and in v0.3+ k8s pod labels via cgroup path) to selector masks. |
| FR-ID-5 | The identity of every connected socket MUST be recorded in socket-local storage (`sk_ident`) for later use by TC (re-evaluation after a policy swap). |
| FR-ID-7 | Executables named by path in the active policy MUST be classified before their first execution after an apply; already-running processes MUST be classified at daemon start. |
| FR-ID-6 | A process matches selector *s* iff it satisfies every dimension *s* constrains (AND across dimensions, OR within a list). |

### 3.3 Egress enforcement (v0.2)
| ID | Requirement |
|----|-------------|
| FR-EG-1 | `socket_connect` (TCP + connected UDP) and `socket_sendmsg` (unconnected UDP) MUST be evaluated against the active egress policy; a `Drop` verdict returns `-EPERM` to the caller. |
| FR-EG-2 | Rules are evaluated in priority order; **first match wins**; no match ⇒ the configured egress default. |
| FR-EG-3 | Destinations MAY be CIDRs, address sets, or FQDNs. FQDNs are resolved by kavachd and kept fresh within their DNS TTL (min 5 s, max 1 h). |
| FR-EG-4 | Every `Drop` and `Log` verdict MUST emit an event with full identity attribution. |
| FR-EG-5 | Loopback traffic MUST bypass egress policy unless a rule explicitly targets `127.0.0.0/8` or `::1`. |

### 3.4 TC / flow tracking (v0.2 – v0.3)
| ID | Requirement |
|----|-------------|
| FR-TC-1 | TC egress MUST record each new outbound flow in `flow_cache` (LRU) under its *reply* key so return traffic hits in O(1). |
| FR-TC-2 | TC ingress MUST apply a cached verdict on hit and evaluate ingress rules on miss for **new** flows only (TCP SYN without ACK, first UDP/ICMP packet). |
| FR-TC-3 | Non-SYN TCP packets with no state MUST be passed by default (the stack resets them) to avoid breaking long-lived connections after LRU eviction; a `strict` mode MAY drop them. |
| FR-TC-4 | Flow cache values MUST carry identity, rule id, verdict, packets, bytes, last-seen. |

### 3.5 Policy as code (v0.3)
| ID | Requirement |
|----|-------------|
| FR-POL-1 | Policy MUST be expressed in `kavach.toml` (schema versioned by `version = N`). |
| FR-POL-2 | The compiler MUST reject: unknown keys, duplicate rule ids, contradictory rules (same match, different verdict), invalid CIDRs/ports, missing TTL when `require_ttl = true`. |
| FR-POL-3 | The compiler MUST report **shadowed** rules (a rule fully covered by an earlier rule) as errors (warnings with `--allow-shadowed`). |
| FR-POL-4 | Compilation pipeline: parse → validate → lower to IR (group by identity) → compile to tables → sign. |
| FR-POL-5 | Bundles MUST be signed with ed25519 over a domain-separated SHA-256 of the canonical payload; kavachd MUST reject unsigned, mis-signed, or version-rolled-back bundles. |
| FR-POL-6 | TTL'd rules MUST stop matching at expiry without operator action (kavachd republishes). |
| FR-POL-7 | Each rule MUST declare (or inherit) `fail = "open" | "closed"`, governing behaviour when a decision needs user space and user space is unavailable. |
| FR-POL-8 | Limits: ≤ 64 selectors, ≤ 1024 rules, ≤ 4096 address-set entries per bundle in v0.3 (enforced with clear errors). |

### 3.6 Atomic hot-swap (v0.3)
| ID | Requirement |
|----|-------------|
| FR-HS-1 | Two policy slots (A/B) MUST exist. kavachd writes the inactive slot, then flips `policy_gen` with a single 32-bit write. |
| FR-HS-2 | Each program invocation MUST read `policy_gen` exactly once, so a packet/connection never sees a mix of two policies. |
| FR-HS-3 | After the flip, kavachd MUST wait one RCU grace period (`membarrier`/sleep ≥ 1 tick of in-flight drain) before clearing the old slot. |
| FR-HS-4 | Flow cache entries carry the generation that produced them; entries from older generations MUST be treated as misses. |
| FR-HS-5 | Applying a bundle MUST NOT require reloading or re-attaching programs, and MUST NOT drop established connections that the new policy still allows. |

### 3.7 kavachd (v0.1 – v0.3)
| ID | Requirement |
|----|-------------|
| FR-D-1 | Load, verify, attach and pin (`/sys/fs/bpf/kavach/`) all programs and maps. |
| FR-D-2 | On restart, re-use pinned maps/links (no enforcement gap). |
| FR-D-3 | Control API over UDS `/run/kavach/kavach.sock` (0600), newline-delimited JSON, peer-credential checked (`SO_PEERCRED` uid 0 or `kavach` group). |
| FR-D-4 | One async task per job (map_sync, ringbuf_reader, identity_broker, event_bus, audit_log, metrics); a crashed task is restarted without touching the kernel side. |
| FR-D-5 | Prometheus metrics on a UDS or opt-in loopback port. |
| FR-D-6 | Watchdog: kernel programs keep enforcing the last good policy if kavachd dies; `kavachctl kill-switch` detaches everything. |

### 3.8 kavachctl (v0.1 – v0.3)
`status`, `block add|del|list`, `ratelimit set`, `apply <bundle|toml> [--dry-run]`, `diff`, `explain <flow>`,
`events --follow`, `stats`, `compile`, `sign`, `keygen`, `verify`, `kill-switch`, `top` (TUI).

| ID | Requirement |
|----|-------------|
| FR-CLI-1 | `explain` MUST evaluate a described flow with the **same** Rust `kavach-core::evaluate` the reference model uses and print the matching rule chain. |
| FR-CLI-2 | `apply --dry-run` MUST show the diff against the active policy and the would-be verdict changes on recent flows. |

### 3.9 Audit (v0.3)
| ID | Requirement |
|----|-------------|
| FR-AUD-1 | Every policy change and sampled verdict MUST be appended to a hash-chained log (`h_n = SHA256(h_{n-1} ‖ record_n)`). |
| FR-AUD-2 | `kavachctl audit verify` MUST detect any modification, deletion or reordering. |

### 3.10 Parsers (v0.3 metadata, used by v0.4 gateway)
| ID | Requirement |
|----|-------------|
| FR-PAR-1 | `kavach-parsers` (no_std, no alloc) MUST extract SNI, ALPN and JA4 inputs from a TLS ClientHello. |
| FR-PAR-2 | It MUST parse DNS queries/responses (names, A/AAAA) with compression-loop protection. |
| FR-PAR-3 | Parsers MUST never panic on any input (enforced by fuzzing). |

### 3.11 Agent gateway (v0.4, specified)
FR-GW-1 per-agent identity (token / SPIFFE); FR-GW-2 MCP tool allowlists; FR-GW-3 calls/min + USD/day budgets;
FR-GW-4 one-command kill-switch per agent; FR-GW-5 verdicts written back to `flow_cache`.

### 3.12 Portability (v0.5, specified)
FR-PORT-1 `kavach-core` implements all decisions behind `trait Platform`; FR-PORT-2 FreeBSD pfil shim;
FR-PORT-3 macOS NEFilterDataProvider shim; FR-PORT-4 Windows WFP callout (later).

---

## 4. Non-functional requirements
| ID | Requirement |
|----|-------------|
| NFR-PERF-1 | XDP blocklist + rate limit: ≥ 10 Mpps/core drop rate on native-XDP NICs; ≤ 60 ns median added per passed packet. |
| NFR-PERF-2 | TC flow-cache hit: ≤ 100 ns median added latency. |
| NFR-PERF-3 | LSM connect evaluation: ≤ 5 µs p99 with 1024 rules. |
| NFR-PERF-4 | Policy apply (compile excluded): ≤ 50 ms for 1024 rules; zero dropped allowed packets during swap. |
| NFR-PERF-5 | kavachd idle RSS ≤ 30 MiB; CPU ≤ 1 % at 10 k events/s. |
| NFR-PERF-6 | CI perf gate fails the build on > 10 % regression. |
| NFR-REL-1 | No kernel panic, oops or verifier rejection across the supported kernel matrix. |
| NFR-REL-2 | Clean unload: `kavachctl kill-switch` + stop leaves no programs, links or pins. |
| NFR-MAINT-1 | C ↔ Rust ABI generated from a single source (`kavach-common`); CI fails on layout drift. |
| NFR-MAINT-2 | `kavach-core`, `kavach-common`, `kavach-parsers` build as `no_std` and pass Miri. |
| NFR-PORT-1 | x86_64 + aarch64; kernels 6.1, 6.6, 6.12, latest. |
| NFR-OBS-1 | Every drop is explainable: event carries reason, rule id, generation, identity. |

## 5. Safety & security requirements
| ID | Requirement |
|----|-------------|
| SR-1 | No network-reachable management surface. |
| SR-2 | Every `unsafe` block carries a `// SAFETY:` justification; `#![deny(unsafe_op_in_unsafe_fn)]` workspace-wide. |
| SR-3 | Bundles: ed25519 signature, monotonic `serial` (anti-rollback), `not_after` expiry, key id. |
| SR-4 | Private signing keys never touch the enforcing host by default; kavachd holds only public keys in `/etc/kavach/trusted_keys/`. |
| SR-5 | UDS control API authorises via `SO_PEERCRED`. |
| SR-6 | Fuzzing: cargo-fuzz targets for every parser and the TOML/bundle decoder; syzkaller for `kavach.ko` (v0.4). |
| SR-7 | Reproducible builds and signed release artefacts. |
| SR-8 | Per-rule fail-open / fail-closed honoured when user space is absent. |
| SR-9 | Supply chain: `cargo deny` (licenses, advisories, bans) in CI; pinned toolchain. |

## 6. External interfaces
* **Kernel:** BPF syscall (via Aya), pinned bpffs objects, LSM hooks `socket_connect`, `socket_sendmsg`,
  `file_open`, `bprm_committed_creds`; XDP; TC (tcx / clsact).
* **Files:** `/etc/kavach/kavachd.toml` (daemon config), `/etc/kavach/trusted_keys/*.pub`,
  `/var/lib/kavach/active.bundle`, `/var/log/kavach/audit.log`.
* **Sockets:** `/run/kavach/kavach.sock` (control), `/run/kavach/metrics.sock` (Prometheus).

## 7. Verification strategy
| Level | Tooling | Covers |
|-------|---------|--------|
| Unit | `cargo test` (std + no_std builds) | common, core, parsers, policy |
| UB | `cargo miri test` | core, common, parsers |
| Differential | `BPF_PROG_TEST_RUN` vs `kavach-core::evaluate` on the same compiled tables | ABI + semantics parity |
| Verifier | load every object on 6.1 / 6.6 / 6.12 / latest (virtme-ng) | NFR-REL-1 |
| Privileged kernel suite | `scripts/priv-test.sh` (`crates/kavachd/tests/bpf.rs`): `BPF_PROG_TEST_RUN` for XDP/TC, live `connect()`/`sendto()` through the LSM hooks | XDP / TC / LSM end-to-end, FR-ID-3, FR-HS-4 |
| Integration | netns + veth harness, real traffic | multi-interface, XDP native mode |
| Fuzz | cargo-fuzz (parsers, toml, bundle), syzkaller (kavach.ko) | SR-6 |
| Perf | pktgen / TRex, criterion | NFR-PERF-* |

## 8. Traceability (roadmap ↔ requirements)
| Release | Requirements |
|---------|--------------|
| v0.1 | FR-XDP-*, FR-D-1/2/3/5, FR-CLI (block, ratelimit, stats, events), NFR-MAINT-1 |
| v0.2 | FR-ID-*, FR-EG-*, FR-TC-1/4 |
| v0.3 | FR-POL-*, FR-HS-*, FR-TC-2/3, FR-CLI-1/2, FR-AUD-*, FR-PAR-1/2 |
| v0.4 | FR-GW-*, kavach.ko kfunc, SR-6 syzkaller |
| v0.5 | FR-PORT-* |
