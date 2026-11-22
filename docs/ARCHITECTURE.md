# KAVACH — Architecture (solution design)

This document turns the two published diagrams into a buildable design. Where it deviates from
the diagrams, the deviation is called out with **Δ** and a reason.

## 1. Repository layout

```
kavach/
├── Cargo.toml                 # workspace root
├── bpf/                       # C eBPF (clang -target bpf), GPL-2.0
│   ├── include/kavach_abi.h   # GENERATED from kavach-common by `cargo xtask codegen` — do not edit
│   ├── include/kavach_bpf.h   # shared helpers: parsing, bounded loops, maps
│   ├── xdp_filter.c           # blocklist + rate limit
│   ├── tc_flow.c              # flow cache, ingress rules, reply tracking
│   └── lsm_egress.c           # socket_connect/sendmsg identity + egress verdict
├── kernel/kavach-ko/          # (v0.4) Rust-for-Linux module exporting kavach_evaluate kfunc
├── crates/
│   ├── kavach-common/         # no_std, #[repr(C)] ABI — single source of truth
│   ├── kavach-parsers/        # no_std, no alloc: TLS ClientHello / JA4 / DNS / QUIC
│   ├── kavach-core/           # no_std: evaluate(), Platform trait, reference semantics
│   ├── kavach-policy/         # kavach.toml → IR → tables → signed bundle
│   ├── kavachd/               # tokio daemon, aya loader
│   ├── kavachctl/             # clap CLI + ratatui TUI
│   └── kavach-gateway/        # (v0.4) L7 proxy: MCP / A2A / WebSocket
├── shims/{freebsd,macos}/     # (v0.5)
├── fuzz/                      # cargo-fuzz targets
├── tests/                     # netns / virtme-ng integration tests
└── xtask/                     # codegen, build-bpf, vmlinux, release
```

## 2. Crate dependency graph

```
kavachctl ──┐                 kavach-gateway ──┐
            ├──> kavach-policy ──> ed25519-dalek, serde, toml
kavachd ────┘        │                          │
   │  (aya loads)    v                          v
   │            kavach-core ───────────> kavach-parsers
   v                 │                          │
 bpf/*.c             └──────> kavach-common <───┘
   ^                                │
   └──── kavach_abi.h (cbindgen) ───┘
```

Rule: `kavach-common`, `kavach-parsers`, `kavach-core` are `#![no_std]` with zero `alloc`, so the
same code can later be linked into `kavach.ko` (Rust-for-Linux) and the BSD kernel.

## 3. The ABI contract

`crates/kavach-common/src/abi.rs` is the only place layouts are defined. `cargo xtask codegen`
runs cbindgen to emit `bpf/include/kavach_abi.h`. Both sides carry compile-time size/offset
assertions (`const _: () = assert!(...)` in Rust, `_Static_assert` in C); CI regenerates the
header and fails if `git diff` is non-empty.

All addresses are stored as 16-byte IPv6; IPv4 is IPv4-mapped (`::ffff:a.b.c.d`). **Δ** The
diagram keys use `[u32;4]` plus a family byte — we keep that, but always fill the mapped form so
one LPM trie serves both families.

```rust
#[repr(C)] pub struct FlowKey {          // 40 bytes
    pub family: u8, pub proto: u8, pub _pad: [u8; 2],
    pub sport: u16, pub dport: u16,      // network byte order
    pub src: [u32; 4], pub dst: [u32; 4],
}
#[repr(C)] pub struct FlowVal {          // 40 bytes
    pub identity: u64,                   // selector mask that matched
    pub rule_id: u32, pub verdict: u8, pub gen: u8, pub flags: u8, pub _pad: u8,
    pub last_seen_ns: u64, pub pkts: u64, pub bytes: u64,
}
#[repr(u8)] pub enum Verdict { Allow = 0, Drop = 1, Log = 2, Punt = 3 }
```

## 4. BPF maps

| Map | Type | Key → Value | Writer | Reader |
|-----|------|-------------|--------|--------|
| `blocklist` | LPM_TRIE | `{prefixlen, addr[16]}` → `BlockVal{reason,expires}` | kavachd | XDP |
| `rate_buckets` | **LRU_PERCPU_HASH** Δ | `addr[16]` → `TokenBucket{tokens,last_ns}` | XDP | XDP |
| `xdp_cfg` | ARRAY[1] | 0 → `XdpConfig{pps,burst,sample_rate,flags}` | kavachd | XDP |
| `stats` | PERCPU_ARRAY | reason → `u64` | all progs | kavachd |
| `flow_cache` | LRU_HASH | `FlowKey` → `FlowVal` | TC, LSM, gateway | TC |
| `identity_by_cookie` | LRU_HASH Δ | socket cookie → `Identity` | LSM | TC, kavachd |
| `exe_class` | HASH | `{dev, ino}` → `u64 selector mask` | kavachd (LSM deletes) | LSM |
| `uid_class` | HASH | `uid` → `u64 mask` | kavachd | LSM |
| `cgroup_class` | HASH | `cgroup_id` → `u64 mask` | kavachd | LSM |
| `policy_slots` | ARRAY[2] | slot → `PolicyHeader{n_rules, defaults, wildcard masks}` | kavachd | LSM, TC |
| `policy_rules` | ARRAY[2·1024] | slot·1024+i → `Rule` | kavachd | LSM, TC |
| `addr_sets` | LPM_TRIE | `{prefixlen, slot, set_id, addr[16]}` → `u8` | kavachd | LSM, TC |
| `policy_gen` | ARRAY[1] | 0 → `u32` generation | kavachd | LSM, TC |
| `events` | RINGBUF (1 MiB) | `Event` records | XDP, TC, LSM | kavachd |
| `punt_queue` | RINGBUF | flows needing L7 decision | LSM, TC | gateway (v0.4) |

**Δ `rate_buckets` is LRU_PERCPU_HASH**, not PERCPU_HASH: a spoofed-source flood would otherwise
fill the map and make new legitimate sources un-trackable. Per-CPU means the configured rate is
divided by `nr_cpus` (exact under RSS, since one source hashes to one queue).
**Δ `identity_by_cookie` is LRU** so closed sockets age out without a close hook.

## 5. Identity model — selector masks (O(1) in the kernel)

A policy has ≤ 64 **selectors** (each distinct `who = {...}`). Selector *i* owns bit *i*.
For each dimension *d* ∈ {exe, uid, cgroup} kavachd publishes:

* `d_class[value]` = bitmask of selectors whose *d*-constraint is satisfied by `value`
* `wild_d` (in `PolicyHeader`) = bitmask of selectors that do **not** constrain *d*

In `lsm/socket_connect`:

```
m = (exe_class[dev,ino] | wild_exe) & (uid_class[uid] | wild_uid) & (cgroup_class[cg] | wild_cg)
```

`m` is exactly the set of selectors the process satisfies (AND across dimensions, OR within a
list) — three hash lookups, no loops. The rule scan then only needs `rule.sel & m`.

**Binary hashes.** kavachd learns new executables from an `lsm/bprm_committed_creds` event, hashes
`/proc/<pid>/exe` (SHA-256, streaming, cached by `(dev, ino, ctime)`), and writes `exe_class`.
`lsm/file_open` deletes the `exe_class` entry when a classified inode is opened for write, so a
modified binary is never trusted under its old hash. **Known gap (v0.2):** a connection made in the
microseconds between exec and classification sees `exe` mask 0 — it matches only selectors that do
not constrain `binary`. v0.4 closes this with sleepable `bprm_check_security` + `bpf_ima_file_hash`
where IMA is available.

## 6. Rule evaluation

```c
struct Rule {                       // 48 bytes
    u64 sel;                        // selector mask (0 = any identity)
    u32 id; u32 dst_set;            // dst_set 0 = any address
    u16 port_lo, port_hi;           // host order; 0..65535 = any
    u8  proto;                      // 0 = any, 6 tcp, 17 udp, 1/58 icmp
    u8  dir;                        // 1 egress, 2 ingress
    u8  verdict; u8 fail;           // fail: 0 open, 1 closed
    u64 not_after_ns;               // 0 = no TTL (CLOCK_BOOTTIME, rebased by kavachd)
    u64 _reserved[2];
};
```

`evaluate(gen, dir, m, key)`: `bpf_loop(hdr.n_rules)` in priority order; first rule where
`(sel==0 || sel&m) && proto ok && port in range && dir ok && (dst_set==0 || addr_sets hit) &&
not expired` wins. No match ⇒ `hdr.default[dir]`. Because LSM runs once per connection and TC only
on flow-cache misses, the loop cost (≤ 1024 iterations, ~2-3 µs worst case) is paid once per flow.

`kavach-core::evaluate()` implements the identical algorithm over the identical `#[repr(C)]` tables
in Rust. It is the reference semantics: `kavachctl explain` uses it, and the differential test suite
feeds random flows to both it and the BPF programs (via `BPF_PROG_TEST_RUN`) and asserts equality.
In v0.4 `kavach.ko` exports it as a kfunc, so the kernel and the tooling run literally the same code.

## 7. Life of a packet / connection

1. **XDP** (`xdp_filter.c`): parse → `blocklist` LPM → token bucket → `XDP_DROP` / `XDP_PASS`.
2. **TC ingress** (`tc_flow.c`): `flow_cache` hit with current gen ⇒ verdict. Miss + new flow ⇒
   ingress rule scan ⇒ cache ⇒ verdict. Miss + mid-stream TCP ⇒ pass (FR-TC-3).
3. **LSM egress** (`lsm_egress.c`): `socket_connect` → identity mask → egress rule scan →
   `-EPERM` or allow; writes `identity_by_cookie`; emits event on Drop/Log.
4. **TC egress**: inserts the reply key into `flow_cache` so return traffic is O(1).
5. **Punt** (v0.4): rule verdict `Punt` → `punt_queue` → gateway decides → writes `flow_cache`;
   until then the rule's `fail` decides.

## 8. Policy lifecycle and atomic hot-swap

```
build time (CI / laptop)                     run time (kavachd, every host)
1 parse  → 2 validate → 3 lower to IR →      6 verify sig + serial + not_after
4 compile tables → 5 sign (ed25519)          7 stage into INACTIVE slot
                                             8 flip policy_gen (one u32 write)
                                             9 drain (synchronize, ≥ 1 grace period) + clear old slot
```

Programs read `policy_gen` **once** per invocation and use `slot = gen & 1` for every subsequent
lookup (`policy_slots`, `policy_rules`, `addr_sets` keyed by slot). A packet therefore never sees
half of each policy (same idea as RCU). `FlowVal.gen` holds the low 8 bits of the generation; a
mismatching entry is a miss, so the new policy takes effect on the next packet of every cached flow.

### Bundle format (`.kvb`)

```
magic "KVB1" | u16 format_ver | u16 flags | u64 serial | u64 not_after_unix | [u8;8] key_id
| u32 payload_len | payload (postcard-encoded CompiledPolicy) | [u8;64] ed25519 signature
signature = Ed25519(sk, SHA-256("kavach-bundle-v1\0" ‖ header ‖ payload))
```

kavachd rejects a bundle if: signature fails, key_id not trusted, `serial ≤ last_applied_serial`
(persisted), `not_after` passed, or payload fails structural validation (defence in depth — the
compiler already validated it).

## 9. kavachd internals

```
control_api (UDS + SO_PEERCRED) ──> map_sync ──> loader (aya: load, attach, pin)
ringbuf_reader (events, punt) ──> event_bus (tokio broadcast) ──> audit_log | metrics | anomaly
identity_broker (exec events → sha256 → exe/uid/cgroup class maps; FQDN resolver → addr_sets)
```

Each box is one tokio task under a supervisor; a panic restarts that task only. Kernel state is
pinned under `/sys/fs/bpf/kavach/`, so restarting the daemon never opens an enforcement gap.

## 10. Failure semantics

| Event | Behaviour |
|-------|-----------|
| kavachd crash / restart | Programs + maps stay pinned; last policy enforces; daemon re-adopts pins on start |
| Punt with no consumer | Rule `fail` decides (open ⇒ allow, closed ⇒ drop) |
| Bundle invalid | Rejected, active policy unchanged, audit record + error to caller |
| Verifier rejects program on this kernel | kavachd refuses to start that feature, reports capability matrix |
| `kavachctl kill-switch` | Detach all links, unpin, remove `/sys/fs/bpf/kavach` |

## 11. Security posture

* The only parser of attacker bytes in C is the XDP/TC header parser, which is verifier-bounded.
  Everything else (TLS, DNS, QUIC, TOML, bundle, JSON control messages) is Rust.
* No TCP listener for control. UDS 0600 + `SO_PEERCRED`.
* `#![forbid(unsafe_code)]` in `kavach-policy`, `kavachctl`, `kavach-parsers`; `unsafe` confined
  to `kavach-common` (Pod impls) and `kavachd` (aya map access), each with `// SAFETY:`.
* Signing keys live with CI; hosts only carry public keys.

## 12. Portability

`kavach-core` exposes `trait Platform { now_ns, identity(cookie), emit(event) }` and a generic
`evaluate<P: Platform>`. Linux eBPF uses the C mirror for the hot path (the verifier cannot run
Rust core today); the BSD kernel module and the macOS Network Extension link the Rust core
directly; `kavach.ko` (v0.4) brings it into the Linux kernel as a kfunc.
