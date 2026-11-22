# KAVACH — Architecture (solution design)

This document turns the two published diagrams into the design that is actually built. Where it
deviates from the diagrams, the deviation is marked **Δ** with a reason. Requirement IDs refer to
[`SRS.md`](SRS.md).

## 1. Repository layout

```
kavach/
├── bpf/                       # C eBPF (clang -target bpf, CO-RE), GPL-2.0-only
│   ├── kavach.bpf.c           # unity build: one object, one set of maps
│   ├── include/kavach_abi.h   # GENERATED from kavach-common (`cargo xtask codegen`) — do not edit
│   ├── include/kavach_bpf.h   # maps, packet parser, counters, ring-buffer helpers
│   ├── include/kavach_eval.h  # snapshot, identity masks, rule scan (mirror of kavach-core)
│   ├── xdp_filter.c           # blocklist + GCRA rate limit
│   ├── tc_flow.c              # flow cache, reply tracking, ingress rules, re-evaluation
│   └── lsm_egress.c           # connect/sendmsg verdicts, exec/taint tracking, task iterator
├── crates/
│   ├── kavach-common/         # no_std #[repr(C)] ABI + address helpers — single source of truth
│   ├── kavach-core/           # no_std, forbid(unsafe): reference evaluator
│   ├── kavach-policy/         # kavach.toml → CompiledPolicy → kernel tables; .kvb bundles; diff
│   ├── kavach-api/            # control protocol (NDJSON over UDS) + hash-chained audit log
│   ├── kavachd/               # tokio daemon, aya loader; tests/bpf.rs = privileged kernel suite
│   └── kavachctl/             # operator CLI
├── examples/                  # kavach.toml (policy), kavachd.toml (host config)
├── packaging/systemd/         # hardened unit
├── scripts/                   # priv-test.sh, ci-deps.sh
└── xtask/                     # codegen [--check], vmlinux, build-bpf
```

Planned (v0.4/v0.5): `kernel/kavach-ko` (Rust-for-Linux kfunc), `crates/kavach-parsers`
(TLS/JA4/DNS), `crates/kavach-gateway` (L7), `shims/{freebsd,macos}`.

## 2. Crate dependency graph

```
kavachctl ──┬──> kavach-api ─────────────┐
            ├──> kavach-policy ──┐       │
kavachd ────┘        │           │       │
   │ (aya)           v           v       v
   │            kavach-core ──> kavach-common
   v                                 │
 bpf/*.c <── kavach_abi.h (cbindgen) ┘
```

`kavach-common` and `kavach-core` are `#![no_std]` without `alloc` (CI builds them for a
bare-metal target), so the same code can later be linked into `kavach.ko` and the BSD kernel.

## 3. The ABI contract

`crates/kavach-common/src/abi.rs` is the only place layouts are defined (bytemuck `Pod`).
`cargo xtask codegen` emits `bpf/include/kavach_abi.h` and appends a `_Static_assert` for the size
of every type; CI runs `codegen --check`.

All addresses are 16 bytes; IPv4 is stored IPv4-mapped (`::ffff:a.b.c.d`), so one LPM trie
serves both families.

| Type | Size | Notes |
|---|---|---|
| `FlowKey` | 40 | family, proto, ports (network order), src, dst |
| `FlowVal` | 48 | identity mask, rule_id, **u32 generation** Δ, verdict, flags (REPLY/INGRESS), counters |
| `ExeKey` | 16 | `{s_dev, i_generation, ino}` read from the kernel inode Δ |
| `ExeClass` | 32 | `mask[2]` (one per policy slot) + `nonce` of the key request |
| `KeyReq` | 16 | one-shot `{nonce, tid}` armed by kavachd |
| `ClassVal` | 16 | `mask[2]` for uid / cgroup classes |
| `PolicyHeader` | 64 | n_rules, defaults, fail mode, flags, wildcard masks, `sel_used` |
| `Rule` | 48 | sel, id, set bitmap index, ports, proto, dir, verdict, fail, not_after |
| `Policy` | header + 1024 rules | one map value per slot |
| `Event` | 104 | ring-buffer record for every kind |

**Δ u32 generation** in `FlowVal`: an 8-bit generation wraps after 256 applies and can make a stale
entry look current.

## 4. BPF maps

All maps except `sync_*` are pinned `LIBBPF_PIN_BY_NAME` under `/sys/fs/bpf/kavach/v1`
(versioned so an incompatible layout never re-adopts old pins).

| Map | Type | Key → Value | Writer | Reader |
|-----|------|-------------|--------|--------|
| `blocklist` | LPM_TRIE | `BlockKey` → `BlockVal{reason, expires}` | kavachd | XDP |
| `rate_buckets` | LRU_HASH Δ | `SrcKey` (v4 host / v6 /64) → `RateState{tat_ns}` | XDP | XDP |
| `xdp_cfg` | ARRAY[1] | GCRA emission/tau, sample rate, feature flags | kavachd | XDP, TC, LSM |
| `stats` | PERCPU_ARRAY[16] | `StatReason` → u64 | all | kavachd |
| `flow_cache` | LRU_HASH 256k | `FlowKey` → `FlowVal` | TC | TC |
| `sk_ident` | SK_STORAGE Δ | socket → `Identity` | LSM | TC |
| `exe_class` | HASH | `ExeKey` → `ExeClass` (present = trusted) | kavachd commits; LSM inserts placeholders, deletes on taint | LSM |
| `uid_class` / `cgroup_class` | HASH | uid / cgroup id → `ClassVal` | kavachd | LSM, TC |
| `policy_slots` | ARRAY[2] | slot → `Policy` | kavachd | LSM, TC |
| `addr_sets` | LPM_TRIE | `{prefixlen, slot, addr}` → u64 set bitmap Δ | kavachd | LSM, TC |
| `policy_gen` | ARRAY[1] | u32 generation | kavachd | LSM, TC |
| `key_req` | ARRAY[1] | `KeyReq` (one-shot key report) | kavachd, LSM clears | LSM |
| `events` | RINGBUF 1 MiB | `Event` | all | kavachd |
| `sync_inner` / `sync_rcu` | ARRAY / ARRAY_OF_MAPS | used only to force `synchronize_rcu()` | kavachd | — |

* **Δ GCRA in a shared LRU_HASH** (not per-CPU token buckets): one 16-byte state per source,
  updated with `cmpxchg`; the rate is exact regardless of RSS, and LRU eviction means spoofed floods
  cannot pin the map. IPv6 sources are keyed per /64 so one host cannot rotate addresses to evade it.
* **Δ SK_STORAGE instead of a cookie-keyed LRU**: lifetime is tied to the socket, with no aging
  and no collisions.
* **Δ one LPM lookup per destination**: the compiler flattens all sets of a slot so that the
  longest matching prefix carries the union bitmap of every set containing that address; a rule
  tests `bitmap & (1 << rule.set)`. That costs O(1) lookups instead of one per rule.

## 5. Identity model — selector masks

A policy has ≤ 64 **selectors** (distinct `who = {...}`); selector *i* owns bit *i*. For each
dimension *d* ∈ {exe, uid, cgroup}, kavachd publishes `d_class[value].mask[slot]` (selectors
satisfied by that value) and `wild_d` in the header (selectors that do not constrain *d*):

```
m = (exe_mask | wild_exe) & (uid_mask | wild_uid) & (cgroup_mask | wild_cgroup) & sel_used
```

* When `wild_d == ~0`, no selector constrains *d*, and the lookup is skipped.
* `sel_used` clears bits of unused selector numbers.
* cgroup selectors match a subtree. The program ORs the class of the task's cgroup and up to
  8 ancestors.

**Executable identity.**
* The LSM reads `task->mm->exe_file->f_inode` via CO-RE and builds `ExeKey{s_dev, i_generation, ino}`.
  The key uses the kernel's own view of the inode rather than userspace `st_dev`, which differs
  on btrfs and overlayfs. **Δ** This chain yields an untrusted pointer, so INODE_STORAGE is not
  usable here; a hash map keyed by `ExeKey` is used instead.
* kavachd learns keys from three sources:
  1. `bprm_committed_creds` exec events.
  2. A startup task iterator (`iter/task`) over all running processes.
  3. **Key reports**: after each apply, kavachd opens every policy-named executable read-only. The
     LSM answers the armed one-shot `key_req` (thread id + nonce) with that inode's kernel key. Those binaries are
     classified before they ever run, and `apply` returns only once this is done (bounded 1 s).
* Each executable is hashed with SHA-256 from the fd the LSM reported. The cache only recomputes
  masks for classes that still exist; it is never used to re-trust a binary, and on restart rows
  without a live `exe_class` entry are dropped.

**Tamper revocation (placeholder protocol, FR-ID-3).** `file_open` for write and `path_truncate`
of *any* regular file (whatever its mode) delete `exe_class[key]`. To classify, kavachd arms
`key_req` and read-opens the file; the LSM inserts a placeholder (mask 0) under the bucket lock,
*then* reads `i_writecount` and reports key + writers. kavachd refuses files with open writers,
hashes the reported fd and commits with `BPF_EXIST`: a write-open after the report deleted the
placeholder, so the commit fails. There is no side table to evict or overflow. At connect time a
binary with open writers gets no exe identity at all.

**Unclassified window.** A process whose binary is not yet classified gets exe mask 0. It still
matches uid/cgroup-only selectors and is counted in `exe_unclassified`. Key reports close this
window for every binary the policy names by path. Binaries named only by hash are closed on
first exec.

## 6. Rule evaluation

`kv_evaluate(snapshot, dir, mask, remote, port, proto)` runs `bpf_loop` over `n_rules`
(≤ 1024), first match wins:

```
(rule.sel == 0 || rule.sel & mask) && dir ok && proto ok && port in [lo, hi]
  && (rule.set == ANY || set_bitmap(remote) & bit(rule.set)) && !expired
```

* No match ⇒ `default[dir]`.
* `Punt` (no L7 consumer before v0.4) resolves through the rule's fail mode: closed ⇒ drop,
  open ⇒ log.
* Egress to loopback bypasses evaluation unless the policy sets `loopback_bypass = false`.
* The scan runs once per connection (LSM) or once per new flow (TC).

`kavach-core::evaluate()` is the same algorithm over the same `#[repr(C)]` tables in Rust. It is
the reference semantics:
* `kavachctl explain` runs it with per-rule traces.
* The privileged differential test feeds 400 random flows to both the C program
  (`BPF_PROG_TEST_RUN`) and the Rust evaluator and asserts identical verdicts.

## 7. Life of a packet / connection

1. **XDP** (`xdp_filter.c`):
   - Parse up to 2 VLAN tags, IPv4 options and 4 IPv6 extension headers.
   - Blocklist LPM lookup (with expiry), then the GCRA check.
   - Result is `XDP_DROP` or `XDP_PASS`; unparseable frames pass and are counted.
2. **LSM egress** (`socket_connect`, and `socket_sendmsg` when it carries a destination):
   - Build the identity mask, run the egress scan, return `-EPERM` or allow.
   - Store `Identity` in `sk_ident`; emit an event on drop or log.
3. **TC egress**:
   - On first sight, insert the reply key with the socket's identity.
   - On a hit whose generation is stale, re-evaluate egress with the socket's identity
     (recomputed for the new slot). An established flow newly denied by a policy swap is cut
     (FR-HS-4).
4. **TC ingress**:
   - A reply-flow hit uses the cached verdict. An ingress-flow hit is used only if its
     generation is current.
   - The always-pass list (ICMP errors, ICMPv6 other than echo request, DHCP replies, non-first
     fragments) is never dropped.
   - Mid-stream TCP with no state passes unless `strict_ingress` is set.
   - New flows run the ingress scan with mask 0 (identity-agnostic in v0.3) and are cached.

## 8. Policy lifecycle and atomic hot-swap

```
build time (CI)                              run time (kavachd)
compile → validate → sign (Ed25519)   ──►    verify (before decoding) → diff → stage → flip → drain
```

`stage()` writes everything for the **inactive** slot:
1. uid, cgroup and exe `mask[slot]`.
2. Flattened `addr_sets`, including resolved FQDNs.
3. The `Policy` table.

It then flips `policy_gen` with one u32 write. Next it forces `synchronize_rcu()` by updating
the `sync_rcu` map-of-maps; after that, no program still runs on the old slot. Each program reads
`policy_gen` once and uses `slot = gen & 1` for every lookup, so a packet never sees half of two
policies. Measured flip and drain on 7.1: 20–100 µs.

### Bundle format (`.kvb`)

```
"KVB1" | u16 version | u16 flags | u64 serial | u64 created | u64 not_after | [u8;8] key_id
| fleet[32] | u32 payload_len | payload (postcard CompiledPolicy) | [u8;64] Ed25519 signature
signature = Ed25519(sk, "kavach-bundle-v1\0" ‖ header ‖ payload)     key_id = SHA-256(pk)[..8]
```

kavachd rejects a bundle when any of these hold:
* The key is untrusted or revoked.
* The signature fails.
* The fleet differs.
* `serial` ≤ the active serial (anti-rollback).
* The payload fails structural decoding.

An **expired** bundle is refused on apply. One that expires while active keeps enforcing and is
flagged in `status` and metrics, because silently dropping protection would be worse.

## 9. kavachd internals

```
control API (UDS NDJSON, SO_PEERCRED roles) ──► Daemon (Mutex) ──► Kernel (aya: load/attach/pin/maps)
ring-buffer reader ──► broadcast (events stream) + audit (≤10 drops/s) + identity jobs
identity broker ──► hash outside the lock ──► exe_class (seq-pair)       housekeeping (30 s):
                                                                         FQDN refresh, blocklist purge
```

* **Attach.** XDP falls back from native to generic and is replaced in place through the pinned
  link on upgrade. TC uses tcx on 6.6+ and clsact before that. Both attach the new program before
  detaching the old, so there is no window.
* **Audit.** Every change is appended to a hash-chained JSONL audit log. `kavachctl audit`
  verifies the chain, and a log that fails verification at startup is rotated aside rather than
  extended.

## 10. Failure semantics

| Event | Behaviour |
|-------|-----------|
| kavachd crash / stop | Programs, links and maps stay pinned; the last policy keeps enforcing (verified live) |
| kavachd restart | Re-adopts pins, continues the generation counter, re-stages the persisted bundle, reconciles exe cache |
| Bundle invalid / rollback / wrong fleet | Rejected; active policy unchanged; audit record + error |
| Punt with no consumer | Rule fail mode decides |
| BPF LSM not active | Identity egress is reported as off; XDP/TC still work |
| `kavachctl kill-switch --yes` (root) | Detach all links, unpin everything, remove the pin dir |

## 11. Security posture

* **Attacker-supplied bytes.** In C, only the verifier-bounded header parser touches them.
  TOML, bundles and control JSON are handled in Rust.
* **Control channel.** No network listener. The UDS is 0600, or 0660 with `control_group`, and
  peers are checked with `SO_PEERCRED`. Operators get read/apply/block; the kill-switch is
  root-only.
* **Unsafe code.** `forbid(unsafe_code)` in kavach-core, kavach-policy, kavach-api and kavachctl.
  Workspace lints require a `// SAFETY:` comment on every `unsafe` block.
* **Keys.** Signing keys live in CI; hosts only carry public keys.

## 12. Portability

`kavach-core` exposes the `Tables` and `Platform` traits.
* **Linux eBPF** runs the C mirror on the hot path, because the verifier cannot run the Rust
  core. The differential test keeps the two in lockstep.
* **v0.4** `kavach.ko` exports the Rust core as a kfunc.
* **v0.5** the BSD kernel module and the macOS Network Extension link the Rust core directly.
