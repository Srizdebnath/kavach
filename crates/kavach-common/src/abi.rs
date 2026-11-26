//! The C <-> Rust ABI. **Single source of truth.**
//!
//! `cargo xtask codegen` turns this file into `bpf/include/kavach_abi.h` with cbindgen.
//! Every struct is `#[repr(C)]`, has only explicit padding (so it is `bytemuck::Pod`), and
//! carries a compile-time size assertion that is mirrored by `_Static_assert` on the C side.
//!
//! Conventions:
//! * Addresses are 16 bytes; IPv4 is stored IPv4-mapped (`::ffff:a.b.c.d`).
//! * Ports inside [`FlowKey`] are **network byte order** (as read from the wire).
//! * Ports inside [`Rule`] are **host byte order** (range comparisons).
//! * Timestamps ending in `_ns` are `CLOCK_BOOTTIME` nanoseconds (`bpf_ktime_get_boot_ns`).

use bytemuck::{Pod, Zeroable};

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------

/// Length of a normalised (IPv6 / IPv4-mapped) address.
pub const KV_ADDR_LEN: usize = 16;
/// Maximum rules per policy slot.
pub const KV_MAX_RULES: u32 = 1024;
/// Number of policy slots (A/B).
pub const KV_SLOTS: u32 = 2;
/// Maximum distinct selectors per policy (one bit each in a `u64` mask).
pub const KV_MAX_SELECTORS: u32 = 64;
/// Maximum distinct address sets per policy (one bit each in a `u64` set bitmap).
pub const KV_MAX_SETS: u32 = 64;
/// Maximum cgroup ancestor levels walked when matching cgroup selectors (subtree semantics).
pub const KV_CGROUP_LEVELS: u32 = 8;
/// Entries in the per-CPU `stats` array.
pub const KV_STAT_MAX: u32 = 16;
/// Address family tags used in [`FlowKey::family`].
pub const KV_AF_INET: u8 = 2;
pub const KV_AF_INET6: u8 = 10;
/// IP protocol numbers.
pub const KV_PROTO_ANY: u8 = 0;
pub const KV_PROTO_ICMP: u8 = 1;
pub const KV_PROTO_TCP: u8 = 6;
pub const KV_PROTO_UDP: u8 = 17;
pub const KV_PROTO_ICMPV6: u8 = 58;

/// Rule direction.
pub const KV_DIR_EGRESS: u8 = 1;
pub const KV_DIR_INGRESS: u8 = 2;

/// Rule failure mode when a decision needs user space and user space is absent.
pub const KV_FAIL_OPEN: u8 = 0;
pub const KV_FAIL_CLOSED: u8 = 1;

/// [`XdpConfig::flags`] bits.
pub const KV_XDP_F_BLOCKLIST: u32 = 1 << 0;
pub const KV_XDP_F_RATELIMIT: u32 = 1 << 1;
/// Opt-in AF_XDP gateway redirect: frames whose (proto, destination port) is in `xsk_ports`
/// go to the AF_XDP socket of their RX queue in `xsk_sockets`, but only while that queue's
/// `xsk_alive` deadline is in the future. Everything else passes. Never set by default.
pub const KV_XDP_F_AFXDP: u32 = 1 << 2;

/// Entries in `xsk_sockets` / `xsk_alive` (RX queue ids `0..KV_XSK_MAX_QUEUES`).
pub const KV_XSK_MAX_QUEUES: u32 = 64;
/// Entries in `xsk_ports` (gateway-selected `(proto, port)` pairs).
pub const KV_XSK_MAX_PORTS: u32 = 256;
/// Indices of the per-CPU `xsk_stats` array.
/// Frame redirected to an AF_XDP socket.
pub const KV_XSK_STAT_REDIRECT: u32 = 0;
/// Port selected but the queue's watchdog deadline had lapsed: passed to the stack.
pub const KV_XSK_STAT_STALE: u32 = 1;
/// Port selected, deadline live, but no socket on that queue: passed to the stack.
pub const KV_XSK_STAT_NO_SOCKET: u32 = 2;
/// Entries in `xsk_stats`.
pub const KV_XSK_STAT_MAX: u32 = 4;

/// `xsk_ports` key: `proto << 16 | port` (port in **host** order). A plain `u32` keeps the map
/// layout out of [`LAYOUT`] (no new struct, no ABI bump).
pub const fn xsk_port_key(proto: u8, port: u16) -> u32 {
    ((proto as u32) << 16) | port as u32
}

/// [`PolicyHeader::flags`] bits.
/// Slot holds a valid, fully written policy.
pub const KV_POL_F_VALID: u32 = 1 << 0;
/// Drop mid-stream TCP packets with no flow state (FR-TC-3 strict mode).
pub const KV_POL_F_STRICT_INGRESS: u32 = 1 << 1;
/// Do not exempt loopback from egress policy.
pub const KV_POL_F_NO_LOOPBACK_BYPASS: u32 = 1 << 2;
/// Refuse egress from a classifiable executable that has no committed hash yet, while the
/// policy has executable selectors (closes the first-run window; `unclassified = "deny"`).
pub const KV_POL_F_UNCLASSIFIED_DENY: u32 = 1 << 3;
/// The policy has k8s / SPIFFE (workload) selectors: OR the `wl_class` mask of the task's
/// nearest classified cgroup (itself, else its deepest listed ancestor) into the cgroup mask.
pub const KV_POL_F_WORKLOAD: u32 = 1 << 4;

/// Entries in `wl_class` (cgroup id → [`ClassVal`]; kavachd counts what does not fit).
pub const KV_WL_MAX: u32 = 16384;

/// [`FlowVal::flags`] bits.
/// Entry is the reply direction of a locally-originated flow (always allowed).
pub const KV_FLOW_F_REPLY: u8 = 1 << 0;
/// Entry was produced by the ingress rule scan.
pub const KV_FLOW_F_INGRESS: u8 = 1 << 1;

/// IPv6 sources are rate-limited per /64 (an attacker controls a whole /64).
pub const KV_RATE_V6_PREFIX: u32 = 64;

// ---------------------------------------------------------------------------------------------
// Enums (encoded as u8 on the wire; Rust enums give type safety in user space)
// ---------------------------------------------------------------------------------------------

/// Final decision for a packet, connection or flow.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    Allow = 0,
    Drop = 1,
    /// Allow and emit an event.
    Log = 2,
    /// Defer to user space / L7 gateway; the rule's `fail` mode applies meanwhile.
    Punt = 3,
}

impl Verdict {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Allow),
            1 => Some(Self::Drop),
            2 => Some(Self::Log),
            3 => Some(Self::Punt),
            _ => None,
        }
    }
}

/// Index into the per-CPU `stats` array.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatReason {
    XdpPass = 0,
    XdpDropBlocklist = 1,
    XdpDropRate = 2,
    XdpUnparsed = 3,
    EgressAllow = 4,
    EgressDrop = 5,
    EgressLog = 6,
    IngressAllow = 7,
    IngressDrop = 8,
    FlowCacheHit = 9,
    FlowCacheMiss = 10,
    EventsLost = 11,
    PolicyNoSlot = 12,
    ExeUnclassified = 13,
    FlowCacheStale = 14,
    /// Egress refused because the executable was not classified yet (strict mode).
    EgressUnclassified = 15,
}

/// Event type tag in [`Event::kind`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    XdpDrop = 1,
    EgressVerdict = 2,
    IngressVerdict = 3,
    /// A new executable started; user space should hash and classify it.
    Exec = 4,
    /// A classified executable was opened for write or truncated; the LSM deleted its
    /// `exe_class` entry.
    ExeTainted = 5,
    /// Answer to a one-shot [`KeyReq`]: kavachd's read-open of a file, with the kernel's key for
    /// that inode. `cgroup_id` echoes the request nonce; `verdict` holds `KV_REPORT_*` bits.
    KeyReport = 6,
}

// ---------------------------------------------------------------------------------------------
// Flow tracking
// ---------------------------------------------------------------------------------------------

/// Directional 5-tuple. 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct FlowKey {
    pub family: u8,
    pub proto: u8,
    pub _pad: [u8; 2],
    /// Network byte order.
    pub sport: u16,
    /// Network byte order.
    pub dport: u16,
    pub src: [u32; 4],
    pub dst: [u32; 4],
}

/// Cached decision for a flow. 48 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct FlowVal {
    /// Selector mask of the identity that owns the flow.
    pub identity: u64,
    pub rule_id: u32,
    /// Policy generation that produced this entry (ignored for `KV_FLOW_F_REPLY` entries).
    pub generation: u32,
    /// [`Verdict`] as u8.
    pub verdict: u8,
    /// `KV_FLOW_F_*`.
    pub flags: u8,
    pub _pad: [u8; 6],
    pub last_seen_ns: u64,
    pub pkts: u64,
    pub bytes: u64,
}

// ---------------------------------------------------------------------------------------------
// XDP: blocklist + rate limiting
// ---------------------------------------------------------------------------------------------

/// `LPM_TRIE` key for the blocklist. `prefixlen` counts bits of `addr` (IPv4 = 96 + len).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct BlockKey {
    pub prefixlen: u32,
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct BlockVal {
    /// 0 = never expires; otherwise `CLOCK_BOOTTIME` ns.
    pub expires_ns: u64,
    /// Operator-defined reason code (threat feed id, rule id...).
    pub reason: u32,
    pub _pad: u32,
}

/// Key for `rate_buckets`: IPv4 /32 or IPv6 /64 (low 64 bits zeroed), mapped form.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct SrcKey {
    pub addr: [u8; 16],
}

/// GCRA state, shared across CPUs and updated with compare-and-swap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct RateState {
    /// Theoretical arrival time of the next conforming packet (`CLOCK_BOOTTIME` ns).
    pub tat_ns: u64,
    /// Packets dropped for this source (approximate, for observability).
    pub drops: u64,
}

/// Singleton XDP configuration (`xdp_cfg[0]`). Rate limiting uses GCRA:
/// `emission_ns = 1e9 / pps`, `tau_ns = emission_ns * (burst - 1)`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct XdpConfig {
    pub emission_ns: u64,
    pub tau_ns: u64,
    /// Emit 1 of every N drop events (0 = no events).
    pub sample_rate: u32,
    /// `KV_XDP_F_*`.
    pub flags: u32,
}

// ---------------------------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------------------------

/// Value of `uid_class` (key `u32` uid) and `cgroup_class` (key `u64` cgroup id):
/// selector masks **per policy slot**, so selector renumbering in a new bundle never mixes
/// with the active slot's rules.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct ClassVal {
    pub mask: [u64; 2],
}

/// Key for `exe_class`: the executable's **live kernel inode** (`struct inode *`) plus its
/// `i_ino`. Distinct live inodes never share a key, whatever the filesystem reports (btrfs
/// subvolumes share `s_dev` and reuse inode numbers; FUSE picks its own). The LSM deletes the
/// class when the inode is freed (`inode_free_security`), so a recycled pointer never inherits
/// one; `dev` (`s_dev`) and `generation` (`i_generation`) must match too, as a second line should
/// that delete ever fail. kavachd only copies keys from events; `inode` is a kernel address and
/// never leaves the daemon (event rendering zeroes it).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct ExeKey {
    pub inode: u64,
    pub ino: u64,
    pub dev: u32,
    pub generation: u32,
}

/// `exe_class` value. Present = trusted: the LSM **deletes** the entry on every write-open or
/// truncate of the inode, whatever its mode, so a modified binary can never keep (or, through
/// map pressure, regain) its classification.
///
/// Classification protocol (closes the hash-then-modify race):
/// 1. kavachd arms [`KeyReq`] and read-opens the file;
/// 2. the LSM inserts a placeholder (`mask = 0`, `nonce`) under the bucket lock, **then** reads
///    `i_writecount` and answers with a `KeyReport`;
/// 3. kavachd hashes that same fd and commits with `BPF_EXIST`. A taint after step 2 deleted the
///    placeholder, so the commit fails; a writer from before step 2 was reported and refused.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct ExeClass {
    pub mask: [u64; 2],
    /// Nonce of the [`KeyReq`] that produced this entry (placeholder or committed).
    pub nonce: u64,
    /// `KV_EXE_F_*`. A placeholder has no flags.
    pub flags: u64,
}

/// [`ExeClass::flags`]: kavachd committed a hash for this entry (not a placeholder). Only
/// committed entries count as classified for exec reporting and mask updates.
pub const KV_EXE_F_COMMITTED: u64 = 1;

/// `KeyReport` [`Event::verdict`] bits.
pub const KV_REPORT_WRITERS: u8 = 1;
/// The file lives on a filesystem whose content kavachd cannot vouch for (memfd / internal
/// mount, FUSE, network, overlay, an nbd/ublk device, ...): it is never classified.
pub const KV_REPORT_UNTRUSTED_FS: u8 = 2;

/// `key_req[0]` (kavachd-owned): the next file_open by thread `tid` answers with a
/// `KeyReport` carrying `nonce`, then the LSM clears `nonce` (one-shot).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct KeyReq {
    pub nonce: u64,
    pub tid: u32,
    pub _pad: u32,
}

/// Socket owner, kept in `sk_ident` (SK_STORAGE, freed with the socket). 72 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct Identity {
    pub cgroup_id: u64,
    pub exe: ExeKey,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    /// Generation `mask` was computed for.
    pub generation: u32,
    /// Selector mask computed at connect time.
    pub mask: u64,
    pub comm: [u8; 16],
}

// ---------------------------------------------------------------------------------------------
// Policy tables
// ---------------------------------------------------------------------------------------------

/// Header of one policy slot. 64 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct PolicyHeader {
    pub n_rules: u32,
    /// `KV_POL_F_*`.
    pub flags: u32,
    /// [`Verdict`] when no egress rule matches.
    pub default_egress: u8,
    /// [`Verdict`] when no ingress rule matches (new flows only).
    pub default_ingress: u8,
    pub _pad: [u8; 6],
    /// Selectors that do not constrain the executable.
    pub wild_exe: u64,
    /// Selectors that do not constrain the uid.
    pub wild_uid: u64,
    /// Selectors that do not constrain the cgroup.
    pub wild_cgroup: u64,
    /// Bundle serial this slot was built from.
    pub serial: u64,
    /// Full policy generation that activated this slot.
    pub generation: u32,
    pub _pad2: u32,
    /// Bitmap of defined selectors; identity masks are ANDed with it. Bits of undefined
    /// selectors are set in every `wild_*` so `wild_* == u64::MAX` means "dimension unused".
    pub sel_used: u64,
}

/// One compiled rule. 48 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct Rule {
    /// Selector mask; 0 = any identity.
    pub sel: u64,
    pub id: u32,
    /// Remote address set id 1..=64 (egress: destination, ingress: source); 0 = any address.
    /// Matches when bit `remote_set - 1` is set in the destination's `addr_sets` bitmap.
    pub remote_set: u32,
    /// Service port range, host order (egress: remote port, ingress: local port).
    pub port_lo: u16,
    pub port_hi: u16,
    /// `KV_PROTO_*`; 0 = any.
    pub proto: u8,
    /// `KV_DIR_*`.
    pub dir: u8,
    /// [`Verdict`] as u8.
    pub verdict: u8,
    /// `KV_FAIL_*`.
    pub fail: u8,
    /// 0 = no TTL; else `CLOCK_BOOTTIME` ns after which the rule no longer matches.
    pub not_after_ns: u64,
    /// Punt rules: 1-based index of the deciding gateway in the compiled policy's `gateways`
    /// (names live there). 0 = none: the kernel never redirects the punt, its fail mode decides.
    pub gateway: u16,
    pub _pad: [u8; 6],
    pub _reserved: u64,
}

/// One whole policy slot (`policy_slots[slot]`): looked up once per evaluation, then indexed.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct Policy {
    pub hdr: PolicyHeader,
    pub rules: [Rule; 1024],
}

impl Default for Policy {
    fn default() -> Self {
        Zeroable::zeroed()
    }
}

/// `LPM_TRIE` key for `addr_sets` → `u64` set bitmap. `slot` is always fully matched, so
/// `prefixlen = 32 + address prefix bits`. The compiler flattens overlapping prefixes so the
/// longest match carries the union of every set containing it — one lookup per evaluation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct AddrKey {
    pub prefixlen: u32,
    pub slot: u32,
    pub addr: [u8; 16],
}

// ---------------------------------------------------------------------------------------------
// L7 gateway redirect (the punt data path)
// ---------------------------------------------------------------------------------------------

/// Entries in the per-CPU `gw_stats` array (indices `KV_GW_STAT_*`).
pub const KV_GW_STAT_MAX: u32 = 8;
/// A punted TCP connect was redirected to the gateway listener.
pub const KV_GW_STAT_REDIRECT: u32 = 0;
/// Punt while the gateway was off or its liveness deadline had lapsed: rule fail mode applied.
pub const KV_GW_STAT_DEAD: u32 = 1;
/// Punt that cannot be redirected (not TCP, or an `IPV6_V6ONLY` socket with no IPv6
/// listener): rule fail mode applied.
pub const KV_GW_STAT_UNREDIRECTABLE: u32 = 2;
/// Punt by the gateway itself (its upstream leg): allowed and never redirected (no loops).
pub const KV_GW_STAT_EXEMPT: u32 = 3;
/// `orig_dst` insert failed: the gateway will not find this connection (and must refuse it).
pub const KV_GW_STAT_ORIG_FAIL: u32 = 4;
/// `orig_dst` entry removed because the client socket closed.
pub const KV_GW_STAT_ORIG_CLOSED: u32 = 5;
/// The connect hook found a punt record that does not describe this connect: ignored.
pub const KV_GW_STAT_STALE: u32 = 6;
/// The punt rule names no gateway: never redirected, rule fail mode applied.
pub const KV_GW_STAT_NO_GATEWAY: u32 = 7;

/// [`GatewayCfg::flags`]: an IPv4 listener is configured (`listen4`).
pub const KV_GW_F_V4: u32 = 1 << 0;
/// [`GatewayCfg::flags`]: an IPv6 listener is configured (`listen6`). Without it IPv6 sockets
/// are redirected to the IPv4-mapped `listen4`, which `IPV6_V6ONLY` sockets cannot reach (those
/// punts resolve through the fail mode instead).
pub const KV_GW_F_V6: u32 = 1 << 1;

/// `gw_cfg[0]` (kavachd-owned): where punted connections go, which process is the gateway, and
/// until when the gateway is known to be alive. 48 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct GatewayCfg {
    /// `CLOCK_BOOTTIME` ns until which punts are redirected. 0 or in the past = no gateway:
    /// punts resolve through the rule's fail mode exactly as before v0.4.
    pub alive_until_ns: u64,
    /// cgroup id of the gateway's processes (exact match; 0 = none).
    pub exempt_cgroup: u64,
    /// IPv4 listener address, network order.
    pub listen4: u32,
    /// Network order.
    pub listen4_port: u16,
    /// Network order.
    pub listen6_port: u16,
    /// IPv6 listener address (with `KV_GW_F_V6`).
    pub listen6: [u32; 4],
    /// Process (tgid) that is the gateway, e.g. kavachd hosting the proxy (0 = none).
    pub exempt_tgid: u32,
    /// `KV_GW_F_*`.
    pub flags: u32,
}

/// [`PuntRecord::flags`]: the LSM decided to redirect this connect; the connect hook has not
/// rewritten it yet.
pub const KV_PUNT_F_PENDING: u8 = 1 << 0;
/// The connect was rewritten to the gateway listener (`target`).
pub const KV_PUNT_F_REDIRECTED: u8 = 1 << 1;
/// kavachd recorded the gateway's connection-level verdict in [`PuntRecord::verdict`].
pub const KV_PUNT_F_DECIDED: u8 = 1 << 2;

/// One punted connection. Value of `sk_punt` (SK_STORAGE on the client socket: written by the
/// LSM, consumed by the connect hook) and of `orig_dst` (keyed by [`OrigKey`]: written by the
/// sockops program once the client's port is bound, deleted when the client socket closes).
/// Addresses are 16-byte IPv4-mapped, ports network order. 72 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct PuntRecord {
    pub cgroup_id: u64,
    /// Original destination.
    pub dst: [u32; 4],
    /// Gateway listener the connect was rewritten to.
    pub target: [u32; 4],
    pub rule_id: u32,
    pub pid: u32,
    pub uid: u32,
    /// Policy generation that punted.
    pub generation: u32,
    /// Original destination port.
    pub dport: u16,
    pub target_port: u16,
    /// [`Rule::gateway`] of the punting rule.
    pub gateway: u16,
    /// Client socket family (`KV_AF_*`).
    pub family: u8,
    /// `KV_PUNT_F_*`.
    pub flags: u8,
    /// Gateway write-back ([`Verdict`]); valid with `KV_PUNT_F_DECIDED`.
    pub verdict: u8,
    pub _pad: [u8; 7],
}

/// `orig_dst` key: the redirected connection as the gateway sees it on accept (`client` =
/// peer, `gateway` = its own local address). IPv4-mapped, ports network order. 36 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct OrigKey {
    pub client: [u32; 4],
    pub gateway: [u32; 4],
    pub client_port: u16,
    pub gateway_port: u16,
}

// ---------------------------------------------------------------------------------------------
// Events (ring buffer)
// ---------------------------------------------------------------------------------------------

/// Fixed-size ring-buffer record. 104 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct Event {
    /// [`EventKind`] as u8.
    pub kind: u8,
    /// [`Verdict`] as u8.
    pub verdict: u8,
    /// [`StatReason`] (low 8 bits).
    pub reason: u8,
    pub _pad: u8,
    pub ifindex: u32,
    pub ts_ns: u64,
    pub key: FlowKey,
    pub pid: u32,
    pub uid: u32,
    pub cgroup_id: u64,
    /// Identity selector mask. For `Exec` / `ExeTainted` / `KeyReport`: the inode number.
    pub identity: u64,
    /// Matching rule id. For `Exec` / `ExeTainted` / `KeyReport`: low half of [`ExeKey::inode`].
    pub rule_id: u32,
    /// Policy generation. For `Exec` / `ExeTainted` / `KeyReport`: high half of
    /// [`ExeKey::inode`] (and `key.dst[0..2]` carry [`ExeKey::dev`] / [`ExeKey::generation`]).
    pub generation: u32,
    pub comm: [u8; 16],
}

impl Event {
    /// The executable key carried by `Exec` / `ExeTainted` / `KeyReport` events.
    pub const fn exe_key(&self) -> ExeKey {
        ExeKey {
            inode: (self.generation as u64) << 32 | self.rule_id as u64,
            ino: self.identity,
            dev: self.key.dst[0],
            generation: self.key.dst[1],
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Layout assertions (mirrored in C by xtask codegen)
// ---------------------------------------------------------------------------------------------

macro_rules! assert_size {
    ($t:ty, $n:expr) => {
        const _: () = assert!(core::mem::size_of::<$t>() == $n);
    };
}
assert_size!(FlowKey, 40);
assert_size!(FlowVal, 48);
assert_size!(BlockKey, 20);
assert_size!(BlockVal, 16);
assert_size!(SrcKey, 16);
assert_size!(RateState, 16);
assert_size!(XdpConfig, 24);
assert_size!(ClassVal, 16);
assert_size!(ExeClass, 32);
assert_size!(ExeKey, 24);
assert_size!(KeyReq, 16);
assert_size!(Identity, 72);
assert_size!(PolicyHeader, 64);
assert_size!(Rule, 48);
assert_size!(Policy, 64 + 48 * KV_MAX_RULES as usize);
assert_size!(AddrKey, 24);
assert_size!(Event, 104);
assert_size!(GatewayCfg, 48);
assert_size!(PuntRecord, 72);
assert_size!(OrigKey, 36);
const _: () = assert!(core::mem::offset_of!(Rule, gateway) == 32);
const _: () = assert!(core::mem::offset_of!(FlowKey, src) == 8);
const _: () = assert!(core::mem::offset_of!(Event, key) == 16);
const _: () = assert!(core::mem::offset_of!(Event, comm) == 88);
const _: () = assert!(core::mem::offset_of!(Policy, rules) == 64);

/// `(name, size)` of every ABI struct, used by `xtask codegen` to emit C `_Static_assert`s.
pub const LAYOUT: &[(&str, usize)] = &[
    ("kv_flow_key", core::mem::size_of::<FlowKey>()),
    ("kv_flow_val", core::mem::size_of::<FlowVal>()),
    ("kv_block_key", core::mem::size_of::<BlockKey>()),
    ("kv_block_val", core::mem::size_of::<BlockVal>()),
    ("kv_src_key", core::mem::size_of::<SrcKey>()),
    ("kv_rate_state", core::mem::size_of::<RateState>()),
    ("kv_xdp_config", core::mem::size_of::<XdpConfig>()),
    ("kv_class_val", core::mem::size_of::<ClassVal>()),
    ("kv_exe_key", core::mem::size_of::<ExeKey>()),
    ("kv_exe_class", core::mem::size_of::<ExeClass>()),
    ("kv_key_req", core::mem::size_of::<KeyReq>()),
    ("kv_identity", core::mem::size_of::<Identity>()),
    ("kv_policy_header", core::mem::size_of::<PolicyHeader>()),
    ("kv_rule", core::mem::size_of::<Rule>()),
    ("kv_policy", core::mem::size_of::<Policy>()),
    ("kv_addr_key", core::mem::size_of::<AddrKey>()),
    ("kv_event", core::mem::size_of::<Event>()),
    ("kv_gateway_cfg", core::mem::size_of::<GatewayCfg>()),
    ("kv_punt_record", core::mem::size_of::<PuntRecord>()),
    ("kv_orig_key", core::mem::size_of::<OrigKey>()),
];
