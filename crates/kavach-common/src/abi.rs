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

/// [`PolicyHeader::flags`] bits.
/// Slot holds a valid, fully written policy.
pub const KV_POL_F_VALID: u32 = 1 << 0;
/// Drop mid-stream TCP packets with no flow state (FR-TC-3 strict mode).
pub const KV_POL_F_STRICT_INGRESS: u32 = 1 << 1;
/// Do not exempt loopback from egress policy.
pub const KV_POL_F_NO_LOOPBACK_BYPASS: u32 = 1 << 2;

/// Fixed-point scale for token buckets: one packet costs this many "nano-tokens".
pub const KV_TOKEN_SCALE: u64 = 1_000_000_000;

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
    /// A classified executable was opened for write; its classification was revoked.
    ExeTainted = 5,
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

/// Cached decision for a flow. 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct FlowVal {
    /// Selector mask of the identity that owns the flow.
    pub identity: u64,
    pub rule_id: u32,
    /// [`Verdict`] as u8.
    pub verdict: u8,
    /// Low 8 bits of the policy generation that produced this entry.
    pub generation: u8,
    pub flags: u8,
    pub _pad: u8,
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

/// Key for `rate_buckets`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct SrcKey {
    pub addr: [u8; 16],
}

/// Per-source, per-CPU token bucket.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct TokenBucket {
    /// Available tokens × [`KV_TOKEN_SCALE`].
    pub tokens: u64,
    pub last_ns: u64,
}

/// Singleton XDP configuration (`xdp_cfg[0]`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct XdpConfig {
    /// Packets per second allowed per source **per CPU** (kavachd divides by nr_cpus).
    pub pps_per_cpu: u64,
    /// Bucket depth in packets.
    pub burst: u64,
    /// Emit 1 of every N drop events (0 = no events).
    pub sample_rate: u32,
    /// `KV_XDP_F_*`.
    pub flags: u32,
}

// ---------------------------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------------------------

/// Key for `exe_class`: the executable's inode. `dev` is the **kernel** `s_dev` encoding
/// (`major << 20 | minor`), not the userspace `st_dev` encoding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Pod, Zeroable)]
pub struct ExeKey {
    pub dev: u32,
    pub _pad: u32,
    pub ino: u64,
}

/// Who owns a socket. Written to `identity_by_cookie` by the LSM program. 48 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct Identity {
    pub cgroup_id: u64,
    /// Selector mask the process matched at connect time.
    pub mask: u64,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub _pad: u32,
    pub comm: [u8; 16],
}

// ---------------------------------------------------------------------------------------------
// Policy tables
// ---------------------------------------------------------------------------------------------

/// Per-slot header (`policy_slots[slot]`). 64 bytes.
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
    pub _reserved: u64,
}

/// One compiled rule (`policy_rules[slot * KV_MAX_RULES + i]`). 48 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct Rule {
    /// Selector mask; 0 = any identity.
    pub sel: u64,
    pub id: u32,
    /// Remote address set (egress: destination, ingress: source); 0 = any address.
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
    pub _reserved: [u64; 2],
}

/// `LPM_TRIE` key for `addr_sets`. `slot` and `set_id` are always fully matched, so
/// `prefixlen = 64 + address prefix bits`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct AddrSetKey {
    pub prefixlen: u32,
    pub slot: u32,
    pub set_id: u32,
    pub addr: [u8; 16],
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
    /// Identity selector mask (or, for `Exec`/`ExeTainted`, the inode number).
    pub identity: u64,
    pub rule_id: u32,
    pub generation: u32,
    pub comm: [u8; 16],
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
assert_size!(FlowVal, 40);
assert_size!(BlockKey, 20);
assert_size!(BlockVal, 16);
assert_size!(SrcKey, 16);
assert_size!(TokenBucket, 16);
assert_size!(XdpConfig, 24);
assert_size!(ExeKey, 16);
assert_size!(Identity, 48);
assert_size!(PolicyHeader, 64);
assert_size!(Rule, 48);
assert_size!(AddrSetKey, 28);
assert_size!(Event, 104);
const _: () = assert!(core::mem::offset_of!(FlowKey, src) == 8);
const _: () = assert!(core::mem::offset_of!(Event, key) == 16);
const _: () = assert!(core::mem::offset_of!(Event, comm) == 88);

/// `(name, size)` of every ABI struct, used by `xtask codegen` to emit C `_Static_assert`s.
pub const LAYOUT: &[(&str, usize)] = &[
    ("kv_flow_key", core::mem::size_of::<FlowKey>()),
    ("kv_flow_val", core::mem::size_of::<FlowVal>()),
    ("kv_block_key", core::mem::size_of::<BlockKey>()),
    ("kv_block_val", core::mem::size_of::<BlockVal>()),
    ("kv_src_key", core::mem::size_of::<SrcKey>()),
    ("kv_token_bucket", core::mem::size_of::<TokenBucket>()),
    ("kv_xdp_config", core::mem::size_of::<XdpConfig>()),
    ("kv_exe_key", core::mem::size_of::<ExeKey>()),
    ("kv_identity", core::mem::size_of::<Identity>()),
    ("kv_policy_header", core::mem::size_of::<PolicyHeader>()),
    ("kv_rule", core::mem::size_of::<Rule>()),
    ("kv_addr_set_key", core::mem::size_of::<AddrSetKey>()),
    ("kv_event", core::mem::size_of::<Event>()),
];
