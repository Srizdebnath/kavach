//! # kavach-core
//!
//! The reference semantics of Kavach policy evaluation, written once in safe, `no_std`,
//! allocation-free Rust. The C eBPF programs (`bpf/include/kavach_eval.h`) implement exactly the
//! same algorithm over exactly the same `#[repr(C)]` tables; the differential test suite runs both
//! and asserts identical verdicts. `kavachctl explain` and `apply --dry-run` use this crate, and in
//! v0.4 `kavach.ko` exports it to the kernel as a kfunc.
//!
//! Evaluation protocol (FR-HS-2): take ONE [`Snapshot`] (generation + slot) and use it for every
//! lookup in the evaluation.
#![no_std]
#![forbid(unsafe_code)]

use kavach_common::abi::*;

/// Where per-host classification state lives (BPF maps in the kernel, hash maps in tests).
pub trait Tables {
    /// Present = trusted: the kernel deletes the entry when the file is modified.
    fn exe_class(&self, key: &ExeKey) -> Option<ExeClass>;
    fn uid_class(&self, uid: u32) -> Option<ClassVal>;
    fn cgroup_class(&self, cgroup_id: u64) -> Option<ClassVal>;
    /// Longest-prefix match in `addr_sets` for `slot`; 0 when nothing matches.
    fn remote_sets(&self, slot: u32, addr: &[u8; 16]) -> u64;
}

/// Platform services (portability trait, see ARCHITECTURE §12).
pub trait Platform {
    /// `CLOCK_BOOTTIME` nanoseconds.
    fn now_ns(&self) -> u64;
    /// Emit an event (ring buffer, log, ...). Default: drop it.
    fn emit(&self, _event: &Event) {}
}

/// One consistent view of the active policy.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot<'a> {
    pub policy: &'a Policy,
    pub generation: u32,
}

impl<'a> Snapshot<'a> {
    /// `None` when the slot is not marked valid (the kernel then allows everything).
    pub fn new(policy: &'a Policy, generation: u32) -> Option<Self> {
        (policy.hdr.flags & KV_POL_F_VALID != 0).then_some(Self { policy, generation })
    }
    pub const fn slot(&self) -> u32 {
        self.generation & 1
    }
}

/// Facts about the process that owns a socket.
#[derive(Clone, Copy, Debug, Default)]
pub struct Who<'a> {
    pub exe: ExeKey,
    pub uid: u32,
    /// The socket's cgroup followed by its ancestors (leaf first, at most `KV_CGROUP_LEVELS + 1`).
    pub cgroups: &'a [u64],
}

/// Mask contributed by an executable. A zero key (kernel thread, untrusted filesystem, open writers)
/// is never classified.
pub fn exe_mask<T: Tables + ?Sized>(t: &T, key: &ExeKey, slot: u32) -> u64 {
    if key.inode == 0 {
        return 0;
    }
    t.exe_class(key).map_or(0, |c| c.mask[(slot & 1) as usize])
}

/// `m = (exe | wild_exe) & (uid | wild_uid) & (cgroup | wild_cgroup)`.
pub fn identity_mask<T: Tables + ?Sized>(t: &T, snap: &Snapshot<'_>, who: &Who<'_>) -> u64 {
    let h = &snap.policy.hdr;
    let slot = snap.slot();
    let exe_m = if h.wild_exe == u64::MAX {
        0
    } else {
        exe_mask(t, &who.exe, slot)
    };
    let uid_m = if h.wild_uid == u64::MAX {
        0
    } else {
        t.uid_class(who.uid)
            .map_or(0, |c| c.mask[(slot & 1) as usize])
    };
    let cg_m = if h.wild_cgroup == u64::MAX {
        0
    } else {
        who.cgroups
            .iter()
            .take(KV_CGROUP_LEVELS as usize + 1)
            .filter_map(|id| t.cgroup_class(*id))
            .fold(0, |acc, c| acc | c.mask[(slot & 1) as usize])
    };
    combine_mask(&h.wild_exe, &h.wild_uid, &h.wild_cgroup, exe_m, uid_m, cg_m) & h.sel_used
}

#[inline]
pub const fn combine_mask(
    wild_exe: &u64,
    wild_uid: &u64,
    wild_cgroup: &u64,
    exe_m: u64,
    uid_m: u64,
    cg_m: u64,
) -> u64 {
    (exe_m | *wild_exe) & (uid_m | *wild_uid) & (cg_m | *wild_cgroup)
}

/// The flow being judged, from the local host's point of view.
#[derive(Clone, Copy, Debug)]
pub struct FlowQuery {
    pub dir: u8,
    /// Selector mask of the local identity (0 for ingress in v0.3).
    pub mask: u64,
    /// Remote address (egress: destination, ingress: source), mapped form.
    pub remote: [u8; 16],
    /// Service port, host order.
    pub port: u16,
    pub proto: u8,
}

/// Why a rule did not match (for `kavachctl explain`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Miss {
    Direction,
    Identity,
    Protocol,
    Port,
    RemoteAddress,
    Expired,
}

/// Outcome of an evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Final verdict: Allow, Drop or Log (Punt is resolved through the rule's fail mode).
    pub verdict: Verdict,
    /// Matching rule id, 0 = default verdict.
    pub rule_id: u32,
    /// Index of the matching rule in the slot.
    pub rule_index: Option<usize>,
    /// The rule asked for an L7 decision that was resolved by its fail mode.
    pub punted: bool,
}

/// Does `r` match `q`? `Ok(())` or the first reason it does not.
pub fn rule_matches(r: &Rule, q: &FlowQuery, sets: u64, now_ns: u64) -> Result<(), Miss> {
    if r.dir != q.dir {
        return Err(Miss::Direction);
    }
    if r.sel != 0 && r.sel & q.mask == 0 {
        return Err(Miss::Identity);
    }
    if r.proto != KV_PROTO_ANY && r.proto != q.proto {
        return Err(Miss::Protocol);
    }
    if q.port < r.port_lo || q.port > r.port_hi {
        return Err(Miss::Port);
    }
    if r.remote_set != 0 {
        let bit = r.remote_set - 1;
        if bit >= 64 || (sets >> bit) & 1 == 0 {
            return Err(Miss::RemoteAddress);
        }
    }
    if r.not_after_ns != 0 && now_ns >= r.not_after_ns {
        return Err(Miss::Expired);
    }
    Ok(())
}

/// Evaluate `q` against the snapshot. `trace` is called for every rule examined (in order) with
/// `None` on match or `Some(reason)` on miss — pass `|_, _| {}` when not explaining.
pub fn evaluate_traced<T: Tables + ?Sized, F: FnMut(usize, Option<Miss>)>(
    t: &T,
    snap: &Snapshot<'_>,
    q: &FlowQuery,
    now_ns: u64,
    mut trace: F,
) -> Decision {
    let pol = snap.policy;
    let sets = t.remote_sets(snap.slot(), &q.remote);
    let n = (pol.hdr.n_rules as usize).min(KV_MAX_RULES as usize);
    for (i, r) in pol.rules[..n].iter().enumerate() {
        match rule_matches(r, q, sets, now_ns) {
            Ok(()) => {
                trace(i, None);
                let v = Verdict::from_u8(r.verdict).unwrap_or(Verdict::Drop);
                let (verdict, punted) = match v {
                    Verdict::Punt if r.fail == KV_FAIL_CLOSED => (Verdict::Drop, true),
                    Verdict::Punt => (Verdict::Log, true),
                    other => (other, false),
                };
                return Decision {
                    verdict,
                    rule_id: r.id,
                    rule_index: Some(i),
                    punted,
                };
            }
            Err(m) => trace(i, Some(m)),
        }
    }
    let d = if q.dir == KV_DIR_EGRESS {
        pol.hdr.default_egress
    } else {
        pol.hdr.default_ingress
    };
    Decision {
        verdict: Verdict::from_u8(d).unwrap_or(Verdict::Drop),
        rule_id: 0,
        rule_index: None,
        punted: false,
    }
}

/// Evaluate without tracing.
pub fn evaluate<T: Tables + ?Sized>(
    t: &T,
    snap: &Snapshot<'_>,
    q: &FlowQuery,
    now_ns: u64,
) -> Decision {
    evaluate_traced(t, snap, q, now_ns, |_, _| {})
}

/// Full egress decision for a connection, as `lsm/socket_connect` makes it: loopback bypass,
/// identity mask, rule scan.
pub fn decide_egress<T: Tables + ?Sized, P: Platform + ?Sized>(
    t: &T,
    p: &P,
    snap: &Snapshot<'_>,
    who: &Who<'_>,
    remote: [u8; 16],
    port: u16,
    proto: u8,
) -> Decision {
    if snap.policy.hdr.flags & KV_POL_F_NO_LOOPBACK_BYPASS == 0
        && kavach_common::addr::is_loopback(remote)
    {
        return Decision {
            verdict: Verdict::Allow,
            rule_id: 0,
            rule_index: None,
            punted: false,
        };
    }
    let mask = identity_mask(t, snap, who);
    let q = FlowQuery {
        dir: KV_DIR_EGRESS,
        mask,
        remote,
        port,
        proto,
    };
    evaluate(t, snap, &q, p.now_ns())
}

#[cfg(test)]
mod tests;
