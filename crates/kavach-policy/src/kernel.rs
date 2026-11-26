//! Lowering a [`CompiledPolicy`] into the exact `#[repr(C)]` tables the kernel reads, plus the
//! host-side identity matching used by kavachd (classification) and `kavachctl explain`.

use std::net::IpAddr;

use ipnet::IpNet;
use kavach_common::abi::*;
use kavach_common::addr::{mapped_prefix, mask_addr, to_mapped};

use crate::compile::{CompiledPolicy, Selector, User};

/// Clock pair used to translate unix TTL deadlines into `CLOCK_BOOTTIME` deadlines.
#[derive(Debug, Clone, Copy)]
pub struct Clocks {
    pub unix_ns: u64,
    pub boot_ns: u64,
}

impl Clocks {
    /// Boot-time deadline for a unix-seconds deadline (0 stays 0 = no TTL).
    pub fn boot_deadline(&self, not_after_unix: u64) -> u64 {
        if not_after_unix == 0 {
            return 0;
        }
        let target = not_after_unix.saturating_mul(1_000_000_000);
        if target <= self.unix_ns {
            return 1; // already expired: any boot time is >= 1
        }
        self.boot_ns.saturating_add(target - self.unix_ns).max(1)
    }
}

impl CompiledPolicy {
    /// Selector bits that do not constrain each dimension, with undefined bits set too.
    pub fn wildcards(&self) -> (u64, u64, u64, u64) {
        let n = self.selectors.len();
        let used = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
        let (mut we, mut wu, mut wc) = (!used, !used, !used);
        for (i, s) in self.selectors.iter().enumerate() {
            if !s.constrains_exe() {
                we |= 1 << i;
            }
            if !s.constrains_uid() {
                wu |= 1 << i;
            }
            if !s.constrains_cgroup() {
                wc |= 1 << i;
            }
        }
        // k8s / SPIFFE selectors constrain the cgroup dimension (through `wl_class`).
        wc &= !self.workload_bits();
        (we, wu, wc, used)
    }

    /// Build the kernel policy table for one slot.
    pub fn to_kernel(&self, generation: u32, serial: u64, clocks: Clocks) -> Box<Policy> {
        let mut p: Box<Policy> = Box::default();
        let (we, wu, wc, used) = self.wildcards();
        let mut flags = KV_POL_F_VALID;
        if self.defaults.strict_ingress {
            flags |= KV_POL_F_STRICT_INGRESS;
        }
        if !self.defaults.loopback_bypass {
            flags |= KV_POL_F_NO_LOOPBACK_BYPASS;
        }
        if self.defaults.unclassified_deny {
            flags |= KV_POL_F_UNCLASSIFIED_DENY;
        }
        if self.workload_bits() != 0 {
            flags |= KV_POL_F_WORKLOAD;
        }
        p.hdr = PolicyHeader {
            n_rules: self.rules.len().min(KV_MAX_RULES as usize) as u32,
            flags,
            default_egress: self.defaults.egress,
            default_ingress: self.defaults.ingress,
            wild_exe: we,
            wild_uid: wu,
            wild_cgroup: wc,
            serial,
            generation,
            sel_used: used,
            ..Default::default()
        };
        for (dst, r) in p.rules.iter_mut().zip(&self.rules) {
            *dst = Rule {
                sel: r.sel,
                id: r.id,
                remote_set: r.remote_set,
                port_lo: r.port_lo,
                port_hi: r.port_hi,
                proto: r.proto,
                dir: r.dir,
                verdict: r.verdict,
                fail: r.fail,
                not_after_ns: clocks.boot_deadline(r.not_after_unix),
                // 1-based into `gateways` (<= MAX_GATEWAYS); 0 = none: the kernel never
                // redirects such a punt, its fail mode decides.
                gateway: u16::try_from(r.gateway).unwrap_or(0),
                ..Rule::default()
            };
        }
        p
    }

    /// The `(set_id, network)` pairs known without DNS (CIDRs only).
    pub fn static_set_entries(&self) -> Vec<(u32, IpNet)> {
        self.sets
            .iter()
            .enumerate()
            .flat_map(|(i, s)| s.cidrs.iter().map(move |c| (i as u32 + 1, *c)))
            .collect()
    }

    /// Mask of selectors satisfied by `facts` (host-side reference of the kernel's three-way AND),
    /// for a process outside any pod.
    pub fn selector_mask(&self, facts: &Facts<'_>) -> u64 {
        self.selector_mask_in(facts, None)
    }

    /// [`Self::selector_mask`] for a process whose cgroup has workload state `wl` (`None` = not
    /// a pod): workload selectors also need their k8s / SPIFFE part satisfied.
    pub fn selector_mask_in(
        &self,
        facts: &Facts<'_>,
        wl: Option<crate::workload::WorkloadState<'_>>,
    ) -> u64 {
        let wl_bits = self.workload_bits();
        let wl_ok = wl.map_or(0, |st| self.workload_mask(st));
        self.selectors
            .iter()
            .enumerate()
            .filter(|(i, s)| {
                let bit = 1u64 << i;
                s.matches(facts) && (wl_bits & bit == 0 || wl_ok & bit != 0)
            })
            .fold(0, |m, (i, _)| m | (1 << i))
    }
}

/// What the host knows about a process (for classification and `explain`).
#[derive(Debug, Clone, Default)]
pub struct Facts<'a> {
    pub sha256: Option<[u8; 32]>,
    pub exe: Option<&'a str>,
    pub uid: Option<u32>,
    pub user_name: Option<&'a str>,
    /// cgroup v2 path relative to /sys/fs/cgroup.
    pub cgroup: Option<&'a str>,
}

impl Selector {
    /// Exe dimension: (binaries empty or digest listed) AND (exes empty or path listed).
    pub fn exe_matches(&self, sha256: Option<[u8; 32]>, exe: Option<&str>) -> bool {
        (self.binaries.is_empty() || sha256.is_some_and(|h| self.binaries.contains(&h)))
            && (self.exes.is_empty() || exe.is_some_and(|e| self.exes.iter().any(|x| x == e)))
    }
    pub fn user_matches(&self, uid: Option<u32>, name: Option<&str>) -> bool {
        self.users.iter().any(|u| match u {
            User::Uid(n) => uid == Some(*n),
            User::Name(n) => name == Some(n.as_str()),
        })
    }
    /// Subtree semantics: `a/b` matches `a/b` and `a/b/c`.
    pub fn cgroup_matches(&self, path: &str) -> bool {
        let path = path.trim_matches('/');
        self.cgroups.iter().any(|c| {
            c.is_empty()
                || path == c
                || path
                    .strip_prefix(c.as_str())
                    .is_some_and(|r| r.starts_with('/'))
        })
    }
    pub fn matches(&self, f: &Facts<'_>) -> bool {
        (!self.constrains_exe() || self.exe_matches(f.sha256, f.exe))
            && (!self.constrains_uid() || self.user_matches(f.uid, f.user_name))
            && (!self.constrains_cgroup() || f.cgroup.is_some_and(|c| self.cgroup_matches(c)))
    }
}

/// One `addr_sets` LPM entry in the 128-bit mapped space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlatPrefix {
    pub prefix: u32,
    pub addr: [u8; 16],
    pub bitmap: u64,
}

impl FlatPrefix {
    pub fn key(&self, slot: u32) -> AddrKey {
        AddrKey {
            prefixlen: AddrKey::HEADER_BITS + self.prefix,
            slot,
            addr: self.addr,
        }
    }
}

/// Flatten overlapping set prefixes so the LONGEST match carries the union of every set that
/// contains it: one LPM lookup then answers "which sets contain this address" exactly.
///
/// Proof sketch: if prefix q contains address a and p is the longest prefix containing a, then
/// both contain a, so one contains the other; p is longest ⇒ q ⊇ p ⇒ q's bits are in p's bitmap.
pub fn flatten_sets(entries: &[(u32, IpNet)]) -> Vec<FlatPrefix> {
    let mut prefixes: Vec<FlatPrefix> = entries
        .iter()
        .filter(|(id, _)| (1..=64).contains(id))
        .map(|(id, net)| {
            let ip: IpAddr = net.network();
            let prefix = mapped_prefix(ip, net.prefix_len());
            FlatPrefix {
                prefix,
                addr: mask_addr(to_mapped(ip), prefix),
                bitmap: 1 << (id - 1),
            }
        })
        .collect();
    // Merge identical prefixes first.
    prefixes.sort();
    let mut merged: Vec<FlatPrefix> = Vec::with_capacity(prefixes.len());
    for p in prefixes {
        match merged.last_mut() {
            Some(m) if m.prefix == p.prefix && m.addr == p.addr => m.bitmap |= p.bitmap,
            _ => merged.push(p),
        }
    }
    let snapshot = merged.clone();
    for p in &mut merged {
        for q in &snapshot {
            if q.prefix < p.prefix && mask_addr(p.addr, q.prefix) == q.addr {
                p.bitmap |= q.bitmap;
            }
        }
    }
    merged
}

/// `kavach_core::Tables` over a compiled policy and host facts — used by `kavachctl explain` and
/// `apply --dry-run` to evaluate flows offline with the exact kernel semantics.
#[derive(Debug)]
pub struct OfflineTables {
    pub mask: u64,
    pub slot: u32,
    pub flat: Vec<FlatPrefix>,
}

impl OfflineTables {
    pub fn new(
        policy: &CompiledPolicy,
        facts: &Facts<'_>,
        extra: &[(u32, IpNet)],
        slot: u32,
    ) -> Self {
        let mut entries = policy.static_set_entries();
        entries.extend_from_slice(extra);
        Self {
            mask: policy.selector_mask(facts),
            slot,
            flat: flatten_sets(&entries),
        }
    }
}

const PROBE_KEY: ExeKey = ExeKey {
    inode: u64::MAX,
    ino: u64::MAX,
    dev: 0,
    generation: 0,
};

impl kavach_core::Tables for OfflineTables {
    fn exe_class(&self, key: &ExeKey) -> Option<ExeClass> {
        // The facts were matched host-side: expose them as one pre-classified "executable".
        (*key == PROBE_KEY).then_some(ExeClass {
            mask: [self.mask; 2],
            nonce: 0,
            flags: KV_EXE_F_COMMITTED,
        })
    }
    fn uid_class(&self, uid: u32) -> Option<ClassVal> {
        (uid == u32::MAX).then_some(ClassVal {
            mask: [self.mask; 2],
        })
    }
    fn cgroup_class(&self, id: u64) -> Option<ClassVal> {
        (id == u64::MAX).then_some(ClassVal {
            mask: [self.mask; 2],
        })
    }
    fn remote_sets(&self, slot: u32, addr: &[u8; 16]) -> u64 {
        if slot != self.slot {
            return 0;
        }
        self.flat
            .iter()
            .filter(|p| mask_addr(*addr, p.prefix) == p.addr)
            .max_by_key(|p| p.prefix)
            .map_or(0, |p| p.bitmap)
    }
}

impl OfflineTables {
    /// The `Who` that makes `kavach_core::identity_mask` return exactly `self.mask`.
    pub fn who(&self) -> kavach_core::Who<'static> {
        kavach_core::Who {
            exe: PROBE_KEY,
            uid: u32::MAX,
            cgroups: &[u64::MAX],
        }
    }
}
