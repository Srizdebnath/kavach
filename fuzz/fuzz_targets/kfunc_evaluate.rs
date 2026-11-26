#![no_main]
//! The inputs the `kavach_evaluate` kfunc (kernel/kavach-ko) hands to kavach-core: an
//! arbitrary policy slot (any bit pattern: the module reads the map value as-is) and an
//! arbitrary request (mask, address-set bitmap, clock, port, protocol, direction).
//!
//! kavach-core must never panic on them, and its decision must be the one a plain first-match
//! scan gives, with the kernel's invariants: the verdict is Allow, Drop or Log (Punt and
//! out-of-range bytes are resolved), the rule index is inside min(n_rules, KV_MAX_RULES), and
//! `punted` is set exactly when the deciding rule said Punt.
use kavach_common::abi::*;
use kavach_core::{FlowQuery, Snapshot, Tables, evaluate, rule_matches};
use libfuzzer_sys::fuzz_target;

/// What the kfunc's `Tables` provides: only the caller-computed address-set bitmap.
struct Sets(u64);
impl Tables for Sets {
    fn exe_class(&self, _: &ExeKey) -> Option<ExeClass> {
        None
    }
    fn uid_class(&self, _: u32) -> Option<ClassVal> {
        None
    }
    fn cgroup_class(&self, _: u64) -> Option<ClassVal> {
        None
    }
    fn remote_sets(&self, _: u32, _: &[u8; 16]) -> u64 {
        self.0
    }
}

const REQ: usize = 32; // struct kavach_eval_req

fuzz_target!(|data: &[u8]| {
    if data.len() < REQ {
        return;
    }
    let (req, table) = data.split_at(REQ);
    let u64_at = |o: usize| u64::from_le_bytes(req[o..o + 8].try_into().unwrap());
    let (mask, sets, now) = (u64_at(0), u64_at(8), u64_at(16));
    let port = u16::from_le_bytes([req[24], req[25]]);
    let (proto, dir) = (req[26], req[27]);

    // The rest of the input is the head of the slot; the remainder of the 48 KiB stays zero.
    let mut pol: Box<Policy> = Box::default();
    let bytes = bytemuck::bytes_of_mut(&mut *pol);
    let n = table.len().min(bytes.len());
    bytes[..n].copy_from_slice(&table[..n]);

    let Some(snap) = Snapshot::new(&pol, 0) else {
        assert_eq!(pol.hdr.flags & KV_POL_F_VALID, 0);
        return;
    };
    let q = FlowQuery {
        dir,
        mask,
        remote: [0; 16],
        port,
        proto,
    };
    let d = evaluate(&Sets(sets), &snap, &q, now);

    assert!(matches!(
        d.verdict,
        Verdict::Allow | Verdict::Drop | Verdict::Log
    ));
    let limit = (pol.hdr.n_rules as usize).min(KV_MAX_RULES as usize);
    let first = (0..limit).find(|&i| rule_matches(&pol.rules[i], &q, sets, now).is_ok());
    assert_eq!(d.rule_index, first);
    match first {
        Some(i) => {
            let r = &pol.rules[i];
            assert_eq!(d.rule_id, r.id);
            assert_eq!(d.punted, r.verdict == Verdict::Punt as u8);
            let want = match Verdict::from_u8(r.verdict) {
                Some(Verdict::Punt) if r.fail == KV_FAIL_CLOSED => Verdict::Drop,
                Some(Verdict::Punt) => Verdict::Log,
                Some(v) => v,
                None => Verdict::Drop,
            };
            assert_eq!(d.verdict, want);
        }
        None => {
            assert_eq!(d.rule_id, 0);
            assert!(!d.punted);
            let def = if dir == KV_DIR_EGRESS {
                pol.hdr.default_egress
            } else {
                pol.hdr.default_ingress
            };
            // A Punt default has no fail mode: fails closed, like an unknown byte.
            let want = match Verdict::from_u8(def) {
                Some(Verdict::Punt) | None => Verdict::Drop,
                Some(v) => v,
            };
            assert_eq!(d.verdict, want);
        }
    }
});
