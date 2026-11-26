extern crate std;

use std::boxed::Box;
use std::collections::HashMap;
use std::vec::Vec;

use kavach_common::addr::{mask_addr, to_mapped, v4};

use super::*;

/// In-memory tables with a linear-scan LPM (good enough for tests).
#[derive(Default)]
struct Mem {
    exe: HashMap<ExeKey, ExeClass>,
    uid: HashMap<u32, ClassVal>,
    cg: HashMap<u64, ClassVal>,
    wl: HashMap<u64, ClassVal>,
    /// (slot, prefix bits in 128-space, masked addr, bitmap)
    sets: Vec<(u32, u32, [u8; 16], u64)>,
}

impl Tables for Mem {
    fn exe_class(&self, k: &ExeKey) -> Option<ExeClass> {
        self.exe.get(k).copied()
    }
    fn uid_class(&self, uid: u32) -> Option<ClassVal> {
        self.uid.get(&uid).copied()
    }
    fn cgroup_class(&self, id: u64) -> Option<ClassVal> {
        self.cg.get(&id).copied()
    }
    fn workload_class(&self, id: u64) -> Option<ClassVal> {
        self.wl.get(&id).copied()
    }
    fn remote_sets(&self, slot: u32, addr: &[u8; 16]) -> u64 {
        self.sets
            .iter()
            .filter(|(s, p, a, _)| *s == slot && mask_addr(*addr, *p) == *a)
            .max_by_key(|(_, p, _, _)| *p)
            .map_or(0, |(_, _, _, b)| *b)
    }
}

struct Clock(u64);
impl Platform for Clock {
    fn now_ns(&self) -> u64 {
        self.0
    }
}

fn policy(rules: &[Rule], default_egress: Verdict) -> Box<Policy> {
    let mut p: Box<Policy> = Box::default();
    p.hdr.flags = KV_POL_F_VALID;
    p.hdr.default_egress = default_egress as u8;
    p.hdr.default_ingress = Verdict::Drop as u8;
    p.hdr.wild_exe = u64::MAX;
    p.hdr.wild_uid = u64::MAX;
    p.hdr.wild_cgroup = u64::MAX;
    p.hdr.n_rules = rules.len() as u32;
    p.rules[..rules.len()].copy_from_slice(rules);
    p
}

fn rule(id: u32, verdict: Verdict) -> Rule {
    Rule {
        id,
        dir: KV_DIR_EGRESS,
        verdict: verdict as u8,
        port_lo: 0,
        port_hi: u16::MAX,
        ..Default::default()
    }
}

fn q(remote: [u8; 16], port: u16, mask: u64) -> FlowQuery {
    FlowQuery {
        dir: KV_DIR_EGRESS,
        mask,
        remote,
        port,
        proto: KV_PROTO_TCP,
    }
}

#[test]
fn default_applies_when_nothing_matches() {
    let p = policy(&[], Verdict::Log);
    let s = Snapshot::new(&p, 4).unwrap();
    let d = evaluate(
        &Mem::default(),
        &s,
        &q(to_mapped(v4(1, 1, 1, 1)), 443, 0),
        0,
    );
    assert_eq!(d.verdict, Verdict::Log);
    assert_eq!(d.rule_id, 0);
}

/// Found by fuzz/fuzz_targets/kfunc_evaluate.rs: a raw slot whose default is Punt (which the
/// compiler never emits) or an unknown byte must not leak an unresolved verdict.
#[test]
fn punt_or_garbage_default_fails_closed() {
    let t = Mem::default();
    for raw in [Verdict::Punt as u8, 4, 0xff] {
        let mut p = policy(&[], Verdict::Allow);
        p.hdr.default_egress = raw;
        p.hdr.default_ingress = raw;
        let s = Snapshot::new(&p, 0).unwrap();
        let mut fq = q([0; 16], 1, 0);
        assert_eq!(
            evaluate(&t, &s, &fq, 0).verdict,
            Verdict::Drop,
            "egress {raw}"
        );
        fq.dir = KV_DIR_INGRESS;
        assert_eq!(
            evaluate(&t, &s, &fq, 0).verdict,
            Verdict::Drop,
            "ingress {raw}"
        );
    }
}

#[test]
fn invalid_slot_has_no_snapshot() {
    let mut p = policy(&[], Verdict::Allow);
    p.hdr.flags = 0;
    assert!(Snapshot::new(&p, 0).is_none());
}

#[test]
fn first_match_wins() {
    let mut a = rule(1, Verdict::Drop);
    a.port_lo = 443;
    a.port_hi = 443;
    let b = rule(2, Verdict::Allow);
    let p = policy(&[a, b], Verdict::Log);
    let s = Snapshot::new(&p, 0).unwrap();
    let t = Mem::default();
    assert_eq!(evaluate(&t, &s, &q([0; 16], 443, 0), 0).rule_id, 1);
    assert_eq!(evaluate(&t, &s, &q([0; 16], 80, 0), 0).rule_id, 2);
}

#[test]
fn remote_set_uses_longest_prefix_bitmap() {
    let mut r = rule(7, Verdict::Allow);
    r.remote_set = 3; // bit 2
    let p = policy(&[r], Verdict::Drop);
    let s = Snapshot::new(&p, 1).unwrap(); // slot 1
    let mut t = Mem::default();
    let net = mask_addr(to_mapped(v4(10, 0, 0, 0)), 104);
    t.sets.push((1, 104, net, 0b100));
    // the more specific prefix is flattened by the compiler to include set 3 too
    t.sets
        .push((1, 120, mask_addr(to_mapped(v4(10, 1, 2, 0)), 120), 0b101));
    assert_eq!(
        evaluate(&t, &s, &q(to_mapped(v4(10, 9, 9, 9)), 1, 0), 0).verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&t, &s, &q(to_mapped(v4(10, 1, 2, 3)), 1, 0), 0).verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&t, &s, &q(to_mapped(v4(11, 0, 0, 1)), 1, 0), 0).verdict,
        Verdict::Drop
    );
    // slot 0 entries are invisible to a slot-1 snapshot
    let s0 = Snapshot::new(&p, 2).unwrap();
    assert_eq!(
        evaluate(&t, &s0, &q(to_mapped(v4(10, 9, 9, 9)), 1, 0), 0).verdict,
        Verdict::Drop
    );
}

#[test]
fn ttl_expires_rule() {
    let mut r = rule(1, Verdict::Allow);
    r.not_after_ns = 1_000;
    let p = policy(&[r], Verdict::Drop);
    let s = Snapshot::new(&p, 0).unwrap();
    let t = Mem::default();
    assert_eq!(
        evaluate(&t, &s, &q([0; 16], 1, 0), 999).verdict,
        Verdict::Allow
    );
    assert_eq!(
        evaluate(&t, &s, &q([0; 16], 1, 0), 1_000).verdict,
        Verdict::Drop
    );
}

#[test]
fn punt_resolves_through_fail_mode() {
    let mut closed = rule(1, Verdict::Punt);
    closed.fail = KV_FAIL_CLOSED;
    closed.port_hi = 100;
    let open = rule(2, Verdict::Punt);
    let p = policy(&[closed, open], Verdict::Allow);
    let s = Snapshot::new(&p, 0).unwrap();
    let t = Mem::default();
    let d = evaluate(&t, &s, &q([0; 16], 50, 0), 0);
    assert_eq!((d.verdict, d.punted), (Verdict::Drop, true));
    let d = evaluate(&t, &s, &q([0; 16], 500, 0), 0);
    assert_eq!((d.verdict, d.punted), (Verdict::Log, true));
}

#[test]
fn identity_mask_and_selectors() {
    // selector bit0 = binary X AND uid 1000 ; selector bit1 = cgroup subtree 77
    let mut r0 = rule(10, Verdict::Allow);
    r0.sel = 0b01;
    let mut r1 = rule(11, Verdict::Log);
    r1.sel = 0b10;
    let mut p = policy(&[r0, r1], Verdict::Drop);
    p.hdr.wild_exe = !0b01;
    p.hdr.wild_uid = !0b01;
    p.hdr.wild_cgroup = !0b10;
    p.hdr.sel_used = 0b11;
    let s = Snapshot::new(&p, 3).unwrap(); // slot 1
    let exe = ExeKey {
        inode: 8,
        ino: 42,
        dev: 0,
        generation: 0,
    };
    let mut t = Mem::default();
    t.exe.insert(
        exe,
        ExeClass {
            mask: [0, 0b01],
            nonce: 0,
            flags: KV_EXE_F_COMMITTED,
        },
    );
    t.uid.insert(1000, ClassVal { mask: [0, 0b01] });
    t.cg.insert(77, ClassVal { mask: [0, 0b10] });

    let ok = Who {
        exe,
        uid: 1000,
        cgroups: &[5],
    };
    assert_eq!(identity_mask(&t, &s, &ok), 0b01);
    let wrong_uid = Who {
        exe,
        uid: 0,
        cgroups: &[5],
    };
    assert_eq!(identity_mask(&t, &s, &wrong_uid), 0);
    // cgroup 77 is an ancestor of the leaf
    let in_tree = Who {
        exe: ExeKey::default(),
        uid: 0,
        cgroups: &[99, 77, 1],
    };
    assert_eq!(identity_mask(&t, &s, &in_tree), 0b10);

    let d = decide_egress(
        &t,
        &Clock(0),
        &s,
        &ok,
        to_mapped(v4(8, 8, 8, 8)),
        53,
        KV_PROTO_UDP,
    );
    assert_eq!(d.rule_id, 10);
}

#[test]
fn tainted_executable_loses_identity() {
    let mut p = policy(&[], Verdict::Drop);
    p.hdr.wild_exe = !1;
    p.hdr.sel_used = 1;
    let s = Snapshot::new(&p, 0).unwrap();
    let exe = ExeKey {
        inode: 1,
        ino: 9,
        dev: 0,
        generation: 0,
    };
    let mut t = Mem::default();
    t.exe.insert(
        exe,
        ExeClass {
            mask: [1, 0],
            nonce: 0,
            flags: KV_EXE_F_COMMITTED,
        },
    );
    let who = Who {
        exe,
        uid: 0,
        cgroups: &[],
    };
    assert_eq!(identity_mask(&t, &s, &who), 1);
    t.exe.remove(&exe); // the LSM deletes the class on write-open / truncate
    assert_eq!(identity_mask(&t, &s, &who), 0);
}

#[test]
fn loopback_bypass() {
    let p = policy(&[], Verdict::Drop);
    let s = Snapshot::new(&p, 0).unwrap();
    let t = Mem::default();
    let who = Who::default();
    let lo = to_mapped(v4(127, 0, 0, 1));
    assert_eq!(
        decide_egress(&t, &Clock(0), &s, &who, lo, 80, 6).verdict,
        Verdict::Allow
    );
    let mut p2 = policy(&[], Verdict::Drop);
    p2.hdr.flags |= KV_POL_F_NO_LOOPBACK_BYPASS;
    let s2 = Snapshot::new(&p2, 0).unwrap();
    assert_eq!(
        decide_egress(&t, &Clock(0), &s2, &who, lo, 80, 6).verdict,
        Verdict::Drop
    );
}

#[test]
fn explain_trace_reports_reasons() {
    let mut a = rule(1, Verdict::Drop);
    a.proto = KV_PROTO_UDP;
    let mut b = rule(2, Verdict::Drop);
    b.sel = 4;
    let c = rule(3, Verdict::Allow);
    let p = policy(&[a, b, c], Verdict::Drop);
    let s = Snapshot::new(&p, 0).unwrap();
    let mut seen = Vec::new();
    let d = evaluate_traced(&Mem::default(), &s, &q([0; 16], 1, 1), 0, |i, m| {
        seen.push((i, m))
    });
    assert_eq!(d.rule_id, 3);
    assert_eq!(
        seen,
        [
            (0, Some(Miss::Protocol)),
            (1, Some(Miss::Identity)),
            (2, None)
        ]
    );
}

mod prop {
    use super::*;
    use proptest::prelude::*;

    fn arb_rule() -> impl Strategy<Value = Rule> {
        (
            any::<u64>(),
            1u32..1000,
            0u32..4,
            any::<u16>(),
            any::<u16>(),
            0u8..3,
            0u8..4,
            0u8..2,
        )
            .prop_map(|(sel, id, set, a, b, p, v, f)| Rule {
                sel: sel & 0b111,
                id,
                remote_set: set,
                port_lo: a.min(b),
                port_hi: a.max(b),
                proto: [0, 6, 17][p as usize],
                dir: KV_DIR_EGRESS,
                verdict: v,
                fail: f,
                ..Default::default()
            })
    }

    proptest! {
        /// The decision always equals "first rule that matches, else default" — a direct
        /// restatement used as an oracle.
        #[test]
        fn first_match_oracle(rules in proptest::collection::vec(arb_rule(), 0..40),
                              mask in 0u64..8, port in any::<u16>(), proto in prop_oneof![Just(6u8), Just(17u8)],
                              sets in 0u64..8) {
            let p = policy(&rules, Verdict::Log);
            let s = Snapshot::new(&p, 0).unwrap();
            let mut t = Mem::default();
            t.sets.push((0, 0, [0; 16], sets));
            let fq = FlowQuery { dir: KV_DIR_EGRESS, mask, remote: [1; 16], port, proto };
            let d = evaluate(&t, &s, &fq, 0);
            let oracle = rules.iter().position(|r| rule_matches(r, &fq, sets, 0).is_ok());
            prop_assert_eq!(d.rule_index, oracle);
            match oracle {
                Some(i) => prop_assert_eq!(d.rule_id, rules[i].id),
                None => prop_assert_eq!(d.verdict, Verdict::Log),
            }
            prop_assert!(d.verdict != Verdict::Punt);
        }
    }
}

#[test]
fn workload_class_nearest_cgroup_wins_and_ors_into_cgroup_dimension() {
    // selector 0: workload (k8s), selector 1: workload "unknown" twin, selector 2: plain cgroup
    let mut p = policy(&[], Verdict::Allow);
    p.hdr.wild_cgroup = !0b111;
    p.hdr.sel_used = 0b111;
    let mut t = Mem::default();
    // kubepods root (id 10) = unknown; pod 20 resolved and matching; container 30 below it.
    t.wl.insert(
        10,
        ClassVal {
            mask: [0b010, 0b010],
        },
    );
    t.wl.insert(
        20,
        ClassVal {
            mask: [0b001, 0b001],
        },
    );
    t.cg.insert(
        10,
        ClassVal {
            mask: [0b100, 0b100],
        },
    );
    let snap = Snapshot::new(&p, 0).unwrap();
    let who = |c: &'static [u64]| Who {
        cgroups: c,
        ..Default::default()
    };
    // without the flag the workload map is ignored
    assert_eq!(identity_mask(&t, &snap, &who(&[30, 20, 10, 1])), 0b100);
    p.hdr.flags |= KV_POL_F_WORKLOAD;
    let snap = Snapshot::new(&p, 0).unwrap();
    assert_eq!(identity_mask(&t, &snap, &who(&[30, 20, 10, 1])), 0b101);
    // an unresolved pod (no entry of its own) inherits the root's unknown bits
    assert_eq!(identity_mask(&t, &snap, &who(&[31, 21, 10, 1])), 0b110);
    // a resolved pod with no matching selector still overrides the root (mask 0 entry)
    t.wl.insert(22, ClassVal { mask: [0, 0] });
    assert_eq!(identity_mask(&t, &snap, &who(&[32, 22, 10, 1])), 0b100);
    // outside kubepods: nothing
    assert_eq!(identity_mask(&t, &snap, &who(&[5, 1])), 0);
}
