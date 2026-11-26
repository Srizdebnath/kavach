// SPDX-License-Identifier: GPL-2.0-only
//! Host unit tests for kavach.ko's Rust half (../kavach_ko.rs), compiled by ../host-check.sh
//! against kernel_stub.rs. They check the glue the kernel build cannot test without a VM: the
//! request/result mirrors, argument validation (size, NULL, alignment), and that the kfunc body
//! answers exactly what kavach-core answers, including the punting rule's gateway index.

#[path = "kavach_ko.rs"]
mod kavach_ko;
// The same vendored crates once more, to build inputs and compute the reference answer.
#[allow(dead_code, unreachable_pub, clippy::all)]
#[path = "kavach_vendor.rs"]
mod v;

use core::ffi::{c_int, c_void};
use v::kavach_common::abi::*;
use v::kavach_core::{self as core_eval, FlowQuery, Snapshot, Tables};

/// The C shim's registration hook (kavach_kfunc.c), referenced by the module's init.
#[no_mangle]
extern "C" fn kavach_kfunc_register() -> c_int {
    0
}

/// `struct kavach_eval_req` (bpf/include/kavach_kfunc.h).
#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct Req {
    mask: u64,
    sets: u64,
    now_ns: u64,
    port: u16,
    proto: u8,
    dir: u8,
    _pad: u32,
}

/// `struct kavach_eval_res`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Res {
    rule_id: u32,
    verdict: u8,
    punted: u8,
    gateway: u16,
}

const UNTOUCHED: Res = Res {
    rule_id: 0xdead_beef,
    verdict: 0xee,
    punted: 0xee,
    gateway: 0xeeee,
};

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

fn call(pol: *const c_void, sz: usize, req: *const c_void, res: &mut Res) -> c_int {
    // SAFETY: the tests pass live, correctly sized buffers (or deliberately bad pointers that
    // the function must reject before dereferencing).
    unsafe { kavach_ko::kavach_rs_evaluate(pol, sz as u32, req, (res as *mut Res).cast()) }
}

fn zeroed_policy() -> Box<Policy> {
    // SAFETY: `Policy` is `#[repr(C)]` plain integers; all-zero is valid.
    unsafe { Box::new_zeroed().assume_init() }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[(self.next() % xs.len() as u64) as usize]
    }
}

#[test]
fn kfunc_body_matches_kavach_core() {
    let mut rng = Rng(0x6b61_7661_6368);
    let mut pol = zeroed_policy();
    let ports = [0u16, 1, 22, 53, 80, 443, 8080, 65535];
    let (mut flows, mut punts) = (0, 0);
    for round in 0..300 {
        *pol = *zeroed_policy();
        let n = if round == 0 {
            1024
        } else {
            1 + (rng.next() % 40) as usize
        };
        pol.hdr.n_rules = if round == 0 { 4000 } else { n as u32 };
        pol.hdr.flags = KV_POL_F_VALID;
        pol.hdr.default_egress = rng.pick(&[0, 1, 2, 3, 9]);
        pol.hdr.default_ingress = rng.pick(&[0, 1, 2, 3, 9]);
        for (i, r) in pol.rules[..n].iter_mut().enumerate() {
            let lo = rng.pick(&ports);
            r.sel = rng.pick(&[0, 0, 1, 2, 3]);
            r.id = 1 + i as u32;
            r.remote_set = rng.pick(&[0, 0, 1, 2, 3, 64, 65]);
            r.port_lo = lo;
            r.port_hi = rng.pick(&[lo, lo, 65535, 443]).max(lo);
            r.proto = rng.pick(&[0, 6, 17, 1]);
            r.dir = rng.pick(&[KV_DIR_EGRESS, KV_DIR_INGRESS]);
            r.verdict = rng.pick(&[0, 1, 2, 3, 3, 7]);
            r.fail = rng.pick(&[KV_FAIL_OPEN, KV_FAIL_CLOSED]);
            r.not_after_ns = rng.pick(&[0, 0, 5_000, u64::MAX]);
            r.gateway = rng.pick(&[0, 1, 2, 7]);
        }
        for _ in 0..50 {
            let req = Req {
                mask: rng.pick(&[0, 1, 2, 3, u64::MAX]),
                sets: rng.next() & 0x8000_0000_0000_000f,
                now_ns: rng.pick(&[0, 4_999, 5_000, 1 << 40]),
                port: rng.pick(&ports),
                proto: rng.pick(&[6, 17, 1]),
                dir: rng.pick(&[KV_DIR_EGRESS, KV_DIR_INGRESS]),
                _pad: 0,
            };
            let mut res = UNTOUCHED;
            let rc = call(
                (&*pol as *const Policy).cast(),
                size_of::<Policy>(),
                (&req as *const Req).cast(),
                &mut res,
            );
            assert_eq!(rc, 0);
            let snap = Snapshot::new(&pol, 0).unwrap();
            let q = FlowQuery {
                dir: req.dir,
                mask: req.mask,
                remote: [0; 16],
                port: req.port,
                proto: req.proto,
            };
            let d = core_eval::evaluate(&Sets(req.sets), &snap, &q, req.now_ns);
            let want = Res {
                rule_id: d.rule_id,
                verdict: d.verdict as u8,
                punted: u8::from(d.punted),
                gateway: match d.rule_index {
                    Some(i) if d.punted => pol.rules[i].gateway,
                    _ => 0,
                },
            };
            assert_eq!(res, want, "round {round}: {d:?}");
            assert!(
                res.verdict <= Verdict::Log as u8,
                "Punt and garbage are resolved"
            );
            flows += 1;
            punts += usize::from(d.punted && want.gateway != 0);
        }
    }
    assert!(punts > 0, "corpus reaches punts with a gateway");
    eprintln!("{flows} flows, {punts} punts with a gateway: kfunc body == kavach-core");
}

#[test]
fn rejects_bad_arguments_without_writing() {
    let mut pol = zeroed_policy();
    pol.hdr.flags = KV_POL_F_VALID;
    let p = (&*pol as *const Policy).cast::<c_void>();
    let req = [Req::default(); 2];
    let r = (&req[0] as *const Req).cast::<c_void>();
    let mut res = UNTOUCHED;

    let einval = -22;
    assert_eq!(call(p, size_of::<Policy>() - 1, r, &mut res), einval);
    assert_eq!(call(p, size_of::<Policy>() + 8, r, &mut res), einval);
    assert_eq!(
        call(core::ptr::null(), size_of::<Policy>(), r, &mut res),
        einval
    );
    assert_eq!(
        call(p, size_of::<Policy>(), core::ptr::null(), &mut res),
        einval
    );
    // Misaligned policy and request (a pointer into the middle of a larger value).
    let p1 = p.cast::<u8>().wrapping_add(4).cast::<c_void>();
    assert_eq!(call(p1, size_of::<Policy>(), r, &mut res), einval);
    let r1 = r.cast::<u8>().wrapping_add(1).cast::<c_void>();
    assert_eq!(call(p, size_of::<Policy>(), r1, &mut res), einval);
    // SAFETY: NULL result must be rejected before any write.
    let rc = unsafe {
        kavach_ko::kavach_rs_evaluate(p, size_of::<Policy>() as u32, r, core::ptr::null_mut())
    };
    assert_eq!(rc, einval);
    assert_eq!(res, UNTOUCHED);

    // Not a valid slot.
    pol.hdr.flags = 0;
    assert_eq!(call(p, size_of::<Policy>(), r, &mut res), -2);
    assert_eq!(res, UNTOUCHED);
}

#[test]
fn abi_sizes() {
    assert_eq!(size_of::<Req>(), 32);
    assert_eq!(size_of::<Res>(), 8);
    assert_eq!(size_of::<Policy>(), 64 + 1024 * 48);
}
