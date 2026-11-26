// SPDX-License-Identifier: GPL-2.0-only
//! kavach.ko: the Kavach policy evaluator (`kavach-core`) exported to eBPF as the
//! `kavach_evaluate` kfunc. See README.md for the design.
//!
//! The kfunc entry point and its BTF registration live in `kavach_kfunc.c`: the module's BTF is
//! produced by pahole from DWARF, and pahole skips Rust compilation units, so the symbol the
//! verifier resolves must be a C function. It forwards to [`kavach_rs_evaluate`] below, which
//! runs the same `kavach_core::evaluate` that `kavachctl explain` runs in user space.

use kernel::prelude::*;

// kavach-common + kavach-core, vendored by vendor.sh at build time (Kbuild Rust has no cargo).
#[allow(dead_code, missing_docs, unreachable_pub, clippy::all)]
mod kavach_vendor;

use kavach_vendor::kavach_common::abi::{ClassVal, ExeClass, ExeKey, Policy, KV_MAX_RULES};
use kavach_vendor::kavach_core::{self as core_eval, FlowQuery, Snapshot, Tables};

module! {
    type: Kavach,
    name: "kavach",
    authors: ["The Kavach Authors"],
    description: "Kavach policy evaluator exported to BPF as a kfunc",
    license: "GPL",
}

/// Mirror of `struct kavach_eval_req` (bpf/include/kavach_kfunc.h).
#[repr(C)]
struct EvalReq {
    mask: u64,
    sets: u64,
    now_ns: u64,
    port: u16,
    proto: u8,
    dir: u8,
    _pad: u32,
}

/// Mirror of `struct kavach_eval_res` (bpf/include/kavach_kfunc.h).
#[repr(C)]
struct EvalRes {
    rule_id: u32,
    verdict: u8,
    punted: u8,
    gateway: u16,
}

// Same numbers as the _Static_asserts in kavach_kfunc.h and the BUILD_BUG_ONs in kavach_kfunc.c.
const _: () = assert!(size_of::<EvalReq>() == 32);
const _: () = assert!(size_of::<EvalRes>() == 8);
const _: () = assert!(core::mem::offset_of!(EvalReq, port) == 24);
const _: () = assert!(core::mem::offset_of!(EvalReq, dir) == 27);
const _: () = assert!(core::mem::offset_of!(EvalRes, verdict) == 4);
const _: () = assert!(core::mem::offset_of!(EvalRes, gateway) == 6);

/// `Tables` for the kfunc: rule evaluation only needs the remote address-set bitmap, which the
/// BPF caller already looked up in `addr_sets` (the module never touches BPF maps). The identity
/// lookups are not used by `evaluate`; the caller passes the finished selector mask.
struct Precomputed {
    sets: u64,
}

impl Tables for Precomputed {
    fn exe_class(&self, _key: &ExeKey) -> Option<ExeClass> {
        None
    }
    fn uid_class(&self, _uid: u32) -> Option<ClassVal> {
        None
    }
    fn cgroup_class(&self, _cgroup_id: u64) -> Option<ClassVal> {
        None
    }
    fn remote_sets(&self, _slot: u32, _addr: &[u8; 16]) -> u64 {
        self.sets
    }
}

/// Non-NULL and aligned for `T` (written out: `<*const T>::is_aligned` needs a newer rustc than
/// the kernel's minimum).
fn usable<T>(p: *const T) -> bool {
    !p.is_null() && (p as usize) % core::mem::align_of::<T>() == 0
}

/// Body of the `kavach_evaluate` kfunc, called from `kavach_kfunc.c`.
///
/// Returns 0 and fills `res`; `-EINVAL` when `pol_sz` is not the size of this build's
/// `struct kv_policy` (BPF objects built against another ABI) or a pointer is NULL or
/// misaligned; `-ENOENT` when the slot is not marked valid. On error `res` is untouched and the
/// caller falls back to the C evaluator.
///
/// # Safety
///
/// Called only through the kfunc, after the verifier proved that `pol` is readable for
/// `pol_sz` bytes (`__sz` argument), and that `req` and `res` point to initialised, writable
/// BPF memory of their struct sizes. The verifier does not prove alignment, and a caller could
/// pass a pointer into the middle of a larger value, so alignment (and, defensively, NULL) is
/// checked here before any reference is formed. `pol` is a value of the `policy_slots` array
/// map: kavachd only ever rewrites the slot that is *not* active (FR-HS-2), so the snapshot read
/// here is not written concurrently; the C evaluator relies on the same protocol.
#[no_mangle]
pub unsafe extern "C" fn kavach_rs_evaluate(
    pol: *const c_void,
    pol_sz: u32,
    req: *const c_void,
    res: *mut c_void,
) -> c_int {
    if pol_sz as usize != size_of::<Policy>() {
        return EINVAL.to_errno();
    }
    let (pol, req, res) = (
        pol.cast::<Policy>(),
        req.cast::<EvalReq>(),
        res.cast::<EvalRes>(),
    );
    if !usable(pol) || !usable(req) || !usable(res.cast_const()) {
        return EINVAL.to_errno();
    }
    // SAFETY: see the function's safety section: the pointers are non-NULL and aligned (checked
    // above), `pol` points to `size_of::<Policy>()` readable bytes, `Policy` is `#[repr(C)]`
    // and valid for any bit pattern; `req`/`res` are valid for their sizes.
    let (policy, req, res) = unsafe { (&*pol, &*req, &mut *res) };
    // The slot passed in is already the one selected by the caller's generation; `Snapshot`
    // only uses the generation to pick a slot for table lookups, which `Precomputed` ignores.
    let Some(snap) = Snapshot::new(policy, 0) else {
        return ENOENT.to_errno();
    };
    let q = FlowQuery {
        dir: req.dir,
        mask: req.mask,
        // Unused: the address-set lookup was done by the caller (`Precomputed::sets`).
        remote: [0; 16],
        port: req.port,
        proto: req.proto,
    };
    let d = core_eval::evaluate(&Precomputed { sets: req.sets }, &snap, &q, req.now_ns);
    res.rule_id = d.rule_id;
    // `Verdict` is `#[repr(u8)]` with the wire values.
    res.verdict = d.verdict as u8;
    res.punted = u8::from(d.punted);
    // The gateway index is not part of `Decision`; take it from the deciding rule, as the C
    // mirror does (`kv_rule.gateway`), so a punt keeps its redirect target.
    res.gateway = match d.rule_index {
        Some(i) if d.punted => policy.rules.get(i).map_or(0, |r| r.gateway),
        _ => 0,
    };
    0
}

extern "C" {
    /// Registers the kfunc set for LSM and TC programs (`kavach_kfunc.c`).
    fn kavach_kfunc_register() -> c_int;
}

struct Kavach;

impl kernel::Module for Kavach {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        // SAFETY: called once, from module init, before any BPF program can reference the set.
        let ret = unsafe { kavach_kfunc_register() };
        if ret != 0 {
            pr_err!("registering the kavach_evaluate kfunc failed: {}\n", ret);
            return Err(Error::from_errno(ret));
        }
        pr_info!(
            "kavach_evaluate kfunc registered (kv_policy {} bytes, {} rules max)\n",
            size_of::<Policy>(),
            KV_MAX_RULES
        );
        Ok(Kavach)
    }
}

impl Drop for Kavach {
    fn drop(&mut self) {
        // Kfunc sets have no unregister call: they live in the module's BTF and go away with it.
        // The module cannot be unloaded while a program that calls the kfunc is loaded (the
        // verifier holds a module reference for every module kfunc a program uses).
        pr_info!("unloaded\n");
    }
}
