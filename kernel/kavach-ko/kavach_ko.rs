// SPDX-License-Identifier: GPL-2.0-only
//! kavach.ko — exports `kavach_evaluate` as a BPF kfunc (v0.4 skeleton; see README.md).
//!
//! Status: planned. This file fixes the module shape so the kfunc ABI can be reviewed; the
//! kfunc body (calling `kavach_core::evaluate`) lands once the out-of-tree build links the
//! no_std crates.

use kernel::prelude::*;

module! {
    type: Kavach,
    name: "kavach",
    authors: ["The Kavach Authors"],
    description: "Kavach policy evaluator exported to BPF as a kfunc",
    license: "GPL",
}

struct Kavach;

impl kernel::Module for Kavach {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("kavach: evaluator module loaded (kfunc registration pending v0.4)\n");
        Ok(Kavach)
    }
}

impl Drop for Kavach {
    fn drop(&mut self) {
        pr_info!("kavach: unloaded\n");
    }
}
