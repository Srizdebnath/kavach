//! # kavach-common
//!
//! `no_std`, allocation-free types shared by every Kavach layer: the C eBPF programs (through
//! the generated `kavach_abi.h`), the future `kavach.ko`, and all user-space crates.
#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(feature = "std")]
extern crate std;

pub mod abi;
pub mod addr;

pub use abi::*;

#[cfg(feature = "aya")]
mod aya_pod {
    use super::abi::*;
    macro_rules! pod {
        ($($t:ty),* $(,)?) => {$(
            // SAFETY: every ABI type is #[repr(C)], has only explicit padding and derives
            // bytemuck::Pod, which statically proves it is valid for any bit pattern.
            unsafe impl aya::Pod for $t {}
        )*};
    }
    pod!(
        FlowKey,
        FlowVal,
        BlockKey,
        BlockVal,
        SrcKey,
        RateState,
        XdpConfig,
        ClassVal,
        ExeKey,
        KeyReq,
        ExeClass,
        Identity,
        PolicyHeader,
        Rule,
        Policy,
        AddrKey,
        Event,
    );
}
