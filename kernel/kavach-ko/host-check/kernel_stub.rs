// SPDX-License-Identifier: GPL-2.0-only
//! Minimal stand-in for the Rust-for-Linux `kernel` crate: exactly the items kavach_ko.rs uses,
//! with the same names and shapes, so the module's Rust half can be compiled and unit-tested on
//! a host without a Rust-enabled kernel tree (see ../host-check.sh). It is never part of the
//! module build.
#![no_std]

use core::ffi::c_int;

/// `kernel::error::Error`: a negative errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(c_int);

impl Error {
    /// `kernel::error::Error::from_errno`.
    pub fn from_errno(errno: c_int) -> Error {
        Error(errno)
    }
    /// `kernel::error::Error::to_errno`.
    pub fn to_errno(self) -> c_int {
        self.0
    }
}

/// `kernel::error::code::EINVAL`.
pub const EINVAL: Error = Error(-22);
/// `kernel::error::code::ENOENT`.
pub const ENOENT: Error = Error(-2);

/// `kernel::error::Result`.
pub type Result<T = (), E = Error> = core::result::Result<T, E>;

/// `kernel::ThisModule`.
pub struct ThisModule;

/// `kernel::Module`.
pub trait Module: Sized {
    /// Module init.
    fn init(module: &'static ThisModule) -> Result<Self>;
}

/// `kernel::pr_info!` (formats, prints nothing).
#[macro_export]
macro_rules! pr_info {
    ($($arg:tt)*) => {{ let _ = ::core::format_args!($($arg)*); }};
}

/// `kernel::pr_err!` (formats, prints nothing).
#[macro_export]
macro_rules! pr_err {
    ($($arg:tt)*) => {{ let _ = ::core::format_args!($($arg)*); }};
}

/// `kernel::module!` (the module type is checked by the host test instead).
#[macro_export]
macro_rules! module {
    ($($arg:tt)*) => {};
}

/// `kernel::prelude`.
pub mod prelude {
    pub use super::{Error, Module, Result, ThisModule, EINVAL, ENOENT};
    pub use crate::{module, pr_err, pr_info};
    pub use core::ffi::{c_int, c_void};
}
