//! # kavach-parsers
//!
//! Parsers for attacker-controlled bytes (SRS FR-PAR-*, SR-6). Every parser here is:
//!
//! * `#![no_std]` and allocation-free, so it can run in kavachd, the L7 gateway and later in
//!   `kavach.ko`;
//! * `forbid(unsafe_code)`: all indexing is checked, malformed input is an `Err`, never a panic
//!   (fuzzed, and property-tested for "never panics");
//! * bounded: no recursion, fixed-size scratch, hard caps on loops (DNS pointer jumps, extension
//!   and cipher counts).
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod dns;
pub mod ja4;
pub mod tls;

mod cursor;

/// Why a parse failed. Deliberately coarse: callers only need to know "not a valid X".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input ended before a length-prefixed field did.
    Truncated,
    /// A field had a value the format does not allow.
    Invalid,
    /// A bounded loop hit its cap (e.g. DNS compression loop).
    Limit,
    /// Well-formed, but not the message type this parser handles.
    Unsupported,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated input",
            Error::Invalid => "invalid field",
            Error::Limit => "parser limit exceeded",
            Error::Unsupported => "unsupported message",
        })
    }
}

/// Parser result.
pub type Result<T> = core::result::Result<T, Error>;
