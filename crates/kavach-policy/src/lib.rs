//! # kavach-policy
//!
//! Policy-as-code pipeline: `kavach.toml` → parse → validate (contradictions, shadowing, limits,
//! TTLs) → lower to IR → compile to kernel tables → ed25519-signed `.kvb` bundle.
#![forbid(unsafe_code)]

pub mod bundle;
pub mod compile;
pub mod diff;
pub mod kernel;
pub mod schema;

pub use compile::{CompileOutput, CompiledPolicy, Diagnostic, Severity, compile};
pub use ed25519_dalek::{SigningKey, VerifyingKey};

#[cfg(test)]
mod tests;
