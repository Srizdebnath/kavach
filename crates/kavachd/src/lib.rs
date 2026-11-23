//! kavachd internals, exposed as a library so integration tests can drive the kernel side.
pub mod anomaly;
pub mod api;
pub mod backing;
pub mod config;
pub mod daemon;
pub mod events;
pub mod gateway_policies;
pub mod kernel;
pub mod scan;
pub mod supervise;
