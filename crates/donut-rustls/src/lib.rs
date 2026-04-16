//! donut-rustls — thin wrapper over `rustls` that exposes the
//! veiled-TLS hooks from [`donut-tls`](../donut-tls/index.html).
//!
//! Public re-exports (`ClientHelloMutator`, `RawClientHelloHook`,
//! `VeilDecision`) come directly from the TLS crate. This wrapper
//! exists as a stable surface for crates that want to use TLS
//! without importing `rustls` by name.

#![forbid(unsafe_op_in_unsafe_fn)]

pub use rustls::client::ClientHelloMutator;
pub use rustls::server::{RawClientHelloHook, VeilDecision};

#[cfg(test)]
mod smoke;
