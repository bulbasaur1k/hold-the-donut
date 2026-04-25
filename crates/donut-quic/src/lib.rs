//! donut-quic — QUIC / HTTP-3 carrier transport.
//!
//! Wraps `quinn` (QUIC), `rustls` (TLS), `h3` and `h3-quinn`
//! (HTTP-3) into the same `stream-one` / `stream-up` / `packet-up`
//! framing the H1/H2 carrier in [`donut-carrier`] uses. Status: M5.
//!
//! M5 step 1 lands `stream-one` end-to-end. The remaining two modes
//! reuse the same per-session pairing dispatcher and are added in
//! follow-up commits within M5.

#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::doc_lazy_continuation)]

mod error;

pub mod client;
pub mod server;

#[cfg(test)]
mod tests;

pub use error::QuicError;
pub use server::{QuicServer, QuicSession};
