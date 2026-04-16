//! donut-rustls — thin wrapper over `rustls` that exposes the REALITY hooks.
//!
//! In M2 this crate switches its rustls dependency to the
//! `rustls-reality` fork, which adds:
//!
//! * `ClientConfig::client_hello_mutator` — called post-marshal to let
//!   REALITY rewrite `SessionID` (32 bytes at offset 39 of ClientHello).
//! * `ServerConfig::raw_client_hello_hook` — called pre-crypto with the
//!   raw ClientHello; returns `RealityDecision::{Tunnel, Forward{..}}`.
//!
//! Status: **M0 stub.**

#![forbid(unsafe_op_in_unsafe_fn)]
