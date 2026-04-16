//! donut-rustls — thin wrapper over `rustls` that exposes the veiled-TLS hooks.
//!
//! In M2 this crate switches its rustls dependency to the forked
//! rustls (see `forks/rustls-reality/`), which adds:
//!
//! * `ClientConfig::client_hello_mutator` — called post-marshal to let
//!   the veil layer rewrite `SessionID` (32 bytes at offset 39 of
//!   ClientHello).
//! * `ServerConfig::raw_client_hello_hook` — called pre-crypto with
//!   the raw ClientHello; returns `VeilDecision::{Tunnel, Forward{..}}`.
//!
//! Status: **M0 stub.**

#![forbid(unsafe_op_in_unsafe_fn)]
