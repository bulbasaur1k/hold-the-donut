//! donut-server — edge daemon library.
//!
//! Wires the carrier, inner-frame and outbound layers into a working
//! proxy. The bin entry point in `main.rs` is a thin wrapper that
//! parses CLI/config and calls into [`run_carrier_proxy`].
//!
//! Status: **M6 step 1.** Plain (no veiled-TLS) carrier proxy with a
//! fixed `freedom` outbound. M6 step 2 layers veiled-TLS on top, M6
//! step 3 brings configurable routing + DNS resolver, M6 step 4 the
//! JSON config loader.

#![forbid(unsafe_op_in_unsafe_fn)]

mod proxy;

pub use proxy::{run_carrier_proxy, ProxyError};
