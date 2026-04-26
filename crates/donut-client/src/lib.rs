//! donut-client — local agent library.
//!
//! Status: **M7 step 1.** SOCKS5 inbound on a local port → carrier
//! outbound to the configured donut-server. Plain (no veiled-TLS)
//! today; veiled-TLS in front of the carrier dial lands in M7 step 2
//! once the server side gains TLS termination (M6 step 2).

#![forbid(unsafe_op_in_unsafe_fn)]

mod local_proxy;

pub use local_proxy::{run_local_socks_proxy, LocalProxyError};
