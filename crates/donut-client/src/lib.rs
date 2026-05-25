//! donut-client — local agent library.
//!
//! Status: **M7 step 1.** SOCKS5 inbound on a local port → carrier
//! outbound to the configured donut-server. Plain (no veiled-TLS)
//! today; veiled-TLS in front of the carrier dial lands in M7 step 2
//! once the server side gains TLS termination (M6 step 2).

#![forbid(unsafe_op_in_unsafe_fn)]

mod h3_dial;
mod local_proxy;
mod veil_dial;
mod xhttp_dial;

pub use h3_dial::H3Client;
pub use local_proxy::{
    run_h3_socks_proxy, run_local_socks_proxy, run_veil_socks_proxy, run_xhttp_socks_proxy,
    LocalProxyError,
};
pub use veil_dial::VeilClient;
pub use xhttp_dial::XhttpClient;
