//! donut-carrier — HTTP-based transport (3 modes, over H1/H2/H3).
//!
//! See `docs/PROTOCOLS.md` § 3 for the frozen byte spec.
//!
//! Modes (status):
//! * `stream-one`  — implemented (M4). Single bidirectional HTTP
//!                   exchange; default under the veiled-TLS layer.
//! * `stream-up`   — implemented (M4). One long POST + one long GET.
//! * `packet-up`   — implemented (M4). Many sequenced POSTs + one GET.
//!
//! HTTP/3 (QUIC) lands in M5.

#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::doc_overindented_list_items)]
// Kept around for the M6 proxy plumbing; the wiring is exercised by
// the e2e tests.
#![allow(dead_code)]

mod config;
mod connect;
mod error;
mod io_glue;
mod mode;
mod placement;
mod session;

pub mod client;
pub mod server;

#[cfg(test)]
mod tests;

pub use config::{ClientConfig, ServerConfig};
pub use connect::{tcp_connector, BoxIo, Connector, DuplexIo};
pub use error::CarrierError;
pub use io_glue::CarrierStream;
pub use mode::Mode;
pub use placement::Placement;
pub use session::SessionId;
