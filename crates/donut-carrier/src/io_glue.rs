//! Plumbing between hyper's request/response bodies and a tokio
//! `AsyncRead + AsyncWrite` surface that the proxy plumbing can use.
//!
//! Internally each `CarrierStream` is just a `tokio::io::DuplexStream`
//! kept on the user side; the carrier-side half is parked inside the
//! per-mode bridges in `client/` and `server/`.

use tokio::io::DuplexStream;

/// Bidirectional byte stream over a carrier-mode HTTP exchange.
/// Implements `AsyncRead + AsyncWrite + Send + Unpin`.
pub type CarrierStream = DuplexStream;

/// Internal buffer size for each direction of a carrier stream.
/// 64 KiB matches the TLS record cap and is enough to absorb a few
/// frames worth of slack.
pub(crate) const PIPE_CAPACITY: usize = 64 * 1024;
