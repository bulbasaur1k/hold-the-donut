//! Client-side carrier dialer.

mod packet_up;
mod stream_one;
mod stream_up;

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::ClientConfig;
use crate::error::CarrierError;
use crate::io_glue::CarrierStream;
use crate::session::SessionId;
use crate::Mode;

/// Open a carrier stream to `target` using `config`. Returns the
/// duplex byte stream that the proxy plumbing reads/writes.
pub async fn dial(
    target: SocketAddr,
    config: &ClientConfig,
) -> Result<CarrierStream, CarrierError> {
    let sid = SessionId::random();
    match config.mode {
        Mode::StreamOne => stream_one::dial(target, config, sid).await,
        Mode::StreamUp => stream_up::dial(target, config, sid).await,
        Mode::PacketUp => packet_up::dial(target, config, sid).await,
    }
}

/// Dial the carrier over an **already-established** byte stream (e.g. a
/// decrypted veiled-TLS stream from [`donut_veil`]/the client TLS dial).
/// Only `stream-one` is supported over a pre-existing single stream —
/// the multi-request modes (`stream-up`, `packet-up`) open their own
/// connections and cannot ride a single tunnel.
pub async fn dial_over_stream<IO>(
    io: IO,
    config: &ClientConfig,
) -> Result<CarrierStream, CarrierError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let sid = SessionId::random();
    match config.mode {
        Mode::StreamOne => stream_one::dial_over_io(io, config, sid).await,
        _ => Err(CarrierError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "carrier dial_over_stream supports only stream-one",
        ))),
    }
}
