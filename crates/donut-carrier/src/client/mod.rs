//! Client-side carrier dialer.

mod packet_up;
mod stream_one;
mod stream_up;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::config::ClientConfig;
use crate::connect::{tcp_connector, Connector};
use crate::error::CarrierError;
use crate::io_glue::CarrierStream;
use crate::session::SessionId;
use crate::Mode;

/// Open a carrier stream to `target` over plain TCP using `config`.
/// Convenience wrapper around [`dial_with`] with a TCP connector (used
/// behind a TLS-terminating reverse proxy and in tests).
pub async fn dial(
    target: SocketAddr,
    config: &ClientConfig,
) -> Result<CarrierStream, CarrierError> {
    dial_with(Arc::new(tcp_connector(target)), config).await
}

/// Open a carrier stream using `connector` to make each underlying
/// connection. `stream-one` uses one connection, `stream-up` two,
/// `packet-up` many — the connector decides the transport (TCP or a
/// fresh TLS 1.3 session for the cert-based donut-server).
pub async fn dial_with(
    connector: Arc<dyn Connector>,
    config: &ClientConfig,
) -> Result<CarrierStream, CarrierError> {
    let sid = SessionId::random();
    match config.mode {
        Mode::StreamOne => {
            let io = connector.connect().await?;
            stream_one::dial_over_io(io, config, sid).await
        }
        Mode::StreamUp => stream_up::dial(connector, config, sid).await,
        Mode::PacketUp => packet_up::dial(connector, config, sid).await,
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
