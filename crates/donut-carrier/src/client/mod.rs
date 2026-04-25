//! Client-side carrier dialer.

mod packet_up;
mod stream_one;
mod stream_up;

use std::net::SocketAddr;

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
