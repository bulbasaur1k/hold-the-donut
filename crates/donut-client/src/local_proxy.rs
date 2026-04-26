//! Local SOCKS5 listener that bridges into a carrier session to
//! the donut-server.
//!
//! Per accepted SOCKS5 CONNECT:
//! 1. Parse the destination via `donut_socks::handshake_connect`.
//! 2. Open a `stream-one` carrier session to the configured donut
//!    server.
//! 3. Encode an inner-frame Request targeting the destination, push
//!    it down the carrier session.
//! 4. Drain the matching Response prefix from the server.
//! 5. Send the SOCKS5 success reply back to the SOCKS5 client.
//! 6. `tokio::io::copy_bidirectional` between the SOCKS5 socket and
//!    the carrier session — the donut-server has already wired the
//!    upstream TCP target on its side.

use std::net::SocketAddr;

use bytes::BytesMut;
use donut_core::{Command, FlowKind, UserId};
use donut_socks::{handshake_connect, SocksError};
use donut_wire::{Request, Response, WireError};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

#[derive(Debug, Error)]
pub enum LocalProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("socks: {0}")]
    Socks(#[from] SocksError),

    #[error("wire: {0}")]
    Wire(#[from] WireError),

    #[error("carrier dial: {0}")]
    Carrier(String),
}

/// Bind a SOCKS5 listener on `local_addr`, dial the donut-server at
/// `server_addr` for each accepted CONNECT, and bridge the bytes.
/// Returns the bound local address.
pub async fn run_local_socks_proxy(
    local_addr: SocketAddr,
    server_addr: SocketAddr,
) -> Result<SocketAddr, LocalProxyError> {
    let listener = TcpListener::bind(local_addr).await?;
    let local = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                if let Err(e) = handle_socks_session(sock, server_addr).await {
                    tracing::trace!(?e, "local socks proxy session ended");
                }
            });
        }
    });
    Ok(local)
}

async fn handle_socks_session(
    sock: tokio::net::TcpStream,
    server_addr: SocketAddr,
) -> Result<(), LocalProxyError> {
    let pending = handshake_connect(sock).await?;
    let target = pending.target.clone();

    // Open carrier session to the server.
    let carrier_cfg = donut_carrier::ClientConfig {
        mode: donut_carrier::Mode::StreamOne,
        ..donut_carrier::ClientConfig::default()
    };
    let mut carrier = donut_carrier::client::dial(server_addr, &carrier_cfg)
        .await
        .map_err(|e| LocalProxyError::Carrier(format!("{e}")))?;

    // Push inner-frame request header. The Response prefix will come
    // back before the upstream payload.
    let request = Request {
        user: UserId::new_v4(),
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(target),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len());
    request.encode(&mut framed);
    tokio::io::AsyncWriteExt::write_all(&mut carrier, &framed).await?;
    tokio::io::AsyncWriteExt::flush(&mut carrier).await?;

    // Drain the Response prefix the server sends before the upstream
    // bytes start flowing.
    let mut prefix = [0u8; 2];
    carrier.read_exact(&mut prefix).await?;
    let mut prefix_view = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut prefix_view)?;

    // Tell the SOCKS client we're connected. The bound address we
    // report doesn't matter much for client correctness; tools tend
    // to ignore it, but echoing the local end of the carrier socket
    // is the safest answer.
    let bound: SocketAddr = "0.0.0.0:0".parse().expect("static literal");
    let mut sock = pending.accept(bound).await?;

    let _ = tokio::io::copy_bidirectional(&mut sock, &mut carrier).await;
    Ok(())
}
