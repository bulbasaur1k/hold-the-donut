//! Per-session proxy plumbing.
//!
//! For each accepted carrier session:
//! 1. Read the inner-frame request header off the session bytes.
//! 2. Resolve the target endpoint (TCP for `Command::Tcp`).
//! 3. Connect — `freedom`-style direct dial, no upstream proxy.
//! 4. `tokio::io::copy_bidirectional` between the carrier session
//!    stream and the target TCP stream.
//!
//! The function is fully generic over the carrier server type — any
//! source of `(stream, target)` pairs satisfies it.

use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use donut_core::{Address, Command, Endpoint};
use donut_wire::{Request, Response, WireError};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("inner frame: {0}")]
    Wire(#[from] WireError),

    #[error("UDP and Mux commands are not supported by the freedom outbound (M6.1)")]
    UnsupportedCommand,

    #[error("could not resolve target {0}")]
    Resolve(String),
}

/// Bind a carrier server in `stream-one` mode on `bind_addr` and run
/// the proxy session loop in the background. Returns the bound local
/// address (useful when `bind_addr` had port 0 — e.g. in tests).
pub async fn run_carrier_proxy(bind_addr: SocketAddr) -> Result<SocketAddr, ProxyError> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;

    let mut server = donut_carrier::server::Server::serve(
        listener,
        donut_carrier::ServerConfig {
            mode: donut_carrier::Mode::StreamOne,
            ..donut_carrier::ServerConfig::default()
        },
    );

    tokio::spawn(async move {
        while let Some(session) = server.accept().await {
            tokio::spawn(async move {
                if let Err(e) = handle_session(session.stream).await {
                    tracing::trace!(?e, "proxy session ended with error");
                }
            });
        }
    });

    Ok(local)
}

async fn handle_session(stream: donut_carrier::CarrierStream) -> Result<(), ProxyError> {
    let mut session = stream;

    // Read enough bytes to parse the inner-frame request header. The
    // header is short (≤ ~280 bytes), so a single buffered read is
    // usually enough — fall through to a small loop if not.
    let mut buf = BytesMut::with_capacity(512);
    let request = loop {
        let mut chunk = [0u8; 512];
        let n = session.read(&mut chunk).await?;
        if n == 0 {
            return Err(ProxyError::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut view = buf.clone().freeze();
        match Request::decode(&mut view) {
            Ok(req) => {
                let consumed = buf.len() - view.len();
                let leftover = buf.split_off(consumed).freeze();
                break (req, leftover);
            }
            Err(WireError::Truncated { .. }) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let (request, leftover) = request;

    let target_endpoint = request.target.ok_or(ProxyError::UnsupportedCommand)?;
    if !matches!(request.command, Command::Tcp) {
        return Err(ProxyError::UnsupportedCommand);
    }

    let target_addr = resolve(&target_endpoint).await?;
    let mut upstream = tokio::net::TcpStream::connect(target_addr).await?;

    // Echo the response prefix back to the client so it can verify
    // the version byte and addons-len before payload starts.
    let mut response_buf = BytesMut::with_capacity(8);
    Response::default().encode(&mut response_buf);
    session.write_all(&response_buf).await?;

    // Push any leftover client bytes that came in the same read as
    // the inner-frame header.
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }

    let _ = tokio::io::copy_bidirectional(&mut session, &mut upstream).await;
    let _ = upstream.shutdown().await;
    let _ = session.shutdown().await;
    Ok(())
}

/// Trivial synchronous resolver: IPs pass through unchanged, domains
/// go through tokio's blocking `to_socket_addrs`.
async fn resolve(ep: &Endpoint) -> Result<SocketAddr, ProxyError> {
    match &ep.address {
        Address::Ip(ip) => Ok(SocketAddr::new(*ip, ep.port)),
        Address::Domain(d) => {
            let host = format!("{d}:{}", ep.port);
            tokio::net::lookup_host(host.clone())
                .await
                .map_err(ProxyError::Io)?
                .next()
                .ok_or(ProxyError::Resolve(d.clone()))
        }
    }
}

// silence unused-import warnings under cfg(test)
#[allow(dead_code)]
fn _unused_anchor(_: Bytes) {}
