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
use std::sync::Arc;

use bytes::BytesMut;
use donut_core::{Address, Command, FlowKind, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_socks::{handshake_connect, SocksError};
use donut_wire::{Request, Response, WireError};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::veil_dial::VeilClient;

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

    #[error("resolve: {0}")]
    Resolve(String),
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

/// Bind a SOCKS5 listener on `local_addr` and, for each CONNECT, dial
/// the donut-server through a **veiled-TLS** tunnel (`VeilClient`) and
/// run the `stream-one` carrier over the decrypted stream. This is the
/// full scenario-2 client path (`VLESS+REALITY+XHTTP`). Returns the
/// bound local address.
pub async fn run_veil_socks_proxy(
    local_addr: SocketAddr,
    veil_client: VeilClient,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
) -> Result<SocketAddr, LocalProxyError> {
    let listener = TcpListener::bind(local_addr).await?;
    let local = listener.local_addr()?;
    let veil_client = Arc::new(veil_client);
    tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let veil_client = veil_client.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_veil_socks_session(sock, veil_client, server_addr, router, resolver)
                        .await
                {
                    tracing::trace!(?e, "local veil socks proxy session ended");
                }
            });
        }
    });
    Ok(local)
}

async fn handle_veil_socks_session(
    sock: tokio::net::TcpStream,
    veil_client: Arc<VeilClient>,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
) -> Result<(), LocalProxyError> {
    let pending = handshake_connect(sock).await?;
    let target = pending.target.clone();

    // Split-tunnel decision. `direct`/`freedom` dials straight from the
    // client (so e.g. domestic `geoip:` traffic keeps the local IP and
    // never reveals itself to the remote server); `block` drops;
    // everything else (default `proxy`) goes through the veiled tunnel.
    match router.route(&target) {
        "block" | "blackhole" => {
            tracing::debug!(%target, "split-tunnel: blocked, dropping");
            return Ok(());
        }
        "direct" | "freedom" => {
            tracing::debug!(%target, "split-tunnel: direct dial (bypassing server)");
            let addr = match &target.address {
                Address::Ip(ip) => SocketAddr::new(*ip, target.port),
                Address::Domain(d) => resolver
                    .resolve_one(d, target.port)
                    .await
                    .map_err(|e| LocalProxyError::Resolve(format!("{d}: {e}")))?,
            };
            let mut upstream = tokio::net::TcpStream::connect(addr).await?;
            let bound: SocketAddr = "0.0.0.0:0".parse().expect("static literal");
            let mut sock = pending.accept(bound).await?;
            let _ = tokio::io::copy_bidirectional(&mut sock, &mut upstream).await;
            return Ok(());
        }
        _ => {}
    }

    // Proxy path: veiled-TLS dial, then carrier over the decrypted stream.
    tracing::trace!(%target, "split-tunnel: via veiled tunnel");
    let tls = veil_client.connect(server_addr).await?;
    let carrier_cfg = donut_carrier::ClientConfig {
        mode: donut_carrier::Mode::StreamOne,
        ..donut_carrier::ClientConfig::default()
    };
    let mut carrier = donut_carrier::client::dial_over_stream(tls, &carrier_cfg)
        .await
        .map_err(|e| LocalProxyError::Carrier(format!("{e}")))?;

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

    let mut prefix = [0u8; 2];
    carrier.read_exact(&mut prefix).await?;
    let mut prefix_view = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut prefix_view)?;

    let bound: SocketAddr = "0.0.0.0:0".parse().expect("static literal");
    let mut sock = pending.accept(bound).await?;

    let _ = tokio::io::copy_bidirectional(&mut sock, &mut carrier).await;
    Ok(())
}
