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
use donut_core::{Address, Command, Endpoint, FlowKind, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_socks::{handshake_connect, PendingConnect, SocksError};
use donut_wire::{Request, Response, WireError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::h3_dial::H3Client;
use crate::raw_dial::RawClient;
use crate::veil_dial::VeilClient;
use crate::xhttp_dial::XhttpClient;

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

/// Split-tunnel route classes the client acts on.
enum Route {
    /// Drop the connection.
    Block,
    /// Dial straight from the client (bypass the server — keeps e.g.
    /// domestic `geoip:`/`geosite:` traffic on the local IP).
    Direct,
    /// Send through the tunnel to the server.
    Proxy,
}

fn classify_route(router: &Router, target: &Endpoint) -> Route {
    match router.route(target) {
        "block" | "blackhole" => Route::Block,
        "direct" | "freedom" => Route::Direct,
        _ => Route::Proxy,
    }
}

/// Direct (split-tunnel) dial: connect to `target` from the local host
/// and bridge the SOCKS client to it. Never touches the server — this is
/// what keeps RU `geoip`/`geosite` traffic on the local IP.
async fn handle_direct_dial(
    pending: PendingConnect,
    resolver: &Resolver,
) -> Result<(), LocalProxyError> {
    let target = &pending.target;
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
    Ok(())
}

/// Bridge a SOCKS5 CONNECT to an already-opened carrier stream: push the
/// VLESS inner-frame Request, drain the Response prefix, accept the SOCKS
/// client, then pipe bytes both ways. Generic over the carrier stream
/// type, so it serves the veil, xhttp and h3 transports alike.
async fn bridge_carrier_to_socks<C>(
    pending: PendingConnect,
    mut carrier: C,
) -> Result<(), LocalProxyError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let request = Request {
        user: UserId::new_v4(),
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(pending.target.clone()),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len());
    request.encode(&mut framed);
    carrier.write_all(&framed).await?;
    carrier.flush().await?;

    let mut prefix = [0u8; 2];
    carrier.read_exact(&mut prefix).await?;
    let mut prefix_view = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut prefix_view)?;

    let bound: SocketAddr = "0.0.0.0:0".parse().expect("static literal");
    let mut sock = pending.accept(bound).await?;
    let _ = tokio::io::copy_bidirectional(&mut sock, &mut carrier).await;
    Ok(())
}

async fn handle_veil_socks_session(
    sock: tokio::net::TcpStream,
    veil_client: Arc<VeilClient>,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
) -> Result<(), LocalProxyError> {
    let pending = handshake_connect(sock).await?;
    match classify_route(&router, &pending.target) {
        Route::Block => {
            tracing::debug!(target = %pending.target, "split-tunnel: blocked, dropping");
            Ok(())
        }
        Route::Direct => handle_direct_dial(pending, &resolver).await,
        Route::Proxy => {
            tracing::trace!(target = %pending.target, "split-tunnel: via veiled tunnel");
            let tls = veil_client.connect(server_addr).await?;
            let carrier_cfg = donut_carrier::ClientConfig {
                mode: donut_carrier::Mode::StreamOne,
                ..donut_carrier::ClientConfig::default()
            };
            let carrier = donut_carrier::client::dial_over_stream(tls, &carrier_cfg)
                .await
                .map_err(|e| LocalProxyError::Carrier(format!("{e}")))?;
            bridge_carrier_to_socks(pending, carrier).await
        }
    }
}

/// Bind a SOCKS5 listener and, for each CONNECT, dial the donut-server
/// through a **cert-based XHTTP** tunnel ([`XhttpClient`]): plain TLS to
/// the reverse-proxy front + `stream-one` carrier at the secret path. No
/// REALITY — the front holds a real certificate and self-steals
/// everything else. Split-tunnel routing is identical to the veil path.
/// Returns the bound local address.
pub async fn run_xhttp_socks_proxy(
    local_addr: SocketAddr,
    xhttp_client: XhttpClient,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
) -> Result<SocketAddr, LocalProxyError> {
    let listener = TcpListener::bind(local_addr).await?;
    let local = listener.local_addr()?;
    let xhttp_client = Arc::new(xhttp_client);
    tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let xhttp_client = xhttp_client.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_xhttp_socks_session(sock, xhttp_client, server_addr, router, resolver)
                        .await
                {
                    tracing::trace!(?e, "local xhttp socks proxy session ended");
                }
            });
        }
    });
    Ok(local)
}

async fn handle_xhttp_socks_session(
    sock: tokio::net::TcpStream,
    xhttp_client: Arc<XhttpClient>,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
) -> Result<(), LocalProxyError> {
    let pending = handshake_connect(sock).await?;
    match classify_route(&router, &pending.target) {
        Route::Block => {
            tracing::debug!(target = %pending.target, "split-tunnel: blocked, dropping");
            Ok(())
        }
        Route::Direct => handle_direct_dial(pending, &resolver).await,
        Route::Proxy => {
            tracing::trace!(target = %pending.target, "split-tunnel: via xhttp tunnel");
            let carrier = xhttp_client.connect(server_addr).await?;
            bridge_carrier_to_socks(pending, carrier).await
        }
    }
}

/// Bind a SOCKS5 listener and, for each CONNECT, dial the donut-server
/// through a **cert-based H3 (HTTP/3)** tunnel ([`H3Client`]). Same
/// model as [`run_xhttp_socks_proxy`] but over QUIC. Split-tunnel
/// routing identical. Returns the bound local address.
pub async fn run_h3_socks_proxy(
    local_addr: SocketAddr,
    h3_client: H3Client,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
) -> Result<SocketAddr, LocalProxyError> {
    let listener = TcpListener::bind(local_addr).await?;
    let local = listener.local_addr()?;
    let h3_client = Arc::new(h3_client);
    tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let h3_client = h3_client.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_h3_socks_session(sock, h3_client, server_addr, router, resolver).await
                {
                    tracing::trace!(?e, "local h3 socks proxy session ended");
                }
            });
        }
    });
    Ok(local)
}

async fn handle_h3_socks_session(
    sock: tokio::net::TcpStream,
    h3_client: Arc<H3Client>,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
) -> Result<(), LocalProxyError> {
    let pending = handshake_connect(sock).await?;
    match classify_route(&router, &pending.target) {
        Route::Block => {
            tracing::debug!(target = %pending.target, "split-tunnel: blocked, dropping");
            Ok(())
        }
        Route::Direct => handle_direct_dial(pending, &resolver).await,
        Route::Proxy => {
            tracing::trace!(target = %pending.target, "split-tunnel: via h3 tunnel");
            let carrier = h3_client.connect(server_addr).await?;
            bridge_carrier_to_socks(pending, carrier).await
        }
    }
}

/// Bind a SOCKS5 listener and, for each CONNECT, dial the donut-server
/// through a **cert-based RAW** tunnel ([`RawClient`]): VLESS straight
/// over TLS 1.3 (no carrier wrapping), the analogue of Xray's RAW/TCP
/// network. Split-tunnel routing identical to the other transports.
/// Returns the bound local address.
pub async fn run_raw_socks_proxy(
    local_addr: SocketAddr,
    raw_client: RawClient,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    flow: FlowKind,
) -> Result<SocketAddr, LocalProxyError> {
    let listener = TcpListener::bind(local_addr).await?;
    let local = listener.local_addr()?;
    let raw_client = Arc::new(raw_client);
    tokio::spawn(async move {
        loop {
            let (sock, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let raw_client = raw_client.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_raw_socks_session(sock, raw_client, server_addr, router, resolver, flow)
                        .await
                {
                    tracing::trace!(?e, "local raw socks proxy session ended");
                }
            });
        }
    });
    Ok(local)
}

async fn handle_raw_socks_session(
    sock: tokio::net::TcpStream,
    raw_client: Arc<RawClient>,
    server_addr: SocketAddr,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    flow: FlowKind,
) -> Result<(), LocalProxyError> {
    let pending = handshake_connect(sock).await?;
    match classify_route(&router, &pending.target) {
        Route::Block => {
            tracing::debug!(target = %pending.target, "split-tunnel: blocked, dropping");
            Ok(())
        }
        Route::Direct => handle_direct_dial(pending, &resolver).await,
        Route::Proxy => {
            tracing::trace!(target = %pending.target, ?flow, "split-tunnel: via raw tunnel");
            let tls = raw_client.connect(server_addr).await?;
            bridge_raw_to_socks(pending, tls, flow).await
        }
    }
}

/// Bridge a SOCKS5 CONNECT over a RAW (no-carrier) tunnel stream: push the
/// VLESS inner-frame Request (carrying `flow`), drain the Response prefix,
/// then run the data-plane. With `FlowKind::Extended` the data-plane is
/// XTLS-Vision (first-packet padding); otherwise it's a raw copy.
async fn bridge_raw_to_socks<C>(
    pending: PendingConnect,
    mut stream: C,
    flow: FlowKind,
) -> Result<(), LocalProxyError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let request = Request {
        user: UserId::new_v4(),
        flow,
        command: Command::Tcp,
        target: Some(pending.target.clone()),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len());
    request.encode(&mut framed);
    stream.write_all(&framed).await?;
    stream.flush().await?;

    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).await?;
    let mut prefix_view = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut prefix_view)?;

    let bound: SocketAddr = "0.0.0.0:0".parse().expect("static literal");
    let sock = pending.accept(bound).await?;
    match flow {
        FlowKind::Extended => {
            let _ = donut_io::vision::copy_bidirectional(
                stream,
                sock,
                donut_io::vision::VisionConfig::default(),
            )
            .await;
        }
        FlowKind::None => {
            let mut sock = sock;
            let _ = tokio::io::copy_bidirectional(&mut sock, &mut stream).await;
        }
    }
    Ok(())
}
