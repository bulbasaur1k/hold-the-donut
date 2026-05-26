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
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use donut_core::{Address, Command, Endpoint, FlowKind, UserAuth};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_veil::VeilServerConfig;
use donut_wire::{Request, Response, WireError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// VLESS inner-frame version byte: the first byte of every tunnel
/// request. A first decrypted byte that is *not* this is treated as a
/// non-tunnel (probe / browser) connection and self-stolen to the decoy.
const VLESS_VERSION: u8 = 0x00;

use crate::metrics::Metrics;
use crate::veil_server::VeilServer;

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

    #[error("tls config: {0}")]
    Tls(String),
}

/// Bind a carrier server in `stream-one` mode on `bind_addr` and run
/// the proxy session loop in the background. Returns the bound local
/// address (useful when `bind_addr` had port 0 — e.g. in tests).
pub async fn run_carrier_proxy(
    bind_addr: SocketAddr,
    auth: Arc<UserAuth>,
) -> Result<SocketAddr, ProxyError> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;

    let mut server = donut_carrier::server::Server::serve(
        listener,
        donut_carrier::ServerConfig {
            mode: donut_carrier::Mode::StreamOne,
            ..donut_carrier::ServerConfig::default()
        },
    );

    // Plain path has no routing table — everything goes direct (freedom).
    let router = Arc::new(Router::new("freedom"));
    let resolver =
        Arc::new(Resolver::system().unwrap_or_else(|_| {
            Resolver::doh(&["1.1.1.1".parse().unwrap()], "cloudflare-dns.com")
        }));
    let metrics = Metrics::new();
    tokio::spawn(async move {
        while let Some(session) = server.accept().await {
            let auth = auth.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_session(session.stream, auth, router, resolver, metrics).await
                {
                    tracing::trace!(?e, "proxy session ended with error");
                }
            });
        }
    });

    Ok(local)
}

/// Bind a **plain carrier backend** on `bind_addr` (no REALITY, no TLS):
/// a reverse proxy (e.g. Caddy) terminates TLS/HTTP-3 and forwards the
/// secret-path requests here over HTTP/1.1. Each carrier `stream-one`
/// session is decoded as a VLESS inner frame and proxied to the routed
/// outbound. `path_prefix` must match the path the front proxy forwards
/// (and the client's `ClientConfig.path_prefix`). Returns the bound
/// local address.
#[allow(clippy::too_many_arguments)] // daemon wiring entry point
pub async fn run_carrier_backend(
    bind_addr: SocketAddr,
    path_prefix: String,
    mode: donut_carrier::Mode,
    auth: Arc<UserAuth>,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
) -> Result<SocketAddr, ProxyError> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;

    // `Server::serve` owns a single shared dispatcher across all accepted
    // connections, so `stream-up`/`packet-up` pair the uplink POST and
    // downlink GET that a reverse proxy / CDN forwards as separate
    // backend connections (closes the Go-reverse-proxy full-duplex
    // deadlock that blocks `stream-one` behind Caddy/CDN).
    let mut server = donut_carrier::server::Server::serve(
        listener,
        donut_carrier::ServerConfig {
            mode,
            path_prefix,
            ..donut_carrier::ServerConfig::default()
        },
    );

    tokio::spawn(async move {
        while let Some(session) = server.accept().await {
            let auth = auth.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            let metrics = metrics.clone();
            metrics.connection_accepted();
            tokio::spawn(async move {
                let _active = metrics.tunnel_started();
                if let Err(e) =
                    handle_session(session.stream, auth, router, resolver, metrics).await
                {
                    tracing::trace!(?e, "carrier backend session ended with error");
                }
            });
        }
    });

    Ok(local)
}

/// Bind a **QUIC / HTTP-3 proxy** on `bind_addr` (UDP): terminates H3
/// directly with `cert_chain`/`key` (no reverse proxy in front) and
/// proxies each carrier session to the routed outbound. Used for the
/// `transport = "quic"` server mode — direct H3, e.g. for exercising the
/// server-side QUIC stack with Caddy disabled, or for clients that speak
/// H3 straight to us.
#[allow(clippy::too_many_arguments)] // daemon wiring entry point
pub async fn run_quic_proxy(
    bind_addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    secret_path: String,
    decoy: Option<SocketAddr>,
    auth: Arc<UserAuth>,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
) -> Result<SocketAddr, ProxyError> {
    let mut server = donut_quic::QuicServer::bind(bind_addr, cert_chain, key, secret_path, decoy)
        .map_err(|e| ProxyError::Tls(e.to_string()))?;
    let local = server.addr;

    tokio::spawn(async move {
        while let Some(session) = server.accept().await {
            let auth = auth.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            let metrics = metrics.clone();
            metrics.connection_accepted();
            tokio::spawn(async move {
                let _active = metrics.tunnel_started();
                if let Err(e) =
                    handle_session(session.stream, auth, router, resolver, metrics).await
                {
                    tracing::trace!(?e, "quic proxy session ended with error");
                }
            });
        }
    });

    Ok(local)
}

/// Bind a **cert-based TLS carrier proxy** on `bind_addr` (TCP): donut-
/// server terminates TLS itself with a real certificate (no REALITY, no
/// reverse proxy in front), serves the `stream-one` carrier directly over
/// the decrypted stream (full-duplex, no Caddy in the path), and
/// self-steals every non-tunnel request to the `decoy` backend (e.g.
/// filebrowser). The client connects straight to this port. This is the
/// recommended TCP transport for a direct VPS.
#[allow(clippy::too_many_arguments)] // daemon wiring entry point
pub async fn run_tls_carrier_proxy(
    bind_addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    secret_path: String,
    mode: donut_carrier::Mode,
    decoy: Option<SocketAddr>,
    auth: Arc<UserAuth>,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
) -> Result<SocketAddr, ProxyError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| ProxyError::Tls(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .map_err(|e| ProxyError::Tls(e.to_string()))?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;

    // One acceptor with a **shared** dispatcher so stream-up / packet-up
    // can pair the uplink POST and downlink GET that arrive on separate
    // TLS connections (stream-one pairs within a single connection too).
    let (acceptor, mut rx) =
        donut_carrier::server::ConnectionAcceptor::new(donut_carrier::ServerConfig {
            mode,
            path_prefix: secret_path,
            decoy,
            ..donut_carrier::ServerConfig::default()
        });

    // Session consumer: each paired carrier session becomes a proxied
    // VLESS tunnel.
    {
        let auth = auth.clone();
        let router = router.clone();
        let resolver = resolver.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            while let Some(session) = rx.recv().await {
                let auth = auth.clone();
                let router = router.clone();
                let resolver = resolver.clone();
                let metrics = metrics.clone();
                tokio::spawn(async move {
                    let _active = metrics.tunnel_started();
                    if let Err(e) =
                        handle_session(session.stream, auth, router, resolver, metrics).await
                    {
                        tracing::trace!(?e, "tls-carrier session ended with error");
                    }
                });
            }
        });
    }

    // Accept loop: terminate TLS, then feed the connection to the shared
    // dispatcher.
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(?e, "tls-carrier accept error");
                    continue;
                }
            };
            let tls_acceptor = tls_acceptor.clone();
            let acceptor = acceptor.clone();
            metrics.connection_accepted();
            tokio::spawn(async move {
                let tls_stream = match tls_acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::trace!(?e, "tls-carrier handshake failed");
                        return;
                    }
                };
                acceptor.drive(tls_stream, peer);
            });
        }
    });

    Ok(local)
}

/// Bind a **veiled** proxy on `bind_addr`: every connection is triaged
/// by the selfsteal front door; unauthenticated callers are relayed to
/// `dest`, authenticated veil peers get their TLS terminated and the
/// `stream-one` carrier served over the decrypted stream, then proxied
/// via the freedom outbound. This is the full scenario-2 server path
/// (`VLESS+REALITY+XHTTP`). Returns the bound local address.
#[allow(clippy::too_many_arguments)] // daemon wiring entry point
pub async fn run_veil_proxy(
    bind_addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    veil: VeilServerConfig,
    dest: SocketAddr,
    auth: Arc<UserAuth>,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
) -> Result<SocketAddr, ProxyError> {
    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;
    let server = Arc::new(
        VeilServer::new(cert_chain, key, veil, dest).map_err(|e| ProxyError::Tls(e.to_string()))?,
    );

    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(?e, "veil proxy accept error");
                    continue;
                }
            };
            let server = server.clone();
            let auth = auth.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            let metrics = metrics.clone();
            metrics.connection_accepted();
            tokio::spawn(async move {
                match server.handle(tcp).await {
                    Ok(Some(tls)) => {
                        // Hold the active gauge up for the connection's life.
                        let _active = metrics.tunnel_started();
                        let mut rx = donut_carrier::server::serve_connection(
                            tls,
                            donut_carrier::ServerConfig {
                                mode: donut_carrier::Mode::StreamOne,
                                ..donut_carrier::ServerConfig::default()
                            },
                            peer,
                        );
                        while let Some(session) = rx.recv().await {
                            let auth = auth.clone();
                            let router = router.clone();
                            let resolver = resolver.clone();
                            let metrics = metrics.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_session(session.stream, auth, router, resolver, metrics)
                                        .await
                                {
                                    tracing::trace!(?e, "veil proxy session ended with error");
                                }
                            });
                        }
                    }
                    Ok(None) => {
                        metrics.forwarded();
                        tracing::trace!("veil proxy: unauthenticated caller relayed to decoy");
                    }
                    Err(e) => {
                        tracing::trace!(?e, "veil proxy: handshake/triage failed");
                    }
                }
            });
        }
    });

    Ok(local)
}

async fn handle_session<S>(
    mut session: S,
    auth: Arc<UserAuth>,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
) -> Result<(), ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
    let flow = request.flow;

    // Credential check — the real VLESS auth. This is the single choke
    // point every transport funnels through, so an unknown UUID is
    // rejected here before any upstream is dialled. We drop silently:
    // by this point the caller has already cleared the transport-level
    // self-steal (TLS/REALITY + the version byte / secret path), and the
    // de-framed stream is not something an HTTP decoy could answer, so a
    // decoy relay would buy no extra cover — closing is the honest move.
    if !auth.is_authorized(&request.user) {
        metrics.rejected_unauthorized();
        tracing::debug!(user = %request.user, "vless auth: unknown UUID — dropping session");
        return Ok(());
    }

    let target_endpoint = request.target.ok_or(ProxyError::UnsupportedCommand)?;
    if !matches!(request.command, Command::Tcp) {
        return Err(ProxyError::UnsupportedCommand);
    }

    // Routing decision. A `block`/`blackhole` outbound drops the
    // connection (the client sees its tunnel close); anything else falls
    // through to the freedom (direct) outbound.
    match router.route(&target_endpoint) {
        "block" | "blackhole" => {
            metrics.blackholed();
            tracing::debug!(target = %target_endpoint, "routing: blackhole — dropping");
            return Ok(());
        }
        _ => {}
    }

    let target_addr = resolve(&resolver, &target_endpoint).await?;
    let mut upstream = tokio::net::TcpStream::connect(target_addr).await?;

    // Echo the response prefix back to the client so it can verify
    // the version byte and addons-len before payload starts.
    let mut response_buf = BytesMut::with_capacity(8);
    Response::default().encode(&mut response_buf);
    session.write_all(&response_buf).await?;

    match flow {
        // XTLS-Vision: the data-plane is framed with first-packet
        // padding. The `leftover` bytes are the start of the first framed
        // packet — replay them into the Vision decoder.
        FlowKind::Extended => {
            let tunnel = Prefixed::new(leftover.to_vec(), session);
            if let Err(e) = donut_io::vision::copy_bidirectional(
                tunnel,
                upstream,
                donut_io::vision::VisionConfig::default(),
            )
            .await
            {
                tracing::trace!(?e, "vision session ended with error");
            }
        }
        // Plain VLESS: raw bidirectional copy. Push any leftover client
        // bytes that came in the same read as the inner-frame header.
        FlowKind::None => {
            if !leftover.is_empty() {
                upstream.write_all(&leftover).await?;
            }
            if let Ok((up, down)) = tokio::io::copy_bidirectional(&mut session, &mut upstream).await
            {
                metrics.add_bytes(up, down);
            }
            let _ = upstream.shutdown().await;
            let _ = session.shutdown().await;
        }
    }
    Ok(())
}

/// Resolve a target endpoint: IP literals pass through; domains go
/// through the configured [`Resolver`] (system or DoH).
async fn resolve(resolver: &Resolver, ep: &Endpoint) -> Result<SocketAddr, ProxyError> {
    match &ep.address {
        Address::Ip(ip) => Ok(SocketAddr::new(*ip, ep.port)),
        Address::Domain(d) => resolver
            .resolve_one(d, ep.port)
            .await
            .map_err(|e| ProxyError::Resolve(format!("{d}: {e}"))),
    }
}

/// Bind a **cert-based RAW proxy** on `bind_addr` (TCP): donut-server
/// terminates TLS itself with a real certificate, then the first
/// decrypted byte decides the connection. A VLESS inner frame
/// (`0x00` version) is proxied directly over the decrypted stream — no
/// HTTP carrier wrapping, the closest analogue to Xray's `RAW`/TCP
/// network and the transport that `xtls-rprx-vision` rides on. Anything
/// else (an HTTP probe / a browser) is relayed to the `decoy` backend
/// (filebrowser) so the port self-steals like an ordinary HTTPS site.
#[allow(clippy::too_many_arguments)] // daemon wiring entry point
pub async fn run_raw_proxy(
    bind_addr: SocketAddr,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    decoy: Option<SocketAddr>,
    auth: Arc<UserAuth>,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
) -> Result<SocketAddr, ProxyError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| ProxyError::Tls(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .map_err(|e| ProxyError::Tls(e.to_string()))?;
    // Offer http/1.1 so a probing browser negotiates a protocol the decoy
    // (filebrowser, HTTP/1.1) can answer; our own client offers the same.
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));

    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(?e, "raw accept error");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let auth = auth.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            let metrics = metrics.clone();
            metrics.connection_accepted();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::trace!(?e, "raw tls handshake failed");
                        return;
                    }
                };
                // Peek the first decrypted byte to triage VLESS vs probe.
                let mut first = [0u8; 1];
                match tls.read(&mut first).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                if first[0] == VLESS_VERSION {
                    let stream = Prefixed::new(vec![first[0]], tls);
                    let _active = metrics.tunnel_started();
                    if let Err(e) = handle_session(stream, auth, router, resolver, metrics).await {
                        tracing::trace!(?e, "raw proxy session ended with error");
                    }
                } else if let Some(decoy) = decoy {
                    tracing::trace!(%decoy, "raw: non-tunnel connection → decoy self-steal");
                    metrics.forwarded();
                    let stream = Prefixed::new(vec![first[0]], tls);
                    relay_to_decoy(stream, decoy).await;
                } else {
                    tracing::trace!("raw: non-tunnel connection, no decoy → drop");
                }
            });
        }
    });

    Ok(local)
}

/// Bidirectionally relay a (partly-consumed) client stream to the decoy
/// backend so a probe sees an ordinary site.
async fn relay_to_decoy<S>(mut client: S, decoy: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match TcpStream::connect(decoy).await {
        Ok(mut up) => {
            let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
            let _ = up.shutdown().await;
        }
        Err(e) => tracing::trace!(?e, %decoy, "raw decoy connect failed"),
    }
}

/// An `AsyncRead + AsyncWrite` that replays `prefix` bytes before the
/// inner stream — used to "un-read" the byte(s) peeked during triage.
struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let rem = &this.prefix[this.pos..];
            let n = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// silence unused-import warnings under cfg(test)
#[allow(dead_code)]
fn _unused_anchor(_: Bytes) {}
