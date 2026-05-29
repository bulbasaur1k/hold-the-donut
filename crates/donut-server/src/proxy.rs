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
use std::time::Duration;

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

/// Runtime tuning passed into the proxy entry points. Built from
/// [`donut_config::TuningConfig`] in `main`; cheap to clone (`Copy`) so it
/// rides along through the call graph without an `Arc`.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeTuning {
    /// Idle timeout for a Mux.Cool / XUDP relay.
    pub mux_idle: Duration,
    /// Idle timeout for a single-target VLESS-UDP relay.
    pub udp_idle: Duration,
    /// Pause between `accept()` retries after a persistent error
    /// (EMFILE / ENOBUFS). 0 disables the backoff.
    pub accept_backoff: Duration,
}

impl RuntimeTuning {
    pub fn from_config(t: &donut_config::TuningConfig) -> Self {
        Self {
            mux_idle: Duration::from_secs(t.mux_idle_secs),
            udp_idle: Duration::from_secs(t.udp_idle_secs),
            accept_backoff: Duration::from_millis(t.accept_backoff_ms),
        }
    }
}

impl Default for RuntimeTuning {
    fn default() -> Self {
        Self::from_config(&donut_config::TuningConfig::default())
    }
}

/// Which `xtls-rprx-vision` data-plane to speak for `flow=Extended`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VisionDialect {
    /// donut's own simpler padding (donut-client ↔ donut-server).
    #[default]
    Donut,
    /// Byte-faithful Xray Vision — interoperates with a real Xray client.
    Xray,
}

impl VisionDialect {
    /// Parse the config string (`"donut"` default / `"xray"`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "donut" | "" => Some(Self::Donut),
            "xray" => Some(Self::Xray),
            _ => None,
        }
    }
}

use crate::metrics::{Metrics, SessErr, SessionKind};
use crate::veil_server::VeilServer;
use crate::vision_xray_splice;

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
                if let Err(e) = handle_session(
                    session.stream,
                    auth,
                    VisionDialect::Donut,
                    router,
                    resolver,
                    metrics,
                )
                .await
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
                if let Err(e) = handle_session(
                    session.stream,
                    auth,
                    VisionDialect::Donut,
                    router,
                    resolver,
                    metrics,
                )
                .await
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
                if let Err(e) = handle_session(
                    session.stream,
                    auth,
                    VisionDialect::Donut,
                    router,
                    resolver,
                    metrics,
                )
                .await
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
    tuning: RuntimeTuning,
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
                    if let Err(e) = handle_session(
                        session.stream,
                        auth,
                        VisionDialect::Donut,
                        router,
                        resolver,
                        metrics,
                    )
                    .await
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
                    // Backoff on a persistent accept error (EMFILE/ENOBUFS)
                    // so the loop can't busy-spin at 100% CPU.
                    tokio::time::sleep(tuning.accept_backoff).await;
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
    tuning: RuntimeTuning,
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
                    // Backoff on a persistent accept error (EMFILE/ENOBUFS)
                    // so the loop can't busy-spin at 100% CPU.
                    tokio::time::sleep(tuning.accept_backoff).await;
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
                                if let Err(e) = handle_session(
                                    session.stream,
                                    auth,
                                    VisionDialect::Donut,
                                    router,
                                    resolver,
                                    metrics,
                                )
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
    vision_dialect: VisionDialect,
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
    let _ = upstream.set_nodelay(true);

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
            match vision_dialect {
                // Faithful Xray Vision needs raw-socket splice, so it runs on a
                // manually-driven TLS conn (handle_xray_vision_session) and is
                // routed there before reaching this opaque-stream path.
                VisionDialect::Xray => unreachable!(
                    "vision:xray is handled by handle_xray_vision_session before handle_session"
                ),
                // donut's own simpler padding (donut-client ↔ donut-server).
                VisionDialect::Donut => {
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

/// Faithful Xray-Vision session over a manually-driven outer-TLS connection
/// (`vision: "xray"`). Unlike [`handle_session`] (which copies through an
/// opaque TLS stream), this owns the rustls session so the Vision data phase
/// can splice to the raw TCP socket — exactly what a real Xray client does
/// after `CommandPaddingDirect`, bypassing the outer TLS to avoid double
/// encryption. See [`crate::vision_xray_splice`].
#[allow(clippy::too_many_arguments)] // wired from the daemon entry point
async fn handle_xray_vision_session(
    mut tunnel: vision_xray_splice::RecordTlsServer,
    decoy: Option<SocketAddr>,
    auth: Arc<UserAuth>,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
    tuning: RuntimeTuning,
) -> Result<(), ProxyError> {
    // Accumulate decrypted plaintext until the VLESS request header decodes.
    let mut buf = BytesMut::with_capacity(512);
    let (request, leftover) = loop {
        let pt = tunnel.read_record().await?;
        if pt.is_empty() {
            return Ok(()); // EOF before a full request
        }
        buf.extend_from_slice(&pt);
        // Triage: a first byte that isn't the VLESS version is a probe/browser
        // → self-steal the (decrypted) bytes to the decoy over the outer TLS.
        if buf[0] != VLESS_VERSION {
            return match decoy {
                Some(d) => {
                    metrics.forwarded();
                    let probe = buf.to_vec();
                    match TcpStream::connect(d).await {
                        Ok(up) => {
                            // decoy traffic — don't count it as tunnelled bytes
                            let _ =
                                vision_xray_splice::tls_plain_relay(tunnel, up, probe, None).await;
                        }
                        Err(e) => tracing::trace!(?e, %d, "raw xray decoy connect failed"),
                    }
                    Ok(())
                }
                None => Ok(()),
            };
        }
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

    if !auth.is_authorized(&request.user) {
        metrics.rejected_unauthorized();
        tracing::debug!(user = %request.user, "vless auth: unknown UUID — dropping session");
        return Ok(());
    }
    let user_uuid = *request.user.as_bytes();
    let flow = request.flow;
    let command = request.command;

    // Mux.Cool / XUDP: multiplexed sub-streams (UDP packet-addressing), no
    // single target in the header. Modern clients use this for UDP/QUIC.
    if matches!(command, Command::Mux) {
        let mut response_buf = BytesMut::with_capacity(8);
        Response::default().encode(&mut response_buf);
        tunnel.write_plaintext(&response_buf).await?;
        let _active = metrics.tunnel_started_kind(SessionKind::Mux);
        // flow=vision wraps the Mux stream in Vision padding (e.g. HAPP XUDP).
        let vision_uuid = matches!(flow, FlowKind::Extended).then_some(user_uuid);
        let result = crate::mux::mux_relay(
            tunnel,
            leftover.to_vec(),
            &metrics,
            vision_uuid,
            tuning.mux_idle,
        )
        .await;
        match &result {
            Ok(()) => metrics.session_ok(),
            Err(e) => metrics.session_error(SessErr::from_io(e)),
        }
        return result.map_err(ProxyError::from);
    }

    // TCP and UDP both carry a target; a missing target we don't serve.
    let target_endpoint = match (request.target, command) {
        (Some(t), Command::Tcp) | (Some(t), Command::Udp) => t,
        (target, cmd) => {
            metrics.session_error(SessErr::Unsupported);
            tracing::debug!(
                command = ?cmd,
                has_target = target.is_some(),
                "vless: unsupported command — dropping (only Tcp/Udp/Mux are served)"
            );
            return Err(ProxyError::UnsupportedCommand);
        }
    };
    if let "block" | "blackhole" = router.route(&target_endpoint) {
        metrics.blackholed();
        tracing::debug!(target = %target_endpoint, "routing: blackhole — dropping");
        return Ok(());
    }

    let target_addr = resolve(&resolver, &target_endpoint).await?;

    // VLESS response prefix — raw, through the outer TLS, before any payload.
    let mut response_buf = BytesMut::with_capacity(8);
    Response::default().encode(&mut response_buf);

    // UDP (QUIC etc.): length-prefixed datagrams to a single target — Vision
    // never applies to UDP, so no dial/splice, just a UDP-socket bridge.
    if matches!(command, Command::Udp) {
        tunnel.write_plaintext(&response_buf).await?;
        let _active = metrics.tunnel_started_kind(SessionKind::Udp);
        let result = vision_xray_splice::vision_udp_relay(
            tunnel,
            target_addr,
            leftover.to_vec(),
            &metrics,
            tuning.udp_idle,
        )
        .await;
        match &result {
            Ok(()) => metrics.session_ok(),
            Err(e) => metrics.session_error(SessErr::from_io(e)),
        }
        return result.map_err(ProxyError::from);
    }

    let dial_start = std::time::Instant::now();
    let upstream = match tokio::net::TcpStream::connect(target_addr).await {
        Ok(u) => {
            metrics.observe_dial(dial_start.elapsed());
            u
        }
        Err(e) => {
            metrics.session_error(SessErr::Dial);
            return Err(e.into());
        }
    };
    let _ = upstream.set_nodelay(true);
    tunnel.write_plaintext(&response_buf).await?;

    let _active = metrics.tunnel_started();
    let result = match flow {
        FlowKind::Extended => {
            vision_xray_splice::vision_server_splice(
                tunnel,
                upstream,
                leftover.to_vec(),
                user_uuid,
                &metrics,
            )
            .await
        }
        // A flow=none client never splices — relay plaintext through the outer TLS.
        FlowKind::None => {
            vision_xray_splice::tls_plain_relay(tunnel, upstream, leftover.to_vec(), Some(&metrics))
                .await
        }
    };
    match &result {
        Ok(()) => metrics.session_ok(),
        Err(e) => metrics.session_error(SessErr::from_io(e)),
    }
    result.map_err(ProxyError::from)
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
    vision_dialect: VisionDialect,
    auth: Arc<UserAuth>,
    router: Arc<Router>,
    resolver: Arc<Resolver>,
    metrics: Arc<Metrics>,
    tuning: RuntimeTuning,
) -> Result<SocketAddr, ProxyError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| ProxyError::Tls(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .map_err(|e| ProxyError::Tls(e.to_string()))?;
    // Offer h2 + http/1.1 like a real HTTPS site: matches what clients/browsers
    // expect and avoids NoApplicationProtocol handshake failures for peers
    // negotiating h2. (The decoy is http/1.1; an h2 probe to it is an accepted
    // edge case — the tunnel itself doesn't depend on the negotiated ALPN.)
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_config = Arc::new(tls);
    let acceptor = TlsAcceptor::from(tls_config.clone());

    let listener = TcpListener::bind(bind_addr).await?;
    let local = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(?e, "raw accept error");
                    // Resource-exhaustion errors (EMFILE/ENFILE: "too many
                    // open files", ENOBUFS) make accept() return immediately;
                    // without a pause we busy-loop at 100% CPU and flood the
                    // log. A short backoff lets the kernel reclaim the FD/
                    // buffer pressure and caps the warning rate.
                    tokio::time::sleep(tuning.accept_backoff).await;
                    continue;
                }
            };
            // Disable Nagle: Vision rides interactive, small TLS records, and
            // after the splice it's a raw relay — buffering hurts latency.
            let _ = tcp.set_nodelay(true);
            let acceptor = acceptor.clone();
            let tls_config = tls_config.clone();
            let auth = auth.clone();
            let router = router.clone();
            let resolver = resolver.clone();
            let metrics = metrics.clone();
            metrics.connection_accepted();
            tokio::spawn(async move {
                // Faithful Xray Vision needs to splice to the raw socket after
                // CommandPaddingDirect, so it drives rustls manually instead of
                // copying through an opaque TLS stream.
                if vision_dialect == VisionDialect::Xray {
                    let mut tunnel = match vision_xray_splice::RecordTlsServer::new(tcp, tls_config)
                    {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::trace!(?e, "raw: rustls server-conn init failed");
                            return;
                        }
                    };
                    if let Err(e) = tunnel.handshake().await {
                        let read = tunnel.bytes_read();
                        // read == 0: the peer reset/closed before sending a
                        // single byte — an ordinary port scan / health check
                        // hitting :443, not a failed tunnel. Don't pollute the
                        // session-error metric with it; count it as a probe.
                        // read > 0: it spoke some TLS then bailed (a picky
                        // probe, an old-TLS/ALPN-mismatch client, or — rarely —
                        // in-path tampering). That's a real handshake failure.
                        if read == 0 {
                            metrics.probe();
                        } else {
                            metrics.session_error(SessErr::Tls);
                        }
                        tracing::debug!(
                            %peer,
                            bytes_read = read,
                            error = %e,
                            error_kind = ?e.kind(),
                            "raw tls handshake failed (xray path)"
                        );
                        return;
                    }
                    if let Err(e) = handle_xray_vision_session(
                        tunnel, decoy, auth, router, resolver, metrics, tuning,
                    )
                    .await
                    {
                        tracing::debug!(%peer, ?e, "raw xray-vision session ended with error");
                    }
                    return;
                }
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(%peer, ?e, "raw tls handshake failed");
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
                    if let Err(e) =
                        handle_session(stream, auth, vision_dialect, router, resolver, metrics)
                            .await
                    {
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
