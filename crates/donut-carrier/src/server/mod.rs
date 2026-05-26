//! Server-side carrier implementation.
//!
//! The public entry point is [`Server`]: a `tokio::net::TcpListener`
//! adapter that serves the configured carrier mode and yields one
//! [`Session`] per incoming exchange.

mod packet_up;
mod session_extract;
mod stream_one;
mod stream_up;

use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::combinators::BoxBody;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::config::ServerConfig;
use crate::error::CarrierError;
use crate::mode::Mode;
use crate::session::SessionId;
use crate::CarrierStream;

/// One accepted carrier session: a duplex byte stream + the parsed
/// session id and remote-peer address.
pub struct Session {
    pub stream: CarrierStream,
    pub session_id: SessionId,
    pub remote: SocketAddr,
}

/// Carrier server bound to a `TcpListener`. The accept loop runs in
/// the background; consume sessions through [`Server::accept`].
pub struct Server {
    rx: mpsc::Receiver<Session>,
}

#[derive(Clone)]
enum SharedDispatcher {
    StreamOne,
    StreamUp(stream_up::Dispatcher),
    PacketUp(packet_up::Dispatcher),
}

impl Server {
    /// Bind a new carrier server to `listener` with `config`. Returns
    /// the [`Server`] handle and spawns the accept loop on the current
    /// tokio runtime.
    pub fn serve(listener: TcpListener, config: ServerConfig) -> Self {
        let (tx, rx) = mpsc::channel::<Session>(64);
        let cfg = Arc::new(config);
        let dispatcher = build_dispatcher(&cfg, &tx);
        tokio::spawn(accept_loop(listener, cfg, tx, dispatcher));
        Self { rx }
    }

    pub async fn accept(&mut self) -> Option<Session> {
        self.rx.recv().await
    }
}

/// Serve the carrier protocol over an **already-established** byte
/// stream (e.g. a decrypted veiled-TLS stream from the server's TLS
/// termination). Sessions opened on the connection are delivered
/// through the returned receiver; the hyper connection is driven on a
/// background task. This is the transport-agnostic counterpart to
/// [`Server::serve`], which owns its own `TcpListener`.
pub fn serve_connection<IO>(
    io: IO,
    config: ServerConfig,
    remote: SocketAddr,
) -> mpsc::Receiver<Session>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (tx, rx) = mpsc::channel::<Session>(64);
    let cfg = Arc::new(config);
    let dispatcher = build_dispatcher(&cfg, &tx);
    tokio::spawn(drive_connection(io, cfg, tx, dispatcher, remote));
    rx
}

/// Drives many incoming carrier connections through a **single shared
/// dispatcher**. The multi-request modes (`stream-up`, `packet-up`) pair
/// requests by session id across *different* connections (e.g. the
/// uplink POST and downlink GET arrive on separate TLS connections to a
/// cert-terminating donut-server); a per-connection dispatcher — as
/// [`serve_connection`] builds — cannot pair them. Build one acceptor,
/// then call [`ConnectionAcceptor::drive`] for every accepted connection;
/// consume the paired sessions from the returned receiver.
#[derive(Clone)]
pub struct ConnectionAcceptor {
    cfg: Arc<ServerConfig>,
    tx: mpsc::Sender<Session>,
    dispatcher: SharedDispatcher,
}

impl ConnectionAcceptor {
    /// Build an acceptor for `config` and the session receiver that all
    /// driven connections feed.
    pub fn new(config: ServerConfig) -> (Self, mpsc::Receiver<Session>) {
        let (tx, rx) = mpsc::channel::<Session>(64);
        let cfg = Arc::new(config);
        let dispatcher = build_dispatcher(&cfg, &tx);
        (
            Self {
                cfg,
                tx,
                dispatcher,
            },
            rx,
        )
    }

    /// Drive a freshly accepted connection's byte stream. The hyper
    /// connection runs on a background task; its requests feed the shared
    /// dispatcher, so sessions surface on the acceptor's receiver.
    pub fn drive<IO>(&self, io: IO, remote: SocketAddr)
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        tokio::spawn(drive_connection(
            io,
            self.cfg.clone(),
            self.tx.clone(),
            self.dispatcher.clone(),
            remote,
        ));
    }
}

fn build_dispatcher(cfg: &Arc<ServerConfig>, tx: &mpsc::Sender<Session>) -> SharedDispatcher {
    match cfg.mode {
        Mode::StreamOne => SharedDispatcher::StreamOne,
        Mode::StreamUp => {
            SharedDispatcher::StreamUp(stream_up::Dispatcher::new(cfg.clone(), tx.clone()))
        }
        Mode::PacketUp => {
            SharedDispatcher::PacketUp(packet_up::Dispatcher::new(cfg.clone(), tx.clone()))
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    tx: mpsc::Sender<Session>,
    dispatcher: SharedDispatcher,
) {
    loop {
        let (sock, remote) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(?e, "carrier server accept error");
                continue;
            }
        };
        tokio::spawn(drive_connection(
            sock,
            config.clone(),
            tx.clone(),
            dispatcher.clone(),
            remote,
        ));
    }
}

/// Drive the carrier protocol over a single connection's byte stream.
/// Shared by the `TcpListener` accept loop and [`serve_connection`].
async fn drive_connection<IO>(
    io: IO,
    config: Arc<ServerConfig>,
    tx: mpsc::Sender<Session>,
    dispatcher: SharedDispatcher,
    remote: SocketAddr,
) where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // Auto-detect HTTP/1.1 vs HTTP/2 (h2c). The veil path speaks h1 over
    // the decrypted TLS stream; a reverse proxy (Caddy) in front of the
    // carrier backend speaks h2c, which — unlike Go's h1 reverse proxy —
    // streams the request and response bodies concurrently (full duplex),
    // as `stream-one` requires.
    let io = TokioIo::new(io);
    let builder = auto::Builder::new(TokioExecutor::new());
    let result = match dispatcher {
        SharedDispatcher::StreamOne => {
            let svc = service_fn(move |req: Request<Incoming>| {
                let config = config.clone();
                let tx = tx.clone();
                async move { stream_one::handle(req, config, tx, remote).await }
            });
            builder.serve_connection(io, svc).await
        }
        SharedDispatcher::StreamUp(d) => {
            let svc = service_fn(move |req: Request<Incoming>| {
                let d = d.clone();
                async move { d.handle(req, remote).await }
            });
            builder.serve_connection(io, svc).await
        }
        SharedDispatcher::PacketUp(d) => {
            let svc = service_fn(move |req: Request<Incoming>| {
                let d = d.clone();
                async move { d.handle(req, remote).await }
            });
            builder.serve_connection(io, svc).await
        }
    };
    if let Err(e) = result {
        tracing::trace!(?e, "carrier server: connection ended");
    }
}

/// Convenience alias used by per-mode handlers.
pub(crate) type ResponseBody = BoxBody<Bytes, std::io::Error>;
pub(crate) type Result<T> = std::result::Result<T, CarrierError>;
pub(crate) use http::StatusCode;
pub(crate) fn empty_response(code: StatusCode) -> Response<ResponseBody> {
    use http_body_util::{BodyExt, Empty};
    let body = Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(code)
        .body(body)
        .expect("static empty body")
}

/// Reverse-proxy a non-tunnel request to the self-steal `decoy` backend
/// (e.g. local filebrowser) over HTTP/1.1 and return its response, so the
/// carrier endpoint looks like an ordinary site to a probe.
pub(crate) async fn proxy_to_decoy(
    req: Request<Incoming>,
    decoy: std::net::SocketAddr,
) -> Result<Response<ResponseBody>> {
    use http_body_util::BodyExt;
    let tcp = tokio::net::TcpStream::connect(decoy).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, Incoming>(TokioIo::new(tcp)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let (parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    // HTTP/2 callers carry the authority in `:authority` (the URI), not a
    // `host` header; HTTP/1.1 callers carry it in `host`. The HTTP/1.1
    // upstream requires a Host header, so derive it from whichever is set.
    let host = parts
        .uri
        .authority()
        .map(|a| a.as_str().to_string())
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "localhost".to_string());
    let mut builder = Request::builder()
        .method(parts.method)
        .uri(path)
        .header(http::header::HOST, host);
    for (k, v) in parts.headers.iter() {
        if k == http::header::HOST
            || k == http::header::CONNECTION
            || k == http::header::TRANSFER_ENCODING
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    let fwd = builder.body(body)?;
    let resp = sender.send_request(fwd).await?;
    let (rparts, rbody) = resp.into_parts();
    let boxed = rbody.map_err(std::io::Error::other).boxed();
    Ok(Response::from_parts(rparts, boxed))
}
