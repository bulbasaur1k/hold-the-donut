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
                // Backoff on a persistent accept error (EMFILE/ENOBUFS) so the
                // loop can't busy-spin at 100% CPU and flood the log.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
    let mut builder = auto::Builder::new(TokioExecutor::new());
    // H2 keepalive: PING the client every 30s so a stateful middlebox / NAT
    // (and TSPU's flow tracking) doesn't reap an xHTTP connection whose
    // downlink GET happens to sit idle, and a dead peer is detected within
    // ~20s instead of hanging. Applies to the h2 path (xhttp/stream-up);
    // the h1 veil/stream-one path ignores it.
    //
    // `.timer()` is MANDATORY here: hyper's keep-alive arms a Sleep on every
    // h2 connection and panics ("You must supply a timer") without one — the
    // executor alone is not enough.
    builder
        .http2()
        .timer(hyper_util::rt::TokioTimer::new())
        .keep_alive_interval(std::time::Duration::from_secs(30))
        .keep_alive_timeout(std::time::Duration::from_secs(20));
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

/// Random alphanumeric `X-Padding` value (Xray default range 100–1000
/// bytes, fresh per response). Without it a DPI box can fingerprint the
/// server by the fixed length of its response header block, so xHTTP
/// mandates random padding on every reply.
pub(crate) fn x_padding() -> String {
    use rand::distributions::{Alphanumeric, DistString};
    use rand::Rng;
    let len = rand::thread_rng().gen_range(100..=1000);
    Alphanumeric.sample_string(&mut rand::thread_rng(), len)
}

pub(crate) fn empty_response(code: StatusCode) -> Response<ResponseBody> {
    use http_body_util::{BodyExt, Empty};
    let body = Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(code)
        .header("X-Padding", x_padding())
        .body(body)
        .expect("static empty body")
}

/// Build the **uplink-POST** keepalive response for `stream-up`.
///
/// In Xray's xHTTP the uplink POST's *response* body is otherwise unused
/// (downlink data rides the separate GET), so the server repurposes it as
/// a keepalive channel: every `secs` (random in range) it writes a chunk
/// of `X` padding. That keeps a middlebox from reaping the long-lived POST
/// (and thus the H2 connection) as idle, without touching the downlink
/// data stream. The client reads and discards this body. The stream is
/// unbounded — hyper drops it (cancelling the timer) when the request /
/// connection ends, mirroring Xray's `request.Context().Done()` exit.
pub(crate) fn uplink_keepalive_response(secs: (u32, u32)) -> Response<ResponseBody> {
    use futures_util::stream;
    use http_body_util::{BodyExt, StreamBody};
    use hyper::body::Frame;
    use rand::Rng;

    let lo = secs.0.max(1);
    let hi = secs.1.max(lo);
    let body_stream = stream::unfold((), move |()| async move {
        let wait = rand::thread_rng().gen_range(lo..=hi) as u64;
        tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
        // Xray writes `bytes.Repeat([]byte{'X'}, rand(xPaddingBytes))`.
        let len = rand::thread_rng().gen_range(100..=1000);
        let pad = Bytes::from(vec![b'X'; len]);
        Some((Ok::<Frame<Bytes>, std::io::Error>(Frame::data(pad)), ()))
    });
    let body = StreamBody::new(body_stream).boxed();
    Response::builder()
        .status(StatusCode::OK)
        .header("X-Accel-Buffering", "no")
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("X-Padding", x_padding())
        .body(body)
        .expect("static keepalive builder")
}

/// Build the streaming **downlink** response shared by every mode's
/// server→client direction, carrying the Xray-faithful header set:
///
/// * `Content-Type: text/event-stream` — masks the long-lived stream as
///   Server-Sent Events so middleboxes treat it as a push channel and
///   don't buffer it. The body is raw tunnel bytes, *not* SSE event
///   lines — this is masking only.
/// * `X-Accel-Buffering: no` + `Cache-Control: no-store` — stop an
///   nginx/apache reverse proxy from buffering or caching the body.
/// * `X-Padding` — random per-response padding (see [`x_padding`]).
/// * permissive CORS so a Browser-Dialer xHTTP client isn't blocked.
pub(crate) fn downlink_response(body: ResponseBody) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/event-stream")
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("X-Accel-Buffering", "no")
        .header("X-Padding", x_padding())
        .header(http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(http::header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST")
        .body(body)
        .expect("static downlink builder")
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
