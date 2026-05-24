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
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
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
    match dispatcher {
        SharedDispatcher::StreamOne => {
            let svc = service_fn(move |req: Request<Incoming>| {
                let config = config.clone();
                let tx = tx.clone();
                async move { stream_one::handle(req, config, tx, remote).await }
            });
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(TokioIo::new(io), svc)
                .await
            {
                tracing::trace!(?e, "carrier server: connection ended");
            }
        }
        SharedDispatcher::StreamUp(d) => {
            let svc = service_fn(move |req: Request<Incoming>| {
                let d = d.clone();
                async move { d.handle(req, remote).await }
            });
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(TokioIo::new(io), svc)
                .await
            {
                tracing::trace!(?e, "carrier server (stream-up): connection ended");
            }
        }
        SharedDispatcher::PacketUp(d) => {
            let svc = service_fn(move |req: Request<Incoming>| {
                let d = d.clone();
                async move { d.handle(req, remote).await }
            });
            if let Err(e) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(TokioIo::new(io), svc)
                .await
            {
                tracing::trace!(?e, "carrier server (packet-up): connection ended");
            }
        }
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
