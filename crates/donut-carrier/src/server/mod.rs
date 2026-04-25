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
        let dispatcher = match cfg.mode {
            Mode::StreamOne => SharedDispatcher::StreamOne,
            Mode::StreamUp => {
                SharedDispatcher::StreamUp(stream_up::Dispatcher::new(cfg.clone(), tx.clone()))
            }
            Mode::PacketUp => {
                SharedDispatcher::PacketUp(packet_up::Dispatcher::new(cfg.clone(), tx.clone()))
            }
        };
        tokio::spawn(accept_loop(listener, cfg, tx, dispatcher));
        Self { rx }
    }

    pub async fn accept(&mut self) -> Option<Session> {
        self.rx.recv().await
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

        let config = config.clone();
        let tx = tx.clone();
        let dispatcher = dispatcher.clone();
        tokio::spawn(async move {
            match dispatcher {
                SharedDispatcher::StreamOne => {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let config = config.clone();
                        let tx = tx.clone();
                        async move { stream_one::handle(req, config, tx, remote).await }
                    });
                    if let Err(e) = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(TokioIo::new(sock), svc)
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
                        .serve_connection(TokioIo::new(sock), svc)
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
                        .serve_connection(TokioIo::new(sock), svc)
                        .await
                    {
                        tracing::trace!(?e, "carrier server (packet-up): connection ended");
                    }
                }
            }
        });
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
