//! `stream-up` server handler.
//!
//! Upstream framing splits the exchange across two HTTP requests
//! sharing a session id:
//! * `POST /<prefix>/<sid>` — long chunked uplink body.
//! * `GET  /<prefix>/<sid>` — long chunked downlink body.
//!
//! The dispatcher pairs them through a per-session map and yields a
//! single [`Session`](super::Session) on the accept channel as soon
//! as both sides arrive.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Method, Request, Response};
use parking_lot::Mutex;
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::io::ReaderStream;

use super::session_extract;
use super::{empty_response, ResponseBody, Result, StatusCode};
use crate::config::ServerConfig;
use crate::io_glue::{CarrierStream, PIPE_CAPACITY};
use crate::session::SessionId;
use crate::Mode;

/// Half a session, parked until its counterpart arrives. Each session
/// has exactly two halves: an uplink POST and a downlink GET.
enum Half {
    /// POST landed first; we hold its read-side (downlink-from-server
    /// write target) waiting for the matching GET.
    UplinkPosted {
        bridge_rd: ReadHalf<CarrierStream>,
        accept_pending: super::Session,
    },
    /// GET landed first; we hold its write-side (where to push the
    /// uplink body bytes) waiting for the POST.
    DownlinkRequested { bridge_wr: WriteHalf<CarrierStream> },
}

#[derive(Clone)]
pub(super) struct Dispatcher {
    config: Arc<ServerConfig>,
    accept: mpsc::Sender<super::Session>,
    table: Arc<Mutex<HashMap<SessionId, Half>>>,
}

impl Dispatcher {
    pub(super) fn new(config: Arc<ServerConfig>, accept: mpsc::Sender<super::Session>) -> Self {
        Self {
            config,
            accept,
            table: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(super) async fn handle(
        &self,
        req: Request<Incoming>,
        remote: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        if !matches!(self.config.mode, Mode::StreamUp) {
            return Ok(empty_response(StatusCode::NOT_FOUND));
        }
        let (sid, _tail) = match session_extract::session_id(&req, &self.config) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(?e, "stream-up: session extraction failed");
                return Ok(empty_response(StatusCode::NOT_FOUND));
            }
        };

        if req.method() == Method::GET {
            self.handle_downlink(sid, remote).await
        } else {
            self.handle_uplink(req, sid, remote).await
        }
    }

    async fn handle_uplink(
        &self,
        req: Request<Incoming>,
        sid: SessionId,
        remote: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
        let (bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

        // Pump the uplink body chunks into bridge_wr (so user_side reads).
        tokio::spawn(async move {
            let mut body = req.into_body();
            while let Some(Ok(frame)) = body.frame().await {
                if let Ok(data) = frame.into_data() {
                    if bridge_wr.write_all(&data).await.is_err() {
                        break;
                    }
                }
            }
            let _ = bridge_wr.shutdown().await;
        });

        let session = super::Session {
            stream: user_side,
            session_id: sid,
            remote,
        };

        enum Action {
            Pair(
                tokio::io::ReadHalf<CarrierStream>,
                tokio::io::WriteHalf<CarrierStream>,
                super::Session,
            ),
            Park,
            Conflict,
        }
        let action = {
            let mut table = self.table.lock();
            match table.remove(&sid) {
                Some(Half::DownlinkRequested {
                    bridge_wr: downlink_wr,
                }) => Action::Pair(bridge_rd, downlink_wr, session),
                Some(prev @ Half::UplinkPosted { .. }) => {
                    table.insert(sid, prev);
                    Action::Conflict
                }
                None => {
                    table.insert(
                        sid,
                        Half::UplinkPosted {
                            bridge_rd,
                            accept_pending: session,
                        },
                    );
                    Action::Park
                }
            }
        };
        match action {
            Action::Pair(rd, wr, session) => {
                spawn_downlink_pump(rd, wr);
                if self.accept.send(session).await.is_err() {
                    tracing::warn!("stream-up: accept channel closed");
                }
                Ok(empty_response(StatusCode::OK))
            }
            Action::Park => Ok(empty_response(StatusCode::OK)),
            Action::Conflict => {
                tracing::warn!(?sid, "duplicate stream-up uplink");
                Ok(empty_response(StatusCode::CONFLICT))
            }
        }
    }

    async fn handle_downlink(
        &self,
        sid: SessionId,
        _remote: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        // Build a duplex pair: write_side is what we feed downlink bytes
        // into, read_side becomes the response body source.
        let (write_side, read_side) = tokio::io::duplex(PIPE_CAPACITY);
        let downlink_wr = tokio::io::split(write_side).1;
        let response_stream = ReaderStream::new(read_side).map_ok(Frame::data);
        let body = StreamBody::new(response_stream).boxed();

        enum DAction {
            Pair(
                tokio::io::ReadHalf<CarrierStream>,
                tokio::io::WriteHalf<CarrierStream>,
                super::Session,
            ),
            Parked,
            Conflict(tokio::io::WriteHalf<CarrierStream>),
        }
        let action = {
            let mut table = self.table.lock();
            match table.remove(&sid) {
                Some(Half::UplinkPosted {
                    bridge_rd,
                    accept_pending,
                }) => DAction::Pair(bridge_rd, downlink_wr, accept_pending),
                Some(prev @ Half::DownlinkRequested { .. }) => {
                    table.insert(sid, prev);
                    DAction::Conflict(downlink_wr)
                }
                None => {
                    table.insert(
                        sid,
                        Half::DownlinkRequested {
                            bridge_wr: downlink_wr,
                        },
                    );
                    DAction::Parked
                }
            }
        };
        match action {
            DAction::Pair(rd, wr, accept_pending) => {
                spawn_downlink_pump(rd, wr);
                if self.accept.send(accept_pending).await.is_err() {
                    tracing::warn!("stream-up: accept channel closed");
                }
            }
            DAction::Parked => {}
            DAction::Conflict(_dropped) => {
                tracing::warn!(?sid, "duplicate stream-up downlink");
                return Ok(empty_response(StatusCode::CONFLICT));
            }
        }

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .expect("static builder"))
    }
}

fn spawn_downlink_pump(
    mut bridge_rd: ReadHalf<CarrierStream>,
    mut downlink_wr: WriteHalf<CarrierStream>,
) {
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut bridge_rd, &mut downlink_wr).await;
        let _ = downlink_wr.shutdown().await;
    });
}

// Silence the unused-imports warning when a stream-up dispatcher
// instance is constructed but never paired. Bytes is referenced
// transitively through StreamBody.
#[allow(dead_code)]
fn _bytes_anchor(_: Bytes) {}
