//! `packet-up` server handler.
//!
//! Many short sequenced POSTs (uplink) + one long GET (downlink). The
//! dispatcher buffers out-of-order POSTs up to
//! `sc_max_buffered_posts` and releases their bodies in `seq` order
//! to the per-session uplink stream. The single GET drives the
//! downlink.

use std::collections::{BTreeMap, HashMap};
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

/// Per-session state. The state is created on whichever request (POST
/// or GET) arrives first; the partial pieces are filled in by the
/// other request.
struct SessionState {
    buffered: BTreeMap<u64, Bytes>,
    next_seq: u64,
    /// Writes here surface as bytes the user reads from `user_side`.
    upload_wr: WriteHalf<CarrierStream>,
    /// Bytes the user writes to `user_side` arrive here. Taken by
    /// the downlink handler to feed the GET response body.
    downlink_rd: Option<ReadHalf<CarrierStream>>,
    /// Session waiting on the accept channel. Sent once both POST
    /// and GET have arrived.
    accept_pending: Option<super::Session>,
    /// Set true once the session has been emitted via accept channel.
    accepted: bool,
}

#[derive(Clone)]
pub(super) struct Dispatcher {
    config: Arc<ServerConfig>,
    accept: mpsc::Sender<super::Session>,
    sessions: Arc<Mutex<HashMap<SessionId, SessionState>>>,
}

impl Dispatcher {
    pub(super) fn new(config: Arc<ServerConfig>, accept: mpsc::Sender<super::Session>) -> Self {
        Self {
            config,
            accept,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(super) async fn handle(
        &self,
        req: Request<Incoming>,
        remote: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        if !matches!(self.config.mode, Mode::PacketUp) {
            return Ok(empty_response(StatusCode::NOT_FOUND));
        }
        let (sid, _tail) = match session_extract::session_id(&req, &self.config) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(?e, "packet-up: session extraction failed");
                return Ok(empty_response(StatusCode::NOT_FOUND));
            }
        };

        if req.method() == Method::GET {
            return self.handle_downlink(sid, remote).await;
        }

        let seq = match session_extract::sequence(&req, &self.config) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(?e, "packet-up: sequence extraction failed");
                return Ok(empty_response(StatusCode::BAD_REQUEST));
            }
        };

        self.handle_uplink(req, sid, seq, remote).await
    }

    async fn handle_uplink(
        &self,
        req: Request<Incoming>,
        sid: SessionId,
        seq: u64,
        remote: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        let chunk = collect_body(req, self.config.max_post_bytes).await?;
        let (writes_to_drive, accept_to_send) = {
            let mut sessions = self.sessions.lock();
            let entry = sessions
                .entry(sid)
                .or_insert_with(|| fresh_state(sid, remote));

            if seq < entry.next_seq {
                // Late/duplicate.
                return Ok(empty_response(StatusCode::OK));
            }
            if seq > entry.next_seq && entry.buffered.len() >= self.config.max_buffered_posts {
                return Ok(empty_response(StatusCode::TOO_MANY_REQUESTS));
            }
            entry.buffered.insert(seq, chunk);

            // Collect ordered prefix to flush after we drop the lock.
            let mut to_write: Vec<Bytes> = Vec::new();
            while let Some(bytes) = entry.buffered.remove(&entry.next_seq) {
                to_write.push(bytes);
                entry.next_seq += 1;
            }

            // Hand off the writer for the duration of the write to keep
            // the lock un-held; we'll re-attach via a different mechanism
            // — see below.
            let writer_ref = std::mem::replace(
                &mut entry.upload_wr,
                tokio::io::split(tokio::io::duplex(1).1).1,
            );
            let accept = if !entry.accepted && entry.downlink_rd.is_none() {
                // GET hasn't arrived yet; don't accept.
                None
            } else if !entry.accepted {
                entry.accepted = true;
                entry.accept_pending.take()
            } else {
                None
            };

            (Some((writer_ref, to_write)), accept)
        };

        if let Some((mut writer, chunks)) = writes_to_drive {
            for c in chunks {
                if writer.write_all(&c).await.is_err() {
                    break;
                }
            }
            // Re-attach the writer.
            let mut sessions = self.sessions.lock();
            if let Some(entry) = sessions.get_mut(&sid) {
                entry.upload_wr = writer;
            }
        }

        if let Some(session) = accept_to_send {
            if self.accept.send(session).await.is_err() {
                tracing::warn!("packet-up: accept channel closed");
            }
        }

        Ok(empty_response(StatusCode::OK))
    }

    async fn handle_downlink(
        &self,
        sid: SessionId,
        remote: SocketAddr,
    ) -> Result<Response<ResponseBody>> {
        let (downlink_rd_taken, accept_to_send) = {
            let mut sessions = self.sessions.lock();
            let entry = sessions
                .entry(sid)
                .or_insert_with(|| fresh_state(sid, remote));
            let rd = entry.downlink_rd.take();
            let accept = if !entry.accepted {
                entry.accepted = true;
                entry.accept_pending.take()
            } else {
                None
            };
            (rd, accept)
        };

        let Some(downlink_rd) = downlink_rd_taken else {
            tracing::warn!(?sid, "packet-up: duplicate downlink GET");
            return Ok(empty_response(StatusCode::CONFLICT));
        };

        let response_stream = ReaderStream::new(downlink_rd).map_ok(Frame::data);
        let body = StreamBody::new(response_stream).boxed();

        if let Some(session) = accept_to_send {
            if self.accept.send(session).await.is_err() {
                tracing::warn!("packet-up: accept channel closed");
            }
        }

        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .expect("static builder"))
    }
}

fn fresh_state(sid: SessionId, remote: SocketAddr) -> SessionState {
    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (downlink_rd, upload_wr) = tokio::io::split(bridge_side);
    SessionState {
        buffered: BTreeMap::new(),
        next_seq: 0,
        upload_wr,
        downlink_rd: Some(downlink_rd),
        accept_pending: Some(super::Session {
            stream: user_side,
            session_id: sid,
            remote,
        }),
        accepted: false,
    }
}

async fn collect_body(req: Request<Incoming>, max: usize) -> Result<Bytes> {
    let mut body = req.into_body();
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Ok(data) = frame.into_data() {
            if out.len() + data.len() > max {
                return Err(crate::error::CarrierError::UploadChunkTooLarge);
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(out))
}
