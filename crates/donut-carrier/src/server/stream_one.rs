//! `stream-one` server handler.
//!
//! One HTTP request → one bidirectional stream:
//! * the request body carries the **uplink** (client → server);
//! * the response body carries the **downlink** (server → client);
//! * both directions stream concurrently for the lifetime of the
//!   exchange.
//!
//! The handler hands a [`CarrierStream`] to the accept channel and
//! returns a streaming `Response` whose body is fed from the same
//! duplex stream. Any of: `POST`, `PUT`, `GET` is accepted as the
//! request method (we do not enforce upstream's "POST-only" since
//! some intermediaries rewrite verbs).

use std::sync::Arc;

use futures_util::TryStreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_util::io::ReaderStream;

use super::session_extract;
use super::{empty_response, ResponseBody, Result, StatusCode};
use crate::config::ServerConfig;
use crate::io_glue::PIPE_CAPACITY;
use crate::session::SessionId;
use crate::Mode;
use std::net::SocketAddr;

pub(super) async fn handle(
    req: Request<Incoming>,
    config: Arc<ServerConfig>,
    accept: mpsc::Sender<super::Session>,
    remote: SocketAddr,
) -> Result<Response<ResponseBody>> {
    if !matches!(config.mode, Mode::StreamOne) {
        return Ok(empty_response(StatusCode::NOT_FOUND));
    }
    let (sid, _tail) = match session_extract::session_id(&req, &config) {
        Ok(v) => v,
        Err(e) => {
            // Not a valid tunnel request (wrong path / bad session). If a
            // self-steal decoy is configured, reverse-proxy there so the
            // endpoint looks like an ordinary site; otherwise 404.
            if let Some(decoy) = config.decoy {
                tracing::trace!(?e, %decoy, "stream-one: non-tunnel request → decoy");
                return super::proxy_to_decoy(req, decoy).await;
            }
            tracing::debug!(?e, "stream-one: session extraction failed");
            return Ok(empty_response(StatusCode::NOT_FOUND));
        }
    };

    Ok(spawn_session(req, sid, accept, remote))
}

fn spawn_session(
    req: Request<Incoming>,
    sid: SessionId,
    accept: mpsc::Sender<super::Session>,
    remote: SocketAddr,
) -> Response<ResponseBody> {
    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

    // Forward incoming HTTP body chunks → bridge_wr (so user_side reads).
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

    // Build a streaming response body driven by bridge_rd.
    let response_stream = ReaderStream::new(bridge_rd).map_ok(Frame::data);
    let response_body = StreamBody::new(response_stream).boxed();

    // Hand the user-facing duplex stream to the accept channel.
    let session = super::Session {
        stream: user_side,
        session_id: sid,
        remote,
    };
    if accept.try_send(session).is_err() {
        tracing::warn!("stream-one: accept channel full or closed");
    }

    super::downlink_response(response_body)
}
