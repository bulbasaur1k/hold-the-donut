//! `stream-one` client dialer.
//!
//! Opens a single TCP connection, sends a long chunked POST whose
//! body carries the uplink, and reads the response body for the
//! downlink. Both directions run concurrently for the lifetime of
//! the request.

use std::net::SocketAddr;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::Request;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::io::ReaderStream;

use crate::config::ClientConfig;
use crate::error::CarrierError;
use crate::io_glue::{CarrierStream, PIPE_CAPACITY};
use crate::placement::Placement;
use crate::session::SessionId;

pub(super) async fn dial(
    target: SocketAddr,
    config: &ClientConfig,
    sid: SessionId,
) -> Result<CarrierStream, CarrierError> {
    let tcp = TcpStream::connect(target).await?;
    tcp.set_nodelay(true).ok();
    dial_over_io(tcp, config, sid).await
}

/// `stream-one` dial over an **already-established** byte stream (e.g. a
/// decrypted veiled-TLS stream). The transport-agnostic core of
/// [`dial`].
pub(super) async fn dial_over_io<IO>(
    io: IO,
    config: &ClientConfig,
    sid: SessionId,
) -> Result<CarrierStream, CarrierError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, conn) = http1::handshake::<_, BoxedRequestBody>(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::trace!(?e, "stream-one client connection ended");
        }
    });

    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

    // Build a streaming request body sourced from bridge_rd. Whatever
    // the user writes to user_side flows here.
    let upload_stream = ReaderStream::new(bridge_rd).map_ok(Frame::data);
    let upload_body: BoxedRequestBody = StreamBody::new(upload_stream).boxed();

    let req = build_request(config, sid, upload_body)?;

    // Do NOT block on the response here. The server's response (the
    // downlink) depends on the uplink the caller writes *after* we
    // return, so awaiting `send_request` would deadlock — most visibly
    // behind an HTTP reverse proxy that won't surface the response while
    // the request body is still open. Instead send the request and pump
    // the response on a background task, full-duplex like the QUIC
    // carrier; the caller detects failure when its first read (the
    // Response prefix) hits EOF.
    tokio::spawn(async move {
        let resp = match sender.send_request(req).await {
            Ok(r) => r,
            Err(e) => {
                tracing::trace!(?e, "stream-one client send_request failed");
                return;
            }
        };
        if !resp.status().is_success() {
            tracing::trace!(status = ?resp.status(), "stream-one client non-success response");
            return;
        }
        let mut body = resp.into_body();
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(data) = frame.into_data() {
                if bridge_wr.write_all(&data).await.is_err() {
                    break;
                }
            }
        }
        let _ = bridge_wr.shutdown().await;
    });

    Ok(user_side)
}

type BoxedRequestBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

fn build_request(
    config: &ClientConfig,
    sid: SessionId,
    body: BoxedRequestBody,
) -> Result<Request<BoxedRequestBody>, CarrierError> {
    let path = compose_path(config, sid);
    let mut builder = Request::builder()
        .method("POST")
        .uri(&path)
        .header(http::header::HOST, config.host.clone())
        .header(http::header::CONTENT_TYPE, "application/grpc");

    match config.session_placement {
        Placement::Header => {
            builder = builder.header(&config.session_header, sid.to_hex());
        }
        Placement::Cookie => {
            builder = builder.header(
                http::header::COOKIE,
                format!("{}={}", config.session_key, sid.to_hex()),
            );
        }
        Placement::Path | Placement::Query => {
            // Already on the URI line.
        }
    }

    builder.body(body).map_err(CarrierError::Http)
}

fn compose_path(config: &ClientConfig, sid: SessionId) -> String {
    match config.session_placement {
        Placement::Path => {
            let mut p = config.path_prefix.clone();
            if !p.ends_with('/') {
                p.push('/');
            }
            p.push_str(&sid.to_hex());
            p
        }
        Placement::Query => {
            let mut p = config.path_prefix.clone();
            if !p.ends_with('/') {
                p.push('/');
            }
            p.push('?');
            p.push_str(&config.session_key);
            p.push('=');
            p.push_str(&sid.to_hex());
            p
        }
        Placement::Header | Placement::Cookie => config.path_prefix.clone(),
    }
}
