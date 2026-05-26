//! `stream-up` client dialer.
//!
//! Opens two HTTP requests on separate TCP connections, both bound to
//! the same session id:
//! * a long chunked POST that streams the uplink;
//! * a long GET whose response body streams the downlink.
//! The two halves are bridged into a single bidirectional
//! [`CarrierStream`] returned to the caller.

use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http::Request;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Frame;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;

use crate::config::ClientConfig;
use crate::connect::Connector;
use crate::error::CarrierError;
use crate::io_glue::{CarrierStream, PIPE_CAPACITY};
use crate::placement::Placement;
use crate::session::SessionId;

type BoxedBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

pub(super) async fn dial(
    connector: Arc<dyn Connector>,
    config: &ClientConfig,
    sid: SessionId,
) -> Result<CarrierStream, CarrierError> {
    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

    // Uplink — a single chunked POST whose body is sourced from the
    // user's writes (i.e. from `bridge_rd`), on its own connection.
    let upload_path = compose_path(config, sid, false);
    let upload_body: BoxedBody =
        StreamBody::new(ReaderStream::new(bridge_rd).map_ok(Frame::data)).boxed();
    let upload_req = build_request("POST", &upload_path, config, sid, upload_body)?;

    let upload_io = connector.connect().await?;
    let (mut upload_sender, upload_conn) =
        http1::handshake::<_, BoxedBody>(TokioIo::new(upload_io)).await?;
    tokio::spawn(async move {
        if let Err(e) = upload_conn.await {
            tracing::trace!(?e, "stream-up uplink connection ended");
        }
    });
    // Move sender into a task that lives until the uplink body stream
    // closes — otherwise dropping `upload_sender` here would tear down
    // the in-flight POST.
    tokio::spawn(async move {
        match upload_sender.send_request(upload_req).await {
            Ok(resp) => {
                let _ = resp.into_body().collect().await;
            }
            Err(e) => tracing::trace!(?e, "stream-up uplink request errored"),
        }
    });

    // Downlink — a separate GET on a separate TCP connection.
    let download_path = compose_path(config, sid, true);
    let download_req = build_request(
        "GET",
        &download_path,
        config,
        sid,
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed(),
    )?;

    let download_io = connector.connect().await?;
    let (mut download_sender, download_conn) =
        http1::handshake::<_, BoxedBody>(TokioIo::new(download_io)).await?;
    tokio::spawn(async move {
        if let Err(e) = download_conn.await {
            tracing::trace!(?e, "stream-up downlink connection ended");
        }
    });
    let download_resp = download_sender.send_request(download_req).await?;
    if !download_resp.status().is_success() {
        return Err(CarrierError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("downlink GET returned {}", download_resp.status()),
        )));
    }

    // Pump the GET response body into bridge_wr (so user_side reads).
    tokio::spawn(async move {
        let mut body = download_resp.into_body();
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

fn build_request(
    method: &str,
    path: &str,
    config: &ClientConfig,
    sid: SessionId,
    body: BoxedBody,
) -> Result<Request<BoxedBody>, CarrierError> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(http::header::HOST, config.host.clone());

    if matches!(method, "POST") {
        builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
    }

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
        Placement::Path | Placement::Query => {}
    }

    builder.body(body).map_err(CarrierError::Http)
}

fn compose_path(config: &ClientConfig, sid: SessionId, _downlink: bool) -> String {
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
