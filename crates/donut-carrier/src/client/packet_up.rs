//! `packet-up` client dialer.
//!
//! Many short sequenced POSTs (uplink) + one long GET (downlink). The
//! client keeps a single TCP connection open for the GET, and opens
//! fresh TCP connections for each chunked POST so middleboxes that
//! limit upload duration aren't tripped.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::ClientConfig;
use crate::error::CarrierError;
use crate::io_glue::{CarrierStream, PIPE_CAPACITY};
use crate::placement::Placement;
use crate::session::SessionId;

type BoxedBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

pub(super) async fn dial(
    target: SocketAddr,
    config: &ClientConfig,
    sid: SessionId,
) -> Result<CarrierStream, CarrierError> {
    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (mut bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

    // Uplink: spawn a task that reads from bridge_rd, packages chunks
    // into sequenced POSTs, and ships them off.
    let cfg = Arc::new(config.clone());
    let cfg_uplink = cfg.clone();
    tokio::spawn(async move {
        let max_chunk = cfg_uplink
            .max_post_bytes
            .clamp(4096, PIPE_CAPACITY.max(4096));
        let mut buf = vec![0u8; max_chunk];
        let mut seq: u64 = 0;
        loop {
            let n = match bridge_rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let chunk = Bytes::copy_from_slice(&buf[..n]);
            if let Err(e) = post_chunk(target, &cfg_uplink, sid, seq, chunk).await {
                tracing::trace!(?e, seq, "packet-up uplink POST failed");
                break;
            }
            seq += 1;
        }
    });

    // Downlink: a single GET whose response body we pipe into bridge_wr.
    let download_path = compose_path(config, sid);
    let download_req = build_request(
        "GET",
        &download_path,
        config,
        sid,
        None,
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed(),
    )?;

    let download_tcp = TcpStream::connect(target).await?;
    download_tcp.set_nodelay(true).ok();
    let (mut download_sender, download_conn) =
        http1::handshake::<_, BoxedBody>(TokioIo::new(download_tcp)).await?;
    tokio::spawn(async move {
        if let Err(e) = download_conn.await {
            tracing::trace!(?e, "packet-up downlink connection ended");
        }
    });
    let download_resp = download_sender.send_request(download_req).await?;
    if !download_resp.status().is_success() {
        return Err(CarrierError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("downlink GET returned {}", download_resp.status()),
        )));
    }

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

async fn post_chunk(
    target: SocketAddr,
    config: &ClientConfig,
    sid: SessionId,
    seq: u64,
    chunk: Bytes,
) -> Result<(), CarrierError> {
    let path = compose_path(config, sid);
    let body: BoxedBody = Full::new(chunk).map_err(|never| match never {}).boxed();
    let req = build_request("POST", &path, config, sid, Some(seq), body)?;

    let tcp = TcpStream::connect(target).await?;
    tcp.set_nodelay(true).ok();
    let (mut sender, conn) = http1::handshake::<_, BoxedBody>(TokioIo::new(tcp)).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::trace!(?e, "packet-up POST connection ended");
        }
    });
    let _resp = sender.send_request(req).await?;
    Ok(())
}

fn build_request(
    method: &str,
    path: &str,
    config: &ClientConfig,
    sid: SessionId,
    seq: Option<u64>,
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

    if let Some(s) = seq {
        match config.seq_placement {
            Placement::Header => {
                builder = builder.header(&config.seq_header, s.to_string());
            }
            Placement::Cookie => {
                builder = builder.header(http::header::COOKIE, format!("x_seq={s}"));
            }
            Placement::Query | Placement::Path => {
                // Already encoded into the URI.
            }
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
