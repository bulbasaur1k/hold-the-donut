//! HTTP-3 / QUIC carrier client (`stream-one` mode).

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use http::{Request, Uri};
use rustls::RootCertStore;
use tokio::io::{AsyncWriteExt, DuplexStream};

use crate::error::QuicError;

const PIPE_CAPACITY: usize = 64 * 1024;

/// Open a QUIC + H3 carrier session to `target` and return a
/// [`DuplexStream`] that the caller treats as a bidirectional byte
/// pipe (uplink = writes, downlink = reads).
///
/// `roots` is the trust store used to authenticate the remote (e.g.
/// WebPKI roots for a real certificate, or a pinned self-signed cert).
/// `server_name` selects the SNI sent in the TLS handshake.
pub async fn dial_stream_one(
    target: SocketAddr,
    server_name: &str,
    roots: RootCertStore,
    request_path: &str,
) -> Result<DuplexStream, QuicError> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("static addr literal"))?;
    endpoint.set_default_client_config(build_client_config(roots)?);

    let conn = endpoint.connect(target, server_name)?.await?;
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| QuicError::H3Conn(format!("h3 client new: {e}")))?;
    // Move the endpoint into the driver task so it lives as long as
    // the connection. Dropping `quinn::Endpoint` shuts the underlying
    // UDP socket and forces an `H3_NO_ERROR` close on all connections.
    tokio::spawn(async move {
        let _endpoint_keep_alive = endpoint;
        let e = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        tracing::trace!(?e, "h3 client driver closed");
    });

    let uri: Uri = format!("https://{server_name}{request_path}")
        .parse()
        .map_err(|e: http::uri::InvalidUri| QuicError::H3Stream(format!("uri: {e}")))?;
    let req = Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(())
        .map_err(|e| QuicError::H3Stream(format!("build req: {e}")))?;

    let stream = send_request
        .send_request(req)
        .await
        .map_err(|e| QuicError::H3Stream(format!("send_request: {e}")))?;
    // Split so the uplink and downlink run on separate tasks — full
    // bidirectional overlap over a single H3 request stream. This lets
    // the caller read the response (e.g. the VLESS Response prefix) while
    // it is still writing the request body — required for a tunnel.
    let (mut send, mut recv) = stream.split();

    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (mut bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

    // Uplink: user writes → H3 request body.
    tokio::spawn(async move {
        let mut read_buf = vec![0u8; PIPE_CAPACITY];
        loop {
            match tokio::io::AsyncReadExt::read(&mut bridge_rd, &mut read_buf[..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send
                        .send_data(Bytes::copy_from_slice(&read_buf[..n]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        let _ = send.finish().await;
    });

    // Downlink: H3 response body → user reads, concurrently with uplink.
    // Hold the `SendRequest` handle alive here (the longer-lived task):
    // dropping it can trigger the client to close the H3 connection, so
    // it must outlive the downlink, not just the uplink.
    tokio::spawn(async move {
        let _send_request_keep_alive = send_request;
        let resp = match recv.recv_response().await {
            Ok(r) => r,
            Err(e) => {
                tracing::trace!(?e, "h3 recv_response failed");
                return;
            }
        };
        if !resp.status().is_success() {
            tracing::trace!(status = ?resp.status(), "h3 non-success response");
            return;
        }
        while let Ok(Some(mut data)) = recv.recv_data().await {
            while data.has_remaining() {
                let chunk = data.chunk().to_vec();
                if bridge_wr.write_all(&chunk).await.is_err() {
                    return;
                }
                data.advance(chunk.len());
            }
        }
        let _ = bridge_wr.shutdown().await;
    });

    Ok(user_side)
}

fn build_client_config(roots: RootCertStore) -> Result<quinn::ClientConfig, QuicError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|e| QuicError::Endpoint(format!("no initial cipher suite: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(qc)))
}
