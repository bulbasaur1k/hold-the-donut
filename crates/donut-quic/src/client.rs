//! HTTP-3 / QUIC carrier client (`stream-one` mode).

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use http::{Request, Uri};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncWriteExt, DuplexStream};

use crate::error::QuicError;

const PIPE_CAPACITY: usize = 64 * 1024;

/// Open a QUIC + H3 carrier session to `target` and return a
/// [`DuplexStream`] that the caller treats as a bidirectional byte
/// pipe (uplink = writes, downlink = reads).
///
/// `roots` is the set of certificates trusted to authenticate the
/// remote. Pass an empty `Vec` to reject everything.
/// `server_name` selects the SNI sent in the TLS handshake.
pub async fn dial_stream_one(
    target: SocketAddr,
    server_name: &str,
    roots: Vec<CertificateDer<'static>>,
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

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| QuicError::H3Stream(format!("send_request: {e}")))?;

    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (mut bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

    // Phase 1 — pump bridge_rd (user uplink writes) onto H3 send_data
    // until the user shuts down their write half. Phase 2 — read the
    // H3 response headers and pipe response body into bridge_wr.
    // Single-task bidirection on h3 0.0.8 is restricted to a
    // request → response shape; see server.rs for context.
    tokio::spawn(async move {
        let _send_request_keep_alive = send_request;
        let mut read_buf = vec![0u8; PIPE_CAPACITY];
        loop {
            match tokio::io::AsyncReadExt::read(&mut bridge_rd, &mut read_buf[..]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stream
                        .send_data(Bytes::copy_from_slice(&read_buf[..n]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        if stream.finish().await.is_err() {
            return;
        }

        let resp = match stream.recv_response().await {
            Ok(r) => r,
            Err(_) => return,
        };
        if !resp.status().is_success() {
            return;
        }

        while let Ok(Some(mut data)) = stream.recv_data().await {
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

fn build_client_config(
    roots: Vec<CertificateDer<'static>>,
) -> Result<quinn::ClientConfig, QuicError> {
    let mut store = rustls::RootCertStore::empty();
    for cert in roots {
        store
            .add(cert)
            .map_err(|e| QuicError::Cert(format!("add: {e}")))?;
    }
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(store)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|e| QuicError::Endpoint(format!("no initial cipher suite: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(qc)))
}
