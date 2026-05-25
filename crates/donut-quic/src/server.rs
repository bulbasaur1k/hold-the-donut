//! HTTP-3 / QUIC carrier server (`stream-one` mode).
//!
//! Wraps `quinn::Endpoint::server` + `h3::server::Connection` and
//! exposes the same `accept().await -> QuicSession` API as the H1
//! carrier. The `stream-one` framing maps onto a single H3 BiDi
//! stream: the request body carries the uplink, the response body
//! carries the downlink.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use crate::error::QuicError;

/// One accepted H3 carrier session.
pub struct QuicSession {
    pub stream: DuplexStream,
    pub remote: SocketAddr,
}

const PIPE_CAPACITY: usize = 64 * 1024;

/// QUIC + H3 carrier server bound to a UDP socket. Drives the accept
/// loop in a background task; consume sessions via `accept`.
pub struct QuicServer {
    rx: mpsc::Receiver<QuicSession>,
    pub addr: SocketAddr,
}

impl QuicServer {
    /// Bind a QUIC endpoint to `addr` with the given certificate
    /// chain and private key, install it as a server, and start the
    /// accept loop. Returns the bound local address (useful when
    /// `addr` had port 0).
    pub fn bind(
        addr: SocketAddr,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, QuicError> {
        let server_config = build_server_config(cert_chain, key)?;
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| QuicError::Endpoint(e.to_string()))?;
        let local = endpoint.local_addr()?;
        let (tx, rx) = mpsc::channel::<QuicSession>(64);
        tokio::spawn(accept_loop(endpoint, tx));
        Ok(Self { rx, addr: local })
    }

    pub async fn accept(&mut self) -> Option<QuicSession> {
        self.rx.recv().await
    }
}

fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, QuicError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = u32::MAX;

    let qc = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
        .map_err(|e| QuicError::Endpoint(format!("no initial cipher suite: {e}")))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(qc)))
}

async fn accept_loop(endpoint: quinn::Endpoint, tx: mpsc::Sender<QuicSession>) {
    while let Some(incoming) = endpoint.accept().await {
        let tx = tx.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    tracing::trace!(?e, "QUIC handshake failed");
                    return;
                }
            };
            let remote = conn.remote_address();
            let h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::trace!(?e, "H3 server new failed");
                    return;
                }
            };
            handle_h3_connection(h3_conn, remote, tx).await;
        });
    }
}

async fn handle_h3_connection(
    mut conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
    remote: SocketAddr,
    tx: mpsc::Sender<QuicSession>,
) {
    loop {
        match conn.accept().await {
            Ok(Some(resolver)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(resolver, remote, tx).await {
                        tracing::trace!(?e, "H3 request handling error");
                    }
                });
            }
            Ok(None) => break, // graceful close
            Err(e) => {
                tracing::trace!(?e, "H3 server accept error");
                break;
            }
        }
    }
}

async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    remote: SocketAddr,
    tx: mpsc::Sender<QuicSession>,
) -> Result<(), QuicError> {
    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| QuicError::H3Stream(format!("resolve request: {e}")))?;

    // The session id itself is opaque to the M5 step-1 handler; M5
    // step-2 will pull it through the shared `session_extract` once
    // we wire the carrier-mode trait.
    let _ = req;

    // Send 200 OK response headers immediately so the client can start
    // reading the downlink.
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(())
        .unwrap();
    stream
        .send_response(response)
        .await
        .map_err(|e| QuicError::H3Stream(format!("send_response: {e}")))?;

    // Full-duplex bridge: split the H3 request stream so the uplink
    // (request body → user) and downlink (user → response body) pump
    // concurrently on separate tasks. This lets the server start sending
    // the downlink before the client has finished its uplink — required
    // to carry an interactive proxy tunnel (the VLESS Response prefix
    // must reach the client while it is still uploading).
    let (mut send, mut recv) = stream.split();
    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (mut bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

    // Uplink: H3 request body → user side.
    tokio::spawn(async move {
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

    // Downlink: user side → H3 response body.
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

    // Hand the user-facing duplex to the accept channel.
    if tx
        .send(QuicSession {
            stream: user_side,
            remote,
        })
        .await
        .is_err()
    {
        tracing::warn!("QUIC accept channel closed");
    }

    Ok(())
}

// `bytes::Buf` is needed for the `chunk()` / `has_remaining()` /
// `advance()` calls in the uplink pump.
use bytes::Buf;
