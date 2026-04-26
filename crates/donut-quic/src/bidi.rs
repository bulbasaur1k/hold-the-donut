//! Raw QUIC bidi-stream carrier mode (M5 step 2).
//!
//! Bypasses HTTP/3 framing entirely: each carrier session is a single
//! QUIC bidirectional stream. Both halves (`SendStream` /
//! `RecvStream`) are independent and can be driven concurrently from
//! their own tasks, restoring the overlapping read+write the H1/H2
//! carrier already supports.
//!
//! ALPN is negotiated as `h3` so the wire-level masquerade matches
//! HTTP/3, but no HTTP/3 frames are sent inside the encrypted
//! streams. Use this mode between donut peers; it is **not**
//! interoperable with strict HTTP/3 servers (xray-core's H3 mode is
//! addressed in M5 step 3 once we wrap H3 framing around the raw
//! bidi).

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use crate::error::QuicError;

const PIPE_CAPACITY: usize = 64 * 1024;

/// One accepted raw-bidi carrier session.
pub struct BidiSession {
    pub stream: DuplexStream,
    pub remote: SocketAddr,
}

/// Carrier server that yields one [`BidiSession`] per incoming QUIC
/// bidi stream.
pub struct BidiServer {
    rx: mpsc::Receiver<BidiSession>,
    pub addr: SocketAddr,
}

impl BidiServer {
    pub fn bind(
        addr: SocketAddr,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, QuicError> {
        let server_config = build_server_config(cert_chain, key)?;
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| QuicError::Endpoint(e.to_string()))?;
        let local = endpoint.local_addr()?;
        let (tx, rx) = mpsc::channel::<BidiSession>(64);
        tokio::spawn(accept_loop(endpoint, tx));
        Ok(Self { rx, addr: local })
    }

    pub async fn accept(&mut self) -> Option<BidiSession> {
        self.rx.recv().await
    }
}

async fn accept_loop(endpoint: quinn::Endpoint, tx: mpsc::Sender<BidiSession>) {
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
            handle_connection(conn, remote, tx).await;
        });
    }
}

async fn handle_connection(
    conn: quinn::Connection,
    remote: SocketAddr,
    tx: mpsc::Sender<BidiSession>,
) {
    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let stream = bridge_bidi_to_duplex(send, recv);
                if tx.send(BidiSession { stream, remote }).await.is_err() {
                    break;
                }
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::LocallyClosed) => break,
            Err(e) => {
                tracing::trace!(?e, "QUIC accept_bi error");
                break;
            }
        }
    }
}

/// Open a raw QUIC bidi stream to `target` and return a
/// [`DuplexStream`] that the caller treats as a bidirectional byte
/// pipe.
pub async fn dial(
    target: SocketAddr,
    server_name: &str,
    roots: Vec<CertificateDer<'static>>,
) -> Result<DuplexStream, QuicError> {
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("static addr literal"))?;
    endpoint.set_default_client_config(build_client_config(roots)?);

    let conn = endpoint.connect(target, server_name)?.await?;
    let (send, recv) = conn.open_bi().await?;

    let stream = bridge_bidi_to_duplex(send, recv);

    // Keep the endpoint and connection alive until both halves of the
    // bidi pipe close. Dropping `endpoint` here would shut the UDP
    // socket; dropping `conn` would close the QUIC connection.
    tokio::spawn(async move {
        let _endpoint_keep_alive = endpoint;
        let _ = conn.closed().await;
    });

    Ok(stream)
}

/// Bridge a `(quinn::SendStream, quinn::RecvStream)` pair into a
/// [`DuplexStream`]. Both halves are pumped concurrently in
/// independent tasks.
fn bridge_bidi_to_duplex(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> DuplexStream {
    let (user_side, bridge_side) = tokio::io::duplex(PIPE_CAPACITY);
    let (mut bridge_rd, mut bridge_wr) = tokio::io::split(bridge_side);

    // Uplink: user_side write → bridge_rd read → send.write_all.
    tokio::spawn(async move {
        let mut buf = vec![0u8; PIPE_CAPACITY];
        loop {
            match bridge_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = send.finish();
    });

    // Downlink: recv.read → bridge_wr write → user_side read.
    tokio::spawn(async move {
        let mut buf = vec![0u8; PIPE_CAPACITY];
        while let Ok(Some(n)) = recv.read(&mut buf).await {
            if bridge_wr.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = bridge_wr.shutdown().await;
    });

    user_side
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
