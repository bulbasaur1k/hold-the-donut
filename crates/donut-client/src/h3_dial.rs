//! Client-side cert-based **H3 (HTTP/3)** dial (no REALITY).
//!
//! Opens a QUIC + HTTP/3 connection to a front that holds a real
//! certificate and runs the `stream-one` carrier over a single H3
//! request stream (full-duplex). Same masking model as `xhttp` — the
//! endpoint looks like an ordinary H3 site and self-steals everything
//! that is not the secret path — but over QUIC instead of TCP/TLS.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use rustls::RootCertStore;
use tokio::io::DuplexStream;

/// A cert-based H3 dialer. Verifies the front's certificate against the
/// Mozilla WebPKI root set.
pub struct H3Client {
    server_name: String,
    path: String,
    roots: RootCertStore,
}

impl H3Client {
    /// `server_name` is the TLS SNI / certificate name of the front;
    /// `path` is the secret request path the front routes to the carrier
    /// backend (for direct H3 the server accepts any path).
    pub fn new(server_name: String, path: String) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self {
            server_name,
            path,
            roots,
        }
    }

    /// Open a full-duplex H3 carrier stream to `addr`, retrying a few
    /// times to ride out an unstable link. The returned duplex carries
    /// raw tunnel bytes (the VLESS inner frame goes straight in — H3
    /// *is* the carrier here).
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<DuplexStream> {
        const ATTEMPTS: usize = 12;
        let mut last = io::Error::other("h3 connect: no attempts");
        for attempt in 1..=ATTEMPTS {
            match tokio::time::timeout(Duration::from_secs(5), self.connect_once(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    tracing::debug!(attempt, error = %e, "h3 connect failed; retrying");
                    last = e;
                }
                Err(_) => {
                    tracing::debug!(attempt, "h3 connect timed out; retrying");
                    last = io::Error::new(io::ErrorKind::TimedOut, "h3 connect timeout");
                }
            }
            if attempt < ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        Err(last)
    }

    async fn connect_once(&self, addr: SocketAddr) -> io::Result<DuplexStream> {
        donut_quic::client::dial_stream_one(addr, &self.server_name, self.roots.clone(), &self.path)
            .await
            .map_err(|e| io::Error::other(format!("h3 dial: {e}")))
    }
}
