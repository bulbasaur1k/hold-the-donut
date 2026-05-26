//! Client-side cert-based **RAW** dial: VLESS directly over TLS 1.3 with
//! no carrier / HTTP wrapping — the analogue of Xray's RAW (TCP) network
//! and the transport that `xtls-rprx-vision` rides on. The server is
//! authenticated by WebPKI (its real certificate) and self-steals probes
//! to a decoy. Randomized uTLS-style ClientHello fingerprint; TLS
//! resumption disabled so every connection is a fresh, randomized
//! handshake.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use donut_veil::Fingerprint;
use rustls::client::ClientHelloMutator;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig as TlsClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// A cert-based RAW dialer. Verifies the server's certificate against the
/// Mozilla WebPKI root set, then hands back the decrypted TLS stream — the
/// caller writes the VLESS inner frame straight onto it.
pub struct RawClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl RawClient {
    /// `server_name` is the TLS SNI / certificate name of the server.
    pub fn new(server_name: ServerName<'static>) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls =
            TlsClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 is supported by the ring provider")
                .with_root_certificates(roots)
                .with_no_client_auth();
        // Match the server's offered ALPN so a passive observer sees a
        // normal `http/1.1` negotiation (the inner bytes are VLESS, not
        // HTTP, but ALPN is chosen at the TLS layer).
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Randomize the ClientHello fingerprint (JA3) so it isn't a fixed,
        // DPI-blockable signature.
        tls.client_hello_mutator = Some(ClientHelloMutator::new(|buf, _kx| {
            Fingerprint::Randomized.apply(buf)
        }));
        tls.resumption = rustls::client::Resumption::disabled();

        Self {
            connector: TlsConnector::from(Arc::new(tls)),
            server_name,
        }
    }

    /// Open a TLS 1.3 connection to `addr`, retrying a few times to ride
    /// out an unstable link. Returns the decrypted stream ready for the
    /// VLESS inner frame.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<TlsStream<TcpStream>> {
        const ATTEMPTS: usize = 12;
        let mut last = io::Error::other("raw connect: no attempts");
        for attempt in 1..=ATTEMPTS {
            match tokio::time::timeout(Duration::from_secs(5), self.connect_once(addr)).await {
                Ok(Ok(s)) => return Ok(s),
                Ok(Err(e)) => {
                    tracing::debug!(attempt, error = %e, "raw connect failed; retrying");
                    last = e;
                }
                Err(_) => {
                    tracing::debug!(attempt, "raw connect timed out; retrying");
                    last = io::Error::new(io::ErrorKind::TimedOut, "raw connect timeout");
                }
            }
            if attempt < ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        Err(last)
    }

    async fn connect_once(&self, addr: SocketAddr) -> io::Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true).ok();
        self.connector.connect(self.server_name.clone(), tcp).await
    }
}
