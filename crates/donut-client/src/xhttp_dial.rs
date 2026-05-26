//! Client-side cert-based **XHTTP** dial (no REALITY).
//!
//! Opens a plain TLS 1.3 connection to a reverse proxy (e.g. Caddy) that
//! holds a real certificate, then runs the `stream-one` carrier at a
//! secret path. Everything that is *not* the secret path is self-stolen
//! by the front to the decoy site, so the endpoint looks like an
//! ordinary HTTPS file host. The server is authenticated by WebPKI (the
//! real certificate), not by the REALITY AuthKey proof.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use donut_carrier::{BoxIo, CarrierStream, ClientConfig as CarrierClientConfig, Connector, Mode};
use donut_veil::Fingerprint;
use rustls::client::ClientHelloMutator;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig as TlsClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// A cert-based XHTTP dialer. Verifies the front's certificate against
/// the Mozilla WebPKI root set.
pub struct XhttpClient {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    carrier_cfg: CarrierClientConfig,
}

impl XhttpClient {
    /// `server_name` is the TLS SNI / certificate name of the front;
    /// `path` is the secret path prefix the front routes to the carrier
    /// backend (must match the server's `inbound.path`); `mode` is the
    /// carrier framing mode (must match the server's `inbound.mode`).
    pub fn new(server_name: ServerName<'static>, path: String, mode: Mode) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls =
            TlsClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 is supported by the ring provider")
                .with_root_certificates(roots)
                .with_no_client_auth();
        // The carrier speaks HTTP/1.1; offer it so the front negotiates
        // a protocol our hyper client can drive.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Randomize the ClientHello fingerprint so the rustls JA3 isn't a
        // fixed, DPI-blockable signature (the front is a normal HTTPS site
        // and we want to look like ordinary traffic to it).
        tls.client_hello_mutator = Some(ClientHelloMutator::new(|buf, _kx| {
            Fingerprint::Randomized.apply(buf)
        }));
        // No TLS resumption: a PSK ticket is its own fixed fingerprint
        // and its binder would force the ClientHello mutator to skip the
        // randomization. Every connection is fresh.
        tls.resumption = rustls::client::Resumption::disabled();

        let host = match &server_name {
            ServerName::DnsName(d) => d.as_ref().to_string(),
            _ => "localhost".to_string(),
        };
        let carrier_cfg = CarrierClientConfig {
            mode,
            path_prefix: path,
            host,
            ..CarrierClientConfig::default()
        };

        Self {
            connector: TlsConnector::from(Arc::new(tls)),
            server_name,
            carrier_cfg,
        }
    }

    /// Open a `stream-one` carrier to `addr`, retrying the connect a few
    /// times to ride out an unstable link (each attempt is a fresh
    /// TCP+TLS+carrier handshake). Returns once the server's response
    /// headers are in, i.e. the tunnel is established.
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<CarrierStream> {
        const ATTEMPTS: usize = 12;
        let mut last = io::Error::other("xhttp connect: no attempts");
        for attempt in 1..=ATTEMPTS {
            match tokio::time::timeout(Duration::from_secs(5), self.connect_once(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    tracing::debug!(attempt, error = %e, "xhttp connect failed; retrying");
                    last = e;
                }
                Err(_) => {
                    tracing::debug!(attempt, "xhttp connect timed out; retrying");
                    last = io::Error::new(io::ErrorKind::TimedOut, "xhttp connect timeout");
                }
            }
            if attempt < ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        Err(last)
    }

    /// One carrier dial attempt. Builds a TLS connection factory (each
    /// call = fresh TCP + TLS 1.3 with a randomized fingerprint) and
    /// hands it to the carrier client, which opens one connection for
    /// `stream-one`, two for `stream-up`, or many for `packet-up`.
    async fn connect_once(&self, addr: SocketAddr) -> io::Result<CarrierStream> {
        let connector = self.connector.clone();
        let server_name = self.server_name.clone();
        let tls_factory: Arc<dyn Connector> = Arc::new(move || {
            let connector = connector.clone();
            let server_name = server_name.clone();
            async move {
                let tcp = TcpStream::connect(addr).await?;
                tcp.set_nodelay(true).ok();
                let tls = connector.connect(server_name, tcp).await?;
                Ok(Box::new(tls) as BoxIo)
            }
        });
        donut_carrier::client::dial_with(tls_factory, &self.carrier_cfg)
            .await
            .map_err(|e| io::Error::other(format!("carrier dial: {e}")))
    }
}
