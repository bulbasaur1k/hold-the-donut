//! Client-side veiled-TLS dial (M7 step 2 + REALITY-hardening).
//!
//! Wraps a TCP connection to the donut-server in a veiled TLS 1.3
//! handshake: the [`donut_veil`] ClientHello mutator stamps the REALITY
//! seal into the SessionID, so the server's hook recognises us.
//!
//! Server authentication is **not** done via WebPKI (no `trusted_cert`
//! to distribute). Instead the TLS cert verifier accepts anything, and
//! the server proves it holds the REALITY static key by sending
//! `HMAC(AuthKey, …)` as the first bytes inside the tunnel; we verify it
//! against the `AuthKey` derived during our own ClientHello mutation. A
//! MITM lacking the server's static key cannot forge that proof.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use donut_veil::{
    build_client_hello_mutator_capturing, crypto_provider, server_proof, AuthKeySink,
    NoCertVerification, VeilClientConfig, PROOF_LEN,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::version;
use rustls::ClientConfig;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// A veiled-TLS dialer. Authenticates the server via the in-tunnel
/// AuthKey proof (no trusted certificate required).
pub struct VeilClient {
    provider: Arc<CryptoProvider>,
    verifier: Arc<NoCertVerification>,
    veil: VeilClientConfig,
    server_name: ServerName<'static>,
}

impl VeilClient {
    /// Build with the veil client config and the SNI `server_name` to
    /// present. No trusted roots are needed — the server is authenticated
    /// by the AuthKey proof.
    pub fn new(veil: VeilClientConfig, server_name: ServerName<'static>) -> Self {
        Self {
            provider: crypto_provider(),
            verifier: NoCertVerification::arc(),
            veil,
            server_name,
        }
    }

    /// Dial `addr`, run the veiled handshake, verify the server-auth
    /// proof, and return the decrypted stream (positioned right after the
    /// proof — the caller reads the tunnel payload next).
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<TlsStream<TcpStream>> {
        // Per-connection config so the mutator can hand us this
        // connection's AuthKey via the sink.
        let sink: AuthKeySink = Arc::new(OnceLock::new());
        let mut config = ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&version::TLS13])
            .expect("TLS 1.3 is supported by the veil provider")
            .dangerous()
            .with_custom_certificate_verifier(self.verifier.clone())
            .with_no_client_auth();
        config.client_hello_mutator = Some(build_client_hello_mutator_capturing(
            self.veil.clone(),
            Some(sink.clone()),
        ));
        // No TLS resumption: REALITY connections are fresh, and a PSK
        // ticket would (a) be its own fingerprint and (b) carry binders
        // the fingerprint mutator would have to leave un-shuffled. This
        // config is already per-connection, but pin it explicitly.
        config.resumption = rustls::client::Resumption::disabled();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = TcpStream::connect(addr).await?;
        let mut tls = connector.connect(self.server_name.clone(), tcp).await?;

        let auth_key = sink
            .get()
            .copied()
            .ok_or_else(|| io::Error::other("veil: AuthKey was not derived (no TLS key share?)"))?;

        // Verify the server-auth proof (REALITY-hardening / MITM defence).
        let mut proof = [0u8; PROOF_LEN];
        tls.read_exact(&mut proof).await?;
        if proof != server_proof(&auth_key) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "veil: server-auth proof mismatch (wrong key or MITM)",
            ));
        }

        Ok(tls)
    }
}
