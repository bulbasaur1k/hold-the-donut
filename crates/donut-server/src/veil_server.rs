//! Server-side veiled-TLS termination (M6 step 2b).
//!
//! Sits behind the selfsteal triage: an authenticated veil peer
//! (`Triage::Tunnel`) gets its TLS terminated here, yielding a
//! decrypted byte stream the proxy plumbing can drive. Unknown callers
//! were already relayed to the decoy by the triage and never reach the
//! TLS layer.
//!
//! Because the triage consumed the ClientHello off the socket to make
//! its decision, we replay those bytes into the TLS acceptor via
//! [`PrefixedStream`].
//!
//! Server authentication (REALITY-hardening): after terminating TLS we
//! emit `HMAC(AuthKey, …)` as the first in-tunnel bytes. The client does
//! not use WebPKI; it verifies this proof against the AuthKey it derived
//! during its own ClientHello. A MITM without the static private key
//! cannot compute AuthKey, so it cannot forge the proof.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use donut_veil::{build_raw_client_hello_hook, server_proof, VeilServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::selfsteal::{triage, Triage};

/// A [`TcpStream`] with bytes pushed back in front of it. Reads drain
/// `prefix` (the ClientHello already consumed by the triage) before
/// falling through to the socket; writes go straight to the socket.
pub struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl PrefixedStream {
    pub fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let remaining = &this.prefix[this.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// A veiled-TLS front door: triages each connection, relays unknown
/// callers to the selfsteal `dest`, and terminates TLS for
/// authenticated veil peers.
pub struct VeilServer {
    acceptor: TlsAcceptor,
    veil: VeilServerConfig,
    dest: SocketAddr,
}

impl VeilServer {
    /// Build with the server cert chain + key (selfsteal: your own
    /// domain's real cert), the veil config, and the selfsteal `dest`
    /// to relay unauthenticated callers to.
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        veil: VeilServerConfig,
        dest: SocketAddr,
    ) -> Result<Self, rustls::Error> {
        let mut config = ServerConfig::builder_with_provider(donut_veil::crypto_provider())
            .with_protocol_versions(&[&version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        config.raw_client_hello_hook = Some(build_raw_client_hello_hook(veil.clone()));
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            veil,
            dest,
        })
    }

    /// Triage one accepted connection. An authenticated veil peer yields
    /// a decrypted [`TlsStream`] (`Some`); an unknown caller is relayed
    /// to the selfsteal `dest` and yields `None`.
    pub async fn handle(&self, tcp: TcpStream) -> io::Result<Option<TlsStream<PrefixedStream>>> {
        match triage(tcp, &self.veil, self.dest).await? {
            Triage::Forwarded => Ok(None),
            Triage::Tunnel {
                client,
                prefix,
                auth_key,
            } => {
                let stream = PrefixedStream::new(prefix, client);
                let mut tls = self.acceptor.accept(stream).await?;
                // Server-auth proof: prove we hold the static private key
                // by HMAC'ing a label with the shared AuthKey (the client
                // checks it before trusting the tunnel — MITM defence).
                tls.write_all(&server_proof(&auth_key)).await?;
                tls.flush().await?;
                Ok(Some(tls))
            }
        }
    }
}
