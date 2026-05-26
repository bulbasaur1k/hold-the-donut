//! Connection factory for the multi-request carrier client modes.
//!
//! `stream-one` rides a single byte stream, but `stream-up` and
//! `packet-up` open several connections (an uplink and a downlink, or
//! many sequenced POSTs). They must not assume *how* a connection is
//! made: behind a reverse proxy it is plain TCP, but against a
//! cert-terminating donut-server it is a fresh TLS 1.3 connection (with
//! a randomized uTLS fingerprint). A [`Connector`] abstracts that so the
//! caller supplies the transport.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Object-safe duplex stream the carrier client drives with hyper.
pub trait DuplexIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> DuplexIo for T {}

/// A boxed, owned duplex connection.
pub type BoxIo = Box<dyn DuplexIo>;

/// Future returned by [`Connector::connect`].
pub type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<BoxIo>> + Send>>;

/// Opens fresh transport connections to the carrier server on demand.
/// `stream-one` calls it once, `stream-up` twice, `packet-up` many
/// times. Implemented for any `Fn() -> Future<Output = io::Result<BoxIo>>`
/// so callers can pass a plain-TCP or a TLS (uTLS) connector.
pub trait Connector: Send + Sync {
    fn connect(&self) -> ConnectFuture;
}

impl<F, Fut> Connector for F
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = io::Result<BoxIo>> + Send + 'static,
{
    fn connect(&self) -> ConnectFuture {
        Box::pin((self)())
    }
}

/// Plain-TCP connector to `target` (with `TCP_NODELAY`). Used behind a
/// reverse proxy / in tests; the donut-client supplies its own TLS
/// connector for the cert-based path.
pub fn tcp_connector(target: SocketAddr) -> impl Connector {
    move || async move {
        let tcp = TcpStream::connect(target).await?;
        tcp.set_nodelay(true).ok();
        Ok(Box::new(tcp) as BoxIo)
    }
}
