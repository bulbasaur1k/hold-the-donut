//! Chain outbounds — relay decrypted traffic to an **upstream** proxy
//! instead of dialing the target directly (cascade: RU entry → foreign exit).
//!
//! After the inbound VLESS tunnel is decrypted and the request header parsed,
//! a routing rule may select a chain outbound by tag. This node then dials the
//! configured upstream (currently VLESS+REALITY / `transport = "veil"`),
//! presents its own VLESS credential, and forwards the **original** target
//! through it — so the exit node performs the real internet egress. The entry
//! never reveals the exit's address to clients, and RU-direct traffic still
//! takes the freedom outbound (decided by the router before we get here).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use anyhow::Context;
use bytes::BytesMut;
use donut_config::OutboundConfig;
use donut_core::{Command, Endpoint, FlowKind, UserId};
use donut_veil::{
    build_client_hello_mutator_capturing, crypto_provider, server_proof, AuthKeySink,
    NoCertVerification, VeilClientConfig, PROOF_LEN,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::{version, ClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::proxy::Prefixed;

/// Anything we can relay through: an async byte duplex. Boxed so the freedom
/// (`TcpStream`) and chain (`TlsStream`) outbounds share one code path.
pub trait Duplex: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Duplex for T {}

/// Outbound runtime: chain outbounds keyed by routing tag, plus the optional
/// freedom-egress ClientHello fragmentation. Empty ⇒ direct egress only.
#[derive(Default)]
pub struct Outbounds {
    map: HashMap<String, Arc<ChainOutbound>>,
    fragment: Option<crate::fragment::FragmentParams>,
}

impl Outbounds {
    /// Compile the `[[outbounds]]` config (+ optional freedom fragmentation)
    /// into runtime dialers.
    pub fn build(
        cfgs: &[OutboundConfig],
        fragment: Option<crate::fragment::FragmentParams>,
    ) -> anyhow::Result<Self> {
        let mut map = HashMap::with_capacity(cfgs.len());
        for c in cfgs {
            let outbound = ChainOutbound::build(c)
                .with_context(|| format!("building chain outbound {:?}", c.tag))?;
            map.insert(c.tag.clone(), Arc::new(outbound));
        }
        Ok(Self { map, fragment })
    }

    /// The chain outbound a routing tag selects, if any.
    pub fn get(&self, tag: &str) -> Option<&Arc<ChainOutbound>> {
        self.map.get(tag)
    }

    /// Freedom-egress ClientHello fragmentation params, if enabled.
    pub fn fragment(&self) -> Option<&crate::fragment::FragmentParams> {
        self.fragment.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// One upstream proxy this node relays to.
pub struct ChainOutbound {
    tag: String,
    /// `host:port` of the upstream exit (resolved per dial).
    server: String,
    /// The VLESS credential this node presents to the exit.
    uuid: UserId,
    dialer: Dialer,
}

enum Dialer {
    Veil(VeilDialer),
}

impl ChainOutbound {
    fn build(c: &OutboundConfig) -> anyhow::Result<Self> {
        let uuid = c.user_id()?;
        let dialer = match c.transport.as_str() {
            "veil" => {
                let r = c
                    .reality
                    .as_ref()
                    .context("transport=\"veil\" outbound requires a [reality] block")?;
                let public_key = r.public_key_bytes()?;
                let short_id = r.short_id_value()?;
                let fingerprint = r
                    .fingerprint
                    .parse::<donut_veil::Fingerprint>()
                    .with_context(|| format!("parsing fingerprint {:?}", r.fingerprint))?;
                let veil = VeilClientConfig::new(public_key, short_id, r.version)
                    .with_fingerprint(fingerprint);
                let server_name = ServerName::try_from(r.server_name.clone())
                    .with_context(|| format!("invalid server_name {:?}", r.server_name))?;
                Dialer::Veil(VeilDialer::new(veil, server_name))
            }
            other => anyhow::bail!(
                "unsupported chain outbound transport {other:?} (only \"veil\" is implemented)"
            ),
        };
        Ok(Self {
            tag: c.tag.clone(),
            server: c.server.clone(),
            uuid,
            dialer,
        })
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Dial the upstream, present our VLESS credential, and ask it to reach
    /// `target`. Returns a stream positioned at the relayed payload (the
    /// upstream's VLESS response prefix is consumed here).
    pub async fn dial(&self, target: &Endpoint) -> io::Result<Box<dyn Duplex>> {
        let addr = lookup_host(&self.server)
            .await?
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("chain outbound {}: cannot resolve {}", self.tag, self.server),
                )
            })?;

        // veil-TLS handshake (REALITY) + server-auth proof.
        let tls = match &self.dialer {
            Dialer::Veil(d) => d.connect(addr).await?,
        };

        // The upstream serves a `stream-one` carrier over the decrypted TLS
        // (same as a donut-client veil dial), so wrap before the VLESS frame.
        let carrier_cfg = donut_carrier::ClientConfig {
            mode: donut_carrier::Mode::StreamOne,
            ..donut_carrier::ClientConfig::default()
        };
        let mut carrier = donut_carrier::client::dial_over_stream(tls, &carrier_cfg)
            .await
            .map_err(|e| io::Error::other(format!("chain carrier dial: {e}")))?;

        // Outbound VLESS request: present our uuid, carry the *original*
        // target so the exit dials it. Plain flow — the inter-node hop is a
        // fresh tunnel; any client-side Vision was already de-framed upstream.
        let req = Request {
            user: self.uuid,
            flow: FlowKind::None,
            command: Command::Tcp,
            target: Some(target.clone()),
            seed: Vec::new(),
        };
        let mut buf = BytesMut::with_capacity(req.encoded_len());
        req.encode(&mut buf);
        carrier.write_all(&buf).await?;
        carrier.flush().await?;

        let leftover = read_response(&mut carrier).await?;
        Ok(Box::new(Prefixed::new(leftover, carrier)))
    }
}

use donut_wire::{Request, Response, WireError};

/// Read and discard the upstream's VLESS response prefix, returning any
/// payload bytes that arrived in the same read (early data → replayed via
/// [`Prefixed`]).
async fn read_response<S: AsyncReadExt + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let mut acc = BytesMut::with_capacity(64);
    loop {
        let mut chunk = [0u8; 64];
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        acc.extend_from_slice(&chunk[..n]);
        let mut view = acc.clone().freeze();
        match Response::decode(&mut view) {
            Ok(_) => {
                let consumed = acc.len() - view.len();
                return Ok(acc.split_off(consumed).to_vec());
            }
            Err(WireError::Truncated { .. }) => continue,
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("chain outbound: bad upstream response: {e}"),
                ))
            }
        }
    }
}

/// Client-side veiled-TLS dialer to the upstream exit. Mirrors
/// [`donut_client::VeilClient`] but lives here so the server can chain
/// without depending on the client binary crate. Authenticates the upstream
/// via the in-tunnel AuthKey proof (no WebPKI / trusted cert).
struct VeilDialer {
    provider: Arc<CryptoProvider>,
    verifier: Arc<NoCertVerification>,
    veil: VeilClientConfig,
    server_name: ServerName<'static>,
}

impl VeilDialer {
    fn new(veil: VeilClientConfig, server_name: ServerName<'static>) -> Self {
        Self {
            provider: crypto_provider(),
            verifier: NoCertVerification::arc(),
            veil,
            server_name,
        }
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<TlsStream<TcpStream>> {
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
        config.resumption = rustls::client::Resumption::disabled();
        let connector = TlsConnector::from(Arc::new(config));

        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true).ok();
        let mut tls = connector.connect(self.server_name.clone(), tcp).await?;

        let auth_key = sink
            .get()
            .copied()
            .ok_or_else(|| io::Error::other("chain veil: AuthKey was not derived"))?;

        let mut proof = [0u8; PROOF_LEN];
        tls.read_exact(&mut proof).await?;
        if proof != server_proof(&auth_key) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chain veil: server-auth proof mismatch (wrong key or MITM)",
            ));
        }
        Ok(tls)
    }
}
