//! End-to-end tests for the cert-based **TLS carrier** transport in the
//! split carrier modes `stream-up` and `packet-up`. Unlike `stream-one`
//! (one full-duplex exchange on a single connection), these modes split
//! the uplink and downlink across *separate* TLS connections, paired by
//! session id on the server's shared dispatcher. The client supplies a
//! TLS connection factory (a fresh TLS 1.3 connection per call).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_carrier::{BoxIo, ClientConfig, Connector, Mode};
use donut_core::{Address, Command, Endpoint, FlowKind, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_wire::{Request, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const SECRET: &str = "/store/sync";

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());
    (cert_der, key_der)
}

/// Build a TLS connection factory: each call opens a fresh TCP + TLS 1.3
/// connection to `addr`, trusting only `cert`, offering `http/1.1` ALPN.
fn tls_factory(cert: CertificateDer<'static>, addr: SocketAddr) -> Arc<dyn Connector> {
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));
    let sni = ServerName::try_from("localhost").unwrap();
    Arc::new(move || {
        let connector = connector.clone();
        let sni = sni.clone();
        async move {
            let tcp = TcpStream::connect(addr).await?;
            tcp.set_nodelay(true).ok();
            let tls = connector.connect(sni, tcp).await?;
            Ok(Box::new(tls) as BoxIo)
        }
    })
}

/// Spawn a minimal HTTP/1.1 decoy backend (one request per connection)
/// returning a recognizable body; returns its address.
async fn spawn_decoy() -> SocketAddr {
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = decoy.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match decoy.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let body = b"DECOY-SITE";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

/// Spawn an echo TCP server; returns its address.
async fn spawn_echo() -> SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match echo.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = s.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
                let _ = wr.shutdown().await;
            });
        }
    });
    addr
}

/// Run a tunnel round-trip in the given carrier `mode` and assert the
/// echo target sees and reflects our bytes through the split tunnel.
async fn tunnel_roundtrip(mode: Mode) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = gen_cert();
    let echo_addr = spawn_echo().await;
    let decoy_addr = spawn_decoy().await;

    let user = UserId::new_v4();
    let server = donut_server::run_tls_carrier_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        SECRET.to_string(),
        mode,
        Some(decoy_addr),
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        donut_server::Metrics::new(),
    )
    .await
    .expect("bind tls carrier");

    let cfg = ClientConfig {
        mode,
        path_prefix: SECRET.to_string(),
        ..ClientConfig::default()
    };
    let mut carrier = timeout(
        Duration::from_secs(5),
        donut_carrier::client::dial_with(tls_factory(cert.clone(), server), &cfg),
    )
    .await
    .expect("dial timeout")
    .expect("carrier dial");

    let request = Request {
        user,
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(
            Address::ipv4(match echo_addr.ip() {
                std::net::IpAddr::V4(v) => v,
                _ => unreachable!(),
            }),
            echo_addr.port(),
        )),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 16);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-split");
    carrier.write_all(&framed).await.unwrap();
    carrier.flush().await.unwrap();

    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), carrier.read_exact(&mut prefix))
        .await
        .expect("prefix timeout")
        .unwrap();
    let mut pv = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut pv).expect("response decode");

    let mut got = vec![0u8; b"hello-split".len()];
    timeout(Duration::from_secs(5), carrier.read_exact(&mut got))
        .await
        .expect("echo timeout")
        .unwrap();
    assert_eq!(got, b"hello-split", "{mode:?} tunnel must echo");

    // Self-steal: a probe to a non-secret path must reverse-proxy to the
    // decoy site in every mode (a regression guard — only stream-one used
    // to do this; stream-up/packet-up returned 404 and leaked).
    {
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(tls));
        let sni = ServerName::try_from("localhost").unwrap();
        let tcp = TcpStream::connect(server).await.unwrap();
        let mut probe = connector.connect(sni, tcp).await.unwrap();
        probe
            .write_all(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        timeout(Duration::from_secs(5), probe.read_to_end(&mut resp))
            .await
            .expect("decoy read timeout")
            .unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(
            text.contains("DECOY-SITE"),
            "{mode:?} self-steal must reach decoy, got: {text}"
        );
    }
}

#[tokio::test]
async fn stream_up_tunnel() {
    tunnel_roundtrip(Mode::StreamUp).await;
}

#[tokio::test]
async fn packet_up_tunnel() {
    tunnel_roundtrip(Mode::PacketUp).await;
}
