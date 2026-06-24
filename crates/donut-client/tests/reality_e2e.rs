//! Faithful-REALITY server e2e: a REALITY client (the xray wire shape — raw
//! VLESS over a REALITY-camouflaged TLS 1.3 handshake, no carrier, no Let's
//! Encrypt) reaches an echo target through `run_reality_proxy`.
//!
//! client → selfsteal triage → REALITY handshake (per-connection HMAC-signed
//! cert + ed25519 CertVerify) → VLESS request → freedom egress → echo.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_core::{Address, Command, Endpoint, FlowKind, ShortId, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_server::run_reality_proxy;
use donut_veil::{build_client_hello_mutator, crypto_provider, NoCertVerification, VeilClientConfig, VeilServerConfig};
use donut_wire::{Request, Response};
use rustls::pki_types::ServerName;
use rustls::{version, ClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

async fn spawn_echo() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match l.accept().await {
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

async fn spawn_decoy() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            if l.accept().await.is_err() {
                return;
            }
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reality_client_reaches_echo() {
    let echo_addr = spawn_echo().await;
    let decoy_addr = spawn_decoy().await;

    // REALITY server: per-connection HMAC-signed cert, freedom egress.
    let priv_bytes = [0x55u8; 32];
    let short_id: ShortId = "deadbeef".parse().unwrap();
    let veil = VeilServerConfig::new(priv_bytes, [short_id]).unwrap();
    let server_pub = veil.public_key_bytes();
    let user = UserId::new_v4();

    let server_addr = run_reality_proxy(
        "127.0.0.1:0".parse().unwrap(),
        veil,
        decoy_addr,
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        Arc::new(donut_server::Outbounds::default()),
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind reality server");

    // REALITY client: veil ClientHello mutator (seals the SessionID so the
    // server authenticates us) + no-PKI verifier (REALITY clients accept the
    // ephemeral cert). VEIL_X25519 provider lets the mutator derive the authKey
    // from the TLS ephemeral, like xray's uTLS.
    let veil_client = VeilClientConfig::new(server_pub, short_id, [26, 4, 15]);
    let mut client_cfg = ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(NoCertVerification::arc())
        .with_no_client_auth();
    client_cfg.client_hello_mutator = Some(build_client_hello_mutator(veil_client));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let mut tls = timeout(
        Duration::from_secs(5),
        connector.connect(ServerName::try_from("localhost").unwrap(), tcp),
    )
    .await
    .expect("REALITY handshake timeout")
    .expect("REALITY handshake");

    // Raw VLESS over the REALITY tunnel (flow=none).
    let echo_v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v) => v,
        _ => unreachable!(),
    };
    let request = Request {
        user,
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(Address::ipv4(echo_v4), echo_addr.port())),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 16);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-reality");
    tls.write_all(&framed).await.unwrap();
    tls.flush().await.unwrap();

    // Server's VLESS response prefix, then the echoed payload.
    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), tls.read_exact(&mut prefix))
        .await
        .expect("response prefix timeout")
        .unwrap();
    let mut pv = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut pv).expect("response decode");

    let mut got = vec![0u8; b"hello-reality".len()];
    timeout(Duration::from_secs(5), tls.read_exact(&mut got))
        .await
        .expect("echo read timeout")
        .unwrap();
    assert_eq!(got, b"hello-reality", "payload must round-trip through REALITY+VLESS");
}
