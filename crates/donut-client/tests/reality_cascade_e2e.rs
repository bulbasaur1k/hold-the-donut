//! REALITY cascade e2e: a REALITY client reaches an echo target through a
//! two-node cascade whose ENTRY is a faithful-REALITY node.
//!
//! REALITY client → REALITY entry (routes everything to chain "exit") → veil
//! exit (freedom egress) → echo. Proves `run_reality_proxy` works as a cascade
//! entry: the off-the-shelf-shaped REALITY ingress chains onward to the exit.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_config::{OutboundConfig, RealityClient};
use donut_core::{Address, Command, Endpoint, FlowKind, ShortId, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_server::{run_reality_proxy, run_veil_proxy, Outbounds};
use donut_veil::{build_client_hello_mutator, crypto_provider, NoCertVerification, VeilClientConfig, VeilServerConfig};
use donut_wire::{Request, Response};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{version, ClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    (
        CertificateDer::from(cert.der().to_vec()),
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

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

fn resolver() -> Arc<Resolver> {
    Arc::new(Resolver::doh(
        &["1.1.1.1".parse().unwrap()],
        "cloudflare-dns.com",
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reality_entry_chains_to_exit() {
    let echo_addr = spawn_echo().await;
    let decoy_addr = spawn_decoy().await;

    // EXIT (veil, freedom egress to echo).
    let (exit_cert, exit_key) = gen_cert();
    let exit_priv = [0x22u8; 32];
    let exit_sid: ShortId = "0123abcd".parse().unwrap();
    let exit_veil = VeilServerConfig::new(exit_priv, [exit_sid]).unwrap();
    let exit_pub = exit_veil.public_key_bytes();
    let link_uuid = UserId::new_v4(); // inter-node credential
    let exit_addr = run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![exit_cert],
        exit_key,
        exit_veil,
        decoy_addr,
        Arc::new(UserAuth::new(vec![link_uuid])),
        Arc::new(Router::new("freedom")),
        resolver(),
        Arc::new(Outbounds::default()),
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind exit");

    // ENTRY (faithful REALITY) routing everything to chain "exit".
    let entry_priv = [0x11u8; 32];
    let entry_sid: ShortId = "deadbeef".parse().unwrap();
    let entry_veil = VeilServerConfig::new(entry_priv, [entry_sid]).unwrap();
    let entry_pub = entry_veil.public_key_bytes();
    let device_uuid = UserId::new_v4(); // the client's credential

    let chain_cfg = OutboundConfig {
        tag: "exit".into(),
        transport: "veil".into(),
        server: exit_addr.to_string(),
        uuid: link_uuid.to_string(),
        reality: Some(RealityClient {
            public_key: hex32(&exit_pub),
            short_id: "0123abcd".into(),
            server_name: "localhost".into(),
            version: [26, 4, 15],
            fingerprint: String::new(),
        }),
    };
    let outbounds = Arc::new(Outbounds::build(&[chain_cfg], None).expect("outbounds"));

    let entry_addr = run_reality_proxy(
        "127.0.0.1:0".parse().unwrap(),
        entry_veil,
        decoy_addr,
        Arc::new(UserAuth::new(vec![device_uuid])),
        Arc::new(Router::new("exit")), // default → chain
        resolver(),
        outbounds,
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind entry");

    // REALITY client → ENTRY (raw VLESS over REALITY, flow=none).
    let veil_client = VeilClientConfig::new(entry_pub, entry_sid, [26, 4, 15]);
    let mut client_cfg = ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(NoCertVerification::arc())
        .with_no_client_auth();
    client_cfg.client_hello_mutator = Some(build_client_hello_mutator(veil_client));
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let tcp = tokio::net::TcpStream::connect(entry_addr).await.unwrap();
    let mut tls = timeout(
        Duration::from_secs(5),
        connector.connect(ServerName::try_from("localhost").unwrap(), tcp),
    )
    .await
    .expect("entry handshake timeout")
    .expect("entry handshake");

    let echo_v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v) => v,
        _ => unreachable!(),
    };
    let request = Request {
        user: device_uuid,
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(Address::ipv4(echo_v4), echo_addr.port())),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 24);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-cascade-reality");
    tls.write_all(&framed).await.unwrap();
    tls.flush().await.unwrap();

    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), tls.read_exact(&mut prefix))
        .await
        .expect("prefix timeout")
        .unwrap();
    let mut pv = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut pv).expect("response decode");

    let mut got = vec![0u8; b"hello-cascade-reality".len()];
    timeout(Duration::from_secs(5), tls.read_exact(&mut got))
        .await
        .expect("echo timeout")
        .unwrap();
    assert_eq!(
        got, b"hello-cascade-reality",
        "payload must round-trip REALITY entry → chain → exit → echo"
    );
}
