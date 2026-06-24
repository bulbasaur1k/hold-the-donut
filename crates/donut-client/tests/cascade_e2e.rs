//! Cascade e2e: the two-node chain works end-to-end over REALITY.
//!
//! client → ENTRY node (REALITY in, routes everything to chain outbound
//! "exit") → EXIT node (REALITY in, freedom egress) → TCP echo target.
//!
//! Proves a donut-server can act as both a proxy *and* a router to another
//! upstream proxy — the RU-entry → foreign-exit cascade. The exit's address
//! lives only in the entry's `[[outbounds]]`, never in the client's config.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_client::VeilClient;
use donut_config::{OutboundConfig, RealityClient};
use donut_core::{Address, Command, Endpoint, FlowKind, ShortId, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_server::{run_veil_proxy, Outbounds};
use donut_veil::{VeilClientConfig, VeilServerConfig};
use donut_wire::{Request, Response};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

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

fn resolver() -> Arc<Resolver> {
    Arc::new(Resolver::doh(
        &["1.1.1.1".parse().unwrap()],
        "cloudflare-dns.com",
    ))
}

/// Bind a TCP echo server and return its address.
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

/// Bind a throwaway decoy listener (needed to build a veil server; unused on
/// the authenticated path).
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
async fn cascade_entry_chains_to_exit() {
    let echo_addr = spawn_echo().await;
    let decoy_addr = spawn_decoy().await;

    // ---- EXIT node (foreign): freedom egress to the echo target. ----
    let (exit_cert, exit_key) = gen_cert();
    let exit_priv = [0x22u8; 32];
    let exit_sid: ShortId = "0123abcd".parse().unwrap();
    let exit_veil = VeilServerConfig::new(exit_priv, [exit_sid]).unwrap();
    let exit_pub = exit_veil.public_key_bytes();
    let exit_uuid = UserId::new_v4();
    let exit_addr = run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![exit_cert],
        exit_key,
        exit_veil,
        decoy_addr,
        Arc::new(UserAuth::new(vec![exit_uuid])),
        Arc::new(Router::new("freedom")),
        resolver(),
        Arc::new(Outbounds::default()),
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind exit");

    // ---- ENTRY node (RU): routes everything to chain outbound "exit". ----
    let (entry_cert, entry_key) = gen_cert();
    let entry_priv = [0x11u8; 32];
    let entry_sid: ShortId = "deadbeef".parse().unwrap();
    let entry_veil = VeilServerConfig::new(entry_priv, [entry_sid]).unwrap();
    let entry_pub = entry_veil.public_key_bytes();
    let entry_uuid = UserId::new_v4();

    let chain_cfg = OutboundConfig {
        tag: "exit".into(),
        transport: "veil".into(),
        server: exit_addr.to_string(),
        uuid: exit_uuid.to_string(),
        reality: Some(RealityClient {
            public_key: hex32(&exit_pub),
            short_id: "0123abcd".into(),
            server_name: "localhost".into(),
            version: [26, 4, 15],
            fingerprint: String::new(),
        }),
    };
    let outbounds = Arc::new(Outbounds::build(&[chain_cfg], None).expect("build outbounds"));

    let entry_addr = run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![entry_cert],
        entry_key,
        entry_veil,
        decoy_addr,
        Arc::new(UserAuth::new(vec![entry_uuid])),
        Arc::new(Router::new("exit")), // default outbound → chain "exit"
        resolver(),
        outbounds,
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind entry");

    // ---- CLIENT → ENTRY over REALITY, then carrier, then VLESS to echo. ----
    let veil_client = VeilClient::new(
        VeilClientConfig::new(entry_pub, entry_sid, [26, 4, 15]),
        ServerName::try_from("localhost").unwrap(),
    );
    let tls = timeout(Duration::from_secs(5), veil_client.connect(entry_addr))
        .await
        .expect("entry connect timeout")
        .expect("entry connect");
    let carrier_cfg = donut_carrier::ClientConfig {
        mode: donut_carrier::Mode::StreamOne,
        ..donut_carrier::ClientConfig::default()
    };
    let mut carrier = donut_carrier::client::dial_over_stream(tls, &carrier_cfg)
        .await
        .expect("carrier dial");

    let echo_v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v) => v,
        _ => unreachable!("ephemeral 127.0.0.1 is v4"),
    };
    let request = Request {
        user: entry_uuid,
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(Address::ipv4(echo_v4), echo_addr.port())),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 16);
    request.encode(&mut framed);
    framed.extend_from_slice(b"cascade-hello");
    carrier.write_all(&framed).await.unwrap();
    carrier.flush().await.unwrap();
    carrier.shutdown().await.unwrap();

    // Drain the entry's Response prefix, then read the echoed payload that
    // travelled entry → exit → echo → exit → entry → client.
    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), carrier.read_exact(&mut prefix))
        .await
        .expect("response prefix timeout")
        .unwrap();
    let mut pv = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut pv).expect("response decode");

    let mut got = Vec::new();
    timeout(Duration::from_secs(5), carrier.read_to_end(&mut got))
        .await
        .expect("echo read timeout")
        .unwrap();
    assert_eq!(got, b"cascade-hello", "payload must round-trip through the cascade");
}
