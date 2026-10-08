//! Cascade UDP e2e: a datagram must traverse **entry → exit → internet** and
//! come back, instead of leaving from the entry's own address.
//!
//! This is the path Telegram voice takes. Before UDP learned the chain, the
//! entry bridged every datagram to a local socket, so calls left from the
//! domestic IP while TCP went abroad — the calls stayed blocked.
//!
//! Two donut-servers are wired into a real cascade over the veil transport and
//! a `Command::Udp` session is driven through the entry with the very same
//! dialer the entry itself uses for its upstream hop. The echo proves the
//! datagrams round-trip; the exit's own counters prove they actually went
//! *through* it, which is what a direct local bridge on the entry would fail.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use donut_config::{OutboundConfig, RealityClient};
use donut_core::{Address, AuthHandle, Endpoint, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_server::{Metrics, Outbounds, RuntimeTuning};
use donut_veil::VeilServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const CLIENT_UUID: &str = "11111111-1111-4111-8111-111111111111";
const LINK_UUID: &str = "22222222-2222-4222-8222-222222222222";
const SHORT_ID: &str = "deadbeef";

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    (
        CertificateDer::from(cert.der().to_vec()),
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
}

fn auth_of(uuid: &str) -> AuthHandle {
    AuthHandle::new(UserAuth::new(vec![uuid.parse::<UserId>().unwrap()]))
}

/// A chain outbound aimed at `server`, i.e. exactly how a node dials the next
/// hop. The test drives the entry with one of these too, standing in for a
/// client.
fn chain_to(tag: &str, server: SocketAddr, public_key: [u8; 32], uuid: &str) -> Arc<Outbounds> {
    let cfg = OutboundConfig {
        tag: tag.to_string(),
        transport: "veil".to_string(),
        server: server.to_string(),
        uuid: uuid.to_string(),
        reality: Some(RealityClient {
            public_key: public_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            short_id: SHORT_ID.to_string(),
            server_name: "localhost".to_string(),
            version: [0, 0, 1],
            fingerprint: String::new(),
        }),
    };
    Arc::new(Outbounds::build(&[cfg], None).unwrap())
}

/// UDP echo: bounces every datagram back to its sender.
async fn udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], src).await;
        }
    });
    addr
}

/// `[len:2 BE][payload]` — the VLESS-UDP datagram framing both hops speak.
fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + payload.len());
    out.push((payload.len() >> 8) as u8);
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_traverses_the_cascade_to_the_exit() {
    let echo = udp_echo().await;
    let resolver = Arc::new(Resolver::system().unwrap());
    let decoy: SocketAddr = "127.0.0.1:9".parse().unwrap();

    // ---- exit node: last hop, egresses to the echo directly. ----
    let exit_veil = VeilServerConfig::new([0x22u8; 32], [SHORT_ID.parse().unwrap()]).unwrap();
    let exit_pub = exit_veil.public_key_bytes();
    let exit_metrics = Metrics::new();
    let (cert, key) = gen_cert();
    let exit_addr = donut_server::run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert],
        key,
        exit_veil,
        decoy,
        auth_of(LINK_UUID),
        Arc::new(Router::new("freedom")),
        resolver.clone(),
        Arc::new(Outbounds::default()),
        exit_metrics.clone(),
        RuntimeTuning::default(),
    )
    .await
    .unwrap();

    // ---- entry node: everything defaults to the chain, i.e. the exit. ----
    let entry_veil = VeilServerConfig::new([0x11u8; 32], [SHORT_ID.parse().unwrap()]).unwrap();
    let entry_pub = entry_veil.public_key_bytes();
    let (cert, key) = gen_cert();
    let entry_addr = donut_server::run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert],
        key,
        entry_veil,
        decoy,
        auth_of(CLIENT_UUID),
        Arc::new(Router::new("proxy")),
        resolver.clone(),
        chain_to("proxy", exit_addr, exit_pub, LINK_UUID),
        Metrics::new(),
        RuntimeTuning::default(),
    )
    .await
    .unwrap();

    // ---- client: open a Command::Udp session at the entry for the echo. ----
    let client = chain_to("entry", entry_addr, entry_pub, CLIENT_UUID);
    let target = Endpoint::new(Address::Ip(echo.ip()), echo.port());
    let mut up = timeout(
        Duration::from_secs(5),
        client.get("entry").unwrap().dial_udp(&target),
    )
    .await
    .expect("dial timed out")
    .expect("entry refused the UDP session");

    up.write_all(&framed(b"ping-through-the-cascade"))
        .await
        .unwrap();
    up.flush().await.unwrap();

    let mut buf = vec![0u8; 128];
    let n = timeout(Duration::from_secs(5), up.read(&mut buf))
        .await
        .expect("no datagram came back through the cascade")
        .unwrap();
    assert_eq!(
        &buf[..n],
        &framed(b"ping-through-the-cascade")[..],
        "the echoed datagram must return framed, byte-for-byte"
    );

    // The echo alone would also pass if the entry had bridged locally — what
    // rules that out is the exit having served a UDP session of its own.
    assert!(
        udp_gauge(&exit_metrics) >= 1.0,
        "the exit must be the node holding the UDP session open"
    );
}

/// The control, and the split-tunnel guarantee: a target the router keeps on
/// this node (`geoip:ru` and friends) must still egress locally. It also proves
/// the assertion above discriminates — the echo round-trips either way, so only
/// the exit's gauge tells the two paths apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_route_keeps_udp_off_the_cascade() {
    let echo = udp_echo().await;
    let resolver = Arc::new(Resolver::system().unwrap());
    let decoy: SocketAddr = "127.0.0.1:9".parse().unwrap();

    let exit_veil = VeilServerConfig::new([0x22u8; 32], [SHORT_ID.parse().unwrap()]).unwrap();
    let exit_pub = exit_veil.public_key_bytes();
    let exit_metrics = Metrics::new();
    let (cert, key) = gen_cert();
    let exit_addr = donut_server::run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert],
        key,
        exit_veil,
        decoy,
        auth_of(LINK_UUID),
        Arc::new(Router::new("freedom")),
        resolver.clone(),
        Arc::new(Outbounds::default()),
        exit_metrics.clone(),
        RuntimeTuning::default(),
    )
    .await
    .unwrap();

    // Same wiring as above, except the entry's default route is `freedom`, so
    // the chain outbound exists but nothing selects it.
    let entry_veil = VeilServerConfig::new([0x11u8; 32], [SHORT_ID.parse().unwrap()]).unwrap();
    let entry_pub = entry_veil.public_key_bytes();
    let (cert, key) = gen_cert();
    let entry_addr = donut_server::run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert],
        key,
        entry_veil,
        decoy,
        auth_of(CLIENT_UUID),
        Arc::new(Router::new("freedom")),
        resolver.clone(),
        chain_to("proxy", exit_addr, exit_pub, LINK_UUID),
        Metrics::new(),
        RuntimeTuning::default(),
    )
    .await
    .unwrap();

    let client = chain_to("entry", entry_addr, entry_pub, CLIENT_UUID);
    let target = Endpoint::new(Address::Ip(echo.ip()), echo.port());
    let mut up = timeout(
        Duration::from_secs(5),
        client.get("entry").unwrap().dial_udp(&target),
    )
    .await
    .expect("dial timed out")
    .expect("entry refused the UDP session");

    up.write_all(&framed(b"ping-stays-local")).await.unwrap();
    up.flush().await.unwrap();

    let mut buf = vec![0u8; 128];
    let n = timeout(Duration::from_secs(5), up.read(&mut buf))
        .await
        .expect("no datagram came back from the local egress")
        .unwrap();
    assert_eq!(&buf[..n], &framed(b"ping-stays-local")[..]);

    assert_eq!(
        udp_gauge(&exit_metrics),
        0.0,
        "a locally-routed datagram must never reach the exit"
    );
}

/// Current value of the exit's active-UDP-session gauge.
fn udp_gauge(metrics: &Arc<Metrics>) -> f64 {
    metrics
        .render()
        .lines()
        .find(|l| l.starts_with("donut_active_sessions{kind=\"udp\"}"))
        .and_then(|l| l.split_whitespace().last()?.parse().ok())
        .expect("exit metrics must expose the udp gauge")
}
