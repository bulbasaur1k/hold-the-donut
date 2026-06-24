//! REALITY + native fragment e2e: a ClientHello sent by a REALITY client
//! through the REALITY node's freedom egress arrives at the target split across
//! several TLS records — sidecar-free SNI de-throttle (YouTube/Discord) on a
//! faithful-REALITY entry.
//!
//! REALITY client → run_reality_proxy (freedom egress, [fragment] on) → capture.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_core::{Address, Command, Endpoint, FlowKind, ShortId, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_server::{run_reality_proxy, FragmentParams, Outbounds};
use donut_veil::{build_client_hello_mutator, crypto_provider, NoCertVerification, VeilClientConfig, VeilServerConfig};
use donut_wire::{Request, Response};
use rustls::pki_types::ServerName;
use rustls::{version, ClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reality_freedom_fragments_clienthello() {
    // Capture target — records what the freedom egress sends.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = s.read_to_end(&mut got).await;
        let _ = tx.send(got);
    });

    // REALITY node, freedom egress with fragmentation enabled.
    let priv_bytes = [0x44u8; 32];
    let short_id: ShortId = "deadbeef".parse().unwrap();
    let veil = VeilServerConfig::new(priv_bytes, [short_id]).unwrap();
    let server_pub = veil.public_key_bytes();
    let user = UserId::new_v4();
    let outbounds = Arc::new(
        Outbounds::build(&[], Some(FragmentParams { len: (64, 64), interval_ms: (0, 0) })).unwrap(),
    );
    let server_addr = run_reality_proxy(
        "127.0.0.1:0".parse().unwrap(),
        veil,
        target_addr, // decoy (unused on the authed path)
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(&["1.1.1.1".parse().unwrap()], "cloudflare-dns.com")),
        outbounds,
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind reality server");

    // REALITY client (flow=none).
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
    .expect("handshake timeout")
    .expect("handshake");

    let target_v4 = match target_addr.ip() {
        std::net::IpAddr::V4(v) => v,
        _ => unreachable!(),
    };
    let request = Request {
        user,
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(Address::ipv4(target_v4), target_addr.port())),
        seed: vec![],
    };
    // Payload = a synthetic ClientHello record (what would go to e.g. YouTube).
    let body = vec![0x01u8; 250];
    let mut hello = vec![0x16, 0x03, 0x01, (body.len() >> 8) as u8, (body.len() & 0xff) as u8];
    hello.extend_from_slice(&body);

    let mut framed = BytesMut::with_capacity(request.encoded_len() + hello.len());
    request.encode(&mut framed);
    framed.extend_from_slice(&hello);
    tls.write_all(&framed).await.unwrap();
    tls.flush().await.unwrap();

    // Drain the server's VLESS response prefix, then close so the capture ends.
    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), tls.read_exact(&mut prefix))
        .await
        .expect("prefix timeout")
        .unwrap();
    let mut pv = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut pv).expect("response");
    drop(tls);

    let got = timeout(Duration::from_secs(5), rx)
        .await
        .expect("target read timeout")
        .expect("target recv");

    let mut i = 0;
    let mut records = 0;
    let mut reassembled = Vec::new();
    while i + 5 <= got.len() && reassembled.len() < body.len() {
        assert_eq!(got[i], 0x16, "fragment {records} is a handshake record");
        let l = u16::from_be_bytes([got[i + 3], got[i + 4]]) as usize;
        reassembled.extend_from_slice(&got[i + 5..i + 5 + l]);
        i += 5 + l;
        records += 1;
    }
    assert!(records > 1, "ClientHello must arrive fragmented (got {records} record(s))");
    assert_eq!(reassembled, body, "fragmentation preserves the ClientHello");
}
