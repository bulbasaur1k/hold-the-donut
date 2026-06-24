//! Fragment e2e: with `[fragment]` enabled, a client's TLS ClientHello sent
//! through the freedom (direct) egress arrives at the target split across
//! several TLS records — the sidecar-free SNI de-throttle path.
//!
//! client → donut-server (veil in, freedom out, fragment on) → capture target.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_client::VeilClient;
use donut_core::{Address, Command, Endpoint, FlowKind, ShortId, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_server::{run_veil_proxy, FragmentParams, Outbounds};
use donut_veil::{VeilClientConfig, VeilServerConfig};
use donut_wire::{Request, Response};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn freedom_egress_fragments_clienthello() {
    // Capture target: reads everything the freedom egress sends and reports it.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = s.read_to_end(&mut got).await;
        let _ = tx.send(got);
    });

    // donut-server: veil inbound, freedom egress with fragmentation on.
    let (cert, key) = gen_cert();
    let priv_bytes = [0x33u8; 32];
    let short_id: ShortId = "deadbeef".parse().unwrap();
    let veil_server = VeilServerConfig::new(priv_bytes, [short_id]).unwrap();
    let server_pub = veil_server.public_key_bytes();
    let user = UserId::new_v4();
    let outbounds = Arc::new(
        Outbounds::build(
            &[],
            Some(FragmentParams {
                len: (64, 64),
                interval_ms: (0, 0),
            }),
        )
        .unwrap(),
    );
    let server_addr = run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert],
        key,
        veil_server,
        target_addr, // decoy (unused on the authed path)
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        outbounds,
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind server");

    // Client dials over REALITY + carrier, then sends a VLESS request whose
    // payload is a synthetic TLS ClientHello record.
    let veil_client = VeilClient::new(
        VeilClientConfig::new(server_pub, short_id, [26, 4, 15]),
        ServerName::try_from("localhost").unwrap(),
    );
    let tls = timeout(Duration::from_secs(5), veil_client.connect(server_addr))
        .await
        .expect("connect timeout")
        .expect("connect");
    let carrier_cfg = donut_carrier::ClientConfig {
        mode: donut_carrier::Mode::StreamOne,
        ..donut_carrier::ClientConfig::default()
    };
    let mut carrier = donut_carrier::client::dial_over_stream(tls, &carrier_cfg)
        .await
        .expect("carrier");

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
    // Synthetic ClientHello record: 0x16 0x03 0x01 <len> 0x01 <body>.
    let body = vec![0x01u8; 250];
    let mut hello = vec![
        0x16,
        0x03,
        0x01,
        (body.len() >> 8) as u8,
        (body.len() & 0xff) as u8,
    ];
    hello.extend_from_slice(&body);

    let mut framed = BytesMut::with_capacity(request.encoded_len() + hello.len());
    request.encode(&mut framed);
    framed.extend_from_slice(&hello);
    carrier.write_all(&framed).await.unwrap();
    carrier.flush().await.unwrap();
    carrier.shutdown().await.unwrap();

    // Drain the server's VLESS response prefix.
    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), carrier.read_exact(&mut prefix))
        .await
        .expect("prefix timeout")
        .unwrap();
    let mut pv = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut pv).expect("response");

    // What did the target receive? Parse TLS records, count + reassemble.
    let got = timeout(Duration::from_secs(5), rx)
        .await
        .expect("target read timeout")
        .expect("target recv");

    let mut i = 0;
    let mut records = 0;
    let mut reassembled = Vec::new();
    while i + 5 <= got.len() {
        assert_eq!(got[i], 0x16, "fragment {records} is a handshake record");
        let l = u16::from_be_bytes([got[i + 3], got[i + 4]]) as usize;
        reassembled.extend_from_slice(&got[i + 5..i + 5 + l]);
        i += 5 + l;
        records += 1;
    }
    assert!(
        records > 1,
        "ClientHello must arrive fragmented (got {records} record(s), {} bytes)",
        got.len()
    );
    assert_eq!(reassembled, body, "fragmentation must preserve the ClientHello body");
}
