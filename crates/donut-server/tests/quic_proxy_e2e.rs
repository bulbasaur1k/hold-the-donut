//! End-to-end test for the direct **QUIC / HTTP-3 proxy**
//! (`transport = "quic"`, no Caddy in front).
//!
//! Spins up an echo server, `run_quic_proxy` with a self-signed cert,
//! and an H3 carrier client that opens a session, pushes a VLESS inner
//! frame targeting the echo server, and verifies the echoed payload.
//! Validates: QUIC/H3 termination → full-duplex carrier → VLESS decode →
//! routed outbound → `copy_bidirectional`.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_core::{Address, Command, Endpoint, FlowKind, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_wire::{Request, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());
    (cert_der, key_der)
}

#[tokio::test]
async fn quic_proxy_relays_payload_over_h3() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Echo TCP server.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match echo_listener.accept().await {
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

    // 2. donut-server QUIC/H3 proxy with a self-signed cert.
    let (cert, key) = gen_cert();
    let user = UserId::new_v4();
    let quic_addr = donut_server::run_quic_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        "/".to_string(),
        None,
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        donut_server::Metrics::new(),
    )
    .await
    .expect("bind quic proxy");

    // 3. H3 carrier client → proxy. Trust the self-signed cert.
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut stream = timeout(
        Duration::from_secs(5),
        donut_quic::client::dial_stream_one(quic_addr, "localhost", roots, "/"),
    )
    .await
    .expect("h3 dial timeout")
    .expect("h3 dial");

    // VLESS inner frame targeting the echo server, then payload.
    let request = Request {
        user,
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(
            Address::ipv4(match echo_addr.ip() {
                std::net::IpAddr::V4(v) => v,
                _ => unreachable!("ephemeral 127.0.0.1 is v4"),
            }),
            echo_addr.port(),
        )),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 16);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-over-h3");
    stream.write_all(&framed).await.unwrap();
    stream.flush().await.unwrap();

    // Drain the Response prefix (must arrive while the stream is still
    // open — proves full-duplex), then read the echo.
    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut prefix))
        .await
        .expect("response prefix read")
        .unwrap();
    let mut prefix_view = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut prefix_view).expect("response decode");

    let mut got = vec![0u8; b"hello-over-h3".len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut got))
        .await
        .expect("echo read timeout")
        .unwrap();
    assert_eq!(got, b"hello-over-h3");
}
