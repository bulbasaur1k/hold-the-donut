//! End-to-end proxy test.
//!
//! Spins up:
//! 1. A throwaway TCP echo server on `127.0.0.1:0`.
//! 2. The donut-server `run_carrier_proxy` on another `127.0.0.1:0`.
//! 3. A donut-carrier client that opens a `stream-one` session to
//!    donut-server, writes an inner-frame Request targeting the
//!    echo server, then sends a payload and reads the echoed bytes
//!    back.
//!
//! Validates the full carrier → wire decode → freedom outbound →
//! `copy_bidirectional` chain.

use std::time::Duration;

use std::sync::Arc;

use bytes::BytesMut;
use donut_core::{Address, Command, Endpoint, FlowKind, UserAuth, UserId};
use donut_wire::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[tokio::test]
async fn proxy_relays_payload_to_freedom_target() {
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

    // 2. donut-server proxy.
    let user = UserId::new_v4();
    let proxy_addr = donut_server::run_carrier_proxy(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(UserAuth::new(vec![user])),
    )
    .await
    .expect("bind proxy");

    // 3. Carrier client → proxy. Encode an inner-frame Request that
    //    targets the echo server, then write a payload and read the
    //    echo back.
    let client_cfg = donut_carrier::ClientConfig {
        mode: donut_carrier::Mode::StreamOne,
        ..donut_carrier::ClientConfig::default()
    };
    let mut stream = timeout(
        Duration::from_secs(5),
        donut_carrier::client::dial(proxy_addr, &client_cfg),
    )
    .await
    .expect("carrier dial timeout")
    .expect("carrier dial");

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
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 12);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-proxy");
    stream.write_all(&framed).await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();

    // The proxy emits a Response prefix (version + 0 addons) before
    // the upstream bytes. Drain it first.
    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut prefix))
        .await
        .expect("response prefix read")
        .unwrap();
    let mut prefix_view = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut prefix_view).expect("response decode");

    // Now read the echoed payload.
    let mut got = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
        .await
        .expect("read echo timeout")
        .unwrap();
    assert_eq!(got, b"hello-proxy");
}
