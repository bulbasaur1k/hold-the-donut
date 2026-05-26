//! End-to-end test for the cert-based **carrier backend** (Caddy-front,
//! no REALITY). Validates that `run_carrier_backend`:
//! 1. serves the `stream-one` carrier at a non-default **secret path**,
//! 2. decodes the VLESS inner frame,
//! 3. honours the routing table (freedom → direct outbound),
//! 4. relays bytes both ways.
//!
//! This is the server half of the `transport = "carrier"` path that sits
//! behind Caddy; the client reaches it through Caddy's reverse_proxy of
//! the same secret path.

use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_core::{Address, Command, Endpoint, FlowKind, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_wire::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[tokio::test]
async fn carrier_backend_relays_over_secret_path() {
    const SECRET_PATH: &str = "/store/sync";

    // 1. Echo TCP server (the "upstream" the tunnel targets).
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

    // 2. donut-server carrier backend on a secret path (what Caddy
    //    reverse-proxies to). No REALITY, no TLS — the front terminates.
    let user = UserId::new_v4();
    let backend_addr = donut_server::run_carrier_backend(
        "127.0.0.1:0".parse().unwrap(),
        SECRET_PATH.to_string(),
        donut_carrier::Mode::StreamOne,
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        donut_server::Metrics::new(),
    )
    .await
    .expect("bind carrier backend");

    // 3. Carrier client → backend, using the SAME secret path prefix.
    //    A request to the default "/" path would be rejected.
    let client_cfg = donut_carrier::ClientConfig {
        mode: donut_carrier::Mode::StreamOne,
        path_prefix: SECRET_PATH.to_string(),
        ..donut_carrier::ClientConfig::default()
    };
    let mut stream = timeout(
        Duration::from_secs(5),
        donut_carrier::client::dial(backend_addr, &client_cfg),
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
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 16);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-xhttp-backend");
    stream.write_all(&framed).await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();

    // Drain the Response prefix, then read the echoed payload.
    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut prefix))
        .await
        .expect("response prefix read")
        .unwrap();
    let mut prefix_view = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut prefix_view).expect("response decode");

    let mut got = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
        .await
        .expect("read echo timeout")
        .unwrap();
    assert_eq!(got, b"hello-xhttp-backend");
}

/// #9 regression: behind a reverse proxy / CDN, `stream-up` must pair the
/// uplink POST and downlink GET that arrive as *separate* backend
/// connections. `Server::serve`'s shared dispatcher makes this work where
/// `stream-one` deadlocks through a Go reverse proxy.
#[tokio::test]
async fn carrier_backend_stream_up_pairs_separate_connections() {
    const SECRET_PATH: &str = "/store/sync";

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

    let user = UserId::new_v4();
    let backend_addr = donut_server::run_carrier_backend(
        "127.0.0.1:0".parse().unwrap(),
        SECRET_PATH.to_string(),
        donut_carrier::Mode::StreamUp,
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        donut_server::Metrics::new(),
    )
    .await
    .expect("bind carrier backend");

    // stream-up client opens two plain-TCP connections (uplink POST,
    // downlink GET) — the dispatcher pairs them by session id.
    let client_cfg = donut_carrier::ClientConfig {
        mode: donut_carrier::Mode::StreamUp,
        path_prefix: SECRET_PATH.to_string(),
        ..donut_carrier::ClientConfig::default()
    };
    let mut stream = timeout(
        Duration::from_secs(5),
        donut_carrier::client::dial(backend_addr, &client_cfg),
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
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 16);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-stream-up");
    stream.write_all(&framed).await.unwrap();
    stream.flush().await.unwrap();

    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut prefix))
        .await
        .expect("response prefix read")
        .unwrap();
    let mut prefix_view = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut prefix_view).expect("response decode");

    let mut got = vec![0u8; b"hello-stream-up".len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut got))
        .await
        .expect("read echo timeout")
        .unwrap();
    assert_eq!(got, b"hello-stream-up");
}
