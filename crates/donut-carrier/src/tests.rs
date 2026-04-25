//! End-to-end tests for the carrier transport.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::client::dial;
use crate::config::{ClientConfig, ServerConfig};
use crate::mode::Mode;
use crate::server::Server;

#[tokio::test]
async fn stream_one_round_trip_path_session() {
    // Spin up a carrier server on an ephemeral port.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_cfg = ServerConfig {
        mode: Mode::StreamOne,
        ..ServerConfig::default()
    };
    let mut server = Server::serve(listener, server_cfg);

    // Server task: accept one session and echo upstream → downstream.
    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        let mut buf = [0u8; 64];
        let n = session.stream.read(&mut buf).await.unwrap();
        let payload = &buf[..n];
        session.stream.write_all(b"echo:").await.unwrap();
        session.stream.write_all(payload).await.unwrap();
        session.stream.flush().await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    // Client side: dial and exchange a small message.
    let client_cfg = ClientConfig {
        mode: Mode::StreamOne,
        ..ClientConfig::default()
    };
    let mut stream = timeout(Duration::from_secs(5), dial(addr, &client_cfg))
        .await
        .expect("dial timeout")
        .expect("dial succeeds");

    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();

    let mut downlink = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut downlink))
        .await
        .expect("read timeout")
        .unwrap();

    assert_eq!(downlink, b"echo:hello");
    server_task.await.unwrap();
}

#[tokio::test]
async fn stream_one_relays_chunked_data() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut server = Server::serve(
        listener,
        ServerConfig {
            mode: Mode::StreamOne,
            ..ServerConfig::default()
        },
    );

    let payload: Vec<u8> = (0..64 * 1024).map(|i| (i & 0xff) as u8).collect();
    let payload_for_server = payload.clone();

    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.unwrap();
        let mut got = Vec::with_capacity(payload_for_server.len());
        let mut buf = [0u8; 4096];
        loop {
            let n = session.stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.len() >= payload_for_server.len() {
                break;
            }
        }
        assert_eq!(got, payload_for_server);
        session.stream.write_all(&got).await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let client_cfg = ClientConfig {
        mode: Mode::StreamOne,
        ..ClientConfig::default()
    };
    let mut stream = dial(addr, &client_cfg).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.shutdown().await.unwrap();

    let mut got = Vec::with_capacity(payload.len());
    timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.len(), payload.len());
    assert_eq!(got, payload);
    server_task.await.unwrap();
}

#[tokio::test]
async fn stream_up_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = ServerConfig {
        mode: Mode::StreamUp,
        ..ServerConfig::default()
    };
    let mut server = Server::serve(listener, server_cfg);

    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        let mut buf = [0u8; 64];
        let n = session.stream.read(&mut buf).await.unwrap();
        let payload = &buf[..n];
        session.stream.write_all(b"echo:").await.unwrap();
        session.stream.write_all(payload).await.unwrap();
        session.stream.flush().await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let client_cfg = ClientConfig {
        mode: Mode::StreamUp,
        ..ClientConfig::default()
    };
    let mut stream = timeout(Duration::from_secs(5), dial(addr, &client_cfg))
        .await
        .expect("dial timeout")
        .expect("dial succeeds");

    stream.write_all(b"world").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();

    let mut downlink = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut downlink))
        .await
        .expect("read timeout")
        .unwrap();

    assert_eq!(downlink, b"echo:world");
    server_task.await.unwrap();
}

#[tokio::test]
async fn packet_up_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_cfg = ServerConfig {
        mode: Mode::PacketUp,
        ..ServerConfig::default()
    };
    let mut server = Server::serve(listener, server_cfg);

    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        // Read the whole uplink (client closes after writing).
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = session.stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.ends_with(b"END") {
                break;
            }
        }
        session.stream.write_all(b"echo:").await.unwrap();
        session.stream.write_all(&got).await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let client_cfg = ClientConfig {
        mode: Mode::PacketUp,
        ..ClientConfig::default()
    };
    let mut stream = timeout(Duration::from_secs(5), dial(addr, &client_cfg))
        .await
        .expect("dial timeout")
        .expect("dial succeeds");

    // Write three sequential pieces — they will become three sequenced POSTs.
    stream.write_all(b"hello-").await.unwrap();
    stream.flush().await.unwrap();
    stream.write_all(b"packet-").await.unwrap();
    stream.flush().await.unwrap();
    stream.write_all(b"up-END").await.unwrap();
    stream.shutdown().await.unwrap();

    let mut downlink = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut downlink))
        .await
        .expect("read timeout")
        .unwrap();

    assert_eq!(downlink, b"echo:hello-packet-up-END");
    server_task.await.unwrap();
}
