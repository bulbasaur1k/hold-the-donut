//! End-to-end test for the QUIC + H3 carrier (`stream-one` mode).

use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::client::dial_stream_one;
use crate::server::QuicServer;

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());
    (cert_der, key_der)
}

#[tokio::test]
async fn h3_stream_one_round_trip() {
    install_provider();

    let (cert, key) = gen_cert();

    let mut server = QuicServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        "/".to_string(),
        None,
    )
    .expect("bind QUIC server");
    let addr = server.addr;

    // Server task: accept one session, drain the uplink, echo the
    // payload, then close. Uses the request → response shape that
    // M5 step 1 implements (full bidirectional overlap lands in M5
    // step 2 over raw QUIC bidi streams).
    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = session.stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        session.stream.write_all(b"echo:").await.unwrap();
        session.stream.write_all(&got).await.unwrap();
        session.stream.flush().await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut stream = timeout(
        Duration::from_secs(5),
        dial_stream_one(addr, "localhost", roots, "/"),
    )
    .await
    .expect("dial timeout")
    .expect("dial succeeds");

    stream.write_all(b"hi-h3").await.unwrap();
    stream.flush().await.unwrap();
    stream.shutdown().await.unwrap();

    let mut downlink = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut downlink))
        .await
        .expect("read timeout")
        .unwrap();

    assert_eq!(downlink, b"echo:hi-h3");
    server_task.await.unwrap();
}

#[tokio::test]
async fn h3_full_duplex_round_trip() {
    // Proves the H3 carrier (QuicServer + dial_stream_one) overlaps both
    // directions on one request stream: the server writes a prefix
    // *before* the client has finished its uplink, and the client reads
    // it concurrently with writing. This is what the half-duplex
    // request→response shape could not do.
    install_provider();

    let (cert, key) = gen_cert();

    let mut server = QuicServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        "/".to_string(),
        None,
    )
    .expect("bind QUIC server");
    let addr = server.addr;

    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");
        // Write a downlink prefix immediately, before reading any uplink.
        session.stream.write_all(b"hi-from-server:").await.unwrap();
        session.stream.flush().await.unwrap();
        // Read the uplink up to the "END" sentinel, then echo it.
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
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
        session.stream.write_all(&got).await.unwrap();
        session.stream.flush().await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let stream = timeout(
        Duration::from_secs(5),
        dial_stream_one(addr, "localhost", roots, "/"),
    )
    .await
    .expect("dial timeout")
    .expect("dial succeeds");

    let (mut rd, mut wr) = tokio::io::split(stream);

    // Read the server prefix concurrently with writing the uplink.
    let mut prefix = vec![0u8; b"hi-from-server:".len()];
    let read_first = rd.read_exact(&mut prefix);
    let write = async {
        wr.write_all(b"client-payload-END").await.unwrap();
        wr.flush().await.unwrap();
    };
    let (read_res, _) = tokio::join!(read_first, write);
    read_res.expect("read prefix");
    assert_eq!(prefix, b"hi-from-server:");

    wr.shutdown().await.unwrap();
    let mut tail = Vec::new();
    timeout(Duration::from_secs(5), rd.read_to_end(&mut tail))
        .await
        .expect("tail read timeout")
        .unwrap();
    assert_eq!(tail, b"client-payload-END");

    server_task.await.unwrap();
}

#[tokio::test]
async fn h3_non_secret_path_self_steals_to_decoy() {
    // A request whose path is NOT the secret tunnel path must be
    // reverse-proxied to the decoy backend, so an H3 probe to this port
    // sees the file site, not the tunnel.
    install_provider();
    let (cert, key) = gen_cert();

    // Minimal HTTP/1.1 decoy backend.
    let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match decoy.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await; // consume the request
                let body = b"DECOY-FILE-SITE";
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(body).await;
                let _ = s.shutdown().await;
            });
        }
    });

    let server = QuicServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        "/tunnel".to_string(),
        Some(decoy_addr),
    )
    .expect("bind QUIC server");
    let addr = server.addr;
    // Keep the server (and its endpoint) alive for the duration.
    let _keep = &server;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut stream = timeout(
        Duration::from_secs(5),
        dial_stream_one(addr, "localhost", roots, "/index.html"),
    )
    .await
    .expect("dial timeout")
    .expect("dial succeeds");

    // No tunnel payload: just finish the (empty) uplink and read the
    // decoy response off the downlink.
    stream.shutdown().await.unwrap();
    let mut got = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut got))
        .await
        .expect("read timeout")
        .unwrap();
    assert!(
        String::from_utf8_lossy(&got).contains("DECOY-FILE-SITE"),
        "expected decoy body, got: {:?}",
        String::from_utf8_lossy(&got)
    );
}

#[tokio::test]
async fn bidi_full_duplex_round_trip() {
    install_provider();

    let (cert, key) = gen_cert();

    let mut server =
        crate::bidi::BidiServer::bind("127.0.0.1:0".parse().unwrap(), vec![cert.clone()], key)
            .expect("bind QUIC bidi server");
    let addr = server.addr;

    // Server task: accept one bidi session, read until "END" sentinel,
    // then echo back interleaved. Demonstrates overlapping I/O on
    // the same session — server starts writing the prefix BEFORE the
    // client has finished its uplink.
    let server_task = tokio::spawn(async move {
        let mut session = server.accept().await.expect("server accepts session");

        // Write a prefix immediately, before reading anything.
        session.stream.write_all(b"hi-from-server:").await.unwrap();
        session.stream.flush().await.unwrap();

        // Read all uplink bytes up to "END".
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
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
        // Now echo the uplink we received.
        session.stream.write_all(&got).await.unwrap();
        session.stream.flush().await.unwrap();
        session.stream.shutdown().await.unwrap();
    });

    let stream = timeout(
        Duration::from_secs(5),
        crate::bidi::dial(addr, "localhost", vec![cert]),
    )
    .await
    .expect("dial timeout")
    .expect("dial succeeds");

    let (mut rd, mut wr) = tokio::io::split(stream);

    // Client reads the server prefix concurrently with writing the
    // uplink — full bidirectional overlap.
    let mut downlink_first = vec![0u8; b"hi-from-server:".len()];
    let read_first = rd.read_exact(&mut downlink_first);
    let write = async {
        wr.write_all(b"client-payload-END").await.unwrap();
        wr.flush().await.unwrap();
    };
    let (read_res, _) = tokio::join!(read_first, write);
    read_res.expect("read prefix");
    assert_eq!(downlink_first, b"hi-from-server:");

    // Now read the echoed uplink.
    wr.shutdown().await.unwrap();
    let mut tail = Vec::new();
    timeout(Duration::from_secs(5), rd.read_to_end(&mut tail))
        .await
        .expect("tail read timeout")
        .unwrap();
    assert_eq!(tail, b"client-payload-END");

    server_task.await.unwrap();
}
