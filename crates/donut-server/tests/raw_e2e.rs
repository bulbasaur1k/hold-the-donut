//! End-to-end test for the cert-based **RAW** transport (`transport =
//! "raw"`): VLESS straight over TLS 1.3 (no carrier wrapping). The first
//! decrypted byte triages the connection — a VLESS frame (`0x00`) is
//! proxied to its target; anything else (an HTTP probe) is self-stolen to
//! the decoy backend.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use donut_core::{Address, Command, Endpoint, FlowKind, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::Router;
use donut_wire::{Request, Response};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());
    (cert_der, key_der)
}

fn client_connector(cert: CertificateDer<'static>) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(tls))
}

async fn spawn_echo() -> SocketAddr {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match echo.accept().await {
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

async fn spawn_decoy() -> SocketAddr {
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = decoy.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match decoy.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let body = b"DECOY-SITE";
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
    addr
}

async fn start_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    auth: Arc<UserAuth>,
) -> (SocketAddr, SocketAddr) {
    let echo_addr = spawn_echo().await;
    let decoy_addr = spawn_decoy().await;
    let addr = donut_server::run_raw_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert],
        key,
        Some(decoy_addr),
        donut_server::VisionDialect::Donut,
        auth,
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        donut_server::Metrics::new(),
    )
    .await
    .expect("bind raw proxy");
    (addr, echo_addr)
}

#[tokio::test]
async fn raw_tunnel_echo() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = gen_cert();
    let connector = client_connector(cert.clone());
    let user = UserId::new_v4();
    let (addr, echo_addr) = start_server(cert, key, Arc::new(UserAuth::new(vec![user]))).await;

    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sni, tcp).await.unwrap();

    let request = Request {
        user,
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(
            Address::ipv4(match echo_addr.ip() {
                std::net::IpAddr::V4(v) => v,
                _ => unreachable!(),
            }),
            echo_addr.port(),
        )),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 16);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-raw");
    tls.write_all(&framed).await.unwrap();
    tls.flush().await.unwrap();

    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), tls.read_exact(&mut prefix))
        .await
        .expect("prefix timeout")
        .unwrap();
    let mut pv = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut pv).expect("response decode");

    let mut got = vec![0u8; b"hello-raw".len()];
    timeout(Duration::from_secs(5), tls.read_exact(&mut got))
        .await
        .expect("echo timeout")
        .unwrap();
    assert_eq!(got, b"hello-raw", "raw tunnel must echo");
}

#[tokio::test]
async fn raw_vision_tunnel_echo() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = gen_cert();
    let connector = client_connector(cert.clone());
    let user = UserId::new_v4();
    let (addr, echo_addr) = start_server(cert, key, Arc::new(UserAuth::new(vec![user]))).await;

    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sni, tcp).await.unwrap();

    // VLESS Request carrying the XTLS-Vision flow.
    let request = Request {
        user,
        flow: FlowKind::Extended,
        command: Command::Tcp,
        target: Some(Endpoint::new(
            Address::ipv4(match echo_addr.ip() {
                std::net::IpAddr::V4(v) => v,
                _ => unreachable!(),
            }),
            echo_addr.port(),
        )),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len());
    request.encode(&mut framed);
    tls.write_all(&framed).await.unwrap();
    tls.flush().await.unwrap();

    // The Response prefix is sent raw, before the Vision data-plane.
    let mut prefix = [0u8; 2];
    timeout(Duration::from_secs(5), tls.read_exact(&mut prefix))
        .await
        .expect("prefix timeout")
        .unwrap();
    let mut pv = bytes::Bytes::copy_from_slice(&prefix);
    Response::decode(&mut pv).expect("response decode");

    // Data-plane is Vision-framed: encode the payload up, decode the echo
    // back down. A full round-trip through the padded + raw phases must
    // reproduce every byte.
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let (mut rd, mut wr) = tokio::io::split(tls);
    let p2 = payload.clone();
    let enc = tokio::spawn(async move {
        let mut src = std::io::Cursor::new(p2);
        donut_io::vision::encode_copy(&mut src, &mut wr, donut_io::vision::VisionConfig::default())
            .await
    });
    let mut sink: Vec<u8> = Vec::new();
    timeout(
        Duration::from_secs(10),
        donut_io::vision::decode_copy(&mut rd, &mut sink),
    )
    .await
    .expect("vision decode timeout")
    .unwrap();
    enc.await.unwrap().unwrap();
    assert_eq!(sink, payload, "vision tunnel must echo the full payload");
}

#[tokio::test]
async fn raw_self_steal() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = gen_cert();
    let connector = client_connector(cert.clone());
    let (addr, _echo) =
        start_server(cert, key, Arc::new(UserAuth::new(vec![UserId::new_v4()]))).await;

    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sni, tcp).await.unwrap();
    // An HTTP probe (first byte 'G' != VLESS 0x00) must self-steal.
    tls.write_all(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    // Read the decoy response. The decoy uses `Connection: close` and may
    // drop the socket without a TLS close_notify, so tolerate an abrupt
    // EOF — the response bytes themselves are what matters.
    let mut resp = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        match timeout(Duration::from_secs(5), tls.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
        }
        if resp.windows(10).any(|w| w == b"DECOY-SITE") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&resp);
    assert!(text.contains("DECOY-SITE"), "raw self-steal must reach decoy, got: {text}");
}

/// A protocol-conformant VLESS frame carrying a UUID that is **not** in
/// the server's allowed-user set must be dropped before reaching the
/// target — no Response prefix, the tunnel just closes. This is the
/// regression guard for the auth bypass (any UUID was previously
/// accepted and proxied).
#[tokio::test]
async fn raw_rejects_unknown_uuid() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = gen_cert();
    let connector = client_connector(cert.clone());

    // The server allows exactly one UUID; the client presents a different one.
    let allowed = UserId::new_v4();
    let (addr, echo_addr) = start_server(cert, key, Arc::new(UserAuth::new(vec![allowed]))).await;

    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(sni, tcp).await.unwrap();

    let request = Request {
        user: UserId::new_v4(), // not `allowed`
        flow: FlowKind::None,
        command: Command::Tcp,
        target: Some(Endpoint::new(
            Address::ipv4(match echo_addr.ip() {
                std::net::IpAddr::V4(v) => v,
                _ => unreachable!(),
            }),
            echo_addr.port(),
        )),
        seed: vec![],
    };
    let mut framed = BytesMut::with_capacity(request.encoded_len() + 16);
    request.encode(&mut framed);
    framed.extend_from_slice(b"hello-raw");
    tls.write_all(&framed).await.unwrap();
    tls.flush().await.unwrap();

    // The server drops the session without writing a Response prefix, so
    // the read must end in EOF — never the echoed payload.
    let mut prefix = [0u8; 2];
    let res = timeout(Duration::from_secs(5), tls.read_exact(&mut prefix))
        .await
        .expect("read must not hang");
    assert!(
        res.is_err(),
        "unauthorized UUID must be dropped (got a response prefix instead)",
    );
}
