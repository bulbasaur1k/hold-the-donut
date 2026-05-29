//! End-to-end test for the cert-based **TLS carrier** transport
//! (`transport = "tls"`): donut-server terminates TLS itself, the secret
//! path is a full-duplex carrier tunnel, and every other request is
//! self-stolen to a decoy backend. No reverse proxy in the path.

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
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

const SECRET: &str = "/store/sync";

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(key.serialize_der().into());
    (cert_der, key_der)
}

fn client_tls(cert: CertificateDer<'static>) -> TlsConnector {
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

#[tokio::test]
async fn tls_carrier_tunnel_and_self_steal() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = gen_cert();

    // Echo TCP server (tunnel target).
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
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

    // Minimal HTTP/1.1 decoy backend.
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
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

    // donut-server TLS carrier with the secret path + decoy.
    let user = UserId::new_v4();
    let addr = donut_server::run_tls_carrier_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        SECRET.to_string(),
        donut_carrier::Mode::StreamOne,
        Some(decoy_addr),
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind tls carrier");

    let connector = client_tls(cert);
    let sni = ServerName::try_from("localhost").unwrap();

    // 1) Tunnel: TLS + carrier at the secret path, VLESS frame → echo.
    {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls = connector.connect(sni.clone(), tcp).await.unwrap();
        let cfg = donut_carrier::ClientConfig {
            mode: donut_carrier::Mode::StreamOne,
            path_prefix: SECRET.to_string(),
            ..donut_carrier::ClientConfig::default()
        };
        let mut carrier = timeout(
            Duration::from_secs(5),
            donut_carrier::client::dial_over_stream(tls, &cfg),
        )
        .await
        .expect("dial timeout")
        .expect("carrier dial");

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
        let mut framed = BytesMut::with_capacity(request.encoded_len() + 8);
        request.encode(&mut framed);
        framed.extend_from_slice(b"hello-tls");
        carrier.write_all(&framed).await.unwrap();
        carrier.flush().await.unwrap();

        let mut prefix = [0u8; 2];
        timeout(Duration::from_secs(5), carrier.read_exact(&mut prefix))
            .await
            .expect("prefix timeout")
            .unwrap();
        let mut pv = bytes::Bytes::copy_from_slice(&prefix);
        Response::decode(&mut pv).expect("response decode");

        let mut got = vec![0u8; b"hello-tls".len()];
        timeout(Duration::from_secs(5), carrier.read_exact(&mut got))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(got, b"hello-tls", "tunnel must echo");
    }

    // 2) Self-steal: a plain GET to a non-secret path → decoy site.
    {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector.connect(sni, tcp).await.unwrap();
        tls.write_all(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        timeout(Duration::from_secs(5), tls.read_to_end(&mut resp))
            .await
            .expect("decoy read timeout")
            .unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("DECOY-SITE"), "expected decoy, got: {text}");
    }
}

/// HTTP/2 probe to a non-secret path must also self-steal to the decoy.
/// h2 callers carry the authority in `:authority` (not a `host` header),
/// so the decoy reverse-proxy must derive the upstream Host from it — a
/// regression guard against the "missing required Host header" 400.
#[tokio::test]
async fn tls_carrier_self_steal_over_h2() {
    use http_body_util::BodyExt;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cert, key) = gen_cert();

    // Minimal HTTP/1.1 decoy backend (one request per connection).
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
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

    let addr = donut_server::run_tls_carrier_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        SECRET.to_string(),
        donut_carrier::Mode::StreamOne,
        Some(decoy_addr),
        Arc::new(UserAuth::new(vec![UserId::new_v4()])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind tls carrier");

    // TLS client that negotiates h2 via ALPN.
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));
    let sni = ServerName::try_from("localhost").unwrap();

    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls_stream = connector.connect(sni, tcp).await.unwrap();
    {
        let (_, conn) = tls_stream.get_ref();
        assert_eq!(
            conn.alpn_protocol(),
            Some(&b"h2"[..]),
            "server must offer h2 in ALPN"
        );
    }

    let (mut sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(tls_stream),
    )
    .await
    .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("GET")
        .uri("https://localhost/index.html")
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = timeout(Duration::from_secs(5), sender.send_request(req))
        .await
        .expect("h2 request timeout")
        .expect("h2 send_request");
    assert_eq!(resp.status(), 200, "h2 self-steal must return decoy 200");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("DECOY-SITE"),
        "expected decoy body over h2"
    );
}
