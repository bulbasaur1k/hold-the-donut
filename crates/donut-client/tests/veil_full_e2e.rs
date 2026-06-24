//! Capstone e2e: the whole scenario-2 path end-to-end over REALITY.
//!
//! SOCKS5 client → donut-client (veiled-TLS dial) → donut-server
//! (selfsteal triage → Tunnel → TLS terminate → carrier serve) →
//! freedom outbound → TCP echo target.
//!
//! Proves the composed stack works as an actual proxy: a SOCKS5 app
//! reaches an upstream target through the veiled REALITY tunnel.

use std::sync::Arc;
use std::time::Duration;

use donut_client::{run_veil_socks_proxy, VeilClient};
use donut_core::{ShortId, UserAuth, UserId};
use donut_dns::Resolver;
use donut_routing::{Router, Rule};
use donut_server::run_veil_proxy;
use donut_veil::{VeilClientConfig, VeilServerConfig};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_through_veiled_reality_tunnel_to_echo() {
    // 1. Upstream echo target.
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

    // A decoy backdrop (needed to build the veil server; unused on the
    // authenticated path).
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            if decoy.accept().await.is_err() {
                return;
            }
        }
    });

    // 2. Veil keypair shared by server + client.
    let (cert, key) = gen_cert();
    let priv_bytes = [0x11u8; 32];
    let short_id: ShortId = "deadbeef".parse().unwrap();
    let veil_server = VeilServerConfig::new(priv_bytes, [short_id]).unwrap();
    let server_pub = veil_server.public_key_bytes();
    let veil_client_cfg = VeilClientConfig::new(server_pub, short_id, [26, 4, 15]);

    // 3. donut-server veiled proxy with a known allowed UUID.
    let user = UserId::new_v4();
    let server_addr = run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        veil_server,
        decoy_addr,
        Arc::new(UserAuth::new(vec![user])),
        Arc::new(Router::new("freedom")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        Arc::new(donut_server::Outbounds::default()),
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind veil server");

    // 4. donut-client veiled SOCKS5 inbound pointing at the server,
    //    presenting the matching UUID.
    let veil_client = VeilClient::new(veil_client_cfg, ServerName::try_from("localhost").unwrap());
    let socks_addr = run_veil_socks_proxy(
        "127.0.0.1:0".parse().unwrap(),
        veil_client,
        server_addr,
        user,
        Arc::new(Router::new("proxy")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
    )
    .await
    .expect("bind veil socks");

    // 5. Hand-crafted SOCKS5 client through the whole chain.
    let mut client = timeout(Duration::from_secs(5), TcpStream::connect(socks_addr))
        .await
        .expect("connect socks timeout")
        .unwrap();

    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    let v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => unreachable!("ephemeral 127.0.0.1 is v4"),
    };
    let port = echo_addr.port().to_be_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4);
    req.extend_from_slice(&port);
    client.write_all(&req).await.unwrap();

    let mut reply_head = [0u8; 4];
    timeout(Duration::from_secs(5), client.read_exact(&mut reply_head))
        .await
        .expect("socks reply timeout")
        .unwrap();
    assert_eq!(reply_head[0], 0x05);
    assert_eq!(reply_head[1], 0x00, "REP=succeeded");
    let bound_len = match reply_head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        atyp => panic!("unexpected ATYP {atyp}"),
    };
    let mut bound = vec![0u8; bound_len];
    client.read_exact(&mut bound).await.unwrap();

    // Transparent pipe to the echo target through the veiled tunnel.
    client.write_all(b"hello-veil-reality").await.unwrap();
    client.flush().await.unwrap();
    client.shutdown().await.unwrap();

    let mut echoed = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut echoed))
        .await
        .expect("read echoed timeout")
        .unwrap();
    assert_eq!(echoed, b"hello-veil-reality");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blackhole_rule_drops_proxied_connection() {
    // Echo target on loopback — which the routing rule blocks.
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
            });
        }
    });

    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            if decoy.accept().await.is_err() {
                return;
            }
        }
    });

    let (cert, key) = gen_cert();
    let priv_bytes = [0x11u8; 32];
    let short_id: ShortId = "deadbeef".parse().unwrap();
    let veil_server = VeilServerConfig::new(priv_bytes, [short_id]).unwrap();
    let server_pub = veil_server.public_key_bytes();
    let veil_client_cfg = VeilClientConfig::new(server_pub, short_id, [26, 4, 15]);

    // Route every loopback target to `block`.
    let router = Arc::new(
        Router::new("freedom").with_rule(Rule::to("block").cidr("127.0.0.0/8".parse().unwrap())),
    );
    let user = UserId::new_v4();
    let server_addr = run_veil_proxy(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        veil_server,
        decoy_addr,
        Arc::new(UserAuth::new(vec![user])),
        router,
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
        Arc::new(donut_server::Outbounds::default()),
        donut_server::Metrics::new(),
        donut_server::RuntimeTuning::default(),
    )
    .await
    .expect("bind veil server");

    let veil_client = VeilClient::new(veil_client_cfg, ServerName::try_from("localhost").unwrap());
    let socks_addr = run_veil_socks_proxy(
        "127.0.0.1:0".parse().unwrap(),
        veil_client,
        server_addr,
        user,
        Arc::new(Router::new("proxy")),
        Arc::new(Resolver::doh(
            &["1.1.1.1".parse().unwrap()],
            "cloudflare-dns.com",
        )),
    )
    .await
    .expect("bind veil socks");

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    let v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => unreachable!("ephemeral 127.0.0.1 is v4"),
    };
    let port = echo_addr.port().to_be_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4);
    req.extend_from_slice(&port);
    client.write_all(&req).await.unwrap();

    // The server blackholes the target, so the tunnel closes before any
    // successful SOCKS CONNECT reply: the read either hits EOF or returns
    // a non-success reply.
    let mut reply_head = [0u8; 4];
    let res = timeout(Duration::from_secs(5), client.read_exact(&mut reply_head))
        .await
        .expect("blackhole read should not hang");
    match res {
        Err(_) => {} // tunnel closed → blocked
        Ok(_) => assert_ne!(
            reply_head[1], 0x00,
            "blocked target must not report SOCKS success"
        ),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_rule_bypasses_the_server() {
    // Echo target on loopback. A `direct` split-tunnel rule must reach it
    // even though the configured server is unreachable — proving the
    // client dials it locally (keeping the local IP), not via the tunnel.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = match echo_listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // Veil client pointed at an unreachable server (closed port).
    let veil_cfg = VeilClientConfig::new([0u8; 32], "deadbeef".parse().unwrap(), [26, 4, 15]);
    let veil_client = VeilClient::new(veil_cfg, ServerName::try_from("localhost").unwrap());
    let unreachable_server = "127.0.0.1:1".parse::<std::net::SocketAddr>().unwrap();

    // Loopback → direct (everything else would go to the dead tunnel).
    let router = Arc::new(
        Router::new("proxy").with_rule(Rule::to("direct").cidr("127.0.0.0/8".parse().unwrap())),
    );
    let resolver = Arc::new(Resolver::doh(
        &["1.1.1.1".parse().unwrap()],
        "cloudflare-dns.com",
    ));

    let socks_addr = run_veil_socks_proxy(
        "127.0.0.1:0".parse().unwrap(),
        veil_client,
        unreachable_server,
        UserId::new_v4(), // direct route never sends a frame to the server
        router,
        resolver,
    )
    .await
    .expect("bind veil socks");

    let mut client = TcpStream::connect(socks_addr).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    let v4 = match echo_addr.ip() {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => unreachable!("ephemeral 127.0.0.1 is v4"),
    };
    let port = echo_addr.port().to_be_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&v4);
    req.extend_from_slice(&port);
    client.write_all(&req).await.unwrap();

    let mut reply_head = [0u8; 4];
    timeout(Duration::from_secs(5), client.read_exact(&mut reply_head))
        .await
        .expect("socks reply timeout")
        .unwrap();
    assert_eq!(reply_head[1], 0x00, "direct dial must succeed via SOCKS");
    let bound_len = match reply_head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        atyp => panic!("unexpected ATYP {atyp}"),
    };
    let mut bound = vec![0u8; bound_len];
    client.read_exact(&mut bound).await.unwrap();

    client.write_all(b"direct-hello").await.unwrap();
    client.flush().await.unwrap();
    client.shutdown().await.unwrap();

    let mut echoed = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut echoed))
        .await
        .expect("read echoed timeout")
        .unwrap();
    assert_eq!(
        echoed, b"direct-hello",
        "direct path round-trips without the server"
    );
}
