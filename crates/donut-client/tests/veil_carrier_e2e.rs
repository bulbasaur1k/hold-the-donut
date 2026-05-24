//! Full inner-stack e2e (M6 step 2c): the XHTTP `stream-one` carrier
//! rides on top of the decrypted veiled-TLS stream on **both** sides.
//!
//! Chain: VeilClient → veiled-TLS → carrier dial_over_stream
//!        ↔ VeilServer (triage→Tunnel→TLS terminate) → carrier
//!          serve_connection → Session → echo.
//!
//! Proves `serve_connection` / `dial_over_stream` compose with the veil
//! tunnel: a byte payload round-trips through the carrier over TLS.

use std::sync::Arc;
use std::time::Duration;

use donut_carrier::{
    client::dial_over_stream, server::serve_connection, ClientConfig, Mode, ServerConfig,
};
use donut_client::VeilClient;
use donut_core::ShortId;
use donut_server::VeilServer;
use donut_veil::{VeilClientConfig, VeilServerConfig};
use rcgen::CertificateParams;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
async fn carrier_rides_on_veiled_tls_tunnel() {
    eprintln!("step: start");
    let (cert, key) = gen_cert();

    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = decoy.accept().await;
    });

    let priv_bytes = [0x11u8; 32];
    let short_id: ShortId = "deadbeef".parse().unwrap();
    let veil_server = VeilServerConfig::new(priv_bytes, [short_id]).unwrap();
    let server_pub = veil_server.public_key_bytes();
    let veil_client = VeilClientConfig::new(server_pub, short_id, [26, 4, 15]);

    let server =
        Arc::new(VeilServer::new(vec![cert.clone()], key, veil_server, decoy_addr).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    {
        let server = server.clone();
        tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.unwrap();
            eprintln!("server: accepted");
            let tls = server
                .handle(tcp)
                .await
                .unwrap()
                .expect("authenticated client must tunnel");
            eprintln!("server: tunnel up; serving carrier");
            let mut rx = serve_connection(
                tls,
                ServerConfig {
                    mode: Mode::StreamOne,
                    ..ServerConfig::default()
                },
                peer,
            );
            let mut session = rx.recv().await.expect("carrier session");
            eprintln!("server: carrier session opened, echoing");
            let mut buf = vec![0u8; 1024];
            let n = session.stream.read(&mut buf).await.unwrap();
            session.stream.write_all(&buf[..n]).await.unwrap();
            session.stream.flush().await.unwrap();
        });
    }

    let client = VeilClient::new(veil_client, ServerName::try_from("localhost").unwrap());

    let tls = tokio::time::timeout(Duration::from_secs(5), client.connect(server_addr))
        .await
        .expect("veil connect timed out")
        .expect("veil handshake");
    eprintln!("client: tunnel up; dialing carrier");

    let client_cfg = ClientConfig {
        mode: Mode::StreamOne,
        ..ClientConfig::default()
    };
    let mut carrier =
        tokio::time::timeout(Duration::from_secs(5), dial_over_stream(tls, &client_cfg))
            .await
            .expect("carrier dial timed out")
            .expect("carrier dial");
    eprintln!("client: carrier stream open");

    carrier.write_all(b"hello carrier").await.unwrap();
    carrier.flush().await.unwrap();

    let mut got = [0u8; 13];
    tokio::time::timeout(Duration::from_secs(5), carrier.read_exact(&mut got))
        .await
        .expect("carrier echo timed out")
        .expect("read carrier echo");
    assert_eq!(
        &got, b"hello carrier",
        "payload round-trips through carrier-over-veiled-TLS"
    );
    eprintln!("carrier-over-tunnel verified");
}
