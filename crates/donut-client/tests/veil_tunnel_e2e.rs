//! Veiled-TLS tunnel e2e (M6 step 2b + M7 step 2): an authenticated
//! veil client dials the server, the server's triage decides `Tunnel`,
//! terminates TLS, and the decrypted byte stream round-trips an echo.
//!
//! This exercises the full veil handshake over real async sockets with
//! both hooks engaged (client mutator + server raw-CH hook) and the
//! `PrefixedStream` replay of the consumed ClientHello.

use std::sync::Arc;
use std::time::Duration;

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
async fn authenticated_client_tunnels_through_veiled_tls() {
    eprintln!("step: start");
    let (cert, key) = gen_cert();

    // A decoy is required to construct the server, though the tunnel
    // path never relays to it.
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = decoy.accept().await;
    });

    // Matched veil keypair + short id.
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
            let (tcp, _) = listener.accept().await.unwrap();
            eprintln!("server: accepted");
            match server.handle(tcp).await.unwrap() {
                Some(mut tls) => {
                    eprintln!("server: tunnel established, echoing");
                    let mut buf = vec![0u8; 1024];
                    let n = tls.read(&mut buf).await.unwrap();
                    tls.write_all(&buf[..n]).await.unwrap();
                    tls.flush().await.unwrap();
                }
                None => panic!("authenticated client must tunnel, not forward"),
            }
        });
    }

    // Client trusts the server's self-signed cert (M3 simplification).
    let client = VeilClient::new(veil_client, ServerName::try_from("localhost").unwrap());

    let mut tls = tokio::time::timeout(Duration::from_secs(5), client.connect(server_addr))
        .await
        .expect("veil connect timed out")
        .expect("veil handshake");
    eprintln!("client: handshake ok");

    tls.write_all(b"hello veil").await.unwrap();
    tls.flush().await.unwrap();

    let mut got = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut got))
        .await
        .expect("echo read timed out")
        .expect("read echo");
    assert_eq!(
        &got, b"hello veil",
        "decrypted payload round-trips through the tunnel"
    );
    eprintln!("tunnel verified");
}
