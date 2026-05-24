//! Selfsteal front-door e2e: an unauthenticated TLS client is relayed
//! byte-for-byte to the decoy `dest`, ClientHello included.
//!
//! We generate a *real* (plain, non-veil) ClientHello with the forked
//! rustls and verify both relay directions independently:
//!   * dest → client: the decoy greets immediately; the client must
//!     receive that banner through the relay.
//!   * client → dest: the decoy collects everything it received; it
//!     must equal exactly the ClientHello + trailing marker the client
//!     sent (proving byte-transparent forwarding, ClientHello included).

use std::sync::Arc;
use std::time::Duration;

use donut_server::{triage, Triage};
use donut_veil::VeilServerConfig;
use rustls::client::{ClientConfig, ClientConnection};
use rustls::pki_types::ServerName;
use rustls::{version, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const BANNER: &[u8] = b"DECOY-BANNER";

/// Produce a genuine first-flight ClientHello record (5-byte TLS record
/// header + handshake message) using the forked rustls. No veil mutator
/// is installed, so the server's AEAD open will fail → Forward.
fn plain_client_hello() -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&version::TLS13])
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let mut conn =
        ClientConnection::new(Arc::new(cfg), ServerName::try_from("decoy.test").unwrap()).unwrap();
    let mut buf = Vec::new();
    conn.write_tls(&mut buf).unwrap();
    assert!(!buf.is_empty(), "rustls must emit a ClientHello");
    assert_eq!(buf[0], 0x16, "first byte must be the TLS handshake type");
    buf
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthenticated_client_is_relayed_to_decoy() {
    eprintln!("step: start");

    // Decoy "backdrop" standing in for the real selfsteal web server:
    // greet immediately, then collect everything until the client's
    // write side closes, and report it back over a channel.
    let decoy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
    let (got_tx, got_rx) = oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        let (mut sock, _) = decoy.accept().await.unwrap();
        eprintln!("decoy: accepted");
        sock.write_all(BANNER).await.unwrap();
        sock.flush().await.unwrap();
        let mut buf = Vec::new();
        let _ = sock.read_to_end(&mut buf).await;
        eprintln!("decoy: collected {} bytes", buf.len());
        let _ = got_tx.send(buf);
    });

    let veil = VeilServerConfig::new([0x11u8; 32], ["deadbeef".parse().unwrap()]).unwrap();

    // Our public front door.
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    let veil_for_server = veil.clone();
    let server = tokio::spawn(async move {
        let (client, _) = front.accept().await.unwrap();
        eprintln!("front: accepted");
        let outcome = triage(client, &veil_for_server, decoy_addr).await.unwrap();
        eprintln!("front: triage done");
        outcome
    });

    // Plain TLS client.
    let hello = plain_client_hello();
    let marker = b"PING-EXTRA";
    let mut sock = TcpStream::connect(front_addr).await.unwrap();
    eprintln!("client: connected");
    sock.write_all(&hello).await.unwrap();
    sock.write_all(marker).await.unwrap();
    sock.flush().await.unwrap();
    eprintln!("client: wrote {}+{} bytes", hello.len(), marker.len());

    // dest → client: banner must arrive through the relay.
    let mut banner = [0u8; BANNER.len()];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut banner))
        .await
        .expect("banner round-trip timed out")
        .expect("read banner");
    assert_eq!(&banner, BANNER, "decoy banner relayed to client");
    eprintln!("client: got banner");

    // Close the client's write side so the relay's client→dest direction
    // hits EOF and the decoy's read_to_end returns.
    sock.shutdown().await.unwrap();
    eprintln!("client: shutdown write");

    // client → dest: the decoy must have collected exactly what we sent.
    let collected = tokio::time::timeout(Duration::from_secs(5), got_rx)
        .await
        .expect("decoy collect timed out")
        .expect("decoy channel");
    let mut expected = hello.clone();
    expected.extend_from_slice(marker);
    assert_eq!(collected, expected, "client→dest relayed verbatim");
    eprintln!("relay verified both directions");

    let outcome = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server join timed out")
        .unwrap();
    assert!(
        matches!(outcome, Triage::Forwarded),
        "verdict must be Forward"
    );
}
