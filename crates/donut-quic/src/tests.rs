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

    let mut server = QuicServer::bind("127.0.0.1:0".parse().unwrap(), vec![cert.clone()], key)
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

    let mut stream = timeout(
        Duration::from_secs(5),
        dial_stream_one(addr, "localhost", vec![cert], "/"),
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
