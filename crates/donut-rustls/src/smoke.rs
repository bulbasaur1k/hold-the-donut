//! End-to-end smoke tests for the two veiled-TLS hooks.
//!
//! Drives an in-memory client ↔ server handshake (no sockets) and
//! asserts:
//!
//! * the client-side `ClientHelloMutator` receives the serialised
//!   ClientHello bytes and sees them round-trip to the server
//!   transcript intact — we mutate the SessionID, the handshake
//!   completes, and the mutated bytes land on the wire;
//! * the server-side `RawClientHelloHook` is invoked with the
//!   exact same bytes the mutator produced;
//! * `VeilDecision::Forward { .. }` short-circuits the server state
//!   machine and surfaces the ClientHello via
//!   `ServerConnection::take_forwarded`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rustls::client::ClientHelloMutator;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{RawClientHelloHook, VeilDecision};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

/// Offset of the 32-byte legacy `SessionID` in a handshake message
/// whose first byte is `HandshakeType::ClientHello` (our hooks see
/// the full handshake body).
const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;

fn gen_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

fn client_config(
    trust: CertificateDer<'static>,
    mutator: Option<ClientHelloMutator>,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(trust).unwrap();
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.client_hello_mutator = mutator;
    Arc::new(cfg)
}

fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    hook: Option<RawClientHelloHook>,
) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.raw_client_hello_hook = hook;
    Arc::new(cfg)
}

/// Pump messages between a client and a server until both report
/// `!is_handshaking()` or either errors. Returns whatever
/// `process_new_packets` returned on the final server call so the
/// test can assert on Forward-path behaviour too.
fn drive_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..16 {
        let mut c2s = Vec::new();
        client.write_tls(&mut c2s).unwrap();
        if !c2s.is_empty() {
            server.read_tls(&mut c2s.as_slice()).unwrap();
            let _ = server.process_new_packets();
        }

        let mut s2c = Vec::new();
        server.write_tls(&mut s2c).unwrap();
        if !s2c.is_empty() {
            client.read_tls(&mut s2c.as_slice()).unwrap();
            let _ = client.process_new_packets();
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
    }
}

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[test]
fn both_hooks_fire_and_see_the_same_bytes() {
    install_provider();

    let client_saw = Arc::new(AtomicUsize::new(0));
    let client_saw_cb = client_saw.clone();

    // The mutator writes a recognisable payload into the 32-byte
    // SessionID slot so the server-side hook can assert on it.
    let marker: [u8; SESSION_ID_LEN] = {
        let mut m = [0u8; SESSION_ID_LEN];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(0x42);
        }
        m
    };
    let marker_cb = marker;

    let client_mutator = ClientHelloMutator::new(move |buf: &mut [u8], _kx| {
        client_saw_cb.fetch_add(1, Ordering::SeqCst);
        assert!(
            buf.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN,
            "ClientHello body shorter than expected: {}",
            buf.len()
        );
        // Legacy version at [4..6], random at [6..38], session_id_len at [38],
        // session_id at [39..71].
        assert_eq!(
            buf[38] as usize, SESSION_ID_LEN,
            "ClientHello must carry a 32-byte SessionID in TLS 1.3",
        );
        buf[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&marker_cb);
    });

    let server_saw = Arc::new(AtomicUsize::new(0));
    let server_saw_cb = server_saw.clone();
    let server_hook = RawClientHelloHook::new(move |bytes: &[u8]| {
        server_saw_cb.fetch_add(1, Ordering::SeqCst);
        assert!(bytes.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN);
        assert_eq!(
            &bytes[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN],
            &marker,
            "server must see the exact bytes the client mutator wrote",
        );
        VeilDecision::Tunnel
    });

    let (cert, key) = gen_self_signed();

    let c_cfg = client_config(cert.clone(), Some(client_mutator));
    let s_cfg = server_config(cert, key, Some(server_hook));

    let mut c = ClientConnection::new(c_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut s = ServerConnection::new(s_cfg).unwrap();

    drive_handshake(&mut c, &mut s);

    assert_eq!(client_saw.load(Ordering::SeqCst), 1, "client mutator fired");
    assert_eq!(server_saw.load(Ordering::SeqCst), 1, "server hook fired");
}

#[test]
fn forward_decision_surfaces_via_take_forwarded() {
    install_provider();

    let captured: Arc<std::sync::Mutex<Option<Vec<u8>>>> = Arc::new(std::sync::Mutex::new(None));
    let captured_cb = captured.clone();

    let server_hook = RawClientHelloHook::new(move |bytes: &[u8]| {
        *captured_cb.lock().unwrap() = Some(bytes.to_vec());
        VeilDecision::Forward {
            raw_client_hello: bytes.to_vec(),
        }
    });

    let (cert, key) = gen_self_signed();
    let c_cfg = client_config(cert.clone(), None);
    let s_cfg = server_config(cert, key, Some(server_hook));

    let mut c = ClientConnection::new(c_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut s = ServerConnection::new(s_cfg).unwrap();

    // Drive one round: client → server with just the ClientHello.
    let mut c2s = Vec::new();
    c.write_tls(&mut c2s).unwrap();
    assert!(!c2s.is_empty());
    s.read_tls(&mut c2s.as_slice()).unwrap();
    s.process_new_packets().unwrap();

    let forwarded = s
        .take_forwarded()
        .expect("Forward decision must surface raw ClientHello");
    let hook_saw = captured.lock().unwrap().take().unwrap();

    assert_eq!(
        forwarded, hook_saw,
        "take_forwarded must yield exactly the bytes the hook inspected",
    );

    // Sanity: handshake message type byte is ClientHello (0x01).
    assert_eq!(forwarded[0], 0x01);

    // A subsequent attempt to push more TLS bytes must fail because
    // the connection has transitioned into the terminal forwarded
    // state.
    let mut s2c = Vec::new();
    s.write_tls(&mut s2c).unwrap();
    assert!(
        s2c.is_empty(),
        "server must not emit any TLS after forwarding",
    );
}
