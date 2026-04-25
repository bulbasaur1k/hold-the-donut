//! End-to-end test: a real rustls handshake driven through the veil
//! hooks completes successfully. The server extracts the configured
//! ShortID from the sealed SessionID and chooses `Tunnel`.

use std::sync::Arc;

use donut_core::ShortId;
use rcgen::CertificateParams;
use rustls::client::{ClientConfig, ClientConnection};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ServerConfig, ServerConnection};
use rustls::{version, RootCertStore};

use crate::client::build_client_hello_mutator;
use crate::config::{VeilClientConfig, VeilServerConfig};
use crate::kx::VEIL_X25519;
use crate::server::build_raw_client_hello_hook;

fn provider() -> Arc<CryptoProvider> {
    let mut p = rustls::crypto::ring::default_provider();
    let mut kxs: Vec<&'static dyn SupportedKxGroup> = vec![&VEIL_X25519];
    // Append the existing groups except for any group named X25519 (we
    // replace it with VeilX25519). For non-X25519 groups, fall through.
    for g in p.kx_groups.iter().copied() {
        if g.name() != rustls::NamedGroup::X25519 {
            kxs.push(g);
        }
    }
    p.kx_groups = kxs;
    Arc::new(p)
}

fn gen_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let signing_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let cert = params.self_signed(&signing_key).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
    (cert_der, key_der)
}

fn drive(c: &mut ClientConnection, s: &mut ServerConnection) -> bool {
    for _ in 0..16 {
        let mut c2s = Vec::new();
        c.write_tls(&mut c2s).unwrap();
        if !c2s.is_empty() {
            s.read_tls(&mut c2s.as_slice()).unwrap();
            if let Err(e) = s.process_new_packets() {
                eprintln!("server process_new_packets error: {e:?}");
                return false;
            }
        }
        let mut s2c = Vec::new();
        s.write_tls(&mut s2c).unwrap();
        if !s2c.is_empty() {
            c.read_tls(&mut s2c.as_slice()).unwrap();
            if let Err(e) = c.process_new_packets() {
                eprintln!("client process_new_packets error: {e:?}");
                return false;
            }
        }
        if !c.is_handshaking() && !s.is_handshaking() {
            return true;
        }
    }
    false
}

#[test]
fn full_handshake_through_veil_hooks() {
    let provider = provider();

    // Server keypair + short id.
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&[
        0xb0, 0x0d, 0xc0, 0xff, 0xee, 0xc0, 0xde, 0xfa, 0xce, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0x0f,
    ]);
    let short_id: ShortId = "deadbeef".parse().unwrap();

    let veil_server = VeilServerConfig::new(priv_bytes, [short_id]).unwrap();
    let server_pub = veil_server.public_key_bytes();
    let veil_client = VeilClientConfig::new(server_pub, short_id, [26, 4, 15]);

    let server_hook = build_raw_client_hello_hook(veil_server);
    let client_mutator = build_client_hello_mutator(veil_client);

    let (cert, key) = gen_cert();

    let server_cfg = {
        let mut c = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        c.raw_client_hello_hook = Some(server_hook);
        Arc::new(c)
    };

    let client_cfg = {
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut c = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.client_hello_mutator = Some(client_mutator);
        Arc::new(c)
    };

    let mut c =
        ClientConnection::new(client_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut s = ServerConnection::new(server_cfg).unwrap();

    assert!(
        drive(&mut c, &mut s),
        "full TLS 1.3 handshake must complete with the veil hooks engaged"
    );
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert!(
        s.take_forwarded().is_none(),
        "Tunnel decision: not forwarded"
    );
}

#[test]
fn unknown_short_id_is_forwarded() {
    let provider = provider();

    let priv_bytes = [0xaau8; 32];
    let configured: ShortId = "deadbeef".parse().unwrap();
    let presented: ShortId = "12345678".parse().unwrap();

    let veil_server = VeilServerConfig::new(priv_bytes, [configured]).unwrap();
    let server_pub = veil_server.public_key_bytes();
    let veil_client = VeilClientConfig::new(server_pub, presented, [26, 4, 15]);

    let (cert, key) = gen_cert();

    let server_cfg = {
        let mut c = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        c.raw_client_hello_hook = Some(build_raw_client_hello_hook(veil_server));
        Arc::new(c)
    };

    let client_cfg = {
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut c = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.client_hello_mutator = Some(build_client_hello_mutator(veil_client));
        Arc::new(c)
    };

    let mut c =
        ClientConnection::new(client_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut s = ServerConnection::new(server_cfg).unwrap();

    let mut c2s = Vec::new();
    c.write_tls(&mut c2s).unwrap();
    s.read_tls(&mut c2s.as_slice()).unwrap();
    s.process_new_packets().unwrap();
    assert!(
        s.take_forwarded().is_some(),
        "unknown short_id must surface as Forward"
    );
}

#[test]
fn unauthenticated_client_is_forwarded() {
    // Plain rustls client, no veil mutator: the server hook's open()
    // fails and we fall through to Forward.
    let provider = provider();

    let priv_bytes = [0xbbu8; 32];
    let short_id: ShortId = "abcdef0123456789".parse().unwrap();
    let veil_server = VeilServerConfig::new(priv_bytes, [short_id]).unwrap();

    let (cert, key) = gen_cert();

    let server_cfg = {
        let mut c = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        c.raw_client_hello_hook = Some(build_raw_client_hello_hook(veil_server));
        Arc::new(c)
    };

    let client_cfg = {
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    };

    let mut c =
        ClientConnection::new(client_cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut s = ServerConnection::new(server_cfg).unwrap();

    let mut c2s = Vec::new();
    c.write_tls(&mut c2s).unwrap();
    s.read_tls(&mut c2s.as_slice()).unwrap();
    s.process_new_packets().unwrap();
    assert!(
        s.take_forwarded().is_some(),
        "plain TLS client must be forwarded (selfsteal path)"
    );
}
