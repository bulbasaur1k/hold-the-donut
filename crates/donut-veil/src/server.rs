//! Build the [`RawClientHelloHook`] that authenticates incoming
//! ClientHellos on the server side, plus a transport-level
//! [`server_verdict`] that runs the same decision off raw socket bytes
//! (used by the selfsteal front door, where the relay must be
//! byte-transparent and never enter the TLS state machine).

use ahash::AHashSet;
use donut_core::ShortId;
use rustls::server::{RawClientHelloHook, VeilDecision};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::auth::{
    derive_auth_key, open as open_seal, NONCE_LEN, SESSION_ID_LEN, SESSION_ID_OFFSET,
};
use crate::config::VeilServerConfig;
use crate::parse::ClientHelloView;

/// Transport-level outcome of inspecting a ClientHello, free of any
/// `rustls` types so callers (e.g. the selfsteal front door) can act on
/// it without driving the TLS state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Authenticated veil peer — proceed to terminate TLS and tunnel.
    /// Carries the per-connection `auth_key` so the server can emit the
    /// server-auth proof (see [`crate::server_proof`]).
    Tunnel { auth_key: [u8; 32] },
    /// Unknown caller (prober/browser/garbage) — relay verbatim to the
    /// selfsteal `dest`.
    Forward,
}

/// Core decision shared by the rustls hook and the socket-level
/// [`server_verdict`]. `client_hello` is the handshake message starting
/// at the `HandshakeType` byte (offset 0 = `0x01` for ClientHello),
/// i.e. the TLS record payload with the 5-byte record header stripped.
fn decide(short_ids: &AHashSet<ShortId>, private: &StaticSecret, client_hello: &[u8]) -> Verdict {
    let view = match ClientHelloView::parse(client_hello) {
        Ok(v) => v,
        Err(e) => {
            tracing::trace!(?e, "veil server: parse failed → forward");
            return Verdict::Forward;
        }
    };

    // Build AAD: full ClientHello with the SessionID slot zeroed.
    let mut aad = client_hello.to_vec();
    aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);

    // ECDH(server_priv, client_x25519_share).
    let client_pub = PublicKey::from(view.x25519_pub);
    let shared = private.diffie_hellman(&client_pub);

    // Derive AuthKey by overwriting shared in place.
    let mut auth_key: [u8; 32] = *shared.as_bytes();
    derive_auth_key(&mut auth_key, &view.random[..20]);

    // Pull the nonce.
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&view.random[20..32]);

    // Open the seal.
    let plaintext = match open_seal(&auth_key, &nonce, &view.session_id, &aad) {
        Ok(p) => p,
        Err(_) => {
            tracing::trace!("veil server: AEAD open failed → forward");
            return Verdict::Forward;
        }
    };

    // Plaintext layout: version(3) | reserved(1) | ts(4) | short_id(8).
    let mut sid_bytes = [0u8; 8];
    sid_bytes.copy_from_slice(&plaintext[8..16]);
    let short_id = ShortId::from_bytes(sid_bytes);

    if !short_ids.contains(&short_id) {
        tracing::trace!(
            short_id = %short_id,
            "veil server: AEAD opened but short_id not configured → forward"
        );
        return Verdict::Forward;
    }

    Verdict::Tunnel { auth_key }
}

/// Decide, off raw ClientHello *handshake-message* bytes, whether the
/// caller is an authenticated veil peer ([`Verdict::Tunnel`]) or an
/// unknown prober ([`Verdict::Forward`], → selfsteal). Carries no
/// `rustls` state, so the selfsteal front door can call it on bytes
/// peeked from the socket and then relay them verbatim.
pub fn server_verdict(config: &VeilServerConfig, client_hello: &[u8]) -> Verdict {
    decide(&config.short_ids, &config.private, client_hello)
}

/// Returns a [`RawClientHelloHook`] that runs [`decide`] and maps the
/// result onto the rustls [`VeilDecision`]. On [`Verdict::Forward`] the
/// raw ClientHello is stashed for `ServerConnection::take_forwarded`.
pub fn build_raw_client_hello_hook(config: VeilServerConfig) -> RawClientHelloHook {
    let short_ids = config.short_ids.clone();
    let private = config.private.clone();

    RawClientHelloHook::new(
        move |bytes: &[u8]| match decide(&short_ids, &private, bytes) {
            Verdict::Tunnel { .. } => VeilDecision::Tunnel,
            Verdict::Forward => VeilDecision::Forward {
                raw_client_hello: bytes.to_vec(),
            },
        },
    )
}
