//! Build the [`RawClientHelloHook`] that authenticates incoming
//! ClientHellos on the server side.

use donut_core::ShortId;
use rustls::server::{RawClientHelloHook, VeilDecision};
use x25519_dalek::PublicKey;

use crate::auth::{
    derive_auth_key, open as open_seal, NONCE_LEN, SESSION_ID_LEN, SESSION_ID_OFFSET,
};
use crate::config::VeilServerConfig;
use crate::parse::ClientHelloView;

/// Returns a [`RawClientHelloHook`] that:
/// 1. Parses the incoming ClientHello.
/// 2. Pulls the X25519 share out of the `key_share` extension.
/// 3. ECDH(server_priv, client_share) → shared.
/// 4. HKDF-SHA256(salt = Random[..20], info = "REALITY") → AuthKey.
/// 5. Reproduces the AAD by zeroing the SessionID slot.
/// 6. AES-GCM Open(SessionID, nonce = Random[20..32], AuthKey, AAD).
/// 7. If open fails → `Forward` (selfsteal).
/// 8. If short_id matches the configured set → `Tunnel`. Otherwise
///    `Forward` (the AEAD authenticates, but we don't recognise the
///    caller — same probe behaviour).
pub fn build_raw_client_hello_hook(config: VeilServerConfig) -> RawClientHelloHook {
    let short_ids = config.short_ids.clone();
    let private = config.private.clone();

    RawClientHelloHook::new(move |bytes: &[u8]| {
        let view = match ClientHelloView::parse(bytes) {
            Ok(v) => v,
            Err(e) => {
                tracing::trace!(?e, "veil server: parse failed → forward");
                return VeilDecision::Forward {
                    raw_client_hello: bytes.to_vec(),
                };
            }
        };

        // Build AAD: full ClientHello with the SessionID slot zeroed.
        let mut aad = bytes.to_vec();
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
                return VeilDecision::Forward {
                    raw_client_hello: bytes.to_vec(),
                };
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
            return VeilDecision::Forward {
                raw_client_hello: bytes.to_vec(),
            };
        }

        VeilDecision::Tunnel
    })
}
