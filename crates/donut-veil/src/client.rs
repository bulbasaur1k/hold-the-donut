//! Build the [`ClientHelloMutator`] that performs the veil handshake
//! sealing on the client side.

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::client::ClientHelloMutator;

use crate::auth::{
    build_plaintext, derive_auth_key, seal, NONCE_LEN, RANDOM_OFFSET, SESSION_ID_LEN,
    SESSION_ID_OFFSET,
};
use crate::config::VeilClientConfig;

/// Per-connection sink for the derived `AuthKey`. The capturing mutator
/// writes it once; the caller reads it after the handshake to verify the
/// server-auth proof.
pub type AuthKeySink = Arc<OnceLock<[u8; 32]>>;

/// Returns a [`ClientHelloMutator`] that, given the in-progress TLS
/// 1.3 X25519 ephemeral, rewrites the 32-byte legacy SessionID with
/// the AES-GCM-sealed `(version, ts, short_id)` plaintext keyed by
/// `HKDF-SHA256(salt = ClientHello.Random[..20], info = "REALITY",
/// IKM = ECDH(client_priv, server_pub))`.
pub fn build_client_hello_mutator(config: VeilClientConfig) -> ClientHelloMutator {
    build_client_hello_mutator_capturing(config, None)
}

/// Like [`build_client_hello_mutator`], but also writes the derived
/// `AuthKey` into `sink` so the caller can verify the server-auth proof
/// after the handshake (REALITY-hardening).
pub fn build_client_hello_mutator_capturing(
    config: VeilClientConfig,
    sink: Option<AuthKeySink>,
) -> ClientHelloMutator {
    let server_pub = config.server_pub;
    let short_id = config.short_id;
    let version = config.version;
    let fingerprint = config.fingerprint;

    ClientHelloMutator::new(move |buf, kx| {
        let Some(kx) = kx else {
            tracing::error!("veil client: no TLS key share available");
            return;
        };
        let Some(shared) = kx.diffie_hellman(server_pub.as_bytes()) else {
            tracing::error!("veil client: kx group does not support diffie_hellman()");
            return;
        };

        if buf.len() < SESSION_ID_OFFSET + SESSION_ID_LEN {
            tracing::error!(
                "veil client: ClientHello shorter than expected ({} bytes)",
                buf.len()
            );
            return;
        }

        // Apply the uTLS-style fingerprint first: it only reorders the
        // cipher-suite and extension lists (length-preserving, all after
        // the SessionID slot), so the REALITY seal computed below — whose
        // AAD is the whole ClientHello with the SessionID zeroed — stays
        // consistent with what the server reconstructs on the wire.
        fingerprint.apply(buf);

        // Stash Random[:20] as the HKDF salt, and Random[20..32] as the
        // AEAD nonce, both before we touch the SessionID slot.
        let mut random_prefix = [0u8; 20];
        random_prefix.copy_from_slice(&buf[RANDOM_OFFSET..RANDOM_OFFSET + 20]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[RANDOM_OFFSET + 20..RANDOM_OFFSET + 32]);

        // Zero the SessionID slot before computing AAD — server does
        // the same on its open.
        buf[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);

        // Derive AuthKey by overwriting the shared secret in place.
        let mut auth_key = [0u8; 32];
        let secret_bytes = shared.secret_bytes();
        if secret_bytes.len() != 32 {
            tracing::error!(
                "veil client: shared secret has unexpected length {}",
                secret_bytes.len()
            );
            return;
        }
        auth_key.copy_from_slice(secret_bytes);
        derive_auth_key(&mut auth_key, &random_prefix);

        // Surface the AuthKey for the post-handshake server-auth proof.
        if let Some(sink) = &sink {
            let _ = sink.set(auth_key);
        }

        // Compose plaintext and seal.
        let unix_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let plaintext = build_plaintext(&version, unix_ts, &short_id);
        let sealed = seal(&auth_key, &nonce, &plaintext, buf);

        // Drop the sealed bytes back into the SessionID slot; AAD bytes
        // outside the slot stay unchanged so the server's open will
        // reproduce the same AAD.
        buf[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&sealed);
    })
}
