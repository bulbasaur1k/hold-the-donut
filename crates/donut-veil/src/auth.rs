//! Auth-key derivation and the AES-GCM seal/open over the SessionID.
//!
//! Key facts (mirroring the upstream wire protocol):
//!
//! * `shared = X25519(client_priv, server_pub)`
//! * `AuthKey = HKDF-SHA256(salt = ClientHello.Random[..20], info = b"REALITY").expand(shared)`
//!   — 32 bytes overwritten back over `shared`.
//! * The 32-byte legacy `SessionID` carries
//!   `AES-256-GCM(AuthKey)` of plaintext `version(3) | reserved(1) |
//!   ts(4) | short_id(8)` (16 bytes), nonce `Random[20..32]` (12 bytes),
//!   AAD = the entire ClientHello with SessionID zeroed. Output is
//!   16-byte ciphertext + 16-byte tag = 32 bytes total — exactly the
//!   SessionID slot.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use donut_core::ShortId;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::VeilError;

/// HKDF info string. **Wire constant** — must match upstream byte for
/// byte. Constructed from a literal so it appears as one string in
/// the binary; this is a protocol invariant, not a chooseable name.
pub(crate) const HKDF_INFO: &[u8] = b"REALITY";

pub(crate) const SESSION_ID_OFFSET: usize = 39;
pub(crate) const SESSION_ID_LEN: usize = 32;
pub(crate) const PLAINTEXT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const RANDOM_OFFSET: usize = 6;

/// Derive AuthKey by overwriting the input shared secret in place.
pub(crate) fn derive_auth_key(shared: &mut [u8; 32], random_prefix: &[u8]) {
    debug_assert_eq!(random_prefix.len(), 20);
    let hk = Hkdf::<Sha256>::new(Some(random_prefix), shared.as_slice());
    hk.expand(HKDF_INFO, shared.as_mut_slice())
        .expect("HKDF expand to 32 bytes never fails");
}

/// Read the 4-byte big-endian unix timestamp the client stamped into the
/// opened plaintext (offset 4..8 — see [`build_plaintext`]). Used by the
/// server for the anti-replay clock-skew check.
pub(crate) fn parse_timestamp(plaintext: &[u8; PLAINTEXT_LEN]) -> u32 {
    let mut ts = [0u8; 4];
    ts.copy_from_slice(&plaintext[4..8]);
    u32::from_be_bytes(ts)
}

/// Plaintext SessionID layout (16 bytes) before sealing.
pub(crate) fn build_plaintext(version: &[u8; 3], unix_ts: u32, short_id: &ShortId) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..3].copy_from_slice(version);
    out[3] = 0;
    out[4..8].copy_from_slice(&unix_ts.to_be_bytes());
    out[8..16].copy_from_slice(short_id.as_bytes());
    out
}

/// Seal the 16-byte plaintext into 32 bytes (16 ciphertext + 16 tag).
/// `aad` is the entire ClientHello body **with the SessionID slot
/// zeroed**.
pub(crate) fn seal(
    auth_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8; PLAINTEXT_LEN],
    aad: &[u8],
) -> [u8; SESSION_ID_LEN] {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key));
    let nonce = Nonce::from_slice(nonce);
    let out = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encrypt never fails for valid inputs");
    debug_assert_eq!(out.len(), SESSION_ID_LEN);
    let mut buf = [0u8; SESSION_ID_LEN];
    buf.copy_from_slice(&out);
    buf
}

/// Open the 32-byte sealed SessionID back into 16 bytes of plaintext.
pub(crate) fn open(
    auth_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8; SESSION_ID_LEN],
    aad: &[u8],
) -> Result<[u8; PLAINTEXT_LEN], VeilError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(auth_key));
    let nonce = Nonce::from_slice(nonce);
    let plain = cipher
        .decrypt(nonce, Payload { msg: sealed, aad })
        .map_err(|_| VeilError::AuthFailed)?;
    if plain.len() != PLAINTEXT_LEN {
        return Err(VeilError::AuthFailed);
    }
    let mut buf = [0u8; PLAINTEXT_LEN];
    buf.copy_from_slice(&plain);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let auth_key = [0xa5u8; 32];
        let nonce = [0x42u8; NONCE_LEN];
        let plaintext = [0x10u8; PLAINTEXT_LEN];
        let aad = b"the entire ClientHello with the SessionID zeroed";
        let sealed = seal(&auth_key, &nonce, &plaintext, aad);
        let opened = open(&auth_key, &nonce, &sealed, aad).unwrap();
        assert_eq!(plaintext, opened);
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let auth_key = [0xa5u8; 32];
        let nonce = [0x42u8; NONCE_LEN];
        let sealed = seal(&auth_key, &nonce, &[0u8; PLAINTEXT_LEN], b"original aad");
        assert!(open(&auth_key, &nonce, &sealed, b"tampered aad").is_err());
    }

    #[test]
    fn derive_auth_key_overwrites_in_place() {
        let mut shared = [1u8; 32];
        let original = shared;
        derive_auth_key(&mut shared, &[2u8; 20]);
        assert_ne!(shared, original);
    }
}
