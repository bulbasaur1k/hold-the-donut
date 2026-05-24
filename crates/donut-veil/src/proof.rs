//! Server-authentication proof (REALITY-hardening).
//!
//! Both peers independently derive the same `AuthKey` from
//! `ECDH(client_ephemeral, server_static)` (the client uses its
//! ephemeral private + the server static public; the server uses its
//! static private + the client ephemeral public). The server proves it
//! holds the static private key — defeating a MITM — by sending
//! `HMAC-SHA256(AuthKey, LABEL)` as the first bytes inside the tunnel.
//! The client recomputes it from its own `AuthKey` and compares in
//! constant time. A MITM that lacks the server static key cannot derive
//! `AuthKey`, so cannot forge the proof.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Length of the server-auth proof.
pub const PROOF_LEN: usize = 32;

const LABEL: &[u8] = b"donut/reality/server-auth/v1";

/// Compute the server-auth proof for a connection's `auth_key`.
pub fn server_proof(auth_key: &[u8; 32]) -> [u8; PROOF_LEN] {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(auth_key).expect("HMAC accepts a key of any length");
    mac.update(LABEL);
    let bytes = mac.finalize().into_bytes();
    let mut proof = [0u8; PROOF_LEN];
    proof.copy_from_slice(&bytes);
    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_is_deterministic_and_key_dependent() {
        let k1 = [7u8; 32];
        let k2 = [8u8; 32];
        assert_eq!(server_proof(&k1), server_proof(&k1));
        assert_ne!(server_proof(&k1), server_proof(&k2));
        assert_eq!(server_proof(&k1).len(), PROOF_LEN);
    }
}
