//! Phase 1 of the faithful xray REALITY server: the temporary-certificate
//! primitive.
//!
//! Per connection the REALITY server clones a fixed ed25519 self-signed
//! certificate and overwrites its trailing 64-byte signature with
//! `HMAC-SHA512(authKey, ed25519_pub)` — exactly as `XTLS/REALITY`
//! (`handshake_server_tls13.go:80-164`). The xray client then verifies
//! `cert.Signature == HMAC-SHA512(authKey, ed25519_pub)`, proving the server
//! holds the REALITY private key (from which authKey is derived), while a
//! normal CertificateVerify (ed25519 over the transcript) proves it holds the
//! matching private key. See [docs/REALITY_SERVER_SPEC.md].

use std::sync::{Arc, OnceLock};

use hmac::{Hmac, Mac};
use rustls::crypto::ring::sign::any_eddsa_type;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use sha2::Sha512;

/// Fixed-per-process REALITY identity material (mirrors REALITY's `init()`).
struct RealityCert {
    /// Self-signed ed25519 certificate DER. The last 64 bytes are the ed25519
    /// signature slot, overwritten per connection with the HMAC.
    template_der: Vec<u8>,
    /// Raw 32-byte ed25519 public key — the HMAC message.
    public_key: [u8; 32],
    /// PKCS#8 DER of the ed25519 private key (signs CertificateVerify).
    private_key_der: Vec<u8>,
}

fn material() -> &'static RealityCert {
    static M: OnceLock<RealityCert> = OnceLock::new();
    M.get_or_init(|| {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .expect("ed25519 keypair generation never fails");
        let params = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("empty cert params are valid");
        let cert = params
            .self_signed(&key)
            .expect("self-signing an ed25519 cert never fails");
        let template_der = cert.der().to_vec();
        // ed25519 raw public key (32 bytes — the BIT STRING content).
        let raw = key.public_key_raw();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(raw);
        RealityCert {
            template_der,
            public_key,
            private_key_der: key.serialize_der(),
        }
    })
}

/// PKCS#8 DER of the ed25519 key that signs CertificateVerify (its public half
/// is embedded in every certificate emitted by [`build_reality_certificate`]).
pub fn reality_signing_key_der() -> Vec<u8> {
    material().private_key_der.clone()
}

/// The raw 32-byte ed25519 public key carried in the REALITY certificate.
pub fn reality_public_key() -> [u8; 32] {
    material().public_key
}

/// Build the per-connection REALITY certificate DER for `auth_key`: the fixed
/// ed25519 self-signed cert with its trailing 64-byte signature replaced by
/// `HMAC-SHA512(auth_key, ed25519_pub)`.
pub fn build_reality_certificate(auth_key: &[u8; 32]) -> Vec<u8> {
    let m = material();
    let mut der = m.template_der.clone();
    let mut mac =
        Hmac::<Sha512>::new_from_slice(auth_key).expect("HMAC accepts a 32-byte key");
    mac.update(&m.public_key);
    let sig = mac.finalize().into_bytes(); // 64 bytes — exactly the ed25519 sig slot
    let n = der.len();
    der[n - 64..].copy_from_slice(&sig);
    der
}

/// The ed25519 [`SigningKey`] that signs the TLS 1.3 CertificateVerify. Its
/// public half is embedded in every REALITY certificate.
pub fn reality_signing_key() -> Arc<dyn SigningKey> {
    let pkcs8 = PrivatePkcs8KeyDer::from(material().private_key_der.clone());
    any_eddsa_type(&pkcs8).expect("the REALITY ed25519 key is a valid PKCS#8 EdDSA key")
}

/// The per-connection REALITY [`CertifiedKey`]: the HMAC-signed certificate for
/// `auth_key` bundled with the ed25519 signing key. This is what the TLS server
/// emits (cert + CertificateVerify) for an authenticated REALITY client,
/// replacing the configured `cert_resolver`.
pub fn reality_certified_key(auth_key: &[u8; 32]) -> Arc<CertifiedKey> {
    let cert = CertificateDer::from(build_reality_certificate(auth_key));
    Arc::new(CertifiedKey::new(vec![cert], reality_signing_key()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_check(auth_key: &[u8; 32], pub_key: &[u8; 32]) -> [u8; 64] {
        let mut mac = Hmac::<Sha512>::new_from_slice(auth_key).unwrap();
        mac.update(pub_key);
        let mut out = [0u8; 64];
        out.copy_from_slice(&mac.finalize().into_bytes());
        out
    }

    #[test]
    fn cert_signature_is_hmac_of_pubkey() {
        // Reproduce the xray client's exact verification.
        let auth_key = [0xA5u8; 32];
        let der = build_reality_certificate(&auth_key);
        let expected = client_check(&auth_key, &reality_public_key());
        assert_eq!(&der[der.len() - 64..], &expected[..]);
    }

    #[test]
    fn different_auth_keys_change_only_the_signature() {
        let a = build_reality_certificate(&[0x01u8; 32]);
        let b = build_reality_certificate(&[0x02u8; 32]);
        // Signature differs per authKey…
        assert_ne!(&a[a.len() - 64..], &b[b.len() - 64..]);
        // …but the TBS + algorithm (everything before the sig) is identical.
        assert_eq!(&a[..a.len() - 64], &b[..b.len() - 64]);
    }

    #[test]
    fn pubkey_is_embedded_in_the_cert() {
        let der = &material().template_der;
        let pk = reality_public_key();
        assert!(
            der.windows(32).any(|w| w == pk),
            "the ed25519 pubkey must appear in the cert SPKI"
        );
    }

    #[test]
    fn signing_key_is_ed25519_and_signs() {
        let key = reality_signing_key();
        let signer = key
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
            .expect("the REALITY key signs ED25519");
        assert_eq!(signer.scheme(), rustls::SignatureScheme::ED25519);
        let sig = signer.sign(b"server CertificateVerify transcript").unwrap();
        assert_eq!(sig.len(), 64, "an ed25519 signature is 64 bytes");
    }

    #[test]
    fn certified_key_carries_the_reality_cert() {
        let auth = [0x07u8; 32];
        let ck = reality_certified_key(&auth);
        let leaf = ck.cert.first().expect("one leaf cert").as_ref();
        let expected = client_check(&auth, &reality_public_key());
        assert_eq!(&leaf[leaf.len() - 64..], &expected[..]);
    }
}
