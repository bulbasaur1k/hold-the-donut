//! Custom X25519 [`SupportedKxGroup`] backed by `x25519-dalek`.
//!
//! Why a custom KX instead of the rustls-default ring/aws-lc-rs ones?
//! The veil layer needs to derive an *auxiliary* X25519 shared secret
//! from the same ephemeral the TLS handshake will later use for its
//! key share, **without** consuming the local private key (rustls
//! still needs it later for the real handshake). Ring's
//! `EphemeralPrivateKey` is one-shot, so we keep the raw 32-byte
//! private key alongside and expose
//! [`ActiveKeyExchange::diffie_hellman`] (a non-consuming method we
//! added to the trait — see the trait definition).

use std::fmt;

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::Error;
use rustls::{NamedGroup, SupportedProtocolVersion};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Sentinel value representing the X25519 named group.
pub static VEIL_X25519: VeilX25519 = VeilX25519;

/// Marker type for the custom X25519 group.
#[derive(Debug, Clone, Copy)]
pub struct VeilX25519;

impl SupportedKxGroup for VeilX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        Ok(Box::new(Active {
            secret: Zeroizing::new(secret),
            public,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct Active {
    secret: Zeroizing<StaticSecret>,
    public: PublicKey,
}

impl fmt::Debug for Active {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VeilX25519::Active").finish_non_exhaustive()
    }
}

impl ActiveKeyExchange for Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer = parse_x25519(peer_pub_key)?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn diffie_hellman(&self, peer_pub_key: &[u8]) -> Option<SharedSecret> {
        let peer = parse_x25519(peer_pub_key).ok()?;
        let shared = self.secret.diffie_hellman(&peer);
        Some(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn complete_for_tls_version(
        self: Box<Self>,
        peer_pub_key: &[u8],
        _tls_version: &SupportedProtocolVersion,
    ) -> Result<SharedSecret, Error> {
        self.complete(peer_pub_key)
    }
}

fn parse_x25519(bytes: &[u8]) -> Result<PublicKey, Error> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::General("X25519 share must be 32 bytes".into()))?;
    Ok(PublicKey::from(arr))
}
