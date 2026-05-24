//! donut-veil — veiled-TLS handshake glue on top of [`donut-rustls`].
//!
//! The crate plugs three things into rustls:
//!
//! 1. A custom X25519 [`SupportedKxGroup`](rustls::crypto::SupportedKxGroup)
//!    backed by `x25519-dalek` that supports a non-consuming
//!    Diffie-Hellman so the same TLS 1.3 ephemeral can also derive
//!    the auxiliary auth key.
//! 2. A `ClientHelloMutator` factory that rewrites the legacy
//!    `SessionID` field with an AES-256-GCM seal of `(version, ts,
//!    short_id)` keyed by `HKDF-SHA256(salt = ClientHello.Random[..20],
//!    info = "REALITY").expand(ECDH(client_priv, server_pub))`.
//! 3. A `RawClientHelloHook` factory that, on the server, parses the
//!    incoming ClientHello, opens the SessionID seal, and either
//!    returns `Tunnel` (authenticated) or `Forward` (selfsteal probe).
//!
//! Byte spec frozen in `docs/PROTOCOLS.md` § "Veiled TLS handshake".
//!
//! Status: **M3**, server + client side, end-to-end handshake test.

#![forbid(unsafe_op_in_unsafe_fn)]

mod auth;
mod client;
mod config;
mod error;
mod kx;
mod parse;
mod proof;
mod server;
mod verifier;

#[cfg(test)]
mod tests;

pub use config::{VeilClientConfig, VeilServerConfig};
pub use error::VeilError;
pub use kx::{crypto_provider, VeilX25519, VEIL_X25519};
pub use proof::{server_proof, PROOF_LEN};
pub use verifier::NoCertVerification;
pub use {
    client::{build_client_hello_mutator, build_client_hello_mutator_capturing, AuthKeySink},
    server::{build_raw_client_hello_hook, server_verdict, Verdict},
};
