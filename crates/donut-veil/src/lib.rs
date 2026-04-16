//! donut-veil — veiled-TLS handshake glue on top of [`donut-rustls`].
//!
//! Byte spec: see `docs/PROTOCOLS.md` § "Veiled TLS handshake".
//!
//! * AuthKey = HKDF-SHA256(salt = ClientHello.Random[:20], info = <7-byte tag>)
//!   .expand( X25519(client_priv, server_pub) ) — 32 bytes.
//! * SessionID layout (32 bytes): `version(4) | ts(4) | shortID(8) | sealed(16)`.
//! * Sealed = AES-256-GCM(AuthKey) over ephemeral material.
//! * Server validates `HMAC-SHA512(AuthKey, cert.signature)` → tunnel/forward.
//!
//! Status: **M0 stub.** Implementation in M3.

#![forbid(unsafe_op_in_unsafe_fn)]
