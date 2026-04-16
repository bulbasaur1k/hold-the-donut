//! donut-reality — REALITY auth logic on top of [`donut-rustls`].
//!
//! Byte spec: see `docs/PROTOCOLS.md` § REALITY.
//!
//! * AuthKey = HKDF-SHA256(salt = ClientHello.Random[:20], info = "REALITY")
//!   .expand( X25519(client_priv, server_pub) ) — 32 bytes.
//! * SessionID layout (32 bytes): `version(4) | ts(4) | shortID(8) | sealed(16)`.
//! * Sealed = AES-256-GCM(AuthKey) over ephemeral material.
//! * Server validates `HMAC-SHA512(AuthKey, cert.signature)` → tunnel/forward.
//!
//! Status: **M0 stub.** Implementation in M3.

#![forbid(unsafe_op_in_unsafe_fn)]
