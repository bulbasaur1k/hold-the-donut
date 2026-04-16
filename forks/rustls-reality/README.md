# rustls-reality (placeholder)

This directory is a **placeholder** for the `rustls` fork that will host the
REALITY hooks required by the `donut-rustls` crate.

## Planned setup (M2)

1. Fork `https://github.com/rustls/rustls` on GitHub; name it `rustls-reality`.
2. Pin a base tag, e.g. `rustls/v/0.23.38`, create branch `reality/main`.
3. Add the remote as a **git submodule** from the root of this repo:
   ```sh
   git submodule add -b reality/main \
     https://github.com/<owner>/rustls-reality.git forks/rustls-reality
   git submodule update --init --recursive
   ```
4. Switch `crates/donut-rustls/Cargo.toml` from the workspace `rustls`
   dependency to a path override:
   ```toml
   [dependencies]
   rustls = { path = "../../forks/rustls-reality/rustls" }
   ```

## Required patches

Kept minimal and documented in
`forks/rustls-reality/PATCH_POINTS.md` (added as part of M2) so they can be
ported forward to newer rustls releases.

### 1. Client-side `ClientHelloMutator`

Expose a post-marshal, pre-send mutator that receives `&mut [u8]`
positioned at the raw ClientHello, so REALITY can:

* HKDF-SHA256(salt = `Random[:20]`, info = `"REALITY"`) using the
  X25519 shared secret.
* Rewrite the 32-byte `SessionID` (at offset **39** in the ClientHello
  body) with the plaintext layout:
  `version[4] | ts[4] | shortID[8] | sealed[16]`.
* AES-256-GCM seal the last 16 bytes with the derived AuthKey.

API sketch:

```rust
pub type ClientHelloMutator = Arc<dyn Fn(&mut [u8]) + Send + Sync>;

impl rustls::ClientConfig {
    pub fn set_client_hello_mutator(&mut self, f: ClientHelloMutator);
}
```

### 2. Server-side raw-ClientHello hook

Invoked with the full raw ClientHello bytes **before** crypto starts.
Returns a `RealityDecision`:

```rust
pub enum RealityDecision {
    /// Continue the rustls handshake from here (tunnel path).
    Tunnel,
    /// Stop being a TLS server; hand the raw ClientHello back to the
    /// caller so it can be proxied verbatim to the selfsteal target.
    Forward { raw_client_hello: Vec<u8> },
}

pub type RawClientHelloHook =
    Arc<dyn Fn(&[u8]) -> RealityDecision + Send + Sync>;

impl rustls::ServerConfig {
    pub fn set_raw_client_hello_hook(&mut self, f: RawClientHelloHook);
}
```

The rustls server state machine must surface a `Forward` decision as a
distinct `ServerConnectionData::Forwarded(Vec<u8>)` variant so the
caller can bail out of TLS and proxy TCP.

### 3. `SessionID` read-through on the server

When taking the `Tunnel` path, the server needs the already-parsed
`ClientHelloPayload::session_id` reflected unchanged to the REALITY
authenticator. No rewrite is needed — only ensuring rustls doesn't fail
on a 32-byte SessionID (it's spec-legal but uncommon in TLS 1.3).

## Fallback plan

If the fork proves unmaintainable (e.g. upstream internals churn too
fast), switch `donut-rustls` to the `boring` crate (BoringSSL FFI),
which exposes `SSL_CTX_set_client_hello_cb` and related callbacks. That
adds a C dependency and loses pure-Rust, but is a documented
Plan-B per `docs/PLAN.md` § M2.
