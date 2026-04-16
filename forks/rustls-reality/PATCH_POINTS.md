# PATCH_POINTS — planned modifications to vendored rustls

Base: upstream `rustls` tag `v/0.23.38` (commit `6b116bc`). This file
lists the **intentional** diffs carried by the fork and pinpoints the
files they touch so they can be re-applied when the pin moves forward.

Current state: **0 patches applied.** Baseline is a clean copy.

---

## Patch 1 — Client-side ClientHello mutator

**Motivation.** The veiled-TLS handshake needs to rewrite the 32-byte
legacy `SessionID` field of the client's ClientHello with a plaintext
layout `version(4) | ts(4) | shortID(8) | sealed(16)`, where the last
16 bytes are an AES-256-GCM seal over ephemeral auth material. This
must happen **after** rustls marshals the ClientHello and **before**
the bytes hit the socket, so the HKDF salt (`Random[:20]`) is already
stable.

**Shape of the public API.**

```rust
// rustls/src/client/client_conn.rs (new)
pub type ClientHelloMutator =
    alloc::sync::Arc<dyn Fn(&mut [u8]) + Send + Sync>;

impl ClientConfig {
    pub fn set_client_hello_mutator(&mut self, f: ClientHelloMutator);
}
```

**Files touched (planned).**

* `rustls/src/client/client_conn.rs` — add `client_hello_mutator:
  Option<ClientHelloMutator>` field on `ClientConfig`, setter method.
* `rustls/src/client/hs.rs` — after the ClientHello is serialised into
  the output buffer, call `config.client_hello_mutator.as_ref().map(|f| f(&mut bytes[..]))`
  on the outgoing handshake message bytes (before `flush`). The
  callback sees the full `ClientHello` body (starting at the
  handshake-header type byte — we document the offset convention).
* `rustls/src/lib.rs` — re-export `ClientHelloMutator`.

**Invariants we rely on for REALITY.**

* rustls emits `SessionID` as 32 bytes in TLS 1.3 (required).
* The bytes of `ClientHello.Random` are stable across the mutator
  call (rustls does not rewrite them post-marshal).

---

## Patch 2 — Server-side raw ClientHello hook

**Motivation.** On the server we need first dibs on the raw ClientHello
bytes: authenticate the veiled header, and if authentication fails
**stop doing TLS** and hand the untouched bytes back to the caller so
it can splice to the selfsteal target.

**Shape of the public API.**

```rust
// rustls/src/server/server_conn.rs (new)
pub enum VeilDecision {
    /// Continue the handshake as a normal TLS 1.3 server.
    Tunnel,
    /// Stop being a TLS server; bail out carrying the raw bytes.
    Forward { raw_client_hello: alloc::vec::Vec<u8> },
}

pub type RawClientHelloHook =
    alloc::sync::Arc<dyn Fn(&[u8]) -> VeilDecision + Send + Sync>;

impl ServerConfig {
    pub fn set_raw_client_hello_hook(&mut self, f: RawClientHelloHook);
}
```

**Surface in the connection API.**

When the hook returns `Forward`, the resulting `ServerConnection`
transitions to a terminal state that yields the raw bytes back to the
caller via a new getter:

```rust
impl ServerConnection {
    pub fn take_forwarded(&mut self) -> Option<Vec<u8>>;
}
```

The main loop in our `donut-rustls` wrapper polls this after each
`read_tls()`; if `Some(bytes)`, it escapes TLS and treats the
underlying socket as a raw byte pipe.

**Files touched (planned).**

* `rustls/src/server/server_conn.rs` — add `raw_client_hello_hook`
  field on `ServerConfig`, setter, and the `VeilDecision` /
  `take_forwarded` API.
* `rustls/src/server/hs.rs` — at the top of `start_handshake`, call
  the hook with the raw bytes of the ClientHello record. On
  `VeilDecision::Forward`, stash the bytes on the connection state
  and short-circuit the state machine into a terminal `Forwarded`
  branch.
* `rustls/src/server/common.rs` (if needed) — new terminal state
  handler that immediately errors all further TLS ops.

---

## Patch 3 — `SessionID` passthrough on the server

**Motivation.** When the hook chooses `Tunnel`, we still need the
already-parsed `SessionID` field reflected unchanged to the veiled
authenticator. Upstream rustls accepts non-zero-length SessionIDs in
TLS 1.3 but we should make sure its echo handling doesn't sanitise
the bytes. Most likely no-op patch; listed here as a place to put an
integration test.

**Files touched (planned).**

* `rustls/src/msgs/handshake.rs` — confirm `ClientHelloPayload`
  preserves `session_id` as raw bytes.
* Add a self-test in the fork demonstrating round-trip of an
  arbitrary 32-byte SessionID.

---

## Non-goals

* No modification of TLS 1.2 codepaths — veiled TLS is TLS 1.3 only.
* No changes to the default cipher suite selection, signature
  algorithm list, or ALPN handling.
* No post-quantum (ML-DSA-65) support in this patch set — deferred
  to M10 as an optional feature.

## Test strategy

Each patch lands with:

1. A narrow unit test inside the fork that exercises the hook without
   any veiled-TLS logic (pure callback wiring).
2. An integration test in `crates/donut-rustls` that drives a full
   client↔server handshake through the hooks.

## Minimising the patch footprint

* No public API changes beyond the new setters and the
  `VeilDecision` / `ClientHelloMutator` types.
* All new code lives in the smallest number of existing files;
  helper logic goes into one new file `rustls/src/veil_hooks.rs` to
  keep the diff reviewable.
