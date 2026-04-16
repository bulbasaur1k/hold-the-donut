# MODIFICATIONS — donut-tls vs upstream rustls

Base: upstream `rustls` at tag `v/0.23.38` (commit `6b116bc`). This
file is the checklist of intentional differences carried by this
crate, so they can be re-applied when the pin moves forward.

Current state: **0 patches applied.** The crate compiles from a clean
upstream snapshot.

---

## Patch 1 — Client-side ClientHello mutator

**Motivation.** The veiled-TLS handshake needs to rewrite the 32-byte
legacy `SessionID` field of the client's ClientHello with a plaintext
layout `version(4) | ts(4) | shortID(8) | sealed(16)`, where the last
16 bytes are an AES-256-GCM seal over ephemeral auth material. This
must happen **after** the ClientHello is marshaled and **before** the
bytes hit the socket, so the HKDF salt (`Random[:20]`) is already
stable.

### Public API (planned)

```rust
// src/client/client_conn.rs
pub type ClientHelloMutator =
    alloc::sync::Arc<dyn Fn(&mut [u8]) + Send + Sync>;

impl ClientConfig {
    pub fn set_client_hello_mutator(&mut self, f: ClientHelloMutator);
}
```

### Files touched (planned)

* `src/client/client_conn.rs` — add `client_hello_mutator:
  Option<ClientHelloMutator>` field on `ClientConfig`, setter method.
* `src/client/hs.rs` — after the ClientHello is serialised into the
  output buffer, call
  `config.client_hello_mutator.as_ref().map(|f| f(&mut bytes[..]))`
  on the outgoing handshake message bytes (before `flush`).
* `src/lib.rs` — re-export `ClientHelloMutator`.

### Invariants we rely on

* rustls emits `SessionID` as 32 bytes in TLS 1.3 (required for the
  veiled handshake).
* The bytes of `ClientHello.Random` are stable across the mutator
  call (rustls does not rewrite them post-marshal).

---

## Patch 2 — Server-side raw ClientHello hook

**Motivation.** On the server we need first dibs on the raw ClientHello
bytes: authenticate the veiled header, and if authentication fails,
**stop doing TLS** and hand the untouched bytes back to the caller so
it can splice to the selfsteal target.

### Public API (planned)

```rust
// src/server/server_conn.rs
pub enum VeilDecision {
    Tunnel,
    Forward { raw_client_hello: alloc::vec::Vec<u8> },
}

pub type RawClientHelloHook =
    alloc::sync::Arc<dyn Fn(&[u8]) -> VeilDecision + Send + Sync>;

impl ServerConfig {
    pub fn set_raw_client_hello_hook(&mut self, f: RawClientHelloHook);
}

impl ServerConnection {
    pub fn take_forwarded(&mut self) -> Option<Vec<u8>>;
}
```

### Files touched (planned)

* `src/server/server_conn.rs` — add `raw_client_hello_hook` field on
  `ServerConfig`, setter, and `VeilDecision` / `take_forwarded` API.
* `src/server/hs.rs` — at the top of `start_handshake`, call the
  hook with the raw ClientHello bytes. On `VeilDecision::Forward`,
  stash them on the connection state and short-circuit the state
  machine into a terminal `Forwarded` branch.
* `src/server/common.rs` (if needed) — terminal state handler that
  errors all further TLS ops.

---

## Patch 3 — `SessionID` passthrough sanity check

**Motivation.** When the hook chooses `Tunnel`, the already-parsed
`SessionID` field must reach the veiled authenticator unchanged.
Upstream rustls accepts non-zero-length SessionIDs in TLS 1.3, but we
add a self-test to catch regressions if that ever changes.

### Files touched (planned)

* `src/msgs/handshake.rs` — confirm `ClientHelloPayload` preserves
  `session_id` as raw bytes (likely no change).
* New self-test (in the crate's `tests/` once we allow dev-deps, or
  in `donut-rustls` smoke tests) round-tripping an arbitrary 32-byte
  SessionID.

---

## Non-goals

* No modification of TLS 1.2 codepaths — veiled TLS is TLS 1.3 only.
* No changes to default cipher suite selection, signature algorithm
  list, or ALPN handling.
* No post-quantum (ML-DSA-65) support here — deferred to M10.

## Test strategy

Each patch lands with:

1. A narrow unit test inside `crates/donut-tls` exercising the hook
   wiring (pure callback, no veiled-TLS logic).
2. An integration test in `crates/donut-rustls` driving a full
   client ↔ server handshake through the hooks.

## Minimising the patch footprint

* New public API limited to the two setters and the `VeilDecision` /
  `ClientHelloMutator` types.
* Helper logic goes into a single new file `src/veil_hooks.rs` to
  keep the diff reviewable and easy to port forward.
