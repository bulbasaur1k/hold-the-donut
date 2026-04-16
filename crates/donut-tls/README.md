# donut-tls

TLS stack for hold-the-donut. Based on upstream `rustls` 0.23.38
(commit `6b116bc`), modified to expose the two hooks needed by the
veiled-handshake layer:

* **Client-side ClientHello mutator** — callback invoked post-marshal,
  pre-send, letting us rewrite the 32-byte legacy `SessionID`
  (authenticates the handshake without touching the server's cert
  chain).
* **Server-side raw ClientHello hook** — callback invoked pre-crypto
  with the full ClientHello bytes, returning either "continue
  handshake" or "forward untouched to the fronted target".

See [MODIFICATIONS.md](MODIFICATIONS.md) for the list of intentional
diffs against the upstream snapshot, their motivation, and the exact
files they touch. When upstream publishes a new 0.23.x patch
release, that document is the checklist for porting the changes
forward.

The crate package name is `donut-tls`; it is wired into the outer
workspace via `[patch.crates-io] rustls = { path = "crates/donut-tls",
package = "donut-tls" }`, so any workspace crate can simply depend
on `rustls = "0.23"` and transparently pick up our version —
including every transitive user (quinn, tokio-rustls, hyper-rustls,
h3-quinn, etc.).

## Why in-tree instead of a separate git fork

The modifications are narrow (three patches, all in the server/client
handshake code), and the code is already ours to support — turning it
into an external repository would add process overhead (release sync,
version pinning) without making the patches easier to review. Keeping
it alongside the rest of the workspace also means `cargo fmt`,
`cargo clippy`, and CI coverage apply uniformly.

## License

Upstream rustls is `Apache-2.0 OR ISC OR MIT`. The LICENSE files from
upstream are preserved unchanged.
