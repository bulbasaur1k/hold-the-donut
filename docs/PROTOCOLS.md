# PROTOCOLS — byte-level specs

> Ground-truth frozen against xray-core **v26.4.15** (2026-04-15).
> Every claim here must be re-verified against upstream when
> `docs/PLAN.md` triggers the monthly xray-core diff review.

Conventions:
* All multi-byte integers are **big-endian** unless stated otherwise.
* Ranges are half-open: `[a..b]` means `a` inclusive, `b` exclusive.
* Offsets are zero-based.
* Test-vector fixtures live at `tests/fixtures/<topic>_<case>.bin`;
  they are captured by the `scripts/xray-testbench/` harness and are
  **not** invented by hand.

---

## 1. VLESS request header

**Source:** `proxy/vless/encoding/encoding.go`, `proxy/vless/vless.go`,
`proxy/vless/encoding/addons.go`.

### Layout

```
offset  size   field
0       1      version (constant 0x00)
1       16    user UUID (raw bytes, not hex)
17      1     addon length L  (uint8)
18      L     addons          (protobuf-encoded Addons message)
18+L    1     command         (0x01=TCP, 0x02=UDP, 0x03=Mux)
19+L    2     port            (BE uint16)           # omitted when command=Mux
21+L    1     address type    (0x01=IPv4, 0x02=Domain, 0x03=IPv6)
22+L    N     address bytes   (see below)
22+L+N  ...   payload
```

### `Addons` protobuf

```proto
// proxy/vless/encoding/addons.proto
message Addons {
  string flow = 1;          // "" | "none" | "xtls-rprx-vision"
  bytes  seed = 2;          // Vision-only; empty otherwise
}
```

Encoded with `proto3` rules. When both fields are default, `L = 0` and the
addons segment is absent.

### Address type encoding

| `addr_type` | Bytes | Field shape |
|---|---|---|
| `0x01` (IPv4) | 4 | 4 raw bytes |
| `0x02` (Domain) | `1 + len` | 1-byte length prefix `len` (uint8, 1..=255), then `len` UTF-8 bytes |
| `0x03` (IPv6) | 16 | 16 raw bytes |

### Flow rules

* `Addons.flow` accepted values in v26.4.15: `""`, `"none"`, `"xtls-rprx-vision"`.
* `xtls-rprx-vision` is valid **only** when the carrier transport is raw
  TCP+REALITY. XHTTP with Vision returns
  `"XTLS only supports TLS and REALITY directly for now"`
  ([issue #5576](https://github.com/XTLS/Xray-core/issues/5576)).
* Vision also uses `Addons.seed`; the full Vision wire behaviour (padding
  frames, trafficState, direct-copy switch) is specified in **§4** and
  implemented in **M5.5**, not M1.

### Response prefix (server → client, first write)

`proxy/vless/encoding/encoding.go: EncodeResponseHeader`:

```
offset  size   field
0       1     response version (echoes request version, 0x00)
1       1     addon length L'
2       L'    response addons (usually empty)
3+L'    ...   payload
```

### Test vectors to capture

| Fixture name | Description |
|---|---|
| `vless_tcp_v4.bin` | command=TCP, addr=IPv4, flow="", payload=empty |
| `vless_tcp_domain.bin` | command=TCP, addr=Domain("example.com") |
| `vless_udp_v6.bin` | command=UDP, addr=IPv6 |
| `vless_tcp_vision.bin` | command=TCP, flow=xtls-rprx-vision, addons.seed=0x00..08 |

Fixtures are pulled from the testbench once M1 starts; until then this
file documents the intent.

---

## 2. REALITY handshake

**Source:** `transport/internet/reality/reality.go`, `reality.proto`.

### Actors & keys

| Party | Long-term key | Ephemeral key | Sees |
|---|---|---|---|
| Server | X25519 static (from `privateKey` in config) | none | Client's `SessionID` from raw ClientHello |
| Client | none | X25519 ephemeral | Server's static `publicKey` from config |

### AuthKey derivation

```
shared  = X25519(client_priv, server_pub)        // 32 bytes
salt    = ClientHello.Random[0..20]              // 20 bytes
info    = b"REALITY"                             // 7 bytes
AuthKey = HKDF-SHA256(salt, info).expand(shared) // 32 bytes
```

The same salt is available to the server because `ClientHello.Random` is
in the raw bytes hook sees.

### ClientHello `SessionID` layout (after veiled-TLS rewrite)

`SessionID` is a legacy TLS field carried in the ClientHello body at
offset **39** from the start of the ClientHello handshake message
(`msg_type[1] + length[3] + legacy_version[2] + random[32] +
session_id_length[1] = 39`). TLS 1.3 ignores this field semantically
(it's echoed back for compat), so the veiled handshake reuses all 32
bytes.

The full 32-byte SessionID slot **is the AES-256-GCM output**
(ciphertext + tag) of a 16-byte plaintext. There is no cleartext
short-id on the wire; the SessionID looks indistinguishable from
random to a probe.

Plaintext layout (16 bytes, fed into AES-GCM as the message):

```
offset  size   field
0       3      Xray version triplet (x, y, z) — major, minor, patch
3       1      reserved, set to 0
4       4      Unix timestamp (BE uint32)
8       8      ShortID (8 raw bytes)
```

Sealed output (16 bytes ciphertext + 16 bytes tag = 32 bytes) lands
in `SessionID[0..32]`. Open parameters on the server:

```
key   = AuthKey                                    // 32 bytes
nonce = ClientHello.Random[20..32]                 // 12 bytes
ad    = entire ClientHello body, with SessionID slot zeroed
ct    = SessionID[0..32]
```

Both sides compute AAD over the SessionID-zeroed ClientHello, so the
check is symmetric.

> ✅ **Verified against v26.4.15 source** (`transport/internet/reality/reality.go`
> @ commit `c5edc12`). Client seal: lines 141–175; cert pinning: 84–101.

### Cert pinning (MITM defense)

REALITY does **not** rely on normal PKI for the authenticated client.
In tunnel mode the server presents a forged self-signed **Ed25519** leaf
cert whose `Signature` field is overwritten with
`HMAC-SHA512(AuthKey, cert.ed25519_pubkey)`. The client's
`VerifyPeerCertificate` recomputes it and compares
(`reality.go:84-101`):

```
pub = certs[0].Ed25519PublicKey            # 32 bytes
ok  = certs[0].Signature == HMAC_SHA512(key = AuthKey, msg = pub)
if ok: Verified = true                     # trust, bypass PKI
```

Optional post-quantum (v25.7.26+): when `mldsa65Verify` is set, the
ML-DSA-65 signature in `certs[0].Extensions[0]` is verified over
`HMAC_SHA512(AuthKey, pub || ClientHello.Raw || ServerHello.Raw)`.

> **donut hardening (implemented, not xray-byte-compatible):** rather than
> embedding the HMAC in the cert (xray's exact scheme above), donut sends a
> standalone `HMAC(AuthKey)` proof as the first in-tunnel bytes; the client
> accepts any TLS cert (`NoCertVerification`) and authenticates the server
> purely by that proof against its own derived `AuthKey`. Same security
> property (server proves possession of the static key; MITM can't forge
> the proof), simpler than cert forgery, and sufficient since xray cert
> interop is out of scope. See `donut-veil::server_proof` +
> `donut-server::VeilServer` + `donut-client::VeilClient`.

### Server decision flow (matches `donut-veil::server::decide`)

```
on ClientHello arrival (server, pre-crypto raw hook):
    raw  = full ClientHello handshake message (from msg_type byte)
    sid  = raw[39..71]                       # 32-byte SessionID slot (AEAD output)
    share = client X25519 key_share extension
    shared  = X25519(server_priv, share)
    authKey = HKDF-SHA256(ikm=shared, salt=raw.Random[:20], info="REALITY")  # 32B
    aad     = raw with the SessionID slot [39..71] zeroed
    nonce   = raw.Random[20..32]
    pt = AES256GCM_open(key=authKey, nonce, ct=sid, aad)   # 16-byte plaintext, or fail
    if pt is None:                       forward(raw → dest)   # probe/foreign → selfsteal
    shortID = pt[8..16]
    if shortID not in config.shortIds:   forward(raw → dest)
    => Tunnel  (then terminate TLS; cert pinning above is the MITM defense)
```

### Server requirements

* TLS 1.3 only. TLS 1.2 ClientHello triggers forward.
* Target cert must be obtained from the real `target:443` during
  bootstrap and cached. v26.3.27 added a four-tier probe of the
  target's `maxUselessRecords` (default 32) and warns on non-443 ports.
* Selfsteal forwarding is byte-transparent: no TLS termination happens
  on the server for non-REALITY clients.

### ShortID config semantics

* `shortIds` in config is a list of hex strings, each 1..=16 nibbles
  (so 0..=8 bytes).
* A shorter string is right-padded with zero bytes to 8 bytes on the
  wire (see `donut-core::ShortId::from_str`).
* An empty string `""` in the list means "accept zero ShortID" — used
  to wave through clients that haven't upgraded yet.

### Post-quantum (optional, v25.7.26+) — **not implemented in MVP**

* `mldsa65Seed` (server) / `mldsa65Verify` (client) enable ML-DSA-65.
* Signs `certSignature || rawClientHello || rawServerHello`.
* Signature size: **3309 bytes**. Goes into `ExtraExtensions` of the
  server cert. Requires a long enough cert chain to fit — typically
  RSA-cert targets.
* Gated behind the `mldsa65` feature flag in M10.

### Test vectors to capture

| Fixture | Contents |
|---|---|
| `reality_ch_mutated.bin` | Raw ClientHello after REALITY mutation, with matching `reality_keys.env` |
| `reality_authkey.bin` | Expected 32-byte AuthKey for a fixed (priv, pub, random, short) tuple |
| `reality_sealed_suffix.bin` | Expected final 16 bytes of SessionID for that fixture |

---

## 3. XHTTP transport

**Source:** `transport/internet/splithttp/` (server/client, mux, dialer).

### Modes

| Mode | Uplink | Downlink | `auto` resolves here when |
|---|---|---|---|
| `packet-up` | many short POSTs, one chunk each, sequence-numbered | one long GET | TLS present, no REALITY |
| `stream-up` | one long chunked POST | one long GET | explicit only |
| `stream-one` | single request carries both directions | — | **REALITY is the TLS layer** |

### Transport versions

Works over HTTP/1.1, HTTP/2, and HTTP/3. HTTP/3 uses BBR congestion
since v26.3.27.

### Session and sequence binding

A session UUID (32 hex chars or raw 16 bytes) ties uplink posts to the
downlink stream. Placements, in priority order:

| Placement key | Default | Notes |
|---|---|---|
| `Path` | **session = Path default** | template path like `/{uuid}` |
| `Query` | — | `?x_session=<uuid>` |
| `Header` | — | `X-Session: <uuid>` |
| `Cookie` | — | `Cookie: x_session=<uuid>` |
| `Body` | — | length-prefixed in first bytes of request body |
| `Auto` | resolves to Path | |
| `QueryInHeader` | — | serialised query, stashed in header |

Sequence numbers (packet-up mode only) default to `X-Seq` header.

### Server tunables (xray defaults)

| Key | Default | Purpose |
|---|---|---|
| `scMaxEachPostBytes` | `1_000_000` | max body bytes per single uplink POST |
| `scMinPostsIntervalMs` | `30` | min interval between uplink posts |
| `scMaxBufferedPosts` | `30` | max out-of-order posts buffered per session |
| `scStreamUpServerSecs` | `20..80` (range) | server picks a random timeout |
| `xPaddingBytes` | `100..1000` (range) | padding length, attached via Referer query in non-obfs mode |

### VLESS framing inside XHTTP

* In `stream-one` / `stream-up`: the VLESS header (§1) is the first
  bytes of the request body.
* In `packet-up`: the VLESS header is the first bytes of the **first
  sequenced post** (`seq = 0`).
* Response body starts with the VLESS response prefix (§1).

### Request examples (illustrative)

Stream-one over HTTP/2, REALITY on top:

```
POST /ab51e5...95 HTTP/2
Host: imitated-target.example
Content-Type: application/grpc        # often imitates gRPC
X-Padding: <random bytes>
Referer: https://imitated-target.example/?x=<padding>
Content-Length: 0                     # chunked or CL depending on proxy

<VLESS header><user payload><server response>
```

Packet-up: multiple

```
POST /ab51e5...95 HTTP/1.1
X-Seq: 0
Content-Length: 4096

<VLESS header + payload chunk>
```

paired with

```
GET /ab51e5...95 HTTP/1.1
Accept: */*

<server → client bytes>
```

### Test vectors to capture

| Fixture | Contents |
|---|---|
| `xhttp_streamone_h2.pcap` | Full H2 conversation, stream-one + REALITY, TLS keylog included |
| `xhttp_packetup_h1.pcap` | H1 conversation with N sequenced POSTs |
| `xhttp_streamup_h2.pcap` | One long POST + one long GET |
| `xhttp_h3.pcap` | Same as stream-one but over QUIC/HTTP-3 |

---

## 4. Vision flow (`xtls-rprx-vision`)

**Source:** `proxy/proxy.go` (`XtlsPadding`, `XtlsUnpadding`, `TrafficState`,
record-detection consts), driven from the `xtls-rprx-vision` reader/writer.

> ✅ **Verified against v26.4.15 source** (`proxy/proxy.go` @ commit `c5edc12`).
> Constants: lines 40–59. `XtlsPadding`: 495–532. `XtlsUnpadding`: 534–614.
> `TrafficState`: 102–148.

### What Vision is for

Vision targets the **TLS-in-TLS** problem. When a plain VLESS+TLS tunnel
carries an *inner* HTTPS session, an observer sees two nested TLS record
streams whose record-length/timing pattern is a strong proxy fingerprint.
Vision inspects the first packets, detects when the inner TLS 1.3 handshake
has finished (the first `application_data` record), and then **stops
wrapping** — bytes are copied 1:1 so the inner records ride directly on the
outer connection, eliminating the double-encryption signature and the copy.

Vision is valid **only** over raw TCP + (REALITY|TLS). It is rejected with
XHTTP (§1, [issue #5576](https://github.com/XTLS/Xray-core/issues/5576)).

### Padding command bytes (`proxy/proxy.go:56-58`)

```
CommandPaddingContinue = 0x00   // more padded frames follow
CommandPaddingEnd      = 0x01   // last padded frame; switch to direct after
CommandPaddingDirect   = 0x02   // direct splice
```

### Padded-frame layout (`XtlsPadding`)

```
offset  size   field
0       16     UserUUID        ← FIRST padded frame ONLY (the receiver keys
                                 off this to detect the start of Vision)
16/0    1      command         (0x00 | 0x01 | 0x02)
+1      2      contentLen      (BE uint16) — real payload byte count
+3      2      paddingLen      (BE uint16) — trailing padding byte count
+5      C      content         (C = contentLen)
+5+C    P      padding         (P = paddingLen; uninitialised buffer bytes,
                                 the receiver only skips them)
```

So the per-frame header is the **5 bytes** `command|contentLenHi|contentLenLo|
paddingLenHi|paddingLenLo`, and the very first frame is additionally prefixed
with the 16-byte UUID. Overhead cap: `paddingLen ≤ bufSize - 21 - contentLen`
(21 = 16 UUID + 5 header).

### `XtlsUnpadding` state machine (`proxy/proxy.go:534-614`)

Per-direction state: `RemainingCommand`, `RemainingContent`, `RemainingPadding`
(all init `-1`), `CurrentCommand`.

1. **Initial** (`-1/-1/-1`): if `len ≥ 21` and the first 16 bytes equal the
   connection's `UserUUID`, advance 16 and set `RemainingCommand = 5`;
   otherwise return the buffer untouched (direct passthrough).
2. Read 5 header bytes → `CurrentCommand`, `RemainingContent` (BE16),
   `RemainingPadding` (BE16).
3. Emit `RemainingContent` content bytes; skip `RemainingPadding` padding bytes.
4. Block done: if `CurrentCommand == 0` (Continue) → next block
   (`RemainingCommand = 5`, **no** UUID again). If non-zero (End/Direct) →
   reset to `-1/-1/-1`, write any remaining bytes raw, and **break** → all
   subsequent traffic is direct (the UUID check in step 1 then fails forever,
   so it stays in passthrough).

### trafficState detection (`proxy/proxy.go:102-148`, record consts `40-59`)

The reader inspects up to `NumberOfPacketToFilter` initial packets
(**default 8**) using these constants:

```
TlsServerHandShakeStart = {0x16, 0x03, 0x03}   // handshake record
TlsApplicationDataStart = {0x17, 0x03, 0x03}   // application_data record
TlsHandshakeTypeClientHello = 0x01,  ServerHello = 0x02
Tls13CipherSuiteDic = {0x1301,0x1302,0x1303,0x1304,0x1305}  // → IsTLS / IsTLS12orAbove
```

When `IsTLS` and a buffer begins with `TlsApplicationDataStart` (the inner
handshake is done), the writer emits `CommandPaddingEnd` and flips to direct.
`TrafficState` fields: `UserUUID`, `NumberOfPacketToFilter`, `EnableXtls`,
`IsTLS12orAbove`, `IsTLS`, `Cipher`, `RemainingServerHello`, `Inbound`,
`Outbound`.

### Direct-copy ("splice") switch

After the End/Direct command the wrapper stops reshaping. xray uses
`splice(2)` on Linux. Our Rust port: default
`tokio::io::copy_bidirectional` once the Vision wrapper signals direct;
optional Linux `splice` fast-path behind a flag.

### `Addons.seed`

`Addons.seed` (§1 field 2) feeds the padding-length randomiser:
`XtlsPadding(..., testseed []uint32)` uses 4 derived values (content
threshold + random ranges). It only affects padding *lengths* (which are
random anyway) — **not** the framing — so interop does not require matching
the seed. donut may emit an empty seed and use its own length ranges.

### Test vectors to capture

| Fixture | Contents |
|---|---|
| `vision_first_frame.bin` | First frame: 16B UUID + `Continue` header + content + padding |
| `vision_pad_end.bin` | The `CommandPaddingEnd` frame at handshake completion |
| `vision_handshake.pcap` | Full raw-TCP+REALITY+Vision conversation with TLS keylog, capturing the padding→direct transition |

---

## 5. Change review cadence

The spec in this document is **frozen** against xray-core v26.4.15. Per
`docs/PLAN.md` § "Ежемесячная рутина":

1. First Monday of each month, run:
   ```sh
   cd scripts/xray-testbench/upstream && git pull
   git diff v26.4.15..HEAD -- \
     transport/internet/reality transport/internet/splithttp proxy/vless
   ```
2. If anything listed in §1–§3 of this file is affected, bump this
   document's frozen version header and update the ANALYSIS/PLAN.

Breaking wire changes on xray's side should be captured here **before**
any implementation change in the Rust crates.
