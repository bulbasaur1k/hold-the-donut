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
* Vision also uses `Addons.seed`; we do not implement Vision in M1.

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

### ClientHello `SessionID` layout (after REALITY rewrite)

`SessionID` is a legacy TLS field carried in the ClientHello body at
offset **39** from the start of the ClientHello handshake message
(`msg_type[1] + length[3] + legacy_version[2] + random[32] +
session_id_length[1] = 39`). TLS 1.3 ignores this field semantically
(it's echoed back for compat), so REALITY reuses all 32 bytes.

Plaintext layout before sealing:

```
offset  size   field
0       3      Xray version triplet (x, y, z) — major, minor, patch
3       1      reserved, set to 0
4       4     Unix timestamp (BE uint32)
8       8     ShortID (8 raw bytes)
16      16    auth blob: AES-256-GCM(AuthKey) over placeholder material
```

The final 16 bytes are the AES-GCM **ciphertext+tag** of a plaintext
chosen so that the full raw ClientHello (post-rewrite) satisfies the
server check `HMAC-SHA512(AuthKey, cert.signature) == certs[0].Signature`
after the server completes handshake with the target's real cert.

### Server decision flow

```
on ClientHello arrival:
    raw = bytes of ClientHello record body
    sid = raw[39..71]                              // 32 bytes
    shortID = sid[8..16]
    if shortID not in config.shortIds:
        forward(raw, to = config.target)            # selfsteal
        return

    shared = X25519(server_priv, ephemeral_pub_derived_from_sid)
    salt   = raw[random_offset..random_offset+20]  // ClientHello.Random[:20]
    authKey = HKDF-SHA256(salt, b"REALITY").expand(shared)
    plaintext = AES_GCM_open(authKey, sid[16..32])
    if plaintext is None:
        forward(raw, to = config.target)
        return

    // tunnel mode: proceed with normal TLS 1.3 handshake,
    // presenting config.target's real cert to the client.
    handshake()
    if HMAC_SHA512(authKey, presented_cert.signature) != expected_from_plaintext:
        drop()
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

## 4. Change review cadence

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
