# XTLS-Vision (`xtls-rprx-vision`) — faithful protocol spec

Ground-truth extracted from xray-core `proxy/proxy.go` (testbench upstream,
v26.x). This is the exact wire behaviour our `raw` transport must speak to
interoperate with a real Xray VLESS client/server. Goal: replace the custom
`donut-io::vision` equivalent with a faithful port.

Vision rides **inside** the VLESS data-plane on the RAW (TCP)+TLS transport.
It pads the first packets to erase the length signature of the *inner* TLS
handshake (defeats TLS-in-TLS detection), then — once it detects the inner
connection is TLS 1.3 — switches to a raw "direct copy" splice for speed.

## Constants

```
CommandPaddingContinue = 0x00   // more padded blocks follow
CommandPaddingEnd      = 0x01   // last padded block; stop padding (no splice)
CommandPaddingDirect   = 0x02   // last padded block; switch to raw splice

TlsClientHandShakeStart = [0x16, 0x03]            // + [5]==0x01 ClientHello
TlsServerHandShakeStart = [0x16, 0x03, 0x03]      // + [5]==0x02 ServerHello
TlsApplicationDataStart = [0x17, 0x03, 0x03]      // TLS app-data record
Tls13SupportedVersions  = [0x00,0x2b,0x00,0x02,0x03,0x04] // ext marker in ServerHello
buf.Size = 8192          // padded block byte budget (cap padLen at Size-21-content)
```

## Padding block wire format (`XtlsPadding`)

```
[16-byte UserUUID]   // ONLY on the very first padded block of a direction
[command : u8]
[contentLen : u16 BE]
[paddingLen : u16 BE]
[content : contentLen bytes]
[padding : paddingLen bytes]   // zero-filled
```
- `userUUID` is written once per direction (the writer holds `writeOnceUserUUID`,
  nil's it after the first block). It is the VLESS user UUID — doubles as the
  "padding has started" marker for the receiver.
- paddingLen: if `contentLen < seed[0]` and `longPadding` → `rand(seed[1]) + seed[2] - contentLen`,
  else `rand(seed[3])`. Default seed `{900,500,900,256}`. Capped at `Size-21-contentLen`.

## Unpadding state machine (`XtlsUnpadding`)

Per-direction state: `remainingCommand`, `remainingContent`, `remainingPadding`
(all init **-1**), `currentCommand`.
- Initial (`all == -1`): if `buf.len()>=21 && buf[0..16]==UserUUID` → advance 16,
  `remainingCommand=5`. Else return buffer unchanged (not yet padded).
- Read 5 command bytes: `[5]=command`, `[4]=contentLen hi`, `[3]=contentLen lo`,
  `[2]=padLen hi`, `[1]=padLen lo`.
- Emit `remainingContent` content bytes; skip `remainingPadding` padding bytes.
- Block done: if `currentCommand==0` (Continue) → `remainingCommand=5` (next block).
  Else (End/Direct) → reset to initial (`-1,-1,-1`); any leftover bytes are raw
  (post-Vision) and passed through.

## TLS filter (`XtlsFilterTls`) — sets `EnableXtls`

Runs while `NumberOfPacketToFilter > 0` (init **8**), decrements per buffer:
- ServerHello (`[0..3]==16 03 03 && [5]==0x02`): `IsTLS=IsTLS12orAbove=true`,
  `RemainingServerHello = (be16(buf[3..5])) + 5`; parse cipher at
  `buf[43+sessionIdLen+1 .. +3]` (sessionIdLen = `buf[43]`).
- ClientHello (`[0..2]==16 03 && [5]==0x01`): `IsTLS=true`.
- While `RemainingServerHello>0`: if buffer contains `Tls13SupportedVersions` →
  **TLS 1.3** → `EnableXtls=true` (unless cipher is `TLS_AES_128_CCM_8_SHA256`)
  → `NumberOfPacketToFilter=0`. Else TLS 1.2 → stop filtering.

## Writer state machine (`VisionWriter`, per write)

- If `switchToDirectCopy` → write raw (splice).
- If `NumberOfPacketToFilter>0` → `XtlsFilterTls`.
- If `isPadding`:
  - First write (`mb==[nil]`): `XtlsPadding(nil, Continue, uuid, longPadding=true)`
    — long padding to hide the VLESS header.
  - Else `ReshapeMultiBuffer` (split buffers ≥ Size-21 at the last app-data marker),
    then per buffer:
    - If `IsTLS && buf.len()>=6 && buf[0..3]==17 03 03 && completeRecord`: this is
      inner app-data after the handshake → `command = End` (or **Direct** if
      `EnableXtls`), set `switchToDirectCopy` (if EnableXtls), `isPadding=false`.
    - Else if `!IsTLS12orAbove && NumberOfPacketToFilter<=1`: `command=End`,
      `isPadding=false` (finish 1 packet early for old receivers).
    - Else `command = Continue` (or End/Direct on last buffer when no longer padding).
    - `XtlsPadding(buf, command, uuid, longPadding)`.

`ReshapeMultiBuffer`: if a buffer ≥ `Size-21`, split at `lastIndexOf(app-data marker)`
(clamped to `[21, Size-21]`, else midpoint) so each padded block fits `Size`.

`IsCompleteRecord`: walks TLS records (`17 03 03` + be16 len) over the buffer; true
if record boundaries tile the buffer exactly.

## Reader state machine (`VisionReader`, per read)

- If `switchToDirectCopy` → return raw.
- If `withinPaddingBuffers || NumberOfPacketToFilter>0` → `XtlsUnpadding` each buffer:
  - after: if `remainingContent>0 || remainingPadding>0 || currentCommand==0`
    → `withinPaddingBuffers=true`; elif `currentCommand==1` → `false`;
    elif `currentCommand==2` → `false` + `switchToDirectCopy=true`.
- If `NumberOfPacketToFilter>0` → `XtlsFilterTls`.
- On `switchToDirectCopy` transition: flush any buffered input, switch to raw reader.

## TrafficState defaults (`NewTrafficState`)

```
NumberOfPacketToFilter = 8
EnableXtls = false ; IsTLS12orAbove = false ; IsTLS = false
per-direction: WithinPaddingBuffers=true, IsPadding=true,
               RemainingCommand=-1, RemainingContent=-1, RemainingPadding=-1
UserUUID = the VLESS user's 16-byte UUID
```

## Direction mapping (server `raw` inbound)

- **uplink** (client→server): client pads, server **unpads** (Reader, `Inbound` state).
  Carries the inner ClientHello.
- **downlink** (server→client): server **pads** (Writer, `Inbound.IsPadding`).
  Carries the inner ServerHello → this is where the server's filter detects TLS 1.3
  and emits `CommandPaddingDirect` to splice.

## Interop status (vs real Xray 26.5.9) — debugging notes

Tested: `teddysun/xray` client (`vless` + `network: tcp` + `tls` allowInsecure
+ `flow: xtls-rprx-vision`) → local `donut-server` `transport: raw`,
`vision: "xray"`, on `0.0.0.0:8443` (self-signed cert) → freedom outbound.
Reproduce from `/tmp/donut-interop/{server,client}.json` (UUID in `uuid.env`).

What works ✅
- **Padding relay**: a plaintext `http://api.ipify.org` request tunnels
  end-to-end and returns 200. The xray client's own logs show byte-exact
  padding/unpadding both directions, TLS-1.3 detection from our ServerHello,
  `CommandPaddingDirect`, and `CopyRawConn splice`.
- HTTPS handshake bytes are valid TLS records in both directions (verified
  via `hex16` head logging): uplink `16 03 01`(ClientHello) → `14 03 03`(CCS)
  +`17 03 03`(Finished) → `17 03 03`(appdata); downlink `16 03 03 .. 02`
  (ServerHello flight) → `17 03 03`(appdata).

What's broken ❌ (the only remaining bug)
- **HTTPS resets post-splice** (`curl` rc=56, no response). It is isolated
  to the **raw-splice data phase** (after `CommandPaddingDirect`): the
  padding relay is fine (HTTP works), the handshake is byte-exact and the
  splice negotiates, but the inner TLS doesn't complete. Suspect a
  drop/dup/ordering byte in the raw passthrough that the head logs don't
  reveal. `try_join!`→`join!` did **not** fix it (so it's not premature
  cancellation).

Next debugging step
- Byte-level diff of the raw phase: point the donut upstream at a **local,
  inspectable** inner-TLS target (or pcap) instead of opaque Cloudflare, and
  compare the exact bytes our server relays vs a direct connection — find the
  lost/extra byte at/after the Direct transition. Check the `Unpadder`
  leftover handling and the downlink `direct` branch around the transition.

## Byte-stream adaptation notes (Rust port)

Xray works on `buf.MultiBuffer` (chunks ≤ `buf.Size`=8192). Our tokio port reads
up to 8192 per chunk and treats it as one buffer, preserving the per-chunk filter
and padding semantics. The fragile assumption (which Xray also relies on, and which
holds because inner TLS records are written as discrete sends) is that early read
chunks begin on a TLS-record boundary. The first-write VLESS-header long padding and
the per-direction `writeOnceUserUUID` marker must be byte-exact for interop.
