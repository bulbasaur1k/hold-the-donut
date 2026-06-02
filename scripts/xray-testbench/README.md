# xray-core interop testbench

Reference xray-core server + client in Docker. Used as the ground-truth
counterparty for byte-level protocol tests of the Rust implementation.

## First-time setup

```sh
./gen-keys.sh                 # one-time; writes reality-keys.env
cp server.json.example server.json          # once templates land in M0-M1
cp client.json.example client.json
# substitute the {PRIV,PUB,SHORT_ID} placeholders using the env file
```

## Routine use

Start the xray server on `127.0.0.1:18443`:

```sh
docker compose up -d xray-server
docker compose logs -f xray-server
```

Run the xray client one-shot against it:

```sh
docker compose run --rm xray-client
```

## What to validate during M1–M5

| Milestone | Capture target | Where it lands |
|---|---|---|
| M1 VLESS | First 18+L bytes of VLESS request inside REALITY TLS (requires key-dump) | `tests/fixtures/vless_request_*.bin` |
| M3 REALITY | ClientHello raw bytes at offset 39 (SessionID) pre- and post-mutation | `tests/fixtures/ch_reality_*.bin` |
| M4 XHTTP | HTTP/1.1 and HTTP/2 request lines for all three XHTTP modes | `tests/fixtures/xhttp_*.txt` |
| M5 QUIC | QUIC long-header initial packet; H3 request frames | `tests/fixtures/h3_*.bin` |

## xHTTP wire-compat test (M1)

One-shot end-to-end proof that a **real xray-core client** interoperates with
`donut-server transport="xhttp"` (TLS+H2, stream-up):

```sh
scripts/xray-testbench/xhttp-test.sh
```

It generates a throwaway cert (`certs/`, gitignored), builds + starts
donut-server with `donut-xhttp-server.json`, runs a local HTTPS target, launches
the xray client container from `xray-client-xhttp.json` (the `__CERT_PIN__`
placeholder is filled with the live cert's SHA-256 — `allowInsecure` was removed
in xray 26.5.x, so we pin), then curls through its SOCKS5 proxy. Prints
`PASS`/`FAIL`. Last run: xray-core 26.5.9, `up=204 down=24237`, HTTP 200.

## Key dump for TLS inspection

Wireshark can decrypt the tunnel if xray is told to dump session keys:

```
XRAY_TLS_KEYLOG=/tmp/keylog.txt xray ...
```

Use the `SSLKEYLOGFILE` Wireshark preference to point at the same file.
