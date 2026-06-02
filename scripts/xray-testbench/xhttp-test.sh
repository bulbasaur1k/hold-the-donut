#!/usr/bin/env bash
# End-to-end xHTTP wire-compat test: a REAL xray-core client (docker
# teddysun/xray) drives our donut-server transport="xhttp" over TLS+H2,
# stream-up. Proves an off-the-shelf VLESS/xHTTP client interoperates.
#
# What it does:
#   1. generate a throwaway TLS cert for tunnel.example (certs/, gitignored)
#   2. build + start donut-server with donut-xhttp-server.json
#   3. start a local HTTPS target (exercises a full multi-roundtrip handshake)
#   4. run the xray client container (SOCKS5 → VLESS xhttp → donut-server)
#   5. curl through the SOCKS proxy and assert the bytes come back
#
# Usage (from repo root):  scripts/xray-testbench/xhttp-test.sh
set -euo pipefail
cd "$(dirname "$0")"
TB="$PWD"
ROOT="$(cd ../.. && pwd)"

SOCKS_PORT=11080
SERVER_PORT=8444
TARGET_PORT=28443
UUID="b831381d-6324-4d53-ad4f-8cda48b30811"

cleanup() {
  docker rm -f donut-xray-client >/dev/null 2>&1 || true
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
  [ -n "${TGT_PID:-}" ] && kill "$TGT_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> 1. cert"
mkdir -p certs
if [ ! -f certs/cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/key.pem -out certs/cert.pem \
    -days 365 -subj "/CN=tunnel.example" -addext "subjectAltName=DNS:tunnel.example" 2>/dev/null
fi
PIN=$(openssl x509 -in certs/cert.pem -outform DER | openssl dgst -sha256 | awk '{print $NF}')
sed "s/__CERT_PIN__/$PIN/" xray-client-xhttp.json > certs/xray-client.live.json

echo "==> 2. build + start donut-server"
( cd "$ROOT" && cargo build -q -p donut-server )
( cd "$ROOT" && RUST_LOG=donut_server=info ./target/debug/donut-server \
    -c scripts/xray-testbench/donut-xhttp-server.json ) >/tmp/donut-xhttp.log 2>&1 &
SRV_PID=$!
sleep 2

echo "==> 3. local HTTPS target on 127.0.0.1:$TARGET_PORT"
python3 - "$TB/certs/cert.pem" "$TB/certs/key.pem" "$TARGET_PORT" >/tmp/https_target.log 2>&1 <<'PY' &
import http.server, ssl, sys, os
cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
os.chdir("/tmp")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
httpd = http.server.HTTPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
TGT_PID=$!
sleep 1

echo "==> 4. xray client container (xray-core, real)"
docker rm -f donut-xray-client >/dev/null 2>&1 || true
docker run -d --name donut-xray-client \
  -p 127.0.0.1:${SOCKS_PORT}:10808 \
  --add-host host.docker.internal:host-gateway \
  -v "$TB/certs/xray-client.live.json:/etc/xray/config.json:ro" \
  teddysun/xray:latest xray -c /etc/xray/config.json >/dev/null
sleep 3

echo "==> 5. drive a full TLS request through the tunnel"
CODE=$(curl -s --insecure --max-time 15 --socks5-hostname 127.0.0.1:${SOCKS_PORT} \
  https://127.0.0.1:${TARGET_PORT}/ -o /dev/null -w "%{http_code}") || true

if [ "$CODE" = "200" ]; then
  echo "PASS: xray-core xHTTP stream-up → donut-server tunnel works (HTTP $CODE)"
  exit 0
else
  echo "FAIL: got HTTP code [$CODE]"
  echo "--- donut-server log ---"; tail -20 /tmp/donut-xhttp.log
  echo "--- xray client log ---"; docker logs donut-xray-client 2>&1 | tail -20
  exit 1
fi
