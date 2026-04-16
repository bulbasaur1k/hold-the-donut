#!/usr/bin/env bash
# Generate a REALITY keypair + shortID using a throwaway xray container.
# Writes ./reality-keys.env.
set -euo pipefail

cd "$(dirname "$0")"

if [ -f reality-keys.env ]; then
  echo "reality-keys.env already exists; refusing to overwrite" >&2
  exit 1
fi

OUT=$(docker run --rm teddysun/xray:latest xray x25519)
PRIV=$(echo "$OUT" | awk -F': ' '/Private key/ {print $2}')
PUB=$(echo "$OUT"  | awk -F': ' '/Public key/  {print $2}')
SHORT_ID=$(openssl rand -hex 8)

cat > reality-keys.env <<EOF
REALITY_PRIVATE_KEY=$PRIV
REALITY_PUBLIC_KEY=$PUB
REALITY_SHORT_ID=$SHORT_ID
EOF

echo "Wrote reality-keys.env"
echo "Public key (for client config): $PUB"
echo "Short ID:                       $SHORT_ID"
