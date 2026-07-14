#!/usr/bin/env bash
# A complete hostwild session on loopback: start a dev zone, resolve magic
# names, register a record over the signed API, and read it back — all in
# one script, no root, no external network.
#
# Usage: bash examples/dev-zone.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${HOSTWILD_BIN:-$ROOT/hostwild}"
[ -x "$BIN" ] || { echo "build first: go build -o hostwild ./cmd/hostwild"; exit 1; }

ZONE="dev.example.test"
KEY="example-shared-key"
LOG="$(mktemp)"
trap 'kill $SERVER_PID 2>/dev/null || true; rm -f "$LOG"' EXIT

# 1. Serve the zone on ephemeral loopback ports (no root needed).
"$BIN" serve --zone "$ZONE" --dns 127.0.0.1:0 --http 127.0.0.1:0 --key "$KEY" > "$LOG" 2>&1 &
SERVER_PID=$!
until grep -q '^ready$' "$LOG" 2>/dev/null; do sleep 0.1; done
DNS="$(sed -n 's/^dns   udp //p' "$LOG")"
API="$(sed -n 's/^http  //p' "$LOG")"
echo "# serving $ZONE — dns $DNS, api $API"

# 2. Magic names work with zero registration.
echo; echo "# query app-10-0-0-7.$ZONE"
"$BIN" query --server "$DNS" "app-10-0-0-7.$ZONE"

# 3. Register a stable name for something that moves around.
echo; echo "# update api -> 192.0.2.44"
"$BIN" update --key "$KEY" --api "$API" api 192.0.2.44
"$BIN" query --server "$DNS" "api.$ZONE"

# 4. List what the zone knows.
echo; echo "# list"
"$BIN" list --key "$KEY" --api "$API"
