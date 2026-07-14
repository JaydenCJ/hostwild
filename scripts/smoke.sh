#!/usr/bin/env bash
# End-to-end smoke test for hostwild: builds the binary, starts a real
# server on loopback ephemeral ports, and drives the full path — magic
# names over UDP and TCP, a signed dynamic update, the DNS-01 helper, and
# auth rejection. No external network, idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  [ -f "$WORKDIR/serve.log" ] && sed 's/^/  serve: /' "$WORKDIR/serve.log" >&2
  exit 1
}

BIN="$WORKDIR/hostwild"
ZONE="dev.example.test"
KEY="smoke-shared-key"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/hostwild) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" version | grep -qx "hostwild 0.1.0" || fail "version mismatch"

echo "3. offline resolve dry-run (no server, no socket)"
"$BIN" resolve --zone "$ZONE" "app.10.0.0.7.$ZONE" | grep -q "10.0.0.7" \
  || fail "offline resolve missed the magic IP"
"$BIN" resolve --zone "$ZONE" "ghost.$ZONE" >/dev/null && fail "NXDOMAIN should exit 1"
[ $? -eq 1 ] || fail "NXDOMAIN exit code is not 1"

echo "4. start the server on loopback ephemeral ports"
"$BIN" serve --zone "$ZONE" --dns 127.0.0.1:0 --http 127.0.0.1:0 \
  --key "$KEY" --state "$WORKDIR/state.json" \
  --record "seeded=203.0.113.9" > "$WORKDIR/serve.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  grep -q '^ready$' "$WORKDIR/serve.log" 2>/dev/null && break
  kill -0 "$SERVER_PID" 2>/dev/null || fail "server exited during startup"
  sleep 0.1
done
grep -q '^ready$' "$WORKDIR/serve.log" || fail "server never became ready"
DNS_ADDR="$(sed -n 's/^dns   udp //p' "$WORKDIR/serve.log")"
API_URL="$(sed -n 's/^http  //p' "$WORKDIR/serve.log")"
[ -n "$DNS_ADDR" ] && [ -n "$API_URL" ] || fail "could not parse bound addresses"

echo "5. magic wildcard names answer over UDP"
"$BIN" query --server "$DNS_ADDR" "app-10-0-0-7.$ZONE" | grep -q "10.0.0.7" \
  || fail "dashed magic name did not resolve"
"$BIN" query --server "$DNS_ADDR" --type AAAA "2001-db8--7.$ZONE" | grep -q "2001:db8::7" \
  || fail "IPv6 magic name did not resolve"

echo "6. seeded static record answers"
"$BIN" query --server "$DNS_ADDR" "seeded.$ZONE" | grep -q "203.0.113.9" \
  || fail "--record seed did not resolve"

echo "7. HMAC-signed dynamic update, visible in DNS immediately"
"$BIN" update --key "$KEY" --api "$API_URL" api 192.0.2.44 \
  | grep -q "api.$ZONE" || fail "update did not confirm"
"$BIN" query --server "$DNS_ADDR" "api.$ZONE" | grep -q "192.0.2.44" \
  || fail "updated record not served"

echo "8. the same answer over TCP framing"
"$BIN" query --tcp --server "$DNS_ADDR" "api.$ZONE" | grep -q "192.0.2.44" \
  || fail "TCP query failed"

echo "9. DNS-01 helper sets and clears the challenge TXT"
"$BIN" acme --key "$KEY" --api "$API_URL" set api tok-smoke-123 >/dev/null \
  || fail "acme set failed"
"$BIN" query --server "$DNS_ADDR" --type TXT "_acme-challenge.api.$ZONE" \
  | grep -q "tok-smoke-123" || fail "challenge TXT not served"
"$BIN" acme --key "$KEY" --api "$API_URL" clear api >/dev/null \
  || fail "acme clear failed"

echo "10. a wrong key is rejected and changes nothing"
if "$BIN" update --key wrong-key --api "$API_URL" evil 10.6.6.6 2>/dev/null; then
  fail "wrong key was accepted"
fi
"$BIN" query --server "$DNS_ADDR" "evil.$ZONE" >/dev/null 2>&1 \
  && fail "unauthorized record was served"

echo "11. sign emits curl-ready headers deterministically"
H1="$("$BIN" sign --key "$KEY" --method GET --path /v1/records --timestamp 1760000000)"
H2="$("$BIN" sign --key "$KEY" --method GET --path /v1/records --timestamp 1760000000)"
[ "$H1" = "$H2" ] || fail "sign is not deterministic"
echo "$H1" | grep -q "X-Hostwild-Signature: " || fail "sign output malformed"

echo "12. registrations persist in the state file"
grep -q '"api"' "$WORKDIR/state.json" || fail "state file missing the record"

echo "SMOKE OK"
