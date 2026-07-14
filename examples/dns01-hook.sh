#!/usr/bin/env bash
# A certbot manual-auth-hook shaped example for DNS-01 validation.
#
# certbot calls the auth hook with CERTBOT_DOMAIN and CERTBOT_VALIDATION in
# the environment; the hook must publish the validation string at
# _acme-challenge.<domain> as TXT. With hostwild that is one command.
#
#   certbot certonly --manual --preferred-challenges dns \
#     --manual-auth-hook    'bash examples/dns01-hook.sh set' \
#     --manual-cleanup-hook 'bash examples/dns01-hook.sh clear' \
#     -d '*.dev.example.test'
#
# Standalone demo (no certbot): bash examples/dns01-hook.sh demo
set -euo pipefail

BIN="${HOSTWILD_BIN:-hostwild}"
API="${HOSTWILD_API:-http://127.0.0.1:8053}"
# The shared key comes from the environment; never hard-code it.
: "${HOSTWILD_KEY:?set HOSTWILD_KEY to the shared HMAC key of the server}"

case "${1:-}" in
set)
  exec "$BIN" acme --api "$API" set "$CERTBOT_DOMAIN" "$CERTBOT_VALIDATION"
  ;;
clear)
  exec "$BIN" acme --api "$API" clear "$CERTBOT_DOMAIN"
  ;;
demo)
  # Show the two calls certbot would make, against a name of our choosing.
  CERTBOT_DOMAIN="app" CERTBOT_VALIDATION="demo-validation-token" \
    bash "${BASH_SOURCE[0]}" set
  "$BIN" query --type TXT "_acme-challenge.app.dev.example.test" || true
  CERTBOT_DOMAIN="app" bash "${BASH_SOURCE[0]}" clear
  ;;
*)
  echo "usage: $0 set|clear|demo" >&2
  exit 2
  ;;
esac
