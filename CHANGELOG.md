# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Authoritative DNS responder with the RFC 1035 wire format implemented
  from scratch: header packing, domain-name codec with message compression
  on encode and decode (backward-only pointers, hop cap against loops),
  A / AAAA / TXT / NS / SOA / CNAME record types, UDP with TC-bit
  truncation at 512 bytes, and TCP with two-byte length framing.
- nip.io-style magic hostnames under your own zone: dotted
  (`10.0.0.7.dev.example.test`), dashed (`app-10-0-0-7…`), 8-hex-digit
  (`0a000007…`), and dashed IPv6 (`2001-db8--7…`) notations, each with
  optional name prefixes and strict near-miss rejection.
- Deliberate answer precedence: registered records beat magic extraction,
  magic beats the optional `--fallback` catch-all; out-of-zone questions
  are REFUSED, and negative answers carry the SOA for RFC 2308 caching.
- Dynamic-update HTTP API authenticated per request with HMAC-SHA256 over
  (method, path, timestamp, body-hash): PUT/DELETE `/v1/records/{name}`,
  GET `/v1/records`, open `/healthz`; constant-time comparison, a
  configurable timestamp window, and opaque 401s.
- DNS-01 helper: PUT/DELETE `/v1/acme/{name}` manages the
  `_acme-challenge.{name}` TXT record (`@` for the apex), plus the
  `hostwild acme set|clear` client for certbot/lego hooks.
- CLI: `serve` (prints concrete bound addresses, `:0` friendly), offline
  `resolve` dry-run, dig-free `query` client over UDP or TCP, `update` /
  `list` API clients, and `sign` for curl-ready authentication headers.
- Static `--record name=address` seeds and a JSON `--state` file that
  persists dynamic registrations (atomic rename) across restarts, with the
  SOA serial bumped on every mutation.
- Runnable examples (`examples/dev-zone.sh`, `examples/dns01-hook.sh`) and
  reference docs (`docs/resolution.md`, `docs/update-api.md`).
- 89 deterministic offline tests (wire codec, magic parsing, resolver
  precedence, HMAC auth, HTTP API, store, in-process CLI with a loopback
  integration) and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/hostwild/releases/tag/v0.1.0
