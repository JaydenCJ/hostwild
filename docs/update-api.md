# The dynamic-update API

The HTTP API (default `127.0.0.1:8053`, `--http` to move, `--no-http` to
disable) mutates the record store while the DNS side keeps answering. It
speaks plain JSON and authenticates every request individually — there are
no sessions, tokens, or cookies, and the shared key never travels on the
wire.

## Request signing

Two headers accompany every request except `GET /healthz`:

```
X-Hostwild-Timestamp: <unix seconds>
X-Hostwild-Signature: hex(HMAC-SHA256(key, signed-string))
```

The signed string is exactly:

```
METHOD \n PATH \n TIMESTAMP \n hex(sha256(BODY))
```

`PATH` is the request path only (no query string, none is used). `BODY` is
the raw bytes; an empty body hashes the empty string. The server rejects
timestamps outside `--auth-window` (default 5 minutes, so a captured
request has a strictly bounded replay lifetime) and compares signatures in
constant time. All authentication failures return the same opaque 401.

This layout is frozen by a known-answer test
(`internal/hmacauth/hmacauth_test.go`) and reproducible with openssl:

```bash
BODYHASH=$(printf '%s' "$BODY" | sha256sum | cut -d' ' -f1)
printf 'PUT\n/v1/records/app\n%s\n%s' "$TS" "$BODYHASH" \
  | openssl dgst -sha256 -hmac "$KEY" -hex
```

`hostwild sign` emits both headers ready for curl, so any tool that can
set headers can drive the API without linking hostwild.

## Routes

| Route | Method | Body | Effect |
|---|---|---|---|
| `/healthz` | GET | — | liveness, version, zone, serial (no auth) |
| `/v1/records` | GET | — | list all registered names, sorted |
| `/v1/records/{name}` | PUT | `{"type","value","ttl"}` | upsert one record (replaces same-type) |
| `/v1/records/{name}` | DELETE | — | remove all records at the name |
| `/v1/acme/{name}` | PUT | `{"value"}` | set `_acme-challenge.{name}` TXT (TTL 30) |
| `/v1/acme/{name}` | DELETE | — | clear the challenge TXT |

`{name}` is relative to the zone (`app`) or fully qualified
(`app.dev.example.test`) — both normalize to the same owner. Names are
1–3 labels of `[a-z0-9_-]`, so the API can never write outside the zone
or at the apex. For `/v1/acme/`, pass `@` to target the apex challenge.
`type` is `A`, `AAAA`, or `TXT`; addresses are validated against the
family and TXT values are capped at 255 bytes. `ttl: 0` (or omitted)
inherits the zone default.

## Persistence

With `--state <file>`, every mutation is written as pretty-printed JSON
via an atomic temp-file-plus-rename, and loaded again at startup. The file
holds the serial and the presentation-form records, so it is diffable and
hand-auditable. Without `--state`, registrations live in memory only.
