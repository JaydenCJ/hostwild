# Contributing to hostwild

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else — the runtime is standard library only.

```bash
git clone https://github.com/JaydenCJ/hostwild && cd hostwild
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary, starts a real server on loopback
ephemeral ports, and drives the whole path — magic names over UDP and TCP,
a signed dynamic update, the DNS-01 helper, and auth rejection; it must
finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (89 deterministic tests, loopback only).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (the wire codec, magic parser, and resolver never touch a
   socket — only `internal/server` and the CLI clients do I/O).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in the PR.
- No outbound network calls, ever — hostwild answers what it is asked and
  initiates nothing. No telemetry. Defaults bind 127.0.0.1.
- Wire-format changes need a byte-level test against the RFC 1035 encoding,
  and hostile-input cases (truncation, pointer games) for every new parser.
- The HMAC signed-string layout is frozen by a known-answer test; changing
  it is a breaking API change and needs a version bump strategy first.
- Code comments and doc comments are written in English.
- Determinism first: identical questions must produce identical answers,
  including record ordering.

## Reporting bugs

Include the output of `hostwild version`, the exact `serve` flags, the
query that misbehaved (`hostwild query --server … <fqdn>` output or a dig
transcript), and — for update-API problems — the request path, timestamp
header, and response body, which is exactly what the verifier sees.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
