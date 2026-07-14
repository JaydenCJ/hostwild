# hostwild examples

Two runnable scripts, both loopback-only and self-contained.

## dev-zone.sh

A complete session in one script: starts `hostwild serve` for
`dev.example.test` on ephemeral loopback ports, resolves a magic
`app-10-0-0-7` name with zero registration, registers `api` → 192.0.2.44
through the HMAC-signed API, and lists the zone contents.

```bash
go build -o hostwild ./cmd/hostwild
bash examples/dev-zone.sh
```

## dns01-hook.sh

The DNS-01 helper wired the way certbot expects: an auth hook that
publishes `CERTBOT_VALIDATION` at `_acme-challenge.<domain>` and a cleanup
hook that removes it. Works identically as a lego `exec` provider script.
It talks to a running server — start one first (or point `HOSTWILD_API` /
`HOSTWILD_BIN` at your deployment), then run the standalone demo:

```bash
./hostwild serve --zone dev.example.test --key example-shared-key &
PATH="$PWD:$PATH" HOSTWILD_KEY=example-shared-key bash examples/dns01-hook.sh demo
```

`dev-zone.sh` picks ephemeral ports and cleans up after itself, so both
scripts can run repeatedly, alongside a real deployment, on any machine.
