# Name resolution in hostwild

hostwild serves exactly one zone (`--zone dev.example.test`). Every
question is answered by walking a fixed precedence ladder; the first rung
that matches wins. This document is the normative description — the
resolver tests pin each rule.

## Precedence ladder

| # | Rule | Answer |
|---|---|---|
| 1 | question outside the zone | `REFUSED` (hostwild is never an open resolver) |
| 2 | question class is not `IN` | `REFUSED` |
| 3 | zone apex | `SOA` / `NS`, plus `A`/`AAAA` when `--apex` is set |
| 4 | NS host (`ns.<zone>` by default) | the `--apex` address, when set |
| 5 | registered record (API or `--record` seed) | the stored record set |
| 6 | magic IP embedded in the labels | synthesized `A` or `AAAA` |
| 7 | `--fallback` configured | the catch-all address |
| 8 | nothing matched | `NXDOMAIN` with the SOA in authority |

Two subtleties worth knowing:

- **NODATA vs NXDOMAIN.** When a name exists but not at the asked type
  (e.g. `AAAA` for `10.0.0.7.<zone>`), hostwild answers `NOERROR` with
  zero answers and the SOA in authority. Answering `NXDOMAIN` there would
  make dual-stack clients drop the working `A` record too.
- **Registered beats magic.** `app-10-0-0-7.<zone>` normally decodes to
  `10.0.0.7`, but registering `app-10-0-0-7` through the API overrides the
  magic reading — explicit intent always wins.

## Magic hostname notations

The labels left of the zone are scanned right-to-left:

| Notation | Example (relative name) | Answer |
|---|---|---|
| dotted IPv4 | `10.0.0.7`, `app.10.0.0.7` | `A 10.0.0.7` |
| dashed IPv4 | `10-0-0-7`, `app-10-0-0-7` | `A 10.0.0.7` |
| hex IPv4 | `0a000007`, `app-c0a80101` | `A` from the 8 hex digits |
| dashed IPv6 | `2001-db8--7`, `--1` | `AAAA` (`-`→`:`, `--`→`::`) |

Deliberate strictness, so ordinary service names never resolve by accident:

- Octets are plain decimals 0–255; leading zeros (`10.01.0.7`) are refused.
- Hex needs exactly eight lowercase hex digits as the last dash-part.
- IPv6 must span the whole label and contain at least one dash; an
  eight-group form like `2001-db8-0-0-0-0-0-42` is read whole, never as a
  dashed IPv4 ending in `0-0-0-42`.

## Negative caching and the SOA serial

Every `NXDOMAIN`/NODATA answer carries the zone SOA whose `MINIMUM` field
is `--neg-ttl` (default 60 s), so upstream resolvers cache misses per
RFC 2308 briefly — long enough to be polite, short enough that a dynamic
registration becomes visible fast. The SOA serial starts at 1 and
increments on every successful mutation, which makes propagation checks
(`hostwild query --type SOA <zone>`) trivially scriptable.
