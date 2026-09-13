# ADR-0008: Dependency policy and the allowed list

Status: accepted · Date: 2026-09-05

## Context

A security tool that needs monthly patches because of somebody else's CVEs sabotages
itself. Every dependency is an update path, an audit surface and a supply-chain risk.

## Policy

1. Standard library first. A dependency needs a line in the table below, with the
   reason, before it is added. A pull request adding a module without that line is
   rejected.
2. Prefer modules from the Go project (`golang.org/x/…`) over third parties.
3. Dependencies are updated in bundles with the release cycle, not ad hoc; Dependabot
   opens the PRs, CI (`govulncheck`) fails the build on a known vulnerability.
4. `go.sum` is authoritative; builds use `-mod=readonly`; CI verifies `go mod tidy`
   produces no diff.
5. Web assets: the console is an npm project (`web/`) whose lockfile is authoritative;
   a package needs a line in ADR-0013 the way a Go module needs one here. The few
   assets of the server-rendered pages are vendored with version and SHA-256 in
   `internal/server/console/static/VENDORED.md`. Nothing is loaded from a CDN — the
   console runs inside an overlay without internet.

## Allowed list

| Module | Why | Used by |
| --- | --- | --- |
| `modernc.org/sqlite` | pure-Go SQLite; the only way to a static binary with SQLite | server store |
| `golang.org/x/sys` | `AF_PACKET` sockets, capability checks on Linux (Go project) | agent discovery |
| `golang.org/x/net` | `icmp`, `ipv4`, `ipv6` helpers and `dns/dnsmessage` for mDNS (Go project) | agent discovery, checks |

Explicitly **not** used, and why:

| Instead of | We use |
| --- | --- |
| a YAML/TOML library | environment-style `KEY=value` config (ADR-0009); rules in Phase 2 will revisit this |
| a web framework / router | `net/http` `ServeMux` with method+path patterns |
| an ORM / query builder | `database/sql` and hand-written SQL in one place per aggregate |
| a logging library | `log/slog` |
| a CLI framework | `flag` |
| `x/crypto` (argon2/bcrypt) | `crypto/pbkdf2` (SHA-256, 600 000 iterations) — OWASP-acceptable, stdlib since Go 1.24 |
| a TOTP library | RFC 6238 is 40 lines on `crypto/hmac` |
| cosign / Sigstore clients | `crypto/ecdsa` verification of cosign's blob signature (ADR-0006) |
| a UUID/ULID library | `internal/id` (crypto/rand + base32) |
| a JS framework on the server | `html/template` for login and status pages; the console itself is a React app built at build time and embedded (ADR-0013) |

Test-only dependencies: none. Integration tests drive Docker through `os/exec`.

Vendored into the console app (no runtime download, ADR-0013): the vendor marks in
`web/src/components/vendor-marks.generated.ts` are path data from
[simple-icons](https://github.com/simple-icons/simple-icons) (CC0-1.0) for the brands we
actually meet in customer networks, written by `web/scripts/gen-vendor-marks.mjs`.
simple-icons itself is a build-time dependency and never ships. The brands are
trademarks of their owners and are used to name the device they stand for.

simple-icons does not carry every brand — most printer makers and most German telephony
makers are missing, Canon, Brother, Ricoh, Innovaphone and Starface among them. Those are
**not** drawn from memory: a logo we invent is wrong in a way nobody can see, and passing
it off as the vendor's is worse than not having it. They get a monogram instead — two
letters from the vendor's name on a colour derived from that same name, so a vendor looks
the same everywhere and never like another one. Only a device whose vendor we never
learned falls back to the kind icon.

**leaflet** (BSD-2-Clause, `web/package.json`) draws the site map. Maps are a solved
problem with a decade of edge cases in panning, zooming and tile handling, and the
alternative was a slippy-map implementation of our own. Its tiles come from a source the
operator configures (`map.tiles`, OpenStreetMap by default) and are the only foreign
thing the console loads — as images, named explicitly in the content policy. The address
lookup that turns an address into coordinates runs on the server (`internal/server/geocode`,
stdlib only), because the geocoder asks callers to identify themselves in the User-Agent
and a browser cannot, and because it keeps the console's `connect-src` at `'self'`.

## Consequences

- `go.sum` stays short enough to read in a review.
- Some things are hand-written that a library would give for free (TOTP, base32 ids,
  DNS messages). Each is small, tested, and ours.
