# ADR-0001: Repository layout, build and versioning

Status: accepted · Date: 2026-09-05

## Context

EX0 ships one binary with two roles (`excubra agent`, `excubra server`) built from the
same commit. Targets are Linux amd64 and arm64 as fully static binaries. Development
happens on macOS. The repository must stay navigable for outside contributors once the
project is public (Apache 2.0).

## Decision

**Module and toolchain.** Module path `github.com/excubra/excubra`. The Go version is the
one in `go.mod`; CI builds with exactly that. All shipped binaries are built with
`CGO_ENABLED=0` (SQLite is pure Go, see ADR-0008).

**One binary, subcommands via the standard `flag` package**, no CLI framework:

```
excubra agent enroll --key <KEY> [--server <URL>] [--state-dir DIR]
excubra agent run    [--state-dir DIR]           (default when no subcommand)
excubra server run   [--env-file FILE]           (default when no subcommand)
excubra server user add <name> | user list | user disable <name>
excubra server backup <dir>   | prune --keep <days>
excubra version
```

**Layout**

```
cmd/excubra/                 main: subcommand dispatch only, no logic
internal/agent/              agent runtime: enrollment, heartbeat loop, config pull, buffer
internal/agent/checks/       icmp, tcp, http checkers — a closed set (ADR-0007)
internal/agent/discovery/    passive ARP/NDP, sweeps, OUI lookup, name resolution
internal/agent/update/       signed self-update with rollback (ADR-0006)
internal/server/             server wiring: config, listeners, workers
internal/server/ingest/      handlers of the public mTLS listener (ADR-0002)
internal/server/overlay/     the overlay listener: mounts console + status API
internal/server/console/     server-rendered console (html/template + vendored htmx)
internal/server/api/         status API v1 (contract v1)
internal/server/state/       the state machine — pure, no I/O (ADR-0004)
internal/server/webhook/     delivery worker (ADR-0012)
internal/server/store/       Store interface + SQLite implementation (ADR-0005)
internal/pki/                internal CA, CSR handling, certificate issue/renew (ADR-0010)
internal/wire/               request/response types of the ingest protocol v1 (shared)
internal/event/              the event envelope and type catalogue (shared, ADR-0003)
internal/sig/                release-signature verification + embedded public key
internal/version/            version, commit, build date (set via ldflags)
fixtures/events/             one signed example per event type, for CRM integrators
deploy/                      systemd units, Dockerfile, compose example, env example
image/                       box image build (Raspberry Pi OS / Debian)
test/integration/            end-to-end test (build tag `integration`, uses Docker)
docs/adr/  docs/de/  docs/en/
```

Everything lives under `internal/` — nothing is importable by third parties before a
v1, so nothing is an API promise.

**Platform split.** Raw sockets (ARP, ICMP, AF_PACKET) are behind `//go:build linux`.
Other platforms compile stubs returning `ErrUnsupported`, so the agent builds and its
logic is unit-tested on macOS with fakes. Only the Linux build is a product.

**Build.** `Makefile` targets: `build` (host binary in `bin/`), `release` (static
`dist/excubra_linux_{amd64,arm64}` + `SHA256SUMS`), `test` (`go test -race ./...`),
`lint` (`go vet` + `golangci-lint`), `integration` (Docker-based end-to-end test),
`fixtures` (regenerates `fixtures/events`). Version information is injected with
`-ldflags "-X github.com/excubra/excubra/internal/version.Version=…"`.

**Versioning.** Semantic version tags `vMAJOR.MINOR.PATCH`. The agent/server
compatibility window (ADR-0002) is defined on MINOR. Untagged builds report
`0.0.0-dev+<commit>`.

**Tests.** Standard library `testing` only. Every state-machine transition has a table
test. Reports and events are compared against golden files under `fixtures/`.

## Consequences

- Static binaries, no distro matrix, one artifact per architecture.
- macOS developers cannot run the real discovery or ICMP code; the integration test in
  CI (Linux containers) covers it.
- Subcommands are hand-written; acceptable, the surface is small.

## Rejected

- Separate repositories for agent and server: two release pipelines, two version
  matrices, and the shared wire types would drift.
- A CLI framework (cobra, urfave): dependency for a dozen flags.
- Building with cgo for SQLite: loses static binaries and easy cross-compilation.
