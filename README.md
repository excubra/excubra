# excubra — EX0 (Excubra Zero)

**Status: pre-alpha, Phase 1 in development.** Nothing here is ready to run in a customer
network yet.

EX0 is open-source monitoring and attack detection for small infrastructures — the
twenty-server business, not the enterprise. A small box (Raspberry Pi with SSD) sits in
the customer's LAN, opens only outbound connections, reports every minute that it is
alive, checks that the systems in the LAN are reachable, knows every device in the
network, and the server turns that into state transitions delivered to a CRM by
webhook. Phase 2 adds log collection, Sigma-style rules and a daily report.

The name: *excubiae* is Latin for the night watch. The zero is the promise — zero open
ports at the customer, zero customer credentials in the centre, zero unsigned updates.
The brand is EX0; the repository, binary and CLI are `excubra` because `ex0` and `exo`
are too easy to confuse.

## Layout

One binary, two roles:

```
excubra agent   — runs on the box
excubra server  — runs in the centre (one container, SQLite, no other services)
```

See [docs/adr](docs/adr/README.md) for the architecture decisions; they are binding.

## Build

Requires the Go version in `go.mod` and, for the console, Node 22 with npm.

```
make build        # bin/excubra for this machine (builds and embeds the console first)
make release      # static Linux amd64 + arm64 in dist/
make test         # unit tests
make lint         # go vet + golangci-lint + console type-check and lint
make web          # only the console: web/ → internal/server/console/webdist
```

`go build ./cmd/excubra` on its own still works without Node; the binary then serves a
placeholder page under `/app/` instead of the console (ADR-0013).

## Updates

Releases are built and signed by the project's GitHub Actions workflow; the public
key is compiled into every binary. Every server imports the release list hourly
(`EXCUBRA_RELEASE_CATALOG`, `off` to disable) and shows it under *Updates* in the
console. From there an operator points a channel (`stable`, `canary`) at a version;
boxes and the server itself follow their channel, verify the signature, trial-run
the new binary, swap it, restart and roll back on their own if the new build does
not confirm within five minutes. Nothing is pushed to a customer network.

```
excubra server release sync                 # import new releases now
excubra server release channel stable 0.2.3 # what boxes on stable should run
excubra server box task <box_id> update     # ask one box to check now
excubra server update now                   # let this server check now
```

## Assistant

`excubra server mcp` serves EX0 over the Model Context Protocol on stdin/stdout:
tenants, sites, devices and their services, findings, events, the situation of a
site, and a tool that stores an assessment written by the assistant. Start it
through SSH from a machine in the operator overlay, so nothing new listens:

```
claude mcp add --scope user ex0 -- ssh -o BatchMode=yes root@<server> excubra server mcp --actor <you>
```

It reads and proposes; it acknowledges nothing and executes nothing (ADR-0019).

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).
