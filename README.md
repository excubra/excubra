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

Requires the Go version in `go.mod`.

```
make build        # bin/excubra for this machine
make release      # static Linux amd64 + arm64 in dist/
make test         # unit tests
make lint         # go vet + golangci-lint
```

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).
