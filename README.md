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
placeholder page instead of the console (ADR-0013).

## Updates

Releases are built and signed by the project's GitHub Actions workflow; the public
key is compiled into every binary. Every server imports the release list hourly
(`EXCUBRA_RELEASE_CATALOG`, `off` to disable) and shows it under *Updates* in the
console. From there an operator points a channel (`stable`, `canary`) at a version;
boxes and the server itself follow their channel, verify the signature, trial-run
the new binary, swap it, restart and roll back on their own if the new build does
not confirm within five minutes. Nothing is pushed to a customer network.

Boxes come first. An agent may be at most two minor versions from the server, so
before installing, the server checks whether the new release would push any box
outside that window. If it would, it stays where it is, asks those boxes to
update now instead of at their daily tick, and installs once they are within
reach — `excubra server update status` and the console name whoever is holding
it back. Add `-anyway` for the rare box that cannot update at all. A box that has
fallen behind is never locked out: `GET /v1/update` and `POST /v1/renew` are
answered outside the window too, so it can always find its way forward.

```
excubra server release sync                 # import new releases now
excubra server release channel stable auto  # follow the newest release, no hand
excubra server release channel stable 0.2.3 # or pin one version
excubra server box task <box_id> update     # ask one box to check now
excubra server update now                   # let this server check now
excubra server update now -anyway           # install even while boxes lag
excubra server update status                # what is holding a release back
```

A channel set to `auto` follows the newest release the catalog knows, so a
published release rolls out without anyone pointing at it: the catalog imports it
within the hour, the server checks straight away, the fleet guard holds until the
boxes are within the window, and the boxes follow the same channel. Pinning a
version stays possible and is what a canary channel is for.

## The console's certificate

The console lives on the overlay and is not reachable from the internet, so it
cannot answer an HTTP challenge — and an operator should not have to install our
CA to avoid a browser warning. `deploy/console-cert.sh` proves the name over DNS
instead (Let's Encrypt DNS-01, a TXT record, no inbound connection), writes the
pair beside the server, and a daily timer renews it. Point the server at it:

```
EXCUBRA_OVERLAY_TLS=files
EXCUBRA_OVERLAY_CERT=/etc/excubra/console.crt
EXCUBRA_OVERLAY_KEY=/etc/excubra/console.key
```

The pair is re-read when it changes, so a renewal costs no restart. The ingest is
untouched: boxes pin our own CA there (ADR-0002), which is stronger for a channel
we control on both ends.

## Assistant

`excubra server mcp` serves EX0 over the Model Context Protocol on stdin/stdout.
Start it through SSH from a machine in the operator overlay. The command is a pipe
to a Unix socket of the running server, so nothing new listens on a network and a
server restart does not end the session (ADR-0024):

```
claude mcp add --scope user ex0 -- ssh -o BatchMode=yes root@<server> excubra server mcp --actor <you>
```

A session reads — tenants, sites, devices and their services, findings, events,
the situation of a site — and stores an assessment it wrote (ADR-0019).

It also sets a customer up, start to finish: tenant, site, the enrollment key
inside the complete installer command (container values and the technicians' SSH
keys included, see [image/README.md](image/README.md)), the site's LAN, the
customer's own VPN, what to watch, and the scan with the customer's consent on
record. `ex0_rollout_status` says for every step of a rollout what is missing.
Each of these is an order to the server, audited under `--actor`; the one command
on the customer's machine is run by whoever has root there.

It acknowledges nothing and operates nothing: findings, outages, maintenance, the
DNS sensor and a device's credentials stay with a person in the console.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).
