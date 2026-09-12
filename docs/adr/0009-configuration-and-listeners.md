# ADR-0009: Configuration and the two listeners

Status: accepted · Date: 2026-09-05

## Context

Operational target: server = one container (or one binary), one config file, one
backup target. Agent = one binary, one key, no config file. The console must be
unreachable from the public internet by construction, not by firewall rule.

## Decision

### Server configuration

Environment variables, optionally read from one file in systemd `EnvironmentFile`
syntax (`KEY=value`, `#` comments), passed with `--env-file` (default
`/etc/excubra/server.env` if it exists). The same variables work in a container. No
other configuration source exists; everything else is data in the database and
edited in the console.

| Variable | Default | Meaning |
| --- | --- | --- |
| `EXCUBRA_DATA_DIR` | `/var/lib/excubra` | database files and PKI |
| `EXCUBRA_INGEST_LISTEN` | `:443` | public mTLS listener |
| `EXCUBRA_INGEST_PUBLIC_HOST` | required | `host[:port]` that boxes connect to; goes into enrollment keys and the ingest certificate |
| `EXCUBRA_OVERLAY_LISTEN` | required | `ip:port` of the console/API listener; must be a specific address, never `0.0.0.0` or `[::]` |
| `EXCUBRA_OVERLAY_ALLOW_ANY` | unset | set to `1` to permit a wildcard overlay address — development only, logs a warning every minute |
| `EXCUBRA_OVERLAY_TLS` | `off` | `off` (plain HTTP inside the overlay) or `internal` (certificate from the internal CA) |
| `EXCUBRA_CONSOLE_URL` | derived | base URL used in webhook `link` fields |
| `EXCUBRA_UPDATE_BASE_URL` | GitHub Releases | where update metadata points |
| `EXCUBRA_LOG_LEVEL` | `info` | `debug` · `info` · `warn` |
| `EXCUBRA_LOG_FORMAT` | `text` | `text` · `json` |
| `EXCUBRA_TIMEZONE` | `Europe/Berlin` | IANA zone the console displays times in; storage and API stay UTC |

Startup validation refuses to run with an unsafe overlay address and prints exactly
what is wrong. Secrets never live in variables: the CA key is a file, webhook secrets
and API tokens are in the database.

### Listeners

Two `http.Server` instances, two muxes, two handler trees, no shared code path beyond
the store:

- **Ingest** (`EXCUBRA_INGEST_LISTEN`): TLS with client-certificate verification
  (ADR-0002). Routes under `/v1/` only. Unknown paths answer `404` with an empty body;
  there is no index, no health page, no redirect.
- **Overlay** (`EXCUBRA_OVERLAY_LISTEN`): console (`/`), status API (`/v1/`), health
  (`/healthz`). Bound to the NetBird interface address in production; the server
  checks at start that the address is assigned to a local interface and that it is
  not a wildcard.

The ingest handler has no reference to the console package; the overlay handler has
no route that could reach the ingest. A request on the wrong listener is a `404`.

### Agent

No configuration file. Flags exist only for `enroll` (`--key`, `--server` as override,
`--state-dir`). Everything else is pulled (ADR-0002). The state directory
(default `/var/lib/excubra-agent`, 0700) holds: `box.key`, `box.crt`, `ca.crt`,
`server` (the ingest host), `config.json` (last pulled config, for a start without
network), `buffer/` (unsent heartbeats), `update/`.

### Logging

`log/slog`, one line per event, to stdout (journald/container). Never log payloads,
keys, tokens or certificates. Log level is the only knob.

## Consequences

- A misconfigured overlay address cannot silently expose the console: the server
  refuses to start.
- Containers and bare metal are configured identically.

## Rejected

- A structured config file (YAML/TOML): a parser dependency for ten settings, and a
  second source of truth beside the database.
- One listener with path-based separation and an allow-list: a single mistake in the
  allow-list exposes the console; two sockets cannot be confused.

## Addendum 2026-09-10: provisioning

The server is not configured by hand. `deploy/provision-server.sh` takes a fresh
Debian to a running server and is idempotent; `deploy/deploy.sh` builds the binary
from the current commit and runs it over SSH. The first real installation found two
faults no test would have: timers that were `enable`d but never started (a backup
that silently never runs), and a CLI that rejected flags after the positional word
although its help promised them. Both are fixed in the repository, which is the
point of having the sequence in a file rather than in a chat log.

## Amendment 2026-09-13: secrets at rest

The database held the NetBird token and API keys in plain text, and the data
directory the CA's private key — and the backup copies both. A stolen backup
was therefore a way into every customer LAN. Now `EXCUBRA_SECRET_KEY_FILE`
names a key (`openssl rand -base64 32`, root:excubra 0640, outside the data
directory) that seals secret settings (`store.SecretSetting`: keys ending in
`.token`, `.api_key`, `.key`, `.secret`, `.password`) and the private key files
of the internal CA and the ingest certificate (`internal/secretbox`,
AES-256-GCM, values prefixed `enc:v1:`). A running installation seals what it
finds in plain text once at start. Without the key a backup holds unusable
tokens and keys, which is the point: the key lives in the password manager,
not on the disk that is backed up. The restore test passes the key file along.
Connector credentials were already sealed to the boxes' keys and never
readable on the server (ADR-0015).

Cleaned up the same day: the demo instance on the overlay was stopped and
archived, SSH now listens for the operator overlay only (the hosting console
is the way in when the overlay is down), unattended upgrades reboot at 04:45
when a kernel asks for it, the stray reusable setup key in the operator stack
was revoked, and EX0 uses a NetBird service user of its own (role admin)
instead of the owner's token.
