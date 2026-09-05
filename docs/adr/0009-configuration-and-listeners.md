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
