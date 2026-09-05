# ADR-0005: Storage layout — SQLite files per tenant and day

Status: accepted · Date: 2026-09-05

## Context

Zero external services (salt: Betriebsprinzipien). Retention must be "delete files",
backup must be "copy files". Tenants are strictly separated from day one. Phase 2 will
add log-derived events with far higher volume; the layout must carry that without
being rebuilt.

## Decision

**Interface first.** `internal/server/store` defines `Store` (grouped by aggregate:
`Tenants`, `Sites`, `Boxes`, `EnrollmentKeys`, `Devices`, `Hosts`, `Maintenance`,
`WebhookTargets`, `APITokens`, `Users`, `Audit`, `State`, `Events`, `Deliveries`,
`Rollups`). The SQLite implementation is the only one in Phase 1; the interface exists
so that the event/rollup side can later move to ClickHouse or Quickwit without touching
handlers.

**Driver.** `modernc.org/sqlite` (pure Go), `database/sql`. Every file is opened with
`journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`, `foreign_keys=ON`.
One writer connection per file (`SetMaxOpenConns(1)` for writes, a small read pool),
because SQLite serialises writers anyway and this removes `SQLITE_BUSY` from the picture.

**Files** under `EXCUBRA_DATA_DIR` (default `/var/lib/excubra`):

```
main.db                          master data and current state
tenants/<tenant_id>/<YYYY-MM-DD>.db   events, deliveries, check rollups of that tenant and UTC day
ca/ca.crt  ca/ca.key  ca/ingest.crt  ca/ingest.key    PKI material (0600), ADR-0010
```

`main.db` tables: `tenants`, `sites`, `boxes`, `enrollment_keys`, `netbird_keys`,
`devices`, `hosts`, `checks`, `maintenance`, `webhook_targets`, `api_tokens`, `users`,
`sessions`, `audit_log`, `box_state`, `host_state`, `revoked_certs`, `schema_version`.

Day-file tables: `events` (`event_id` PK, envelope columns, `payload` JSON),
`deliveries` (`event_id`, `target_id`, `state`, `attempts`, `next_attempt_at`,
`last_status`, `last_error`, PK `(event_id, target_id)`), `check_rollups`
(`host_id`, `hour`, `check_type`, `rounds`, `failed`, `latency_sum_ms`,
`latency_max_ms`, PK `(host_id, hour, check_type)`).

Day boundaries are **UTC**. A file is created on first write. Reads that span days open
the files in range; the retry worker only looks at today and yesterday (the retry window
is 24 h). An event written at 23:59:59 and its deliveries live in the same file — the
event's day — so retention can never orphan a delivery.

**Retention** is `excubra server prune --keep <days>`: delete day files older than the
limit, nothing else. Scheduled by a systemd timer in `deploy/`; the server itself runs no
cleanup, no VACUUM, nothing at three in the morning.

**Backup** is `excubra server backup <dir>`: `VACUUM INTO` for `main.db` (a consistent
snapshot without stopping the server), plain copies for day files older than today, and
a copy of `ca/`. The operator syncs `<dir>` to an append-only object store (rclone /
Litestream pattern). Restore = put the files back. `deploy/restore-test.sh` restores into
a temporary directory and starts a throwaway server against it; it runs monthly from a
timer and fails loudly.

**Schema migrations** are numbered SQL files embedded in the binary, applied at start,
tracked in `schema_version`. Only additive migrations are allowed inside a MAJOR
version.

**Identifiers.** Prefixed, human-readable: `ten_`, `site_`, `box_`, `host_`, `dev_`,
`key_`, `tgt_`, `tok_`, `usr_`, `evt_`. Tenants, sites and hosts may carry an
operator-chosen slug (`[a-z0-9-]{1,40}`, unique per parent) after the prefix, as the
contract's examples do (`ten_kundea`, `site_ludwigshafen`); otherwise 12 random base32
characters. Boxes, devices, keys, tokens and events are always random.

## Consequences

- Retention and backup are file operations; there is nothing that can half-succeed
  inside a database at night.
- Cross-tenant queries do not exist by construction — a tenant's history is its
  directory.
- Phase 2 volume lands in day files, which are already per tenant; the master data file
  stays small.

## Rejected

- One database for everything with a `deleted_at` sweep: needs a nightly job and VACUUM
  to actually free space, and it keeps tenants in one file.
- PostgreSQL: a second service with its own updates, backups and failure modes;
  nothing in Phase 1 or 2 needs it.
- Per-tenant single file without day split: retention becomes `DELETE … WHERE` again.
