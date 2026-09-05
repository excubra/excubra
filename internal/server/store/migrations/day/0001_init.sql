-- tenants/<tenant>/<YYYY-MM-DD>.db: what happened that day (ADR-0005).

CREATE TABLE events (
  event_id    TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  severity    TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  since       TEXT NOT NULL DEFAULT '',
  tenant_id   TEXT NOT NULL,
  site_id     TEXT NOT NULL DEFAULT '',
  box_id      TEXT NOT NULL DEFAULT '',
  host_id     TEXT NOT NULL DEFAULT '',
  device_id   TEXT NOT NULL DEFAULT '',
  source      TEXT NOT NULL,
  body        TEXT NOT NULL
);
CREATE INDEX events_occurred ON events(occurred_at);
CREATE INDEX events_host ON events(host_id, occurred_at);

CREATE TABLE deliveries (
  event_id        TEXT NOT NULL,
  target_id       TEXT NOT NULL,
  state           TEXT NOT NULL,
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_status     INTEGER NOT NULL DEFAULT 0,
  last_error      TEXT NOT NULL DEFAULT '',
  body            TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  delivered_at    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (event_id, target_id)
);
CREATE INDEX deliveries_due ON deliveries(state, next_attempt_at);

CREATE TABLE check_rollups (
  host_id        TEXT NOT NULL,
  hour           TEXT NOT NULL,
  check_type     TEXT NOT NULL,
  rounds         INTEGER NOT NULL,
  failed         INTEGER NOT NULL,
  latency_sum_ms INTEGER NOT NULL,
  latency_max_ms INTEGER NOT NULL,
  PRIMARY KEY (host_id, hour, check_type)
);
