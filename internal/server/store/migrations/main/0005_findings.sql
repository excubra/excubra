-- Findings: what the rules say about a device (salt: Vollausbau 3.8). One row per
-- device, rule and key; open while the condition holds, resolved when a reading no
-- longer shows it, reopened with a fresh first_seen when it comes back.
CREATE TABLE findings (
  id           TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL,
  site_id      TEXT NOT NULL,
  device_id    TEXT NOT NULL,
  connector_id TEXT NOT NULL DEFAULT '',
  rule         TEXT NOT NULL,
  key          TEXT NOT NULL DEFAULT '',
  severity     TEXT NOT NULL,
  title        TEXT NOT NULL,
  detail       TEXT NOT NULL DEFAULT '',
  evidence     TEXT NOT NULL DEFAULT '{}',
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL,
  resolved_at  TEXT,
  UNIQUE (device_id, rule, key)
);
CREATE INDEX findings_open ON findings(resolved_at, severity);
CREATE INDEX findings_device ON findings(device_id, resolved_at);
