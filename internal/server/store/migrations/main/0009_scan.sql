-- ADR-0018 (decision E20): the box's service scan. What listens on which device,
-- with banner, product and certificate. A service a later round no longer sees is
-- marked gone, not deleted, so "since when" stays answerable.
CREATE TABLE services (
  device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  port       INTEGER NOT NULL,
  proto      TEXT NOT NULL DEFAULT 'tcp',
  name       TEXT NOT NULL DEFAULT '',
  product    TEXT NOT NULL DEFAULT '',
  version    TEXT NOT NULL DEFAULT '',
  banner     TEXT NOT NULL DEFAULT '',
  title      TEXT NOT NULL DEFAULT '',
  tls        TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  gone_at    TEXT,
  PRIMARY KEY (device_id, port, proto)
);
CREATE INDEX services_open ON services(device_id, gone_at);

-- one row per scan round a box ran, for "when did we last look"
CREATE TABLE scan_rounds (
  id          TEXT PRIMARY KEY,
  box_id      TEXT NOT NULL,
  site_id     TEXT NOT NULL,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  hosts       INTEGER NOT NULL DEFAULT 0,
  services    INTEGER NOT NULL DEFAULT 0,
  errors      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX scan_rounds_site ON scan_rounds(site_id, started_at);

-- the switch per site: the scan runs only where a person turned it on
ALTER TABLE sites ADD COLUMN scan_enabled INTEGER NOT NULL DEFAULT 0;
