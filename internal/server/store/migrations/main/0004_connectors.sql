-- Connectors (ADR-0015): the box reads a device through its API. The credential is
-- sealed in the browser to the box's seal key; this table only ever holds ciphertext.
-- The latest reading lives on the row (facts as JSON), samples of the numbers go to
-- the day databases.
ALTER TABLE boxes ADD COLUMN seal_key TEXT NOT NULL DEFAULT '';

CREATE TABLE connectors (
  id               TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL,
  site_id          TEXT NOT NULL,
  box_id           TEXT NOT NULL,
  device_id        TEXT NOT NULL,
  kind             TEXT NOT NULL,
  url              TEXT NOT NULL,
  sealed           TEXT NOT NULL,
  sealed_by        TEXT NOT NULL DEFAULT '',
  sealed_at        TEXT NOT NULL,
  interval_s       INTEGER NOT NULL DEFAULT 300,
  tls_fingerprint  TEXT NOT NULL DEFAULT '',
  created_at       TEXT NOT NULL,
  disabled         INTEGER NOT NULL DEFAULT 0,
  last_ok          INTEGER,
  last_error       TEXT NOT NULL DEFAULT '',
  last_at          TEXT,
  seen_fingerprint TEXT NOT NULL DEFAULT '',
  facts            TEXT NOT NULL DEFAULT '{}',
  facts_at         TEXT,
  metrics          TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX connectors_box ON connectors(box_id);
CREATE INDEX connectors_device ON connectors(device_id);
