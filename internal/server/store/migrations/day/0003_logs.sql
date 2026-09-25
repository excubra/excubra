-- What a source reported (ADR-0023). Not the contract's transitions — those stay
-- in events. V5's syslog lines will land here too, with another source.
CREATE TABLE logs (
  device_id   TEXT NOT NULL,
  event_id    TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  source      TEXT NOT NULL,
  kind        TEXT NOT NULL,
  actor       TEXT NOT NULL DEFAULT '',
  ip          TEXT NOT NULL DEFAULT '',
  target      TEXT NOT NULL DEFAULT '',
  summary     TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (device_id, event_id)
);
CREATE INDEX logs_device_time ON logs(device_id, occurred_at);
