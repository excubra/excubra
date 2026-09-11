-- Numbers a connector reported (cpu, sessions, tunnels up …), one row per key and
-- reading, for the charts on the device page (ADR-0015).
CREATE TABLE connector_samples (
  connector_id TEXT NOT NULL,
  at           TEXT NOT NULL,
  key          TEXT NOT NULL,
  value        REAL NOT NULL
);
CREATE INDEX connector_samples_idx ON connector_samples(connector_id, key, at);
