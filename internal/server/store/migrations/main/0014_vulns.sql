-- ADR-0018 §8: what the vulnerability databases said about a product version
-- (NVD, OSV, CISA KEV), cached so the findings work from the store and an outage
-- of a database costs nothing but freshness.
CREATE TABLE vulns (
  key        TEXT PRIMARY KEY,
  fetched_at TEXT NOT NULL,
  body       TEXT NOT NULL
);
