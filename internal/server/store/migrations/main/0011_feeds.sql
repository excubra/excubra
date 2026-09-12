-- ADR-0018: end-of-life and latest-release data per product, from endoflife.date,
-- cached here so the version rules work from the store and a feed outage costs
-- nothing but freshness.
CREATE TABLE feeds (
  slug       TEXT PRIMARY KEY,
  fetched_at TEXT NOT NULL,
  body       TEXT NOT NULL
);
