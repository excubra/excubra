-- ADR-0020: the DNS sensor. The switches per site (off by default: the router
-- must point at the box first), the box's last report, the blocklist the boxes
-- fetch, and daily totals per site for the console.
ALTER TABLE sites ADD COLUMN dns_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN dns_block INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN dns_upstreams TEXT NOT NULL DEFAULT '[]';
ALTER TABLE boxes ADD COLUMN dns TEXT NOT NULL DEFAULT '';
ALTER TABLE boxes ADD COLUMN lan_ip TEXT NOT NULL DEFAULT '';

CREATE TABLE blocklist (
  domain TEXT PRIMARY KEY,
  source TEXT NOT NULL DEFAULT '',
  added  TEXT NOT NULL
);

CREATE TABLE dns_days (
  site_id  TEXT NOT NULL,
  day      TEXT NOT NULL,
  queries  INTEGER NOT NULL DEFAULT 0,
  blocked  INTEGER NOT NULL DEFAULT 0,
  nxdomain INTEGER NOT NULL DEFAULT 0,
  failed   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (site_id, day)
);
