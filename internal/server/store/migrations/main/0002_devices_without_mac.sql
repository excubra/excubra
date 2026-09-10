-- Devices found by an ICMP sweep of another subnet have no visible MAC (a router
-- sits in between). They are keyed by IP instead: mac = '' and the unique key
-- becomes (site_id, mac, ip). A device with a MAC keeps a single row across IP
-- changes because the store looks it up by (site_id, mac) first and updates in place.
CREATE TABLE devices_new (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  site_id    TEXT NOT NULL,
  mac        TEXT NOT NULL DEFAULT '',
  ip         TEXT NOT NULL DEFAULT '',
  vendor     TEXT NOT NULL DEFAULT '',
  hostname   TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  gone_at    TEXT,
  ignored    INTEGER NOT NULL DEFAULT 0,
  UNIQUE (site_id, mac, ip)
);
INSERT INTO devices_new SELECT id, tenant_id, site_id, mac, ip, vendor, hostname, first_seen, last_seen, gone_at, ignored FROM devices;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
CREATE INDEX devices_tenant ON devices(tenant_id, last_seen);
CREATE INDEX devices_site_mac ON devices(site_id, mac);
