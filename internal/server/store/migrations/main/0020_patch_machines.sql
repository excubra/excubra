-- Every machine the endpoint manager knows for a linked customer, whether EX0
-- has a device for it or not. Keeping the unmatched ones is the point: they are
-- what a person has to look at and assign, and a machine that is only mentioned
-- in a status line is a machine nobody assigns.
--
-- pinned separates the two ways a machine finds its device. 0 is the hostname
-- match, redone at every sync. 1 is a person's decision, which survives a sync
-- and beats the automatic one — because the reason somebody assigns by hand is
-- that the names do not agree, and an automatic match would overwrite them
-- every hour.
CREATE TABLE patch_machines (
  provider    TEXT NOT NULL,             -- action1
  endpoint_id TEXT NOT NULL,
  tenant_id   TEXT NOT NULL REFERENCES tenants(id),
  org_id      TEXT NOT NULL,
  name        TEXT NOT NULL,
  device_id   TEXT REFERENCES devices(id) ON DELETE SET NULL,
  pinned      INTEGER NOT NULL DEFAULT 0,
  online      INTEGER NOT NULL DEFAULT 0,
  last_seen   TEXT NOT NULL DEFAULT '',  -- last contact with the manager
  inventoried TEXT NOT NULL DEFAULT '',  -- newest inventory row
  pending     INTEGER NOT NULL DEFAULT 0,
  cve_count   INTEGER NOT NULL DEFAULT 0,
  worst_cvss  REAL    NOT NULL DEFAULT 0,
  kev         INTEGER NOT NULL DEFAULT 0,
  cves        TEXT NOT NULL DEFAULT '[]', -- the holes, with product and version
  updates     TEXT NOT NULL DEFAULT '[]', -- applications with an update waiting
  software    TEXT NOT NULL DEFAULT '[]', -- the whole inventory, read on demand
  synced_at   TEXT NOT NULL,
  PRIMARY KEY (provider, endpoint_id)
);
CREATE INDEX patch_machines_tenant ON patch_machines(tenant_id, name);
CREATE INDEX patch_machines_device ON patch_machines(device_id);
