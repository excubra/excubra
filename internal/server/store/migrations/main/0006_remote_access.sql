ALTER TABLE boxes ADD COLUMN netbird_op_status TEXT NOT NULL DEFAULT '';
ALTER TABLE boxes ADD COLUMN netbird_op_ip TEXT NOT NULL DEFAULT '';

-- Remote access per site (salt: Vollausbau, Stufe B): the box joins VIICO's own
-- overlay as a second peer and offers the customer LAN as a network resource. This
-- row remembers what EX0 created there and how far the switch-on got.
CREATE TABLE remote_access (
  site_id      TEXT PRIMARY KEY,
  tenant_id    TEXT NOT NULL,
  box_id       TEXT NOT NULL,
  cidr         TEXT NOT NULL,
  enabled      INTEGER NOT NULL DEFAULT 1,
  state        TEXT NOT NULL,            -- key | joining | wiring | active | off | error
  detail       TEXT NOT NULL DEFAULT '',
  peer_id      TEXT NOT NULL DEFAULT '',
  peer_ip      TEXT NOT NULL DEFAULT '',
  network_id   TEXT NOT NULL DEFAULT '',
  resource_id  TEXT NOT NULL DEFAULT '',
  router_id    TEXT NOT NULL DEFAULT '',
  requested_by TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

-- a box may hold one pending setup key per NetBird profile: the customer's stack
-- (profile 'customer', the row that existed) and VIICO's stack (profile 'operator')
CREATE TABLE netbird_keys_new (
  box_id         TEXT NOT NULL REFERENCES boxes(id) ON DELETE CASCADE,
  profile        TEXT NOT NULL DEFAULT 'customer',
  management_url TEXT NOT NULL,
  setup_key      TEXT NOT NULL,
  created_at     TEXT NOT NULL,
  claimed_at     TEXT,
  PRIMARY KEY (box_id, profile)
);
INSERT INTO netbird_keys_new (box_id, profile, management_url, setup_key, created_at, claimed_at)
  SELECT box_id, 'customer', management_url, setup_key, created_at, claimed_at FROM netbird_keys;
DROP TABLE netbird_keys;
ALTER TABLE netbird_keys_new RENAME TO netbird_keys;
