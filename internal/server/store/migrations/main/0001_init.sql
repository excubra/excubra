-- main.db: master data and current state (ADR-0005). Additive migrations only.

CREATE TABLE tenants (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE sites (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL REFERENCES tenants(id),
  name       TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX sites_tenant ON sites(tenant_id);

CREATE TABLE boxes (
  id             TEXT PRIMARY KEY,
  site_id        TEXT REFERENCES sites(id),
  name           TEXT NOT NULL DEFAULT '',
  hw_id          TEXT NOT NULL,
  agent_version  TEXT NOT NULL DEFAULT '',
  os             TEXT NOT NULL DEFAULT '',
  arch           TEXT NOT NULL DEFAULT '',
  cert_serial    TEXT NOT NULL,
  cert_not_after TEXT NOT NULL,
  channel        TEXT NOT NULL DEFAULT 'stable',
  discovery_mode    TEXT NOT NULL DEFAULT 'sweep',
  discovery_subnets TEXT NOT NULL DEFAULT '[]',
  netbird_status    TEXT NOT NULL DEFAULT '',
  netbird_ip        TEXT NOT NULL DEFAULT '',
  disk_total_bytes  INTEGER NOT NULL DEFAULT 0,
  disk_free_bytes   INTEGER NOT NULL DEFAULT 0,
  uptime_s          INTEGER NOT NULL DEFAULT 0,
  last_seen         TEXT NOT NULL DEFAULT '',
  enrolled_at    TEXT NOT NULL,
  revoked_at     TEXT
);
CREATE INDEX boxes_site ON boxes(site_id);

CREATE TABLE revoked_certs (
  serial     TEXT PRIMARY KEY,
  box_id     TEXT NOT NULL,
  revoked_at TEXT NOT NULL
);

CREATE TABLE enrollment_keys (
  id          TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL UNIQUE,
  note        TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,
  used_at     TEXT,
  used_by_box TEXT,
  revoked_at  TEXT
);

CREATE TABLE netbird_keys (
  box_id         TEXT PRIMARY KEY REFERENCES boxes(id) ON DELETE CASCADE,
  management_url TEXT NOT NULL,
  setup_key      TEXT NOT NULL,
  created_at     TEXT NOT NULL,
  claimed_at     TEXT
);

CREATE TABLE devices (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  site_id    TEXT NOT NULL,
  mac        TEXT NOT NULL,
  ip         TEXT NOT NULL DEFAULT '',
  vendor     TEXT NOT NULL DEFAULT '',
  hostname   TEXT NOT NULL DEFAULT '',
  first_seen TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  gone_at    TEXT,
  ignored    INTEGER NOT NULL DEFAULT 0,
  UNIQUE (site_id, mac)
);
CREATE INDEX devices_tenant ON devices(tenant_id, last_seen);

CREATE TABLE hosts (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  site_id    TEXT NOT NULL,
  box_id     TEXT NOT NULL REFERENCES boxes(id),
  device_id  TEXT NOT NULL DEFAULT '',
  name       TEXT NOT NULL,
  address    TEXT NOT NULL,
  mac        TEXT NOT NULL DEFAULT '',
  vendor     TEXT NOT NULL DEFAULT '',
  parent_id  TEXT NOT NULL DEFAULT '',
  is_uplink  INTEGER NOT NULL DEFAULT 0,
  checks     TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);
CREATE INDEX hosts_box ON hosts(box_id);
CREATE INDEX hosts_tenant ON hosts(tenant_id);

CREATE TABLE host_state (
  host_id            TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
  observed           TEXT NOT NULL,
  reported           TEXT NOT NULL,
  failures           INTEGER NOT NULL,
  successes          INTEGER NOT NULL,
  since              TEXT NOT NULL DEFAULT '',
  run_start          TEXT NOT NULL DEFAULT '',
  down_since         TEXT NOT NULL DEFAULT '',
  last_failed_checks TEXT NOT NULL DEFAULT '[]',
  last_checks        TEXT NOT NULL DEFAULT '[]',
  last_box_time      TEXT NOT NULL DEFAULT '',
  updated_at         TEXT NOT NULL
);

CREATE TABLE box_state (
  box_id         TEXT PRIMARY KEY REFERENCES boxes(id) ON DELETE CASCADE,
  status         TEXT NOT NULL,
  last_heartbeat TEXT NOT NULL DEFAULT '',
  silent_since   TEXT NOT NULL DEFAULT '',
  updated_at     TEXT NOT NULL
);

CREATE TABLE maintenance (
  id         TEXT PRIMARY KEY,
  tenant_id  TEXT NOT NULL,
  site_id    TEXT NOT NULL DEFAULT '',
  scope      TEXT NOT NULL,
  target_id  TEXT NOT NULL,
  until_at   TEXT NOT NULL,
  reason     TEXT NOT NULL DEFAULT '',
  set_by     TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE webhook_targets (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  url          TEXT NOT NULL,
  secret       TEXT NOT NULL,
  tenant_scope TEXT NOT NULL DEFAULT '*',
  enabled      INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL
);

CREATE TABLE api_tokens (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  tenants      TEXT NOT NULL DEFAULT '["*"]',
  created_at   TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at   TEXT
);

CREATE TABLE users (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL UNIQUE,
  password_hash     TEXT NOT NULL,
  totp_secret       TEXT NOT NULL,
  totp_last_counter INTEGER NOT NULL DEFAULT 0,
  failed_logins     INTEGER NOT NULL DEFAULT 0,
  locked_until      TEXT,
  disabled          INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen  TEXT NOT NULL,
  ip         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  at      TEXT NOT NULL,
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  target  TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL DEFAULT ''
);

-- release metadata served by GET /v1/update; the server never holds binaries
CREATE TABLE releases (
  version           TEXT NOT NULL,
  os                TEXT NOT NULL,
  arch              TEXT NOT NULL,
  url               TEXT NOT NULL,
  sha256            TEXT NOT NULL,
  signature         TEXT NOT NULL,
  min_agent_version TEXT NOT NULL DEFAULT '',
  created_at        TEXT NOT NULL,
  PRIMARY KEY (version, os, arch)
);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
