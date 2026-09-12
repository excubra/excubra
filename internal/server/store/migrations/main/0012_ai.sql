-- E21 / ADR-0019: the AI reads and proposes, a person decides. Per tenant, what the
-- AI may see ("off" = nothing leaves the server for this tenant); per site, the
-- briefs it wrote.
ALTER TABLE tenants ADD COLUMN ai_scope TEXT NOT NULL DEFAULT 'off';
CREATE TABLE ai_briefs (
  id             TEXT PRIMARY KEY,
  site_id        TEXT NOT NULL,
  tenant_id      TEXT NOT NULL,
  at             TEXT NOT NULL,
  provider       TEXT NOT NULL,
  model          TEXT NOT NULL,
  risk           TEXT NOT NULL DEFAULT '',
  summary        TEXT NOT NULL DEFAULT '',
  body           TEXT NOT NULL DEFAULT '{}',
  prompt_bytes   INTEGER NOT NULL DEFAULT 0,
  response_bytes INTEGER NOT NULL DEFAULT 0,
  duration_ms    INTEGER NOT NULL DEFAULT 0,
  requested_by   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX ai_briefs_site ON ai_briefs(site_id, at);
