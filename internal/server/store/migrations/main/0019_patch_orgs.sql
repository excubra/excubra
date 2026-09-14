-- Which customer is which organization in the endpoint manager. Set by hand and
-- never guessed: five organizations and one wrong row would put one customer's
-- patch state on another customer's page, and that is the mistake nobody makes
-- twice.
CREATE TABLE patch_orgs (
  tenant_id  TEXT PRIMARY KEY REFERENCES tenants(id),
  provider   TEXT NOT NULL,   -- action1
  org_id     TEXT NOT NULL,
  org_name   TEXT NOT NULL DEFAULT '',
  linked_at  TEXT NOT NULL,
  linked_by  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX patch_orgs_org ON patch_orgs(provider, org_id);
