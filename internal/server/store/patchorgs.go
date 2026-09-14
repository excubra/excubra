package store

import (
	"context"
	"time"
)

// Which customer is which organization in the endpoint manager.
//
// One row per customer, set by hand in the console. Never derived from a name:
// "Muster GmbH" over there and "Muster GmbH" over here look like the same
// customer right up until the day they are not, and the cost of being wrong is a
// customer seeing another customer's machines.

// PatchOrg links one tenant to one organization at one provider.
type PatchOrg struct {
	TenantID string    `json:"tenantId"`
	Provider string    `json:"provider"`
	OrgID    string    `json:"orgId"`
	OrgName  string    `json:"orgName"`
	LinkedAt time.Time `json:"linkedAt"`
	LinkedBy string    `json:"linkedBy"`
}

// SetPatchOrg links a tenant, replacing any earlier link.
func (s *Store) SetPatchOrg(ctx context.Context, p PatchOrg, at time.Time) error {
	_, err := s.main.ExecContext(ctx,
		`INSERT INTO patch_orgs (tenant_id, provider, org_id, org_name, linked_at, linked_by)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT (tenant_id) DO UPDATE SET provider = excluded.provider, org_id = excluded.org_id,
		   org_name = excluded.org_name, linked_at = excluded.linked_at, linked_by = excluded.linked_by`,
		p.TenantID, p.Provider, p.OrgID, p.OrgName, ts(at), p.LinkedBy)
	return wrap("set patch org", err)
}

// ClearPatchOrg unlinks a tenant.
func (s *Store) ClearPatchOrg(ctx context.Context, tenantID string) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM patch_orgs WHERE tenant_id = ?`, tenantID)
	return wrap("clear patch org", err)
}

// PatchOrgs lists every link, with the customer's name for the console.
func (s *Store) PatchOrgs(ctx context.Context) ([]PatchOrg, error) {
	rows, err := s.main.QueryContext(ctx,
		`SELECT p.tenant_id, p.provider, p.org_id, p.org_name, p.linked_at, p.linked_by
		 FROM patch_orgs p JOIN tenants t ON t.id = p.tenant_id ORDER BY t.name`)
	if err != nil {
		return nil, wrap("patch orgs", err)
	}
	defer func() { _ = rows.Close() }()
	out := []PatchOrg{}
	for rows.Next() {
		var p PatchOrg
		var at string
		if err := rows.Scan(&p.TenantID, &p.Provider, &p.OrgID, &p.OrgName, &at, &p.LinkedBy); err != nil {
			return nil, wrap("patch orgs", err)
		}
		p.LinkedAt = parseTS(at)
		out = append(out, p)
	}
	return out, wrap("patch orgs", rows.Err())
}
