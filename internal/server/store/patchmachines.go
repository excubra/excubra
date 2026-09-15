package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Every machine the endpoint manager knows, and which device it is here.
//
// The unmatched ones are kept on purpose. A machine EX0 cannot place is the one
// a person has to deal with, and the only way to deal with it is to see it.

// PatchMachine is one machine of the endpoint manager.
type PatchMachine struct {
	Provider    string    `json:"provider"`
	EndpointID  string    `json:"endpointId"`
	TenantID    string    `json:"tenantId"`
	OrgID       string    `json:"orgId"`
	Name        string    `json:"name"`
	DeviceID    string    `json:"deviceId"` // "" when EX0 has no device for it
	Pinned      bool      `json:"pinned"`   // a person chose the device
	Online      bool      `json:"online"`
	LastSeen    time.Time `json:"lastSeen"`
	Inventoried time.Time `json:"inventoried"`
	Pending     int       `json:"pending"`
	CVECount    int       `json:"cveCount"`
	WorstCVSS   float64   `json:"worstCvss"`
	KEV         bool      `json:"kev"`
	SyncedAt    time.Time `json:"syncedAt"`

	// Raw JSON, as the sync wrote it. Software is the big one and is only read
	// where it is shown.
	CVEs     json.RawMessage `json:"cves,omitempty"`
	Updates  json.RawMessage `json:"updates,omitempty"`
	Software json.RawMessage `json:"software,omitempty"`

	// Filled in by the console for display, never stored.
	DeviceName string `json:"deviceName,omitempty"`
}

const patchMachineCols = `provider, endpoint_id, tenant_id, org_id, name, COALESCE(device_id, ''), pinned,
	online, last_seen, inventoried, pending, cve_count, worst_cvss, kev, synced_at`

// SavePatchMachine writes one machine's state. A device chosen by hand is not
// touched: the sync passes what it matched, and a pinned row keeps its own.
func (s *Store) SavePatchMachine(ctx context.Context, m PatchMachine, cves, updates, software []byte) error {
	_, err := s.main.ExecContext(ctx,
		`INSERT INTO patch_machines (provider, endpoint_id, tenant_id, org_id, name, device_id, pinned,
			online, last_seen, inventoried, pending, cve_count, worst_cvss, kev, cves, updates, software, synced_at)
		 VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (provider, endpoint_id) DO UPDATE SET
			tenant_id = excluded.tenant_id, org_id = excluded.org_id, name = excluded.name,
			device_id = CASE WHEN patch_machines.pinned = 1 THEN patch_machines.device_id ELSE excluded.device_id END,
			online = excluded.online, last_seen = excluded.last_seen, inventoried = excluded.inventoried,
			pending = excluded.pending, cve_count = excluded.cve_count, worst_cvss = excluded.worst_cvss,
			kev = excluded.kev, cves = excluded.cves, updates = excluded.updates, software = excluded.software,
			synced_at = excluded.synced_at`,
		m.Provider, m.EndpointID, m.TenantID, m.OrgID, m.Name, m.DeviceID,
		m.Online, ts(m.LastSeen), ts(m.Inventoried), m.Pending, m.CVECount, m.WorstCVSS, m.KEV,
		string(cves), string(updates), string(software), ts(m.SyncedAt))
	return wrap("save patch machine", err)
}

// PinPatchMachine ties a machine to a device by hand, or lets go of it again.
// An empty device clears the choice and hands the machine back to the automatic
// match at the next sync.
func (s *Store) PinPatchMachine(ctx context.Context, provider, endpointID, deviceID string) error {
	_, err := s.main.ExecContext(ctx,
		`UPDATE patch_machines SET device_id = NULLIF(?, ''), pinned = ? WHERE provider = ? AND endpoint_id = ?`,
		deviceID, boolInt(deviceID != ""), provider, endpointID)
	return wrap("pin patch machine", err)
}

// PatchMachine returns one machine, software included.
func (s *Store) PatchMachine(ctx context.Context, provider, endpointID string) (PatchMachine, error) {
	row := s.main.QueryRowContext(ctx,
		`SELECT `+patchMachineCols+`, cves, updates, software FROM patch_machines
		 WHERE provider = ? AND endpoint_id = ?`, provider, endpointID)
	m, err := scanPatchMachineFull(row)
	return m, wrap("patch machine", err)
}

// PatchMachineForDevice returns the machine tied to a device, if there is one.
func (s *Store) PatchMachineForDevice(ctx context.Context, deviceID string) (PatchMachine, bool, error) {
	row := s.main.QueryRowContext(ctx,
		`SELECT `+patchMachineCols+`, cves, updates, software FROM patch_machines WHERE device_id = ?`, deviceID)
	m, err := scanPatchMachineFull(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PatchMachine{}, false, nil
	}
	if err != nil {
		return PatchMachine{}, false, wrap("patch machine for device", err)
	}
	return m, true, nil
}

func scanPatchMachineFull(row interface{ Scan(...any) error }) (PatchMachine, error) {
	var m PatchMachine
	var last, inv, synced string
	var cves, updates, software string
	err := row.Scan(&m.Provider, &m.EndpointID, &m.TenantID, &m.OrgID, &m.Name, &m.DeviceID, &m.Pinned,
		&m.Online, &last, &inv, &m.Pending, &m.CVECount, &m.WorstCVSS, &m.KEV, &synced,
		&cves, &updates, &software)
	if err != nil {
		return PatchMachine{}, err
	}
	m.LastSeen, m.Inventoried, m.SyncedAt = parseTS(last), parseTS(inv), parseTS(synced)
	m.CVEs, m.Updates, m.Software = json.RawMessage(cves), json.RawMessage(updates), json.RawMessage(software)
	return m, nil
}

// PatchMachines lists a customer's machines, or every one when tenantID is empty.
// Software is left out: it is large and only one machine's is ever shown.
func (s *Store) PatchMachines(ctx context.Context, tenantID string) ([]PatchMachine, error) {
	q := `SELECT ` + patchMachineCols + `, cves, updates FROM patch_machines`
	args := []any{}
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	// Machines without a device first: they are the ones waiting for a decision.
	q += ` ORDER BY device_id IS NULL DESC, name`
	rows, err := s.main.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap("patch machines", err)
	}
	defer func() { _ = rows.Close() }()
	out := []PatchMachine{}
	for rows.Next() {
		var m PatchMachine
		var last, inv, synced, cves, updates string
		if err := rows.Scan(&m.Provider, &m.EndpointID, &m.TenantID, &m.OrgID, &m.Name, &m.DeviceID, &m.Pinned,
			&m.Online, &last, &inv, &m.Pending, &m.CVECount, &m.WorstCVSS, &m.KEV, &synced, &cves, &updates); err != nil {
			return nil, wrap("patch machines", err)
		}
		m.LastSeen, m.Inventoried, m.SyncedAt = parseTS(last), parseTS(inv), parseTS(synced)
		m.CVEs, m.Updates = json.RawMessage(cves), json.RawMessage(updates)
		out = append(out, m)
	}
	return out, wrap("patch machines", rows.Err())
}

// DropPatchMachines removes the machines of one organization that this sync did
// not see — a machine somebody retired over there stops being a row here.
func (s *Store) DropPatchMachines(ctx context.Context, provider, orgID string, before time.Time) error {
	_, err := s.main.ExecContext(ctx,
		`DELETE FROM patch_machines WHERE provider = ? AND org_id = ? AND synced_at < ?`,
		provider, orgID, ts(before))
	return wrap("drop patch machines", err)
}

// DropPatchMachinesOfTenant removes every machine of a customer, for when the
// organization link is cut: nothing of that customer is read any more, so
// nothing of it should stay on the page either.
func (s *Store) DropPatchMachinesOfTenant(ctx context.Context, tenantID string) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM patch_machines WHERE tenant_id = ?`, tenantID)
	return wrap("drop patch machines", err)
}
