package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/wire"
)

// ErrKeyInvalid is returned by UseEnrollmentKey when the key is unknown, used,
// expired or revoked — deliberately one error for all four.
var ErrKeyInvalid = errors.New("store: enrollment key invalid")

// ---- tenants ---------------------------------------------------------------------

// CreateTenant inserts a tenant.
func (s *Store) CreateTenant(ctx context.Context, t Tenant) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO tenants (id, name, created_at) VALUES (?, ?, ?)`, t.ID, t.Name, ts(t.CreatedAt))
	return wrap("create tenant", err)
}

// Tenant returns one tenant.
func (s *Store) Tenant(ctx context.Context, tenantID string) (Tenant, error) {
	var t Tenant
	var created string
	err := s.main.QueryRowContext(ctx, `SELECT id, name, created_at FROM tenants WHERE id = ?`, tenantID).Scan(&t.ID, &t.Name, &created)
	t.CreatedAt = parseTS(created)
	return t, wrap("tenant", err)
}

// Tenants returns all tenants by name.
func (s *Store) Tenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT id, name, created_at FROM tenants ORDER BY name`)
	if err != nil {
		return nil, wrap("tenants", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		var created string
		if err := rows.Scan(&t.ID, &t.Name, &created); err != nil {
			return nil, wrap("tenants", err)
		}
		t.CreatedAt = parseTS(created)
		out = append(out, t)
	}
	return out, wrap("tenants", rows.Err())
}

// RenameTenant changes the name.
func (s *Store) RenameTenant(ctx context.Context, tenantID, name string) error {
	return s.exec1(ctx, "rename tenant", `UPDATE tenants SET name = ? WHERE id = ?`, name, tenantID)
}

// ---- sites -----------------------------------------------------------------------

// CreateSite inserts a site.
func (s *Store) CreateSite(ctx context.Context, st Site) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO sites (id, tenant_id, name, created_at) VALUES (?, ?, ?, ?)`, st.ID, st.TenantID, st.Name, ts(st.CreatedAt))
	return wrap("create site", err)
}

// Site returns one site.
func (s *Store) Site(ctx context.Context, siteID string) (Site, error) {
	var st Site
	var created string
	err := s.main.QueryRowContext(ctx, `SELECT id, tenant_id, name, created_at FROM sites WHERE id = ?`, siteID).Scan(&st.ID, &st.TenantID, &st.Name, &created)
	st.CreatedAt = parseTS(created)
	return st, wrap("site", err)
}

// Sites returns all sites, or those of one tenant when tenantID is not empty.
func (s *Store) Sites(ctx context.Context, tenantID string) ([]Site, error) {
	q := `SELECT id, tenant_id, name, created_at FROM sites`
	var args []any
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	rows, err := s.main.QueryContext(ctx, q+` ORDER BY tenant_id, name`, args...)
	if err != nil {
		return nil, wrap("sites", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Site
	for rows.Next() {
		var st Site
		var created string
		if err := rows.Scan(&st.ID, &st.TenantID, &st.Name, &created); err != nil {
			return nil, wrap("sites", err)
		}
		st.CreatedAt = parseTS(created)
		out = append(out, st)
	}
	return out, wrap("sites", rows.Err())
}

// RenameSite changes the name.
func (s *Store) RenameSite(ctx context.Context, siteID, name string) error {
	return s.exec1(ctx, "rename site", `UPDATE sites SET name = ? WHERE id = ?`, name, siteID)
}

// ---- boxes -----------------------------------------------------------------------

const boxCols = `id, site_id, name, hw_id, agent_version, os, arch, cert_serial, cert_not_after, channel, discovery_mode, discovery_subnets,
	netbird_status, netbird_ip, disk_total_bytes, disk_free_bytes, uptime_s, last_seen, enrolled_at, revoked_at`

func scanBox(sc interface{ Scan(...any) error }) (Box, error) {
	var b Box
	var site, revoked sql.NullString
	var notAfter, enrolled, subnets, lastSeen string
	err := sc.Scan(&b.ID, &site, &b.Name, &b.HWID, &b.AgentVersion, &b.OS, &b.Arch, &b.CertSerial, &notAfter, &b.Channel, &b.DiscoveryMode, &subnets,
		&b.NetbirdStatus, &b.NetbirdIP, &b.DiskTotalBytes, &b.DiskFreeBytes, &b.UptimeS, &lastSeen, &enrolled, &revoked)
	b.SiteID = site.String
	b.CertNotAfter = parseTS(notAfter)
	b.LastSeen = parseTS(lastSeen)
	b.EnrolledAt = parseTS(enrolled)
	b.RevokedAt = parseTSP(revoked)
	_ = json.Unmarshal([]byte(subnets), &b.DiscoverySubnets)
	return b, err
}

// CreateBox inserts a freshly enrolled box (unassigned).
func (s *Store) CreateBox(ctx context.Context, b Box) error {
	if b.Channel == "" {
		b.Channel = wire.ChannelStable
	}
	if b.DiscoveryMode == "" {
		b.DiscoveryMode = wire.DiscoverySweep
	}
	subnets, _ := json.Marshal(nonNil(b.DiscoverySubnets))
	_, err := s.main.ExecContext(ctx, `INSERT INTO boxes (`+boxCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ID, nullIfEmpty(b.SiteID), b.Name, b.HWID, b.AgentVersion, b.OS, b.Arch, b.CertSerial, ts(b.CertNotAfter), b.Channel, b.DiscoveryMode, string(subnets),
		b.NetbirdStatus, b.NetbirdIP, b.DiskTotalBytes, b.DiskFreeBytes, b.UptimeS, ts(b.LastSeen), ts(b.EnrolledAt), tsp(b.RevokedAt))
	return wrap("create box", err)
}

// UpdateBoxHeartbeat records what the last heartbeat said about the box.
func (s *Store) UpdateBoxHeartbeat(ctx context.Context, boxID string, hb wire.Heartbeat, at time.Time) error {
	return s.exec1(ctx, "update box heartbeat", `UPDATE boxes SET agent_version = ?, os = ?, arch = ?, netbird_status = ?, netbird_ip = ?,
		disk_total_bytes = ?, disk_free_bytes = ?, uptime_s = ?, last_seen = ? WHERE id = ?`,
		hb.Agent.Version, hb.Agent.OS, hb.Agent.Arch, hb.Netbird.Status, hb.Netbird.IP, hb.Box.DiskTotalBytes, hb.Box.DiskFreeBytes, hb.Agent.UptimeS, ts(at), boxID)
}

// SetBoxDiscovery sets the discovery mode and the additional subnets to sweep.
func (s *Store) SetBoxDiscovery(ctx context.Context, boxID, mode string, subnets []string) error {
	js, _ := json.Marshal(nonNil(subnets))
	return s.exec1(ctx, "set box discovery", `UPDATE boxes SET discovery_mode = ?, discovery_subnets = ? WHERE id = ?`, mode, string(js), boxID)
}

// Box returns one box.
func (s *Store) Box(ctx context.Context, boxID string) (Box, error) {
	b, err := scanBox(s.main.QueryRowContext(ctx, `SELECT `+boxCols+` FROM boxes WHERE id = ?`, boxID))
	return b, wrap("box", err)
}

// Boxes returns all boxes, or those of one site when siteID is not empty.
func (s *Store) Boxes(ctx context.Context, siteID string) ([]Box, error) {
	q := `SELECT ` + boxCols + ` FROM boxes`
	var args []any
	if siteID != "" {
		q += ` WHERE site_id = ?`
		args = append(args, siteID)
	}
	rows, err := s.main.QueryContext(ctx, q+` ORDER BY enrolled_at`, args...)
	if err != nil {
		return nil, wrap("boxes", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Box
	for rows.Next() {
		b, err := scanBox(rows)
		if err != nil {
			return nil, wrap("boxes", err)
		}
		out = append(out, b)
	}
	return out, wrap("boxes", rows.Err())
}

// AssignBox binds a box to a site; an empty siteID unassigns it.
func (s *Store) AssignBox(ctx context.Context, boxID, siteID string) error {
	return s.exec1(ctx, "assign box", `UPDATE boxes SET site_id = ? WHERE id = ?`, nullIfEmpty(siteID), boxID)
}

// UpdateBoxAgent records what the agent reported about itself.
func (s *Store) UpdateBoxAgent(ctx context.Context, boxID, version, osName, arch string) error {
	return s.exec1(ctx, "update box agent", `UPDATE boxes SET agent_version = ?, os = ?, arch = ? WHERE id = ?`, version, osName, arch, boxID)
}

// UpdateBoxCert records a renewed certificate.
func (s *Store) UpdateBoxCert(ctx context.Context, boxID, serial string, notAfter time.Time) error {
	return s.exec1(ctx, "update box cert", `UPDATE boxes SET cert_serial = ?, cert_not_after = ? WHERE id = ?`, serial, ts(notAfter), boxID)
}

// SetBoxChannel sets the release channel.
func (s *Store) SetBoxChannel(ctx context.Context, boxID, channel string) error {
	return s.exec1(ctx, "set box channel", `UPDATE boxes SET channel = ? WHERE id = ?`, channel, boxID)
}

// RenameBox sets the display name.
func (s *Store) RenameBox(ctx context.Context, boxID, name string) error {
	return s.exec1(ctx, "rename box", `UPDATE boxes SET name = ? WHERE id = ?`, name, boxID)
}

// RevokeBox marks the box revoked and its current certificate serial denied.
func (s *Store) RevokeBox(ctx context.Context, boxID string, at time.Time) error {
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return wrap("revoke box", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op
	var serial string
	if err := tx.QueryRowContext(ctx, `SELECT cert_serial FROM boxes WHERE id = ?`, boxID).Scan(&serial); err != nil {
		return wrap("revoke box", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE boxes SET revoked_at = ? WHERE id = ?`, ts(at), boxID); err != nil {
		return wrap("revoke box", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO revoked_certs (serial, box_id, revoked_at) VALUES (?, ?, ?)`, serial, boxID, ts(at)); err != nil {
		return wrap("revoke box", err)
	}
	return wrap("revoke box", tx.Commit())
}

// RevokedSerials returns every denied certificate serial.
func (s *Store) RevokedSerials(ctx context.Context) ([]string, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT serial FROM revoked_certs`)
	if err != nil {
		return nil, wrap("revoked serials", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var sn string
		if err := rows.Scan(&sn); err != nil {
			return nil, wrap("revoked serials", err)
		}
		out = append(out, sn)
	}
	return out, wrap("revoked serials", rows.Err())
}

// DeleteBox removes a box and its hosts, state and pending NetBird key. The
// certificate serial stays on the deny list.
func (s *Store) DeleteBox(ctx context.Context, boxID string) error {
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return wrap("delete box", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE box_id = ?`, boxID); err != nil {
		return wrap("delete box", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM boxes WHERE id = ?`, boxID)
	if err != nil {
		return wrap("delete box", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return wrap("delete box", tx.Commit())
}

// ---- enrollment keys -------------------------------------------------------------

const keyCols = `id, secret_hash, note, created_at, expires_at, used_at, used_by_box, revoked_at`

func scanKey(sc interface{ Scan(...any) error }) (EnrollmentKey, error) {
	var k EnrollmentKey
	var created, expires string
	var used, usedBy, revoked sql.NullString
	err := sc.Scan(&k.ID, &k.SecretHash, &k.Note, &created, &expires, &used, &usedBy, &revoked)
	k.CreatedAt, k.ExpiresAt = parseTS(created), parseTS(expires)
	k.UsedAt, k.UsedByBox, k.RevokedAt = parseTSP(used), usedBy.String, parseTSP(revoked)
	return k, err
}

// CreateEnrollmentKey stores a key (hash only).
func (s *Store) CreateEnrollmentKey(ctx context.Context, k EnrollmentKey) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO enrollment_keys (id, secret_hash, note, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		k.ID, k.SecretHash, k.Note, ts(k.CreatedAt), ts(k.ExpiresAt))
	return wrap("create enrollment key", err)
}

// EnrollmentKeys lists keys, newest first.
func (s *Store) EnrollmentKeys(ctx context.Context) ([]EnrollmentKey, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT `+keyCols+` FROM enrollment_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, wrap("enrollment keys", err)
	}
	defer func() { _ = rows.Close() }()
	var out []EnrollmentKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, wrap("enrollment keys", err)
		}
		out = append(out, k)
	}
	return out, wrap("enrollment keys", rows.Err())
}

// UseEnrollmentKey atomically marks the key with the given secret hash as used by
// boxID. It fails with ErrKeyInvalid unless the key exists, is unused, unexpired
// and unrevoked.
func (s *Store) UseEnrollmentKey(ctx context.Context, secretHash, boxID string, at time.Time) (EnrollmentKey, error) {
	res, err := s.main.ExecContext(ctx, `UPDATE enrollment_keys SET used_at = ?, used_by_box = ?
		WHERE secret_hash = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
		ts(at), boxID, secretHash, ts(at))
	if err != nil {
		return EnrollmentKey{}, wrap("use enrollment key", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return EnrollmentKey{}, ErrKeyInvalid
	}
	k, err := scanKey(s.main.QueryRowContext(ctx, `SELECT `+keyCols+` FROM enrollment_keys WHERE secret_hash = ?`, secretHash))
	return k, wrap("use enrollment key", err)
}

// RevokeEnrollmentKey makes an unused key unusable.
func (s *Store) RevokeEnrollmentKey(ctx context.Context, keyID string, at time.Time) error {
	return s.exec1(ctx, "revoke enrollment key", `UPDATE enrollment_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, ts(at), keyID)
}

// ---- netbird keys ----------------------------------------------------------------

// SetNetbirdKey stores (or replaces) the pending hand-over for a box.
func (s *Store) SetNetbirdKey(ctx context.Context, k NetbirdKey) error {
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO netbird_keys (box_id, management_url, setup_key, created_at, claimed_at) VALUES (?, ?, ?, ?, NULL)`,
		k.BoxID, k.ManagementURL, k.SetupKey, ts(k.CreatedAt))
	return wrap("set netbird key", err)
}

// NetbirdKey returns the hand-over record of a box.
func (s *Store) NetbirdKey(ctx context.Context, boxID string) (NetbirdKey, error) {
	var k NetbirdKey
	var created string
	var claimed sql.NullString
	err := s.main.QueryRowContext(ctx, `SELECT box_id, management_url, setup_key, created_at, claimed_at FROM netbird_keys WHERE box_id = ?`, boxID).
		Scan(&k.BoxID, &k.ManagementURL, &k.SetupKey, &created, &claimed)
	k.CreatedAt, k.ClaimedAt = parseTS(created), parseTSP(claimed)
	return k, wrap("netbird key", err)
}

// ClaimNetbirdKey hands the key over exactly once; a second claim is ErrNotFound.
func (s *Store) ClaimNetbirdKey(ctx context.Context, boxID string, at time.Time) (NetbirdKey, error) {
	res, err := s.main.ExecContext(ctx, `UPDATE netbird_keys SET claimed_at = ? WHERE box_id = ? AND claimed_at IS NULL`, ts(at), boxID)
	if err != nil {
		return NetbirdKey{}, wrap("claim netbird key", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return NetbirdKey{}, ErrNotFound
	}
	return s.NetbirdKey(ctx, boxID)
}

// DeleteNetbirdKey removes the record.
func (s *Store) DeleteNetbirdKey(ctx context.Context, boxID string) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM netbird_keys WHERE box_id = ?`, boxID)
	return wrap("delete netbird key", err)
}

// ---- devices ---------------------------------------------------------------------

const deviceCols = `id, tenant_id, site_id, mac, ip, vendor, hostname, first_seen, last_seen, gone_at, ignored`

func scanDevice(sc interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var first, last string
	var gone sql.NullString
	var ignored int
	err := sc.Scan(&d.ID, &d.TenantID, &d.SiteID, &d.MAC, &d.IP, &d.Vendor, &d.Hostname, &first, &last, &gone, &ignored)
	d.FirstSeen, d.LastSeen, d.GoneAt, d.Ignored = parseTS(first), parseTS(last), parseTSP(gone), ignored != 0
	return d, err
}

// UpsertSighting records that a box at siteID saw a device. It returns the device,
// whether it is new to the site, and whether it had been marked gone.
func (s *Store) UpsertSighting(ctx context.Context, tenantID, siteID string, sg wire.Sighting, seenAt time.Time) (Device, bool, bool, error) {
	mac := strings.ToLower(strings.TrimSpace(sg.MAC))
	if mac == "" {
		return Device{}, false, false, errors.New("store: sighting without MAC")
	}
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, false, false, wrap("sighting", err)
	}
	defer tx.Rollback() //nolint:errcheck
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE site_id = ? AND mac = ?`, siteID, mac))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		d = Device{ID: id.New("dev"), TenantID: tenantID, SiteID: siteID, MAC: mac, IP: sg.IP, Vendor: sg.Vendor, Hostname: sg.Hostname, FirstSeen: seenAt, LastSeen: seenAt}
		if _, err := tx.ExecContext(ctx, `INSERT INTO devices (`+deviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0)`,
			d.ID, d.TenantID, d.SiteID, d.MAC, d.IP, d.Vendor, d.Hostname, ts(d.FirstSeen), ts(d.LastSeen)); err != nil {
			return Device{}, false, false, wrap("sighting", err)
		}
		return d, true, false, wrap("sighting", tx.Commit())
	case err != nil:
		return Device{}, false, false, wrap("sighting", err)
	}
	wasGone := d.GoneAt != nil
	if sg.IP != "" {
		d.IP = sg.IP
	}
	if sg.Vendor != "" {
		d.Vendor = sg.Vendor
	}
	if sg.Hostname != "" {
		d.Hostname = sg.Hostname
	}
	if seenAt.After(d.LastSeen) {
		d.LastSeen = seenAt
	}
	d.GoneAt = nil
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET ip = ?, vendor = ?, hostname = ?, last_seen = ?, gone_at = NULL WHERE id = ?`,
		d.IP, d.Vendor, d.Hostname, ts(d.LastSeen), d.ID); err != nil {
		return Device{}, false, false, wrap("sighting", err)
	}
	return d, false, wasGone, wrap("sighting", tx.Commit())
}

// Device returns one device.
func (s *Store) Device(ctx context.Context, deviceID string) (Device, error) {
	d, err := scanDevice(s.main.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE id = ?`, deviceID))
	return d, wrap("device", err)
}

// Devices returns the devices of a tenant seen since `since` (zero = all), or of
// one site when siteID is set. Newest sighting first.
func (s *Store) Devices(ctx context.Context, tenantID, siteID string, since time.Time) ([]Device, error) {
	q := `SELECT ` + deviceCols + ` FROM devices WHERE tenant_id = ?`
	args := []any{tenantID}
	if siteID != "" {
		q += ` AND site_id = ?`
		args = append(args, siteID)
	}
	if !since.IsZero() {
		q += ` AND last_seen >= ?`
		args = append(args, ts(since))
	}
	rows, err := s.main.QueryContext(ctx, q+` ORDER BY last_seen DESC`, args...)
	if err != nil {
		return nil, wrap("devices", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, wrap("devices", err)
		}
		out = append(out, d)
	}
	return out, wrap("devices", rows.Err())
}

// MarkDevicesGone flags devices not seen since cutoff and returns them.
func (s *Store) MarkDevicesGone(ctx context.Context, cutoff, now time.Time) ([]Device, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE gone_at IS NULL AND last_seen < ?`, ts(cutoff))
	if err != nil {
		return nil, wrap("mark gone", err)
	}
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			_ = rows.Close()
			return nil, wrap("mark gone", err)
		}
		out = append(out, d)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, wrap("mark gone", err)
	}
	for i := range out {
		if _, err := s.main.ExecContext(ctx, `UPDATE devices SET gone_at = ? WHERE id = ?`, ts(now), out[i].ID); err != nil {
			return nil, wrap("mark gone", err)
		}
		t := now
		out[i].GoneAt = &t
	}
	return out, nil
}

// SetDeviceIgnored hides a device from "to be assigned" lists.
func (s *Store) SetDeviceIgnored(ctx context.Context, deviceID string, ignored bool) error {
	return s.exec1(ctx, "ignore device", `UPDATE devices SET ignored = ? WHERE id = ?`, boolInt(ignored), deviceID)
}

// ---- hosts ------------------------------------------------------------------------

const hostCols = `id, tenant_id, site_id, box_id, device_id, name, address, mac, vendor, parent_id, is_uplink, checks, created_at`

func scanHost(sc interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var uplink int
	var checks, created string
	err := sc.Scan(&h.ID, &h.TenantID, &h.SiteID, &h.BoxID, &h.DeviceID, &h.Name, &h.Address, &h.MAC, &h.Vendor, &h.ParentID, &uplink, &checks, &created)
	if err != nil {
		return h, err
	}
	h.IsUplink = uplink != 0
	h.CreatedAt = parseTS(created)
	if err := json.Unmarshal([]byte(checks), &h.Checks); err != nil {
		return h, fmt.Errorf("host %s checks: %w", h.ID, err)
	}
	return h, nil
}

// CreateHost inserts a monitored host.
func (s *Store) CreateHost(ctx context.Context, h Host) error {
	checks, err := json.Marshal(nonNil(h.Checks))
	if err != nil {
		return wrap("create host", err)
	}
	_, err = s.main.ExecContext(ctx, `INSERT INTO hosts (`+hostCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.TenantID, h.SiteID, h.BoxID, h.DeviceID, h.Name, h.Address, h.MAC, h.Vendor, h.ParentID, boolInt(h.IsUplink), string(checks), ts(h.CreatedAt))
	return wrap("create host", err)
}

// Host returns one host.
func (s *Store) Host(ctx context.Context, hostID string) (Host, error) {
	h, err := scanHost(s.main.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id = ?`, hostID))
	return h, wrap("host", err)
}

// Hosts returns hosts filtered by tenant and/or box (empty = no filter), by name.
func (s *Store) Hosts(ctx context.Context, tenantID, boxID string) ([]Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts WHERE 1 = 1`
	var args []any
	if tenantID != "" {
		q += ` AND tenant_id = ?`
		args = append(args, tenantID)
	}
	if boxID != "" {
		q += ` AND box_id = ?`
		args = append(args, boxID)
	}
	rows, err := s.main.QueryContext(ctx, q+` ORDER BY name, id`, args...)
	if err != nil {
		return nil, wrap("hosts", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, wrap("hosts", err)
		}
		out = append(out, h)
	}
	return out, wrap("hosts", rows.Err())
}

// UpdateHost changes the editable fields of a host.
func (s *Store) UpdateHost(ctx context.Context, h Host) error {
	checks, err := json.Marshal(nonNil(h.Checks))
	if err != nil {
		return wrap("update host", err)
	}
	return s.exec1(ctx, "update host", `UPDATE hosts SET device_id = ?, name = ?, address = ?, mac = ?, vendor = ?, parent_id = ?, is_uplink = ?, checks = ? WHERE id = ?`,
		h.DeviceID, h.Name, h.Address, h.MAC, h.Vendor, h.ParentID, boolInt(h.IsUplink), string(checks), h.ID)
}

// DeleteHost removes a host; children lose their parent.
func (s *Store) DeleteHost(ctx context.Context, hostID string) error {
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return wrap("delete host", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET parent_id = '' WHERE parent_id = ?`, hostID); err != nil {
		return wrap("delete host", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, hostID)
	if err != nil {
		return wrap("delete host", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return wrap("delete host", tx.Commit())
}

// ---- state -------------------------------------------------------------------------

// SaveHostState persists the state-machine fields of a host.
func (s *Store) SaveHostState(ctx context.Context, h state.Host, now time.Time) error {
	failed, _ := json.Marshal(nonNil(h.LastFailedChecks))
	checks, _ := json.Marshal(nonNil(h.LastChecks))
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO host_state
		(host_id, observed, reported, failures, successes, since, run_start, down_since, last_failed_checks, last_checks, last_box_time, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, string(h.Observed), string(h.Reported), h.Failures, h.Successes, ts(h.Since), ts(h.RunStart), ts(h.DownSince), string(failed), string(checks), ts(h.LastBoxTime), ts(now))
	return wrap("save host state", err)
}

// HostStates returns the persisted state fields keyed by host id.
func (s *Store) HostStates(ctx context.Context) (map[string]state.Host, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT host_id, observed, reported, failures, successes, since, run_start, down_since, last_failed_checks, last_checks, last_box_time FROM host_state`)
	if err != nil {
		return nil, wrap("host states", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]state.Host{}
	for rows.Next() {
		var h state.Host
		var observed, reported, since, runStart, downSince, failed, checks, boxTime string
		if err := rows.Scan(&h.ID, &observed, &reported, &h.Failures, &h.Successes, &since, &runStart, &downSince, &failed, &checks, &boxTime); err != nil {
			return nil, wrap("host states", err)
		}
		h.Observed, h.Reported = state.HostState(observed), state.HostState(reported)
		h.Since, h.RunStart, h.DownSince, h.LastBoxTime = parseTS(since), parseTS(runStart), parseTS(downSince), parseTS(boxTime)
		_ = json.Unmarshal([]byte(failed), &h.LastFailedChecks)
		_ = json.Unmarshal([]byte(checks), &h.LastChecks)
		out[h.ID] = h
	}
	return out, wrap("host states", rows.Err())
}

// SaveBoxState persists the state-machine fields of a box.
func (s *Store) SaveBoxState(ctx context.Context, b state.Box, now time.Time) error {
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO box_state (box_id, status, last_heartbeat, silent_since, updated_at) VALUES (?, ?, ?, ?, ?)`,
		b.ID, string(b.Status), ts(b.LastHeartbeat), ts(b.SilentSince), ts(now))
	return wrap("save box state", err)
}

// BoxStates returns the persisted state fields keyed by box id.
func (s *Store) BoxStates(ctx context.Context) (map[string]state.Box, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT box_id, status, last_heartbeat, silent_since FROM box_state`)
	if err != nil {
		return nil, wrap("box states", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]state.Box{}
	for rows.Next() {
		var b state.Box
		var status, last, silent string
		if err := rows.Scan(&b.ID, &status, &last, &silent); err != nil {
			return nil, wrap("box states", err)
		}
		b.Status, b.LastHeartbeat, b.SilentSince = state.BoxStatus(status), parseTS(last), parseTS(silent)
		out[b.ID] = b
	}
	return out, wrap("box states", rows.Err())
}

// ---- maintenance --------------------------------------------------------------------

const maintCols = `id, tenant_id, site_id, scope, target_id, until_at, reason, set_by, created_at`

// CreateMaintenance inserts (or replaces, same id) a window.
func (s *Store) CreateMaintenance(ctx context.Context, m Maintenance) error {
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO maintenance (`+maintCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.TenantID, m.SiteID, m.Scope, m.TargetID, ts(m.Until), m.Reason, m.SetBy, ts(m.CreatedAt))
	return wrap("create maintenance", err)
}

// DeleteMaintenance removes a window.
func (s *Store) DeleteMaintenance(ctx context.Context, maintID string) error {
	return s.exec1(ctx, "delete maintenance", `DELETE FROM maintenance WHERE id = ?`, maintID)
}

// Maintenances lists windows, all or per tenant.
func (s *Store) Maintenances(ctx context.Context, tenantID string) ([]Maintenance, error) {
	q := `SELECT ` + maintCols + ` FROM maintenance`
	var args []any
	if tenantID != "" {
		q += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	rows, err := s.main.QueryContext(ctx, q+` ORDER BY until_at`, args...)
	if err != nil {
		return nil, wrap("maintenances", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Maintenance
	for rows.Next() {
		var m Maintenance
		var until, created string
		if err := rows.Scan(&m.ID, &m.TenantID, &m.SiteID, &m.Scope, &m.TargetID, &until, &m.Reason, &m.SetBy, &created); err != nil {
			return nil, wrap("maintenances", err)
		}
		m.Until, m.CreatedAt = parseTS(until), parseTS(created)
		out = append(out, m)
	}
	return out, wrap("maintenances", rows.Err())
}

// ---- webhook targets ------------------------------------------------------------------

const targetCols = `id, name, url, secret, tenant_scope, enabled, created_at`

func scanTarget(sc interface{ Scan(...any) error }) (WebhookTarget, error) {
	var t WebhookTarget
	var enabled int
	var created string
	err := sc.Scan(&t.ID, &t.Name, &t.URL, &t.Secret, &t.TenantScope, &enabled, &created)
	t.Enabled, t.CreatedAt = enabled != 0, parseTS(created)
	return t, err
}

// CreateWebhookTarget inserts a target.
func (s *Store) CreateWebhookTarget(ctx context.Context, t WebhookTarget) error {
	if t.TenantScope == "" {
		t.TenantScope = "*"
	}
	_, err := s.main.ExecContext(ctx, `INSERT INTO webhook_targets (`+targetCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.URL, t.Secret, t.TenantScope, boolInt(t.Enabled), ts(t.CreatedAt))
	return wrap("create webhook target", err)
}

// WebhookTarget returns one target.
func (s *Store) WebhookTarget(ctx context.Context, targetID string) (WebhookTarget, error) {
	t, err := scanTarget(s.main.QueryRowContext(ctx, `SELECT `+targetCols+` FROM webhook_targets WHERE id = ?`, targetID))
	return t, wrap("webhook target", err)
}

// WebhookTargets lists all targets.
func (s *Store) WebhookTargets(ctx context.Context) ([]WebhookTarget, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT `+targetCols+` FROM webhook_targets ORDER BY name`)
	if err != nil {
		return nil, wrap("webhook targets", err)
	}
	defer func() { _ = rows.Close() }()
	var out []WebhookTarget
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, wrap("webhook targets", err)
		}
		out = append(out, t)
	}
	return out, wrap("webhook targets", rows.Err())
}

// TargetsForTenant returns the enabled targets that receive a tenant's events.
func (s *Store) TargetsForTenant(ctx context.Context, tenantID string) ([]WebhookTarget, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT `+targetCols+` FROM webhook_targets WHERE enabled = 1 AND (tenant_scope = '*' OR tenant_scope = ?) ORDER BY id`, tenantID)
	if err != nil {
		return nil, wrap("targets for tenant", err)
	}
	defer func() { _ = rows.Close() }()
	var out []WebhookTarget
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, wrap("targets for tenant", err)
		}
		out = append(out, t)
	}
	return out, wrap("targets for tenant", rows.Err())
}

// UpdateWebhookTarget changes name, URL, scope and enabled; the secret only when non-empty.
func (s *Store) UpdateWebhookTarget(ctx context.Context, t WebhookTarget) error {
	if t.Secret != "" {
		return s.exec1(ctx, "update webhook target", `UPDATE webhook_targets SET name = ?, url = ?, secret = ?, tenant_scope = ?, enabled = ? WHERE id = ?`,
			t.Name, t.URL, t.Secret, t.TenantScope, boolInt(t.Enabled), t.ID)
	}
	return s.exec1(ctx, "update webhook target", `UPDATE webhook_targets SET name = ?, url = ?, tenant_scope = ?, enabled = ? WHERE id = ?`,
		t.Name, t.URL, t.TenantScope, boolInt(t.Enabled), t.ID)
}

// DeleteWebhookTarget removes a target; its past deliveries stay in the day files.
func (s *Store) DeleteWebhookTarget(ctx context.Context, targetID string) error {
	return s.exec1(ctx, "delete webhook target", `DELETE FROM webhook_targets WHERE id = ?`, targetID)
}

// ---- api tokens -----------------------------------------------------------------------

const tokenCols = `id, name, token_hash, tenants, created_at, last_used_at, revoked_at` //nolint:gosec // column names, not credentials

func scanToken(sc interface{ Scan(...any) error }) (APIToken, error) {
	var t APIToken
	var tenants, created string
	var used, revoked sql.NullString
	err := sc.Scan(&t.ID, &t.Name, &t.TokenHash, &tenants, &created, &used, &revoked)
	if err != nil {
		return t, err
	}
	t.CreatedAt, t.LastUsedAt, t.RevokedAt = parseTS(created), parseTSP(used), parseTSP(revoked)
	return t, json.Unmarshal([]byte(tenants), &t.Tenants)
}

// CreateAPIToken stores a token (hash only).
func (s *Store) CreateAPIToken(ctx context.Context, t APIToken) error {
	if len(t.Tenants) == 0 {
		t.Tenants = []string{"*"}
	}
	tenants, _ := json.Marshal(t.Tenants)
	_, err := s.main.ExecContext(ctx, `INSERT INTO api_tokens (id, name, token_hash, tenants, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.TokenHash, string(tenants), ts(t.CreatedAt))
	return wrap("create api token", err)
}

// APITokenByHash returns a live (unrevoked) token.
func (s *Store) APITokenByHash(ctx context.Context, hash string) (APIToken, error) {
	t, err := scanToken(s.main.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM api_tokens WHERE token_hash = ? AND revoked_at IS NULL`, hash))
	return t, wrap("api token", err)
}

// APITokens lists all tokens.
func (s *Store) APITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT `+tokenCols+` FROM api_tokens ORDER BY created_at`)
	if err != nil {
		return nil, wrap("api tokens", err)
	}
	defer func() { _ = rows.Close() }()
	var out []APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, wrap("api tokens", err)
		}
		out = append(out, t)
	}
	return out, wrap("api tokens", rows.Err())
}

// TouchAPIToken records a use.
func (s *Store) TouchAPIToken(ctx context.Context, tokenID string, at time.Time) error {
	_, err := s.main.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, ts(at), tokenID)
	return wrap("touch api token", err)
}

// RevokeAPIToken revokes a token.
func (s *Store) RevokeAPIToken(ctx context.Context, tokenID string, at time.Time) error {
	return s.exec1(ctx, "revoke api token", `UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, ts(at), tokenID)
}

// ---- users and sessions ---------------------------------------------------------------

const userCols = `id, name, password_hash, totp_secret, totp_last_counter, failed_logins, locked_until, disabled, created_at`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var u User
	var locked sql.NullString
	var disabled int
	var created string
	err := sc.Scan(&u.ID, &u.Name, &u.PasswordHash, &u.TOTPSecret, &u.TOTPLastCounter, &u.FailedLogins, &locked, &disabled, &created)
	u.LockedUntil, u.Disabled, u.CreatedAt = parseTSP(locked), disabled != 0, parseTS(created)
	return u, err
}

// CreateUser inserts a console account.
func (s *Store) CreateUser(ctx context.Context, u User) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO users (id, name, password_hash, totp_secret, created_at) VALUES (?, ?, ?, ?, ?)`,
		u.ID, u.Name, u.PasswordHash, u.TOTPSecret, ts(u.CreatedAt))
	return wrap("create user", err)
}

// UserByName returns a user by login name.
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	u, err := scanUser(s.main.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE name = ?`, name))
	return u, wrap("user", err)
}

// User returns a user by id.
func (s *Store) User(ctx context.Context, userID string) (User, error) {
	u, err := scanUser(s.main.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, userID))
	return u, wrap("user", err)
}

// Users lists all accounts.
func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY name`)
	if err != nil {
		return nil, wrap("users", err)
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, wrap("users", err)
		}
		out = append(out, u)
	}
	return out, wrap("users", rows.Err())
}

// UpdateUserLoginState persists lockout and TOTP replay state after a login attempt.
func (s *Store) UpdateUserLoginState(ctx context.Context, userID string, failedLogins int, lockedUntil *time.Time, totpLastCounter int64) error {
	return s.exec1(ctx, "update user login state", `UPDATE users SET failed_logins = ?, locked_until = ?, totp_last_counter = ? WHERE id = ?`,
		failedLogins, tsp(lockedUntil), totpLastCounter, userID)
}

// SetUserDisabled locks or unlocks an account.
func (s *Store) SetUserDisabled(ctx context.Context, userID string, disabled bool) error {
	return s.exec1(ctx, "disable user", `UPDATE users SET disabled = ? WHERE id = ?`, boolInt(disabled), userID)
}

// SetUserPassword replaces the password hash.
func (s *Store) SetUserPassword(ctx context.Context, userID, hash string) error {
	return s.exec1(ctx, "set password", `UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID)
}

// CreateSession stores a login session (hash only).
func (s *Store) CreateSession(ctx context.Context, sess Session) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, csrf, created_at, last_seen, ip) VALUES (?, ?, ?, ?, ?, ?)`,
		sess.TokenHash, sess.UserID, sess.CSRF, ts(sess.CreatedAt), ts(sess.LastSeen), sess.IP)
	return wrap("create session", err)
}

// Session returns a session by cookie hash.
func (s *Store) Session(ctx context.Context, hash string) (Session, error) {
	var sess Session
	var created, last string
	err := s.main.QueryRowContext(ctx, `SELECT token_hash, user_id, csrf, created_at, last_seen, ip FROM sessions WHERE token_hash = ?`, hash).
		Scan(&sess.TokenHash, &sess.UserID, &sess.CSRF, &created, &last, &sess.IP)
	sess.CreatedAt, sess.LastSeen = parseTS(created), parseTS(last)
	return sess, wrap("session", err)
}

// TouchSession updates last_seen.
func (s *Store) TouchSession(ctx context.Context, hash string, at time.Time) error {
	_, err := s.main.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE token_hash = ?`, ts(at), hash)
	return wrap("touch session", err)
}

// DeleteSession logs out.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hash)
	return wrap("delete session", err)
}

// DeleteStaleSessions removes sessions idle since idleBefore or created before absBefore.
func (s *Store) DeleteStaleSessions(ctx context.Context, idleBefore, absBefore time.Time) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM sessions WHERE last_seen < ? OR created_at < ?`, ts(idleBefore), ts(absBefore))
	return wrap("delete stale sessions", err)
}

// ---- audit --------------------------------------------------------------------------

// Audit appends an entry.
func (s *Store) Audit(ctx context.Context, at time.Time, actor, action, target, summary string) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO audit_log (at, actor, action, target, summary) VALUES (?, ?, ?, ?, ?)`, ts(at), actor, action, target, summary)
	return wrap("audit", err)
}

// AuditEntries returns up to limit entries with id < beforeID (0 = newest), newest first.
func (s *Store) AuditEntries(ctx context.Context, limit int, beforeID int64) ([]AuditEntry, error) {
	if beforeID <= 0 {
		beforeID = 1<<62 - 1
	}
	rows, err := s.main.QueryContext(ctx, `SELECT id, at, actor, action, target, summary FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?`, beforeID, limit)
	if err != nil {
		return nil, wrap("audit entries", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Summary); err != nil {
			return nil, wrap("audit entries", err)
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, wrap("audit entries", rows.Err())
}

// ---- releases and settings -------------------------------------------------------------

// PutRelease stores (or replaces) update metadata.
func (s *Store) PutRelease(ctx context.Context, r Release) error {
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO releases (version, os, arch, url, sha256, signature, min_agent_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Version, r.OS, r.Arch, r.URL, r.SHA256, r.Signature, r.MinAgentVersion, ts(r.CreatedAt))
	return wrap("put release", err)
}

// Release returns the metadata for one version/os/arch.
func (s *Store) Release(ctx context.Context, version, osName, arch string) (Release, error) {
	var r Release
	var created string
	err := s.main.QueryRowContext(ctx, `SELECT version, os, arch, url, sha256, signature, min_agent_version, created_at FROM releases WHERE version = ? AND os = ? AND arch = ?`, version, osName, arch).
		Scan(&r.Version, &r.OS, &r.Arch, &r.URL, &r.SHA256, &r.Signature, &r.MinAgentVersion, &created)
	r.CreatedAt = parseTS(created)
	return r, wrap("release", err)
}

// Releases lists all stored releases, newest first.
func (s *Store) Releases(ctx context.Context) ([]Release, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT version, os, arch, url, sha256, signature, min_agent_version, created_at FROM releases ORDER BY created_at DESC, version DESC, os, arch`)
	if err != nil {
		return nil, wrap("releases", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Release
	for rows.Next() {
		var r Release
		var created string
		if err := rows.Scan(&r.Version, &r.OS, &r.Arch, &r.URL, &r.SHA256, &r.Signature, &r.MinAgentVersion, &created); err != nil {
			return nil, wrap("releases", err)
		}
		r.CreatedAt = parseTS(created)
		out = append(out, r)
	}
	return out, wrap("releases", rows.Err())
}

// SetChannelVersion points a channel (stable/canary) at a version; "" clears it.
func (s *Store) SetChannelVersion(ctx context.Context, channel, version string) error {
	return s.SetSetting(ctx, "channel."+channel, version)
}

// ChannelVersion returns the version a channel points at ("" if none).
func (s *Store) ChannelVersion(ctx context.Context, channel string) (string, error) {
	return s.Setting(ctx, "channel."+channel)
}

// Setting returns a setting value ("" if unset).
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.main.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, wrap("setting", err)
}

// SetSetting stores a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, key, value)
	return wrap("set setting", err)
}

// ---- helpers --------------------------------------------------------------------------

// exec1 runs a statement that must affect exactly one row, else ErrNotFound.
func (s *Store) exec1(ctx context.Context, op, q string, args ...any) error {
	res, err := s.main.ExecContext(ctx, q, args...)
	if err != nil {
		return wrap(op, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
