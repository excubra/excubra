package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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
	err := s.main.QueryRowContext(ctx, `SELECT id, name, created_at, ai_scope FROM tenants WHERE id = ?`, tenantID).Scan(&t.ID, &t.Name, &created, &t.AIScope)
	t.CreatedAt = parseTS(created)
	return t, wrap("tenant", err)
}

// Tenants returns all tenants by name.
func (s *Store) Tenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT id, name, created_at, ai_scope FROM tenants ORDER BY name`)
	if err != nil {
		return nil, wrap("tenants", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		var created string
		if err := rows.Scan(&t.ID, &t.Name, &created, &t.AIScope); err != nil {
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
	var scan, canary int
	err := s.main.QueryRowContext(ctx, `SELECT id, tenant_id, name, created_at, scan_enabled, canary_enabled FROM sites WHERE id = ?`, siteID).Scan(&st.ID, &st.TenantID, &st.Name, &created, &scan, &canary)
	st.CreatedAt, st.ScanEnabled, st.CanaryEnabled = parseTS(created), scan != 0, canary != 0
	return st, wrap("site", err)
}

// Sites returns all sites, or those of one tenant when tenantID is not empty.
func (s *Store) Sites(ctx context.Context, tenantID string) ([]Site, error) {
	q := `SELECT id, tenant_id, name, created_at, scan_enabled, canary_enabled FROM sites`
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
		var scan, canary int
		if err := rows.Scan(&st.ID, &st.TenantID, &st.Name, &created, &scan, &canary); err != nil {
			return nil, wrap("sites", err)
		}
		st.CreatedAt, st.ScanEnabled, st.CanaryEnabled = parseTS(created), scan != 0, canary != 0
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
	netbird_status, netbird_ip, disk_total_bytes, disk_free_bytes, uptime_s, last_seen, enrolled_at, revoked_at, seal_key, netbird_op_status, netbird_op_ip, lan, public_ip, role, canary`

func scanBox(sc interface{ Scan(...any) error }) (Box, error) {
	var b Box
	var site, revoked sql.NullString
	var notAfter, enrolled, subnets, lastSeen, lan, canary string
	err := sc.Scan(&b.ID, &site, &b.Name, &b.HWID, &b.AgentVersion, &b.OS, &b.Arch, &b.CertSerial, &notAfter, &b.Channel, &b.DiscoveryMode, &subnets,
		&b.NetbirdStatus, &b.NetbirdIP, &b.DiskTotalBytes, &b.DiskFreeBytes, &b.UptimeS, &lastSeen, &enrolled, &revoked, &b.SealKey, &b.NetbirdOpStatus, &b.NetbirdOpIP, &lan, &b.PublicIP, &b.Role, &canary)
	_ = json.Unmarshal([]byte(lan), &b.LAN)
	_ = json.Unmarshal([]byte(canary), &b.Canary)
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
	if b.Role == "" {
		b.Role = RoleBox
	}
	lanJSON, _ := json.Marshal(nonNil(b.LAN))
	_, err := s.main.ExecContext(ctx, `INSERT INTO boxes (`+boxCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]')`,
		b.ID, nullIfEmpty(b.SiteID), b.Name, b.HWID, b.AgentVersion, b.OS, b.Arch, b.CertSerial, ts(b.CertNotAfter), b.Channel, b.DiscoveryMode, string(subnets),
		b.NetbirdStatus, b.NetbirdIP, b.DiskTotalBytes, b.DiskFreeBytes, b.UptimeS, ts(b.LastSeen), ts(b.EnrolledAt), tsp(b.RevokedAt), b.SealKey, b.NetbirdOpStatus, b.NetbirdOpIP, string(lanJSON), b.PublicIP, b.Role)
	return wrap("create box", err)
}

// UpdateBoxHeartbeat records what the last heartbeat said about the box.
func (s *Store) UpdateBoxHeartbeat(ctx context.Context, boxID string, hb wire.Heartbeat, at time.Time) error {
	opStatus, opIP := "", ""
	if hb.NetbirdOperator != nil {
		opStatus, opIP = hb.NetbirdOperator.Status, hb.NetbirdOperator.IP
	}
	lanJSON, _ := json.Marshal(nonNil(hb.Box.LAN))
	canary := hb.Box.Canary
	if canary == nil {
		canary = []int{}
	}
	canaryJSON, _ := json.Marshal(canary)
	return s.exec1(ctx, "update box heartbeat", `UPDATE boxes SET agent_version = ?, os = ?, arch = ?, netbird_status = ?, netbird_ip = ?,
		disk_total_bytes = ?, disk_free_bytes = ?, uptime_s = ?, last_seen = ?, netbird_op_status = ?, netbird_op_ip = ?, lan = ?, canary = ? WHERE id = ?`,
		hb.Agent.Version, hb.Agent.OS, hb.Agent.Arch, hb.Netbird.Status, hb.Netbird.IP, hb.Box.DiskTotalBytes, hb.Box.DiskFreeBytes, hb.Agent.UptimeS, ts(at), opStatus, opIP, string(lanJSON), string(canaryJSON), boxID)
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

const keyCols = `id, secret_hash, note, created_at, expires_at, used_at, used_by_box, revoked_at, site_id`

func scanKey(sc interface{ Scan(...any) error }) (EnrollmentKey, error) {
	var k EnrollmentKey
	var created, expires string
	var used, usedBy, revoked, site sql.NullString
	err := sc.Scan(&k.ID, &k.SecretHash, &k.Note, &created, &expires, &used, &usedBy, &revoked, &site)
	k.CreatedAt, k.ExpiresAt = parseTS(created), parseTS(expires)
	k.UsedAt, k.UsedByBox, k.RevokedAt, k.SiteID = parseTSP(used), usedBy.String, parseTSP(revoked), site.String
	return k, err
}

// CreateEnrollmentKey stores a key (hash only).
func (s *Store) CreateEnrollmentKey(ctx context.Context, k EnrollmentKey) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO enrollment_keys (id, secret_hash, note, created_at, expires_at, site_id) VALUES (?, ?, ?, ?, ?, ?)`,
		k.ID, k.SecretHash, k.Note, ts(k.CreatedAt), ts(k.ExpiresAt), nullIfEmpty(k.SiteID))
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
	if k.Profile == "" {
		k.Profile = wire.NetbirdProfileCustomer
	}
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO netbird_keys (box_id, profile, management_url, setup_key, created_at, claimed_at) VALUES (?, ?, ?, ?, ?, NULL)`,
		k.BoxID, k.Profile, k.ManagementURL, k.SetupKey, ts(k.CreatedAt))
	return wrap("set netbird key", err)
}

// NetbirdKey returns the customer-stack hand-over record of a box.
func (s *Store) NetbirdKey(ctx context.Context, boxID string) (NetbirdKey, error) {
	return s.NetbirdKeyProfile(ctx, boxID, wire.NetbirdProfileCustomer)
}

// NetbirdKeyProfile returns the hand-over record of a box for one profile.
func (s *Store) NetbirdKeyProfile(ctx context.Context, boxID, profile string) (NetbirdKey, error) {
	var k NetbirdKey
	var created string
	var claimed sql.NullString
	err := s.main.QueryRowContext(ctx, `SELECT box_id, profile, management_url, setup_key, created_at, claimed_at FROM netbird_keys WHERE box_id = ? AND profile = ?`, boxID, profile).
		Scan(&k.BoxID, &k.Profile, &k.ManagementURL, &k.SetupKey, &created, &claimed)
	k.CreatedAt, k.ClaimedAt = parseTS(created), parseTSP(claimed)
	return k, wrap("netbird key", err)
}

// ClaimNetbirdKey hands the customer-stack key over exactly once.
func (s *Store) ClaimNetbirdKey(ctx context.Context, boxID string, at time.Time) (NetbirdKey, error) {
	return s.ClaimNetbirdKeyProfile(ctx, boxID, wire.NetbirdProfileCustomer, at)
}

// ClaimNetbirdKeyProfile hands a key over exactly once; a second claim is ErrNotFound.
func (s *Store) ClaimNetbirdKeyProfile(ctx context.Context, boxID, profile string, at time.Time) (NetbirdKey, error) {
	res, err := s.main.ExecContext(ctx, `UPDATE netbird_keys SET claimed_at = ? WHERE box_id = ? AND profile = ? AND claimed_at IS NULL`, ts(at), boxID, profile)
	if err != nil {
		return NetbirdKey{}, wrap("claim netbird key", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return NetbirdKey{}, ErrNotFound
	}
	return s.NetbirdKeyProfile(ctx, boxID, profile)
}

// DeleteNetbirdKey removes the customer-stack record.
func (s *Store) DeleteNetbirdKey(ctx context.Context, boxID string) error {
	return s.DeleteNetbirdKeyProfile(ctx, boxID, wire.NetbirdProfileCustomer)
}

// DeleteNetbirdKeyProfile removes one profile's record.
func (s *Store) DeleteNetbirdKeyProfile(ctx context.Context, boxID, profile string) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM netbird_keys WHERE box_id = ? AND profile = ?`, boxID, profile)
	return wrap("delete netbird key", err)
}

// ---- remote access (salt: Vollausbau B) ----------------------------------------------------

const remoteCols = `site_id, tenant_id, box_id, cidr, enabled, state, detail, peer_id, peer_ip, network_id, resource_id, router_id, resource_name, requested_by, created_at, updated_at`

func scanRemote(sc interface{ Scan(...any) error }) (RemoteAccess, error) {
	var r RemoteAccess
	var enabled int
	var created, updated string
	err := sc.Scan(&r.SiteID, &r.TenantID, &r.BoxID, &r.CIDR, &enabled, &r.State, &r.Detail, &r.PeerID, &r.PeerIP, &r.NetworkID, &r.ResourceID, &r.RouterID, &r.ResourceName, &r.RequestedBy, &created, &updated)
	r.Enabled = enabled != 0
	r.CreatedAt, r.UpdatedAt = parseTS(created), parseTS(updated)
	return r, err
}

// SetRemoteAccess inserts or replaces a site's remote-access row.
func (s *Store) SetRemoteAccess(ctx context.Context, r RemoteAccess) error {
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO remote_access (`+remoteCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.SiteID, r.TenantID, r.BoxID, r.CIDR, boolInt(r.Enabled), r.State, r.Detail, r.PeerID, r.PeerIP, r.NetworkID, r.ResourceID, r.RouterID, r.ResourceName, r.RequestedBy, ts(r.CreatedAt), ts(r.UpdatedAt))
	return wrap("set remote access", err)
}

// RemoteAccess returns a site's row.
func (s *Store) RemoteAccess(ctx context.Context, siteID string) (RemoteAccess, error) {
	r, err := scanRemote(s.main.QueryRowContext(ctx, `SELECT `+remoteCols+` FROM remote_access WHERE site_id = ?`, siteID))
	return r, wrap("remote access", err)
}

// RemoteAccesses returns every row.
func (s *Store) RemoteAccesses(ctx context.Context) ([]RemoteAccess, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT `+remoteCols+` FROM remote_access ORDER BY tenant_id, site_id`)
	if err != nil {
		return nil, wrap("remote accesses", err)
	}
	defer func() { _ = rows.Close() }()
	var out []RemoteAccess
	for rows.Next() {
		r, err := scanRemote(rows)
		if err != nil {
			return nil, wrap("remote accesses", err)
		}
		out = append(out, r)
	}
	return out, wrap("remote accesses", rows.Err())
}

// DeleteRemoteAccess removes a site's row.
func (s *Store) DeleteRemoteAccess(ctx context.Context, siteID string) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM remote_access WHERE site_id = ?`, siteID)
	return wrap("delete remote access", err)
}

// ---- devices ---------------------------------------------------------------------

const deviceCols = `id, tenant_id, site_id, mac, ip, vendor, hostname, first_seen, last_seen, gone_at, ignored, external`

func scanDevice(sc interface{ Scan(...any) error }) (Device, error) {
	var d Device
	var first, last string
	var gone sql.NullString
	var ignored, external int
	err := sc.Scan(&d.ID, &d.TenantID, &d.SiteID, &d.MAC, &d.IP, &d.Vendor, &d.Hostname, &first, &last, &gone, &ignored, &external)
	d.FirstSeen, d.LastSeen, d.GoneAt, d.Ignored, d.External = parseTS(first), parseTS(last), parseTSP(gone), ignored != 0, external != 0
	return d, err
}

// UpsertSighting records that a box at siteID saw a device. It returns the device,
// whether it is new to the site, and whether it had been marked gone.
func (s *Store) UpsertSighting(ctx context.Context, tenantID, siteID string, sg wire.Sighting, seenAt time.Time) (Device, bool, bool, error) {
	mac := strings.ToLower(strings.TrimSpace(sg.MAC))
	ip := strings.TrimSpace(sg.IP)
	if mac == "" && ip == "" {
		return Device{}, false, false, errors.New("store: sighting without MAC and without IP")
	}
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, false, false, wrap("sighting", err)
	}
	defer tx.Rollback() //nolint:errcheck
	// A MAC identifies a device across IP changes; without one (ICMP sweep of another
	// subnet, ADR-0007) the IP is all there is.
	var row *sql.Row
	if mac != "" {
		row = tx.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE site_id = ? AND mac = ?`, siteID, mac)
	} else {
		row = tx.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE site_id = ? AND mac = '' AND ip = ?`, siteID, ip)
	}
	d, err := scanDevice(row)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		d = Device{ID: id.New("dev"), TenantID: tenantID, SiteID: siteID, MAC: mac, IP: ip, Vendor: sg.Vendor, Hostname: sg.Hostname, FirstSeen: seenAt, LastSeen: seenAt}
		if _, err := tx.ExecContext(ctx, `INSERT INTO devices (`+deviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0)`,
			d.ID, d.TenantID, d.SiteID, d.MAC, d.IP, d.Vendor, d.Hostname, ts(d.FirstSeen), ts(d.LastSeen)); err != nil {
			return Device{}, false, false, wrap("sighting", err)
		}
		return d, true, false, wrap("sighting", tx.Commit())
	case err != nil:
		return Device{}, false, false, wrap("sighting", err)
	}
	wasGone := d.GoneAt != nil
	if ip != "" {
		d.IP = ip
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
	q := `SELECT ` + deviceCols + ` FROM devices WHERE tenant_id = ? AND external = 0`
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

// ---- box tasks (ADR-0014) --------------------------------------------------------------

const taskCols = `id, box_id, kind, issued_at, issued_by, expires_at, done_at, ok, detail`

func scanTask(sc interface{ Scan(...any) error }) (BoxTask, error) {
	var t BoxTask
	var issued, expires string
	var done sql.NullString
	var ok sql.NullBool
	err := sc.Scan(&t.ID, &t.BoxID, &t.Kind, &issued, &t.IssuedBy, &expires, &done, &ok, &t.Detail)
	t.IssuedAt, t.ExpiresAt = parseTS(issued), parseTS(expires)
	t.DoneAt = parseTSP(done)
	if ok.Valid {
		v := ok.Bool
		t.OK = &v
	}
	return t, err
}

// CreateBoxTask queues a task.
func (s *Store) CreateBoxTask(ctx context.Context, t BoxTask) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO box_tasks (`+taskCols+`) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, '')`,
		t.ID, t.BoxID, t.Kind, ts(t.IssuedAt), t.IssuedBy, ts(t.ExpiresAt))
	return wrap("create box task", err)
}

// PendingBoxTasks returns the tasks of a box that are neither done nor expired, oldest first.
func (s *Store) PendingBoxTasks(ctx context.Context, boxID string, now time.Time) ([]BoxTask, error) {
	return s.tasks(ctx, `SELECT `+taskCols+` FROM box_tasks WHERE box_id = ? AND done_at IS NULL AND expires_at > ? ORDER BY issued_at, id`, boxID, ts(now))
}

// BoxTasks returns the newest tasks of a box, or of every box when boxID is empty.
func (s *Store) BoxTasks(ctx context.Context, boxID string, limit int) ([]BoxTask, error) {
	if boxID == "" {
		return s.tasks(ctx, `SELECT `+taskCols+` FROM box_tasks ORDER BY issued_at DESC, id DESC LIMIT ?`, limit)
	}
	return s.tasks(ctx, `SELECT `+taskCols+` FROM box_tasks WHERE box_id = ? ORDER BY issued_at DESC, id DESC LIMIT ?`, boxID, limit)
}

func (s *Store) tasks(ctx context.Context, q string, args ...any) ([]BoxTask, error) {
	rows, err := s.main.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap("box tasks", err)
	}
	defer func() { _ = rows.Close() }()
	var out []BoxTask
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, wrap("box tasks", err)
		}
		out = append(out, t)
	}
	return out, wrap("box tasks", rows.Err())
}

// CompleteBoxTask records a result. A second result for the same task, or one for
// a task that already expired, is ErrNotFound and changes nothing.
func (s *Store) CompleteBoxTask(ctx context.Context, boxID, taskID string, ok bool, detail string, at time.Time) error {
	return s.exec1(ctx, "complete box task", `UPDATE box_tasks SET done_at = ?, ok = ?, detail = ? WHERE id = ? AND box_id = ? AND done_at IS NULL`, ts(at), boolInt(ok), detail, taskID, boxID)
}

// ExpireBoxTasks fails every pending task whose deadline has passed and returns them.
func (s *Store) ExpireBoxTasks(ctx context.Context, now time.Time) ([]BoxTask, error) {
	expired, err := s.tasks(ctx, `SELECT `+taskCols+` FROM box_tasks WHERE done_at IS NULL AND expires_at <= ?`, ts(now))
	if err != nil || len(expired) == 0 {
		return nil, err
	}
	_, err = s.main.ExecContext(ctx, `UPDATE box_tasks SET done_at = ?, ok = 0, detail = 'not picked up: the box did not pull its config in time' WHERE done_at IS NULL AND expires_at <= ?`, ts(now), ts(now))
	return expired, wrap("expire box tasks", err)
}

// PruneBoxTasks deletes finished tasks older than before.
func (s *Store) PruneBoxTasks(ctx context.Context, before time.Time) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM box_tasks WHERE done_at IS NOT NULL AND done_at < ?`, ts(before))
	return wrap("prune box tasks", err)
}

// ---- box notes ----------------------------------------------------------------------------

// boxNotesKeep is how many notes a box keeps; older ones go when a new one arrives.
const boxNotesKeep = 50

// AddBoxNote stores a heartbeat note and trims the box to the newest boxNotesKeep.
func (s *Store) AddBoxNote(ctx context.Context, boxID string, at time.Time, text string) error {
	if _, err := s.main.ExecContext(ctx, `INSERT INTO box_notes (box_id, at, text) VALUES (?, ?, ?)`, boxID, ts(at), text); err != nil {
		return wrap("add box note", err)
	}
	_, err := s.main.ExecContext(ctx, `DELETE FROM box_notes WHERE box_id = ? AND id NOT IN (SELECT id FROM box_notes WHERE box_id = ? ORDER BY id DESC LIMIT ?)`, boxID, boxID, boxNotesKeep)
	return wrap("trim box notes", err)
}

func (s *Store) notes(ctx context.Context, q string, args ...any) ([]BoxNote, error) {
	rows, err := s.main.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap("box notes", err)
	}
	defer func() { _ = rows.Close() }()
	var out []BoxNote
	for rows.Next() {
		var n BoxNote
		var at string
		if err := rows.Scan(&n.ID, &n.BoxID, &at, &n.Text); err != nil {
			return nil, wrap("box notes", err)
		}
		n.At = parseTS(at)
		out = append(out, n)
	}
	return out, wrap("box notes", rows.Err())
}

// BoxNotes returns the newest notes of a box.
func (s *Store) BoxNotes(ctx context.Context, boxID string, limit int) ([]BoxNote, error) {
	return s.notes(ctx, `SELECT id, box_id, at, text FROM box_notes WHERE box_id = ? ORDER BY id DESC LIMIT ?`, boxID, limit)
}

// LatestBoxNotes returns the newest note of every box that has one.
func (s *Store) LatestBoxNotes(ctx context.Context) (map[string]BoxNote, error) {
	ns, err := s.notes(ctx, `SELECT id, box_id, at, text FROM box_notes WHERE id IN (SELECT MAX(id) FROM box_notes GROUP BY box_id)`)
	if err != nil {
		return nil, err
	}
	out := map[string]BoxNote{}
	for _, n := range ns {
		out[n.BoxID] = n
	}
	return out, nil
}

// ---- acknowledgements --------------------------------------------------------------------

// SetAck records an acknowledgement, replacing an older one for the same problem.
func (s *Store) SetAck(ctx context.Context, a Ack) error {
	_, err := s.main.ExecContext(ctx, `INSERT OR REPLACE INTO acks (kind, target_id, since, actor, at, note) VALUES (?, ?, ?, ?, ?, ?)`,
		a.Kind, a.TargetID, ts(a.Since), a.Actor, ts(a.At), a.Note)
	return wrap("set ack", err)
}

// DeleteAck removes an acknowledgement; a missing one is not an error.
func (s *Store) DeleteAck(ctx context.Context, kind, targetID string) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM acks WHERE kind = ? AND target_id = ?`, kind, targetID)
	return wrap("delete ack", err)
}

// Acks returns every acknowledgement, keyed by kind + "/" + target id.
func (s *Store) Acks(ctx context.Context) (map[string]Ack, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT kind, target_id, since, actor, at, note FROM acks`)
	if err != nil {
		return nil, wrap("acks", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]Ack{}
	for rows.Next() {
		var a Ack
		var since, at string
		if err := rows.Scan(&a.Kind, &a.TargetID, &since, &a.Actor, &at, &a.Note); err != nil {
			return nil, wrap("acks", err)
		}
		a.Since, a.At = parseTS(since), parseTS(at)
		out[a.Kind+"/"+a.TargetID] = a
	}
	return out, wrap("acks", rows.Err())
}

// ---- connectors (ADR-0015) ----------------------------------------------------------------

// SetBoxSealKey records the seal key a box reported; unchanged keys cost nothing.
func (s *Store) SetBoxSealKey(ctx context.Context, boxID, key string) error {
	_, err := s.main.ExecContext(ctx, `UPDATE boxes SET seal_key = ? WHERE id = ? AND seal_key != ?`, key, boxID, key)
	return wrap("set box seal key", err)
}

const connCols = `id, tenant_id, site_id, box_id, device_id, kind, url, sealed, sealed_by, sealed_at, interval_s, tls_fingerprint, created_at, disabled,
	last_ok, last_error, last_at, seen_fingerprint, facts, facts_at, metrics`

func scanConnector(sc interface{ Scan(...any) error }) (Connector, error) {
	var c Connector
	var sealedAt, createdAt, facts, metrics string
	var disabled int
	var lastOK sql.NullBool
	var lastAt, factsAt sql.NullString
	err := sc.Scan(&c.ID, &c.TenantID, &c.SiteID, &c.BoxID, &c.DeviceID, &c.Kind, &c.URL, &c.Sealed, &c.SealedBy, &sealedAt, &c.IntervalS, &c.TLSFingerprint, &createdAt, &disabled,
		&lastOK, &c.LastError, &lastAt, &c.SeenFingerprint, &facts, &factsAt, &metrics)
	if err != nil {
		return c, err
	}
	c.SealedAt, c.CreatedAt = parseTS(sealedAt), parseTS(createdAt)
	c.Disabled = disabled != 0
	if lastOK.Valid {
		v := lastOK.Bool
		c.LastOK = &v
	}
	c.LastAt, c.FactsAt = parseTSP(lastAt), parseTSP(factsAt)
	c.Facts = json.RawMessage(facts)
	c.Metrics = map[string]float64{}
	_ = json.Unmarshal([]byte(metrics), &c.Metrics)
	return c, nil
}

// CreateConnector stores a connector with its sealed credential.
func (s *Store) CreateConnector(ctx context.Context, c Connector) error {
	if c.IntervalS <= 0 {
		c.IntervalS = 300
	}
	_, err := s.main.ExecContext(ctx, `INSERT INTO connectors (id, tenant_id, site_id, box_id, device_id, kind, url, sealed, sealed_by, sealed_at, interval_s, tls_fingerprint, created_at, disabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.TenantID, c.SiteID, c.BoxID, c.DeviceID, c.Kind, c.URL, c.Sealed, c.SealedBy, ts(c.SealedAt), c.IntervalS, c.TLSFingerprint, ts(c.CreatedAt), boolInt(c.Disabled))
	return wrap("create connector", err)
}

// Connector returns one connector.
func (s *Store) Connector(ctx context.Context, id string) (Connector, error) {
	c, err := scanConnector(s.main.QueryRowContext(ctx, `SELECT `+connCols+` FROM connectors WHERE id = ?`, id))
	return c, wrap("connector", err)
}

func (s *Store) connectors(ctx context.Context, q string, args ...any) ([]Connector, error) {
	rows, err := s.main.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap("connectors", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Connector
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, wrap("connectors", err)
		}
		out = append(out, c)
	}
	return out, wrap("connectors", rows.Err())
}

// ConnectorsForBox returns the connectors a box has to read, including disabled ones.
func (s *Store) ConnectorsForBox(ctx context.Context, boxID string) ([]Connector, error) {
	return s.connectors(ctx, `SELECT `+connCols+` FROM connectors WHERE box_id = ? ORDER BY created_at, id`, boxID)
}

// ConnectorsForDevice returns the connectors of one device.
func (s *Store) ConnectorsForDevice(ctx context.Context, deviceID string) ([]Connector, error) {
	return s.connectors(ctx, `SELECT `+connCols+` FROM connectors WHERE device_id = ? ORDER BY created_at, id`, deviceID)
}

// Connectors returns every connector of a tenant, or of all tenants when tenantID is empty.
func (s *Store) Connectors(ctx context.Context, tenantID string) ([]Connector, error) {
	if tenantID == "" {
		return s.connectors(ctx, `SELECT `+connCols+` FROM connectors ORDER BY tenant_id, site_id, created_at`)
	}
	return s.connectors(ctx, `SELECT `+connCols+` FROM connectors WHERE tenant_id = ? ORDER BY site_id, created_at`, tenantID)
}

// UpdateConnectorSecret replaces the sealed credential, URL and pin; the box re-reads.
func (s *Store) UpdateConnectorSecret(ctx context.Context, id, url, sealed, by, fingerprint string, intervalS int, at time.Time) error {
	return s.exec1(ctx, "update connector", `UPDATE connectors SET url = ?, sealed = ?, sealed_by = ?, sealed_at = ?, tls_fingerprint = ?, interval_s = ?, last_ok = NULL, last_error = '' WHERE id = ?`,
		url, sealed, by, ts(at), fingerprint, intervalS, id)
}

// SetConnectorDisabled pauses or resumes a connector.
func (s *Store) SetConnectorDisabled(ctx context.Context, id string, disabled bool) error {
	return s.exec1(ctx, "set connector disabled", `UPDATE connectors SET disabled = ? WHERE id = ?`, boolInt(disabled), id)
}

// DeleteConnector removes a connector; its samples in the day databases stay until pruned.
func (s *Store) DeleteConnector(ctx context.Context, id string) error {
	return s.exec1(ctx, "delete connector", `DELETE FROM connectors WHERE id = ?`, id)
}

// UpdateConnectorReading records what a box reported. Facts are kept when the report
// carries none (the box sends them only on change). A report for a connector the
// box does not own is ErrNotFound.
func (s *Store) UpdateConnectorReading(ctx context.Context, boxID string, r wire.ConnectorReport, at time.Time) error {
	metrics, _ := json.Marshal(r.Metrics)
	if r.Metrics == nil {
		metrics = []byte("{}")
	}
	q := `UPDATE connectors SET last_ok = ?, last_error = ?, last_at = ?, metrics = ?`
	args := []any{boolInt(r.OK), r.Error, ts(at), string(metrics)}
	if r.TLSFingerprint != "" {
		q += `, seen_fingerprint = ?`
		args = append(args, r.TLSFingerprint)
	}
	if len(r.Facts) > 0 && json.Valid(r.Facts) {
		q += `, facts = ?, facts_at = ?`
		args = append(args, string(r.Facts), ts(at))
	}
	q += ` WHERE id = ? AND box_id = ?`
	args = append(args, r.ID, boxID)
	return s.exec1(ctx, "update connector reading", q, args...)
}

// ReplaceConnectorSealed swaps in the credential the box made for itself (bootstrap):
// the admin login the operator sealed is gone from the server from now on.
func (s *Store) ReplaceConnectorSealed(ctx context.Context, boxID, id, sealed string, at time.Time) error {
	return s.exec1(ctx, "replace connector sealed", `UPDATE connectors SET sealed = ?, sealed_by = ?, sealed_at = ? WHERE id = ? AND box_id = ?`, sealed, "box:"+boxID, ts(at), id, boxID)
}

// ---- findings ------------------------------------------------------------------------------

const findingCols = `id, tenant_id, site_id, device_id, connector_id, rule, key, severity, title, detail, evidence, first_seen, last_seen, resolved_at`

func scanFinding(sc interface{ Scan(...any) error }) (Finding, error) {
	var f Finding
	var ev, first, last string
	var resolved sql.NullString
	err := sc.Scan(&f.ID, &f.TenantID, &f.SiteID, &f.DeviceID, &f.ConnectorID, &f.Rule, &f.Key, &f.Severity, &f.Title, &f.Detail, &ev, &first, &last, &resolved)
	f.Evidence = json.RawMessage(ev)
	f.FirstSeen, f.LastSeen = parseTS(first), parseTS(last)
	f.ResolvedAt = parseTSP(resolved)
	return f, err
}

func (s *Store) findings(ctx context.Context, q string, args ...any) ([]Finding, error) {
	rows, err := s.main.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap("findings", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, wrap("findings", err)
		}
		out = append(out, f)
	}
	return out, wrap("findings", rows.Err())
}

// SyncFindings makes the open findings of one connector equal to current: known ones
// get a new last_seen (and title/detail/severity), new or previously resolved ones open
// with first_seen = now, and open ones that are not in current are resolved. It
// returns the ids of the findings it resolved, so their acknowledgements can go too.
func (s *Store) SyncFindings(ctx context.Context, connectorID string, current []Finding, now time.Time) ([]string, error) {
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return nil, wrap("sync findings", err)
	}
	defer func() { _ = tx.Rollback() }()
	keys := make([]any, 0, len(current))
	for _, f := range current {
		if len(f.Evidence) == 0 {
			f.Evidence = json.RawMessage("{}")
		}
		keys = append(keys, f.Rule+"/"+f.Key)
		_, err := tx.ExecContext(ctx, `INSERT INTO findings (`+findingCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
			ON CONFLICT (device_id, rule, key) DO UPDATE SET
				connector_id = excluded.connector_id, severity = excluded.severity, title = excluded.title, detail = excluded.detail, evidence = excluded.evidence,
				last_seen = excluded.last_seen,
				first_seen = CASE WHEN findings.resolved_at IS NULL THEN findings.first_seen ELSE excluded.first_seen END,
				resolved_at = NULL`,
			f.ID, f.TenantID, f.SiteID, f.DeviceID, connectorID, f.Rule, f.Key, f.Severity, f.Title, f.Detail, string(f.Evidence), ts(now), ts(now))
		if err != nil {
			return nil, wrap("sync findings", err)
		}
	}
	where := ` WHERE connector_id = ? AND resolved_at IS NULL`
	args := []any{connectorID}
	if len(keys) > 0 {
		where += ` AND (rule || '/' || key) NOT IN (?` + strings.Repeat(", ?", len(keys)-1) + `)` //nolint:gosec // placeholders only; the values are bound
		args = append(args, keys...)
	}
	resolved, err := idsOf(tx.QueryContext(ctx, `SELECT id FROM findings`+where, args...))
	if err != nil {
		return nil, wrap("sync findings", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET resolved_at = ?`+where, append([]any{ts(now)}, args...)...); err != nil {
		return nil, wrap("sync findings", err)
	}
	return resolved, wrap("sync findings", tx.Commit())
}

// ResolveConnectorFindings closes every open finding of a connector (it was deleted or
// paused) and returns their ids.
func (s *Store) ResolveConnectorFindings(ctx context.Context, connectorID string, now time.Time) ([]string, error) {
	ids, err := idsOf(s.main.QueryContext(ctx, `SELECT id FROM findings WHERE connector_id = ? AND resolved_at IS NULL`, connectorID))
	if err != nil {
		return nil, wrap("resolve connector findings", err)
	}
	_, err = s.main.ExecContext(ctx, `UPDATE findings SET resolved_at = ? WHERE connector_id = ? AND resolved_at IS NULL`, ts(now), connectorID)
	return ids, wrap("resolve connector findings", err)
}

func idsOf(rows *sql.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// OpenFindings returns every open finding, worst first, oldest first within a severity.
func (s *Store) OpenFindings(ctx context.Context, tenantID string) ([]Finding, error) {
	order := ` ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, first_seen, id`
	if tenantID == "" {
		return s.findings(ctx, `SELECT `+findingCols+` FROM findings WHERE resolved_at IS NULL`+order)
	}
	return s.findings(ctx, `SELECT `+findingCols+` FROM findings WHERE resolved_at IS NULL AND tenant_id = ?`+order, tenantID)
}

// FindingsForDevice returns the open findings of a device plus those resolved since.
func (s *Store) FindingsForDevice(ctx context.Context, deviceID string, resolvedSince time.Time) ([]Finding, error) {
	return s.findings(ctx, `SELECT `+findingCols+` FROM findings WHERE device_id = ? AND (resolved_at IS NULL OR resolved_at >= ?)
		ORDER BY resolved_at IS NOT NULL, CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, first_seen`, deviceID, ts(resolvedSince))
}

// FindingCounts counts open findings per severity.
func (s *Store) FindingCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT severity, COUNT(*) FROM findings WHERE resolved_at IS NULL GROUP BY severity`)
	if err != nil {
		return nil, wrap("finding counts", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, wrap("finding counts", err)
		}
		out[sev] = n
	}
	return out, wrap("finding counts", rows.Err())
}

// PruneFindings deletes findings resolved before the cutoff.
func (s *Store) PruneFindings(ctx context.Context, before time.Time) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ?`, ts(before))
	return wrap("prune findings", err)
}

// ---- services and scan rounds (ADR-0018) ------------------------------------------------

const serviceCols = `device_id, port, proto, name, product, version, banner, title, tls, first_seen, last_seen, gone_at`

func scanService(sc interface{ Scan(...any) error }) (Service, error) {
	var v Service
	var tlsJSON, first, last string
	var gone sql.NullString
	err := sc.Scan(&v.DeviceID, &v.Port, &v.Proto, &v.Name, &v.Product, &v.Version, &v.Banner, &v.Title, &tlsJSON, &first, &last, &gone)
	if tlsJSON != "" {
		v.TLS = json.RawMessage(tlsJSON)
	}
	v.FirstSeen, v.LastSeen, v.GoneAt = parseTS(first), parseTS(last), parseTSP(gone)
	return v, err
}

// DeviceByAddress finds a site's device by MAC, else by IPv4 address.
func (s *Store) DeviceByAddress(ctx context.Context, siteID, mac, ip string) (Device, error) {
	if mac != "" {
		d, err := scanDevice(s.main.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE site_id = ? AND mac = ?`, siteID, strings.ToLower(mac)))
		if err == nil {
			return d, nil
		}
	}
	if ip == "" {
		return Device{}, ErrNotFound
	}
	d, err := scanDevice(s.main.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE site_id = ? AND ip = ? ORDER BY last_seen DESC LIMIT 1`, siteID, ip))
	return d, wrap("device by address", err)
}

// UpsertServices records what one round saw on a device: listed services are
// current (first_seen kept, or reset when they had gone), everything else the
// device had is marked gone. It returns what appeared and what disappeared.
func (s *Store) UpsertServices(ctx context.Context, deviceID string, svcs []Service, now time.Time) (added, gone []Service, err error) {
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, wrap("upsert services", err)
	}
	defer func() { _ = tx.Rollback() }()
	before := map[string]Service{}
	rows, err := tx.QueryContext(ctx, `SELECT `+serviceCols+` FROM services WHERE device_id = ?`, deviceID)
	if err != nil {
		return nil, nil, wrap("upsert services", err)
	}
	for rows.Next() {
		v, err := scanService(rows)
		if err != nil {
			_ = rows.Close()
			return nil, nil, wrap("upsert services", err)
		}
		before[v.Proto+"/"+strconv.Itoa(v.Port)] = v
	}
	_ = rows.Close()
	seen := map[string]bool{}
	for _, v := range svcs {
		if v.Proto == "" {
			v.Proto = "tcp"
		}
		key := v.Proto + "/" + strconv.Itoa(v.Port)
		seen[key] = true
		tlsJSON := ""
		if len(v.TLS) > 0 {
			tlsJSON = string(v.TLS)
		}
		old, had := before[key]
		if !had || old.GoneAt != nil {
			added = append(added, v)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO services (`+serviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
			ON CONFLICT (device_id, port, proto) DO UPDATE SET
				name = excluded.name, product = excluded.product, version = excluded.version, banner = excluded.banner, title = excluded.title, tls = excluded.tls,
				last_seen = excluded.last_seen,
				first_seen = CASE WHEN services.gone_at IS NULL THEN services.first_seen ELSE excluded.first_seen END,
				gone_at = NULL`,
			deviceID, v.Port, v.Proto, v.Name, v.Product, v.Version, v.Banner, v.Title, tlsJSON, ts(now), ts(now))
		if err != nil {
			return nil, nil, wrap("upsert services", err)
		}
	}
	for key, old := range before {
		if !seen[key] && old.GoneAt == nil {
			gone = append(gone, old)
			if _, err := tx.ExecContext(ctx, `UPDATE services SET gone_at = ? WHERE device_id = ? AND port = ? AND proto = ?`, ts(now), deviceID, old.Port, old.Proto); err != nil {
				return nil, nil, wrap("upsert services", err)
			}
		}
	}
	return added, gone, wrap("upsert services", tx.Commit())
}

// ServicesForDevice lists a device's services, open first, by port; gone ones follow.
func (s *Store) ServicesForDevice(ctx context.Context, deviceID string) ([]Service, error) {
	return s.services(ctx, `SELECT `+serviceCols+` FROM services WHERE device_id = ? ORDER BY gone_at IS NOT NULL, port`, deviceID)
}

// OpenServicesForSite lists every open service of a site's devices.
func (s *Store) OpenServicesForSite(ctx context.Context, siteID string) ([]Service, error) {
	return s.services(ctx, `SELECT `+serviceCols+` FROM services WHERE gone_at IS NULL AND device_id IN (SELECT id FROM devices WHERE site_id = ?) ORDER BY device_id, port`, siteID)
}

func (s *Store) services(ctx context.Context, q string, args ...any) ([]Service, error) {
	rows, err := s.main.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, wrap("services", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Service
	for rows.Next() {
		v, err := scanService(rows)
		if err != nil {
			return nil, wrap("services", err)
		}
		out = append(out, v)
	}
	return out, wrap("services", rows.Err())
}

// SetScanRound inserts or updates a round.
func (s *Store) SetScanRound(ctx context.Context, r ScanRound) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO scan_rounds (id, box_id, site_id, started_at, finished_at, hosts, services, errors, external) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET finished_at = excluded.finished_at, hosts = excluded.hosts, services = excluded.services, errors = excluded.errors`,
		r.ID, r.BoxID, r.SiteID, ts(r.StartedAt), tsp(r.FinishedAt), r.Hosts, r.Services, r.Errors, boolInt(r.External))
	return wrap("set scan round", err)
}

// ScanRound returns one round.
func (s *Store) ScanRound(ctx context.Context, id string) (ScanRound, error) {
	var r ScanRound
	var started string
	var finished sql.NullString
	var external int
	err := s.main.QueryRowContext(ctx, `SELECT id, box_id, site_id, started_at, finished_at, hosts, services, errors, external FROM scan_rounds WHERE id = ?`, id).
		Scan(&r.ID, &r.BoxID, &r.SiteID, &started, &finished, &r.Hosts, &r.Services, &r.Errors, &external)
	r.External = external != 0
	r.StartedAt, r.FinishedAt = parseTS(started), parseTSP(finished)
	return r, wrap("scan round", err)
}

// ScanRounds lists a site's rounds, newest first.
func (s *Store) ScanRounds(ctx context.Context, siteID string, limit int) ([]ScanRound, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.main.QueryContext(ctx, `SELECT id, box_id, site_id, started_at, finished_at, hosts, services, errors, external FROM scan_rounds WHERE site_id = ? ORDER BY started_at DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, wrap("scan rounds", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ScanRound
	for rows.Next() {
		var r ScanRound
		var started string
		var finished sql.NullString
		var external int
		if err := rows.Scan(&r.ID, &r.BoxID, &r.SiteID, &started, &finished, &r.Hosts, &r.Services, &r.Errors, &external); err != nil {
			return nil, wrap("scan rounds", err)
		}
		r.StartedAt, r.FinishedAt, r.External = parseTS(started), parseTSP(finished), external != 0
		out = append(out, r)
	}
	return out, wrap("scan rounds", rows.Err())
}

// SetSiteScan switches the service scan of a site on or off.
func (s *Store) SetSiteScan(ctx context.Context, siteID string, enabled bool) error {
	return s.exec1(ctx, "set site scan", `UPDATE sites SET scan_enabled = ? WHERE id = ?`, boolInt(enabled), siteID)
}

// SetSiteCanary switches a site's decoy ports and live signals (ADR-0018 §7).
func (s *Store) SetSiteCanary(ctx context.Context, siteID string, enabled bool) error {
	return s.exec1(ctx, "set site canary", `UPDATE sites SET canary_enabled = ? WHERE id = ?`, boolInt(enabled), siteID)
}

// OpenFinding returns the open finding of a device under rule and key, or ErrNotFound.
func (s *Store) OpenFinding(ctx context.Context, deviceID, rule, key string) (Finding, error) {
	f, err := scanFinding(s.main.QueryRowContext(ctx, `SELECT `+findingCols+` FROM findings WHERE device_id = ? AND rule = ? AND key = ? AND resolved_at IS NULL`, deviceID, rule, key))
	return f, wrap("open finding", err)
}

// UpsertFinding opens a finding or refreshes the one that is open under the same
// device, rule and key: for sources that report incidents one by one instead of
// a complete list (the live signals), where SyncDeviceFindings would resolve the
// rest. A resolved finding of the same key is reopened with a fresh first_seen.
func (s *Store) UpsertFinding(ctx context.Context, f Finding, now time.Time) error {
	if len(f.Evidence) == 0 {
		f.Evidence = json.RawMessage("{}")
	}
	_, err := s.main.ExecContext(ctx, `INSERT INTO findings (`+findingCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		ON CONFLICT (device_id, rule, key) DO UPDATE SET
			connector_id = excluded.connector_id, severity = excluded.severity, title = excluded.title, detail = excluded.detail, evidence = excluded.evidence,
			last_seen = excluded.last_seen,
			first_seen = CASE WHEN findings.resolved_at IS NULL THEN findings.first_seen ELSE excluded.first_seen END,
			resolved_at = NULL`,
		f.ID, f.TenantID, f.SiteID, f.DeviceID, f.ConnectorID, f.Rule, f.Key, f.Severity, f.Title, f.Detail, string(f.Evidence), ts(now), ts(now))
	return wrap("upsert finding", err)
}

// ResolveQuietFindings resolves the open findings of a source that have not been
// seen since the given time and returns their ids. Incidents end when they stop.
func (s *Store) ResolveQuietFindings(ctx context.Context, source string, quietSince, now time.Time) ([]string, error) {
	ids, err := idsOf(s.main.QueryContext(ctx, `SELECT id FROM findings WHERE connector_id = ? AND resolved_at IS NULL AND last_seen < ?`, source, ts(quietSince)))
	if err != nil || len(ids) == 0 {
		return nil, wrap("resolve quiet findings", err)
	}
	_, err = s.main.ExecContext(ctx, `UPDATE findings SET resolved_at = ? WHERE connector_id = ? AND resolved_at IS NULL AND last_seen < ?`, ts(now), source, ts(quietSince))
	return ids, wrap("resolve quiet findings", err)
}

// SyncDeviceFindings is SyncFindings for findings that come from a source other
// than a connector (the scan): scoped to one device and that source, so syncing
// one device never resolves another's.
func (s *Store) SyncDeviceFindings(ctx context.Context, deviceID, source string, current []Finding, now time.Time) ([]string, error) {
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return nil, wrap("sync device findings", err)
	}
	defer func() { _ = tx.Rollback() }()
	keys := make([]any, 0, len(current))
	for _, f := range current {
		if len(f.Evidence) == 0 {
			f.Evidence = json.RawMessage("{}")
		}
		keys = append(keys, f.Rule+"/"+f.Key)
		_, err := tx.ExecContext(ctx, `INSERT INTO findings (`+findingCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
			ON CONFLICT (device_id, rule, key) DO UPDATE SET
				connector_id = excluded.connector_id, severity = excluded.severity, title = excluded.title, detail = excluded.detail, evidence = excluded.evidence,
				last_seen = excluded.last_seen,
				first_seen = CASE WHEN findings.resolved_at IS NULL THEN findings.first_seen ELSE excluded.first_seen END,
				resolved_at = NULL`,
			f.ID, f.TenantID, f.SiteID, deviceID, source, f.Rule, f.Key, f.Severity, f.Title, f.Detail, string(f.Evidence), ts(now), ts(now))
		if err != nil {
			return nil, wrap("sync device findings", err)
		}
	}
	where := ` WHERE device_id = ? AND connector_id = ? AND resolved_at IS NULL`
	args := []any{deviceID, source}
	if len(keys) > 0 {
		where += ` AND (rule || '/' || key) NOT IN (?` + strings.Repeat(", ?", len(keys)-1) + `)` //nolint:gosec // placeholders only; the values are bound
		args = append(args, keys...)
	}
	resolved, err := idsOf(tx.QueryContext(ctx, `SELECT id FROM findings`+where, args...))
	if err != nil {
		return nil, wrap("sync device findings", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET resolved_at = ?`+where, append([]any{ts(now)}, args...)...); err != nil {
		return nil, wrap("sync device findings", err)
	}
	return resolved, wrap("sync device findings", tx.Commit())
}

// ---- the outside view (ADR-0018) ---------------------------------------------------------

// SetBoxPublicIP records where the box's heartbeats come from.
func (s *Store) SetBoxPublicIP(ctx context.Context, boxID, ip string) error {
	return s.exec1(ctx, "set box public ip", `UPDATE boxes SET public_ip = ? WHERE id = ?`, ip, boxID)
}

// SetBoxRole makes a box an outpost, or a box again.
func (s *Store) SetBoxRole(ctx context.Context, boxID, role string) error {
	if role != RoleBox && role != RoleOutpost {
		return errors.New("store: role must be box or outpost")
	}
	return s.exec1(ctx, "set box role", `UPDATE boxes SET role = ? WHERE id = ?`, role, boxID)
}

// ScanTargets lists the public addresses the outposts scan: every site with the
// scan switched on whose box reported one.
func (s *Store) ScanTargets(ctx context.Context) ([]ScanTarget, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT DISTINCT s.id, s.tenant_id, b.public_ip FROM sites s JOIN boxes b ON b.site_id = s.id
		WHERE s.scan_enabled = 1 AND b.revoked_at IS NULL AND b.public_ip <> '' AND b.role = ? ORDER BY s.id, b.public_ip`, RoleBox)
	if err != nil {
		return nil, wrap("scan targets", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ScanTarget
	for rows.Next() {
		var t ScanTarget
		if err := rows.Scan(&t.SiteID, &t.TenantID, &t.IP); err != nil {
			return nil, wrap("scan targets", err)
		}
		out = append(out, t)
	}
	return out, wrap("scan targets", rows.Err())
}

// ExternalDevice returns the device that stands for a site's public address.
func (s *Store) ExternalDevice(ctx context.Context, siteID string) (Device, error) {
	d, err := scanDevice(s.main.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE site_id = ? AND external = 1`, siteID))
	return d, wrap("external device", err)
}

// EnsureExternalDevice returns that device, creating it or moving it to the
// current address.
func (s *Store) EnsureExternalDevice(ctx context.Context, tenantID, siteID, ip string, now time.Time) (Device, error) {
	d, err := s.ExternalDevice(ctx, siteID)
	switch {
	case errors.Is(err, ErrNotFound):
		d = Device{ID: id.New("dev"), TenantID: tenantID, SiteID: siteID, IP: ip, Hostname: "", FirstSeen: now, LastSeen: now, External: true}
		_, err := s.main.ExecContext(ctx, `INSERT INTO devices (`+deviceCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 1)`,
			d.ID, d.TenantID, d.SiteID, "", d.IP, "", "", ts(now), ts(now))
		return d, wrap("external device", err)
	case err != nil:
		return Device{}, err
	}
	_, err = s.main.ExecContext(ctx, `UPDATE devices SET ip = ?, last_seen = ?, gone_at = NULL WHERE id = ?`, ip, ts(now), d.ID)
	d.IP, d.LastSeen, d.GoneAt = ip, now, nil
	return d, wrap("external device", err)
}

// ---- feeds (ADR-0018, version rules) ------------------------------------------------------

// Feed is one product's cached end-of-life data.
type Feed struct {
	Slug      string
	FetchedAt time.Time
	Body      []byte
}

// Vuln is a cached vulnerability lookup (ADR-0018 §8).
type Vuln struct {
	Key       string
	FetchedAt time.Time
	Body      []byte
}

// SetVuln stores a lookup's result.
func (s *Store) SetVuln(ctx context.Context, key string, body []byte, at time.Time) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO vulns (key, fetched_at, body) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE SET fetched_at = excluded.fetched_at, body = excluded.body`, key, ts(at), string(body))
	return wrap("set vuln", err)
}

// Vulns returns every cached lookup.
func (s *Store) Vulns(ctx context.Context) ([]Vuln, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT key, fetched_at, body FROM vulns ORDER BY key`)
	if err != nil {
		return nil, wrap("vulns", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Vuln
	for rows.Next() {
		var v Vuln
		var at, body string
		if err := rows.Scan(&v.Key, &at, &body); err != nil {
			return nil, wrap("vulns", err)
		}
		v.FetchedAt, v.Body = parseTS(at), []byte(body)
		out = append(out, v)
	}
	return out, wrap("vulns", rows.Err())
}

// SetFeed stores a product's data.
func (s *Store) SetFeed(ctx context.Context, slug string, body []byte, at time.Time) error {
	_, err := s.main.ExecContext(ctx, `INSERT INTO feeds (slug, fetched_at, body) VALUES (?, ?, ?) ON CONFLICT (slug) DO UPDATE SET fetched_at = excluded.fetched_at, body = excluded.body`, slug, ts(at), string(body))
	return wrap("set feed", err)
}

// Feeds returns every cached product.
func (s *Store) Feeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.main.QueryContext(ctx, `SELECT slug, fetched_at, body FROM feeds ORDER BY slug`)
	if err != nil {
		return nil, wrap("feeds", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Feed
	for rows.Next() {
		var f Feed
		var at, body string
		if err := rows.Scan(&f.Slug, &at, &body); err != nil {
			return nil, wrap("feeds", err)
		}
		f.FetchedAt, f.Body = parseTS(at), []byte(body)
		out = append(out, f)
	}
	return out, wrap("feeds", rows.Err())
}

// OpenServices lists every open service of every device, for a fresh look at
// versions when the feed changed.
func (s *Store) OpenServices(ctx context.Context) ([]Service, error) {
	return s.services(ctx, `SELECT `+serviceCols+` FROM services WHERE gone_at IS NULL ORDER BY device_id, port`)
}

// ---- AI (ADR-0019) ------------------------------------------------------------------------

// SetTenantAI sets what the AI may see for a tenant.
func (s *Store) SetTenantAI(ctx context.Context, tenantID, scope string) error {
	if scope != AIScopeOff && scope != AIScopeFacts {
		return errors.New("store: ai scope must be off or facts")
	}
	return s.exec1(ctx, "set tenant ai", `UPDATE tenants SET ai_scope = ? WHERE id = ?`, scope, tenantID)
}

// SetAIBrief stores an assessment.
func (s *Store) SetAIBrief(ctx context.Context, b AIBrief) error {
	if len(b.Body) == 0 {
		b.Body = json.RawMessage("{}")
	}
	_, err := s.main.ExecContext(ctx, `INSERT INTO ai_briefs (id, site_id, tenant_id, at, provider, model, risk, summary, body, prompt_bytes, response_bytes, duration_ms, requested_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.SiteID, b.TenantID, ts(b.At), b.Provider, b.Model, b.Risk, b.Summary, string(b.Body), b.PromptBytes, b.ResponseBytes, b.DurationMS, b.RequestedBy)
	return wrap("set ai brief", err)
}

const aiBriefCols = `id, site_id, tenant_id, at, provider, model, risk, summary, body, prompt_bytes, response_bytes, duration_ms, requested_by`

func scanAIBrief(sc interface{ Scan(...any) error }) (AIBrief, error) {
	var b AIBrief
	var at, body string
	err := sc.Scan(&b.ID, &b.SiteID, &b.TenantID, &at, &b.Provider, &b.Model, &b.Risk, &b.Summary, &body, &b.PromptBytes, &b.ResponseBytes, &b.DurationMS, &b.RequestedBy)
	b.At, b.Body = parseTS(at), json.RawMessage(body)
	return b, err
}

// AIBriefs lists a site's assessments, newest first.
func (s *Store) AIBriefs(ctx context.Context, siteID string, limit int) ([]AIBrief, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.main.QueryContext(ctx, `SELECT `+aiBriefCols+` FROM ai_briefs WHERE site_id = ? ORDER BY at DESC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, wrap("ai briefs", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AIBrief
	for rows.Next() {
		b, err := scanAIBrief(rows)
		if err != nil {
			return nil, wrap("ai briefs", err)
		}
		out = append(out, b)
	}
	return out, wrap("ai briefs", rows.Err())
}

// PruneAIBriefs keeps the newest n briefs per site.
func (s *Store) PruneAIBriefs(ctx context.Context, siteID string, keep int) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM ai_briefs WHERE site_id = ? AND id NOT IN (SELECT id FROM ai_briefs WHERE site_id = ? ORDER BY at DESC LIMIT ?)`, siteID, siteID, keep)
	return wrap("prune ai briefs", err)
}
