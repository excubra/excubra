package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/id"
)

// Sources (ADR-0023): an application that reports itself. It is a device of its
// own on a site, without a MAC, under its name, and a token bound to that device
// that can do one thing: post the source's events. The events land in the
// tenant's day file of their occurrence, table logs.

// SourceVendor is what a source's device shows where a device shows its maker.
const SourceVendor = "Anwendung"

// Source is a registered application: its device and its token.
type Source struct {
	Device Device
	Token  APIToken
}

// LogEntry is one event a source reported.
type LogEntry struct {
	DeviceID   string
	EventID    string
	OccurredAt time.Time
	ReceivedAt time.Time
	Source     string
	Kind       string
	Actor      string
	IP         string
	Target     string
	Summary    string
}

// ErrSourceExists says the site already has a device at that address.
var ErrSourceExists = errors.New("store: an diesem Standort gibt es schon ein Gerät mit dieser Adresse")

// ErrSourceInvalid says a source needs a short name and an IP address.
var ErrSourceInvalid = errors.New("store: eine Quelle braucht einen Namen (bis 64 Zeichen) und eine IP-Adresse")

// CreateSource registers an application on a site: its device and its token, in
// one transaction. The token's hash comes from the caller, which shows the value
// once and keeps nothing.
func (s *Store) CreateSource(ctx context.Context, site Site, name, address, tokenName, tokenHash string, now time.Time) (Source, error) {
	name = strings.TrimSpace(name)
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if name == "" || len(name) > 64 || err != nil {
		return Source{}, ErrSourceInvalid
	}
	address = addr.Unmap().String()
	d := Device{ID: id.New("dev"), TenantID: site.TenantID, SiteID: site.ID, IP: address, Vendor: SourceVendor,
		Hostname: name, FirstSeen: now, LastSeen: now}
	t := APIToken{ID: id.New("tok"), Name: tokenName, TokenHash: tokenHash, Tenants: []string{site.TenantID},
		CreatedAt: now, DeviceID: d.ID}
	tenants, _ := json.Marshal(t.Tenants)
	tx, err := s.main.BeginTx(ctx, nil)
	if err != nil {
		return Source{}, wrap("create source", err)
	}
	defer tx.Rollback() //nolint:errcheck
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE site_id = ? AND mac = '' AND ip = ?`,
		site.ID, address).Scan(&n); err != nil {
		return Source{}, wrap("create source", err)
	}
	if n > 0 {
		return Source{}, ErrSourceExists
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO devices (`+deviceCols+`) VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, NULL, 0, 0)`,
		d.ID, d.TenantID, d.SiteID, d.IP, d.Vendor, d.Hostname, ts(now), ts(now)); err != nil {
		return Source{}, wrap("create source", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO api_tokens (id, name, token_hash, tenants, created_at, device_id) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.TokenHash, string(tenants), ts(now), t.DeviceID); err != nil {
		return Source{}, wrap("create source", err)
	}
	if err := tx.Commit(); err != nil {
		return Source{}, wrap("create source", err)
	}
	return Source{Device: d, Token: t}, nil
}

// Sources lists the registered sources whose token is not revoked.
func (s *Store) Sources(ctx context.Context) ([]Source, error) {
	tokens, err := s.APITokens(ctx)
	if err != nil {
		return nil, err
	}
	var out []Source
	for _, t := range tokens {
		if t.DeviceID == "" || t.RevokedAt != nil {
			continue
		}
		d, err := s.Device(ctx, t.DeviceID)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Source{Device: d, Token: t})
	}
	return out, nil
}

// TouchDevice records that a device made contact: a source's post is its
// heartbeat.
func (s *Store) TouchDevice(ctx context.Context, deviceID string, now time.Time) error {
	return s.exec1(ctx, "touch device", `UPDATE devices SET last_seen = ?, gone_at = NULL WHERE id = ?`, ts(now), deviceID)
}

// AddLogs stores what a source reported, each entry in the day file of its
// occurrence. A repeated event id is dropped there — delivery is at-least-once,
// and a retry keeps its occurred_at. It returns the entries newly stored.
func (s *Store) AddLogs(ctx context.Context, tenantID string, entries []LogEntry) ([]LogEntry, error) {
	byDay := map[string][]LogEntry{}
	for _, e := range entries {
		byDay[DayOf(e.OccurredAt)] = append(byDay[DayOf(e.OccurredAt)], e)
	}
	days := make([]string, 0, len(byDay))
	for d := range byDay {
		days = append(days, d)
	}
	sort.Strings(days)
	var fresh []LogEntry
	for _, day := range days {
		db, err := s.day(tenantID, day)
		if err != nil {
			return fresh, err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fresh, wrap("add logs", err)
		}
		var added []LogEntry
		for _, e := range byDay[day] {
			res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO logs (device_id, event_id, occurred_at, received_at, source, kind, actor, ip, target, summary)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				e.DeviceID, e.EventID, ts(e.OccurredAt), ts(e.ReceivedAt), e.Source, e.Kind, e.Actor, e.IP, e.Target, e.Summary)
			if err != nil {
				_ = tx.Rollback()
				return fresh, wrap("add logs", err)
			}
			if n, _ := res.RowsAffected(); n == 1 {
				added = append(added, e)
			}
		}
		if err := tx.Commit(); err != nil {
			return fresh, wrap("add logs", err)
		}
		fresh = append(fresh, added...)
	}
	return fresh, nil
}

// Logs lists a device's entries that occurred in [from, to], newest first, at
// most limit. kind, when set, keeps the entries of that kind and its sub-kinds
// ("auth" keeps "auth.login"). Reads never create a day file.
func (s *Store) Logs(ctx context.Context, tenantID, deviceID string, from, to time.Time, kind string, limit int) ([]LogEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	var out []LogEntry
	for day := to.UTC(); !day.Before(from.UTC().Truncate(24 * time.Hour)); day = day.AddDate(0, 0, -1) {
		db, err := s.dayIfExists(tenantID, DayOf(day))
		if err != nil {
			return nil, err
		}
		if db == nil {
			continue
		}
		q := `SELECT device_id, event_id, occurred_at, received_at, source, kind, actor, ip, target, summary FROM logs
			WHERE device_id = ? AND occurred_at >= ? AND occurred_at <= ?`
		args := []any{deviceID, ts(from), ts(to)}
		if kind != "" {
			q += ` AND (kind = ? OR kind LIKE ? ESCAPE '\')`
			args = append(args, kind, strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(kind)+".%")
		}
		q += ` ORDER BY occurred_at DESC LIMIT ?`
		args = append(args, limit-len(out))
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, wrap("logs", err)
		}
		for rows.Next() {
			var e LogEntry
			var occurred, received string
			if err := rows.Scan(&e.DeviceID, &e.EventID, &occurred, &received, &e.Source, &e.Kind, &e.Actor, &e.IP, &e.Target, &e.Summary); err != nil {
				_ = rows.Close()
				return nil, wrap("logs", err)
			}
			e.OccurredAt, e.ReceivedAt = parseTS(occurred), parseTS(received)
			out = append(out, e)
		}
		if err := rows.Close(); err != nil {
			return nil, wrap("logs", err)
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// SourceTokenName is how a source's token is listed beside the operator tokens.
func SourceTokenName(name string) string { return "Quelle " + name }
