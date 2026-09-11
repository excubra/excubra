package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/id"
)

// InsertEvent stores an event in its tenant's day file together with one pending
// delivery per target, in one transaction. body is the serialised webhook body
// (ADR-0012: retries resend exactly these bytes).
func (s *Store) InsertEvent(ctx context.Context, ev event.Event, body []byte, targetIDs []string, now time.Time) error {
	if ev.TenantID == "" {
		return errors.New("store: event without tenant")
	}
	db, err := s.day(ev.TenantID, DayOf(ev.OccurredAt))
	if err != nil {
		return err
	}
	stored, err := json.Marshal(ev)
	if err != nil {
		return wrap("insert event", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return wrap("insert event", err)
	}
	defer tx.Rollback() //nolint:errcheck
	var since string
	if ev.Since != nil {
		since = ts(*ev.Since)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO events (event_id, type, severity, occurred_at, received_at, since, tenant_id, site_id, box_id, host_id, device_id, source, body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, string(ev.Type), string(ev.Severity), ts(ev.OccurredAt), ts(ev.ReceivedAt), since, ev.TenantID, ev.SiteID, ev.BoxID, ev.HostID, ev.DeviceID, ev.Source, string(stored)); err != nil {
		return wrap("insert event", err)
	}
	for _, tid := range targetIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO deliveries (event_id, target_id, state, attempts, next_attempt_at, body, created_at) VALUES (?, ?, ?, 0, ?, ?, ?)`,
			ev.ID, tid, DeliveryPending, ts(now), string(body), ts(now)); err != nil {
			return wrap("insert delivery", err)
		}
	}
	return wrap("insert event", tx.Commit())
}

// Event returns one event; the day file is derived from the id's timestamp.
func (s *Store) Event(ctx context.Context, tenantID, eventID string) (event.Event, error) {
	t, ok := id.TimeOf(eventID)
	if !ok {
		return event.Event{}, ErrNotFound
	}
	db, err := s.dayIfExists(tenantID, DayOf(t))
	if err != nil || db == nil {
		if err == nil {
			err = ErrNotFound
		}
		return event.Event{}, err
	}
	var body string
	if err := db.QueryRowContext(ctx, `SELECT body FROM events WHERE event_id = ?`, eventID).Scan(&body); err != nil {
		return event.Event{}, wrap("event", err)
	}
	var ev event.Event
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		return event.Event{}, wrap("event", err)
	}
	return ev, nil
}

// Events returns a tenant's events with since <= occurred_at < until (zero until =
// now+1h), oldest first, at most limit. hostID filters to one host when set.
func (s *Store) Events(ctx context.Context, tenantID string, since, until time.Time, hostID string, limit int) ([]event.Event, error) {
	if until.IsZero() {
		until = time.Now().Add(time.Hour)
	}
	if limit <= 0 {
		limit = 500
	}
	days, err := s.Days(tenantID)
	if err != nil {
		return nil, err
	}
	from, to := DayOf(since), DayOf(until)
	var out []event.Event
	for _, d := range days {
		if d < from || d > to || len(out) >= limit {
			continue
		}
		db, err := s.day(tenantID, d)
		if err != nil {
			return nil, err
		}
		q := `SELECT body FROM events WHERE occurred_at >= ? AND occurred_at < ?`
		args := []any{ts(since), ts(until)}
		if hostID != "" {
			q += ` AND host_id = ?`
			args = append(args, hostID)
		}
		args = append(args, limit-len(out))
		rows, err := db.QueryContext(ctx, q+` ORDER BY occurred_at, event_id LIMIT ?`, args...)
		if err != nil {
			return nil, wrap("events", err)
		}
		for rows.Next() {
			var body string
			if err := rows.Scan(&body); err != nil {
				_ = rows.Close()
				return nil, wrap("events", err)
			}
			var ev event.Event
			if err := json.Unmarshal([]byte(body), &ev); err != nil {
				_ = rows.Close()
				return nil, wrap("events", err)
			}
			out = append(out, ev)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return nil, wrap("events", err)
		}
	}
	return out, nil
}

// ---- deliveries ------------------------------------------------------------------------

const deliveryCols = `event_id, target_id, state, attempts, next_attempt_at, last_status, last_error, body, created_at, delivered_at`

func scanDelivery(sc interface{ Scan(...any) error }, tenantID, day string) (Delivery, error) {
	d := Delivery{TenantID: tenantID, Day: day}
	var next, created, delivered string
	err := sc.Scan(&d.EventID, &d.TargetID, &d.State, &d.Attempts, &next, &d.LastStatus, &d.LastError, &d.Body, &created, &delivered)
	d.NextAttemptAt, d.CreatedAt, d.DeliveredAt = parseTS(next), parseTS(created), parseTS(delivered)
	return d, err
}

// DueDeliveries returns pending deliveries whose next attempt is due, across all
// tenants, looking at today's and yesterday's files (the retry window is 24 h).
func (s *Store) DueDeliveries(ctx context.Context, now time.Time, limit int) ([]Delivery, error) {
	tenants, err := os.ReadDir(filepath.Join(s.dir, "tenants"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, wrap("due deliveries", err)
	}
	days := []string{DayOf(now.Add(-24 * time.Hour)), DayOf(now)}
	var out []Delivery
	for _, t := range tenants {
		if !t.IsDir() || !validID(t.Name()) {
			continue
		}
		for _, d := range days {
			if len(out) >= limit {
				return out, nil
			}
			db, err := s.dayIfExists(t.Name(), d)
			if err != nil {
				return nil, err
			}
			if db == nil {
				continue
			}
			rows, err := db.QueryContext(ctx, `SELECT `+deliveryCols+` FROM deliveries WHERE state = ? AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?`,
				DeliveryPending, ts(now), limit-len(out))
			if err != nil {
				return nil, wrap("due deliveries", err)
			}
			for rows.Next() {
				dl, err := scanDelivery(rows, t.Name(), d)
				if err != nil {
					_ = rows.Close()
					return nil, wrap("due deliveries", err)
				}
				out = append(out, dl)
			}
			_ = rows.Close()
			if err := rows.Err(); err != nil {
				return nil, wrap("due deliveries", err)
			}
		}
	}
	return out, nil
}

// UpdateDelivery persists the outcome of an attempt.
func (s *Store) UpdateDelivery(ctx context.Context, d Delivery) error {
	db, err := s.day(d.TenantID, d.Day)
	if err != nil {
		return err
	}
	res, err := db.ExecContext(ctx, `UPDATE deliveries SET state = ?, attempts = ?, next_attempt_at = ?, last_status = ?, last_error = ?, delivered_at = ? WHERE event_id = ? AND target_id = ?`,
		d.State, d.Attempts, ts(d.NextAttemptAt), d.LastStatus, d.LastError, ts(d.DeliveredAt), d.EventID, d.TargetID)
	if err != nil {
		return wrap("update delivery", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Deliveries returns the deliveries of one event.
func (s *Store) Deliveries(ctx context.Context, tenantID, eventID string) ([]Delivery, error) {
	t, ok := id.TimeOf(eventID)
	if !ok {
		return nil, ErrNotFound
	}
	day := DayOf(t)
	db, err := s.dayIfExists(tenantID, day)
	if err != nil || db == nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT `+deliveryCols+` FROM deliveries WHERE event_id = ? ORDER BY target_id`, eventID)
	if err != nil {
		return nil, wrap("deliveries", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Delivery
	for rows.Next() {
		d, err := scanDelivery(rows, tenantID, day)
		if err != nil {
			return nil, wrap("deliveries", err)
		}
		out = append(out, d)
	}
	return out, wrap("deliveries", rows.Err())
}

// DeliveriesByState lists a tenant's deliveries in a state over the last n days,
// newest first — the console's "failed deliveries" view.
func (s *Store) DeliveriesByState(ctx context.Context, tenantID, st string, days int, now time.Time) ([]Delivery, error) {
	all, err := s.Days(tenantID)
	if err != nil {
		return nil, err
	}
	from := DayOf(now.Add(-time.Duration(days) * 24 * time.Hour))
	var out []Delivery
	for i := len(all) - 1; i >= 0; i-- {
		d := all[i]
		if d < from {
			break
		}
		db, err := s.day(tenantID, d)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(ctx, `SELECT `+deliveryCols+` FROM deliveries WHERE state = ? ORDER BY created_at DESC`, st)
		if err != nil {
			return nil, wrap("deliveries by state", err)
		}
		for rows.Next() {
			dl, err := scanDelivery(rows, tenantID, d)
			if err != nil {
				_ = rows.Close()
				return nil, wrap("deliveries by state", err)
			}
			out = append(out, dl)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return nil, wrap("deliveries by state", err)
		}
	}
	return out, nil
}

// ---- check rollups ---------------------------------------------------------------------

// AddRollup folds one check result into the hour bucket of its host.
func (s *Store) AddRollup(ctx context.Context, tenantID, hostID string, at time.Time, checkType string, ok bool, latencyMS *int64) error {
	db, err := s.day(tenantID, DayOf(at))
	if err != nil {
		return err
	}
	hour := at.UTC().Truncate(time.Hour)
	failed := 0
	if !ok {
		failed = 1
	}
	var lat int64
	if latencyMS != nil {
		lat = *latencyMS
	}
	_, err = db.ExecContext(ctx, `INSERT INTO check_rollups (host_id, hour, check_type, rounds, failed, latency_sum_ms, latency_max_ms) VALUES (?, ?, ?, 1, ?, ?, ?)
		ON CONFLICT (host_id, hour, check_type) DO UPDATE SET rounds = rounds + 1, failed = failed + excluded.failed,
		latency_sum_ms = latency_sum_ms + excluded.latency_sum_ms, latency_max_ms = max(latency_max_ms, excluded.latency_max_ms)`,
		hostID, ts(hour), checkType, failed, lat, lat)
	return wrap("add rollup", err)
}

// Rollups returns the hour buckets of a host (or of every host when hostID is empty)
// between from and to, oldest first.
func (s *Store) Rollups(ctx context.Context, tenantID, hostID string, from, to time.Time) ([]Rollup, error) {
	days, err := s.Days(tenantID)
	if err != nil {
		return nil, err
	}
	dFrom, dTo := DayOf(from), DayOf(to)
	var out []Rollup
	for _, d := range days {
		if d < dFrom || d > dTo {
			continue
		}
		db, err := s.day(tenantID, d)
		if err != nil {
			return nil, err
		}
		q := `SELECT host_id, hour, check_type, rounds, failed, latency_sum_ms, latency_max_ms FROM check_rollups WHERE host_id = ? AND hour >= ? AND hour < ? ORDER BY hour, check_type`
		args := []any{hostID, ts(from.UTC().Truncate(time.Hour)), ts(to)}
		if hostID == "" { // every host of the tenant, for charts across a site or the fleet
			q = `SELECT host_id, hour, check_type, rounds, failed, latency_sum_ms, latency_max_ms FROM check_rollups WHERE hour >= ? AND hour < ? ORDER BY hour, host_id, check_type`
			args = args[1:]
		}
		rows, err := db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, wrap("rollups", err)
		}
		for rows.Next() {
			var r Rollup
			var hour string
			if err := rows.Scan(&r.HostID, &hour, &r.CheckType, &r.Rounds, &r.Failed, &r.LatencySumMS, &r.LatencyMaxMS); err != nil {
				_ = rows.Close()
				return nil, wrap("rollups", err)
			}
			r.Hour = parseTS(hour)
			out = append(out, r)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return nil, wrap("rollups", err)
		}
	}
	return out, nil
}
