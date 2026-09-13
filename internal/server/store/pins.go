package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// What an operator pinned. A sidebar that lists every customer stops being a
// shortcut somewhere around the twentieth; the handful somebody is working on
// today belongs at the top, and which handful that is changes by the day and by
// the person.

// Pin kinds. Only things with a page worth returning to.
const (
	PinTenant = "tenant"
	PinSite   = "site"
)

// Pin is one entry in a user's pinned list.
type Pin struct {
	Kind     string    `json:"kind"`
	TargetID string    `json:"id"`
	Name     string    `json:"name"`
	Sub      string    `json:"sub"` // the customer a site belongs to, empty for a customer
	PinnedAt time.Time `json:"pinnedAt"`
}

// AddPin pins a target for one user. Pinning twice is not an error: the button
// is a toggle and a double click should not be a failure.
func (s *Store) AddPin(ctx context.Context, userID, kind, targetID string, at time.Time) error {
	if kind != PinTenant && kind != PinSite {
		return fmt.Errorf("pin: %q is neither a tenant nor a site", kind)
	}
	_, err := s.main.ExecContext(ctx,
		`INSERT INTO pins (user_id, kind, target_id, pinned_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT (user_id, kind, target_id) DO NOTHING`,
		userID, kind, targetID, ts(at))
	return wrap("add pin", err)
}

// RemovePin unpins a target. Removing what is not pinned is not an error either.
func (s *Store) RemovePin(ctx context.Context, userID, kind, targetID string) error {
	_, err := s.main.ExecContext(ctx, `DELETE FROM pins WHERE user_id = ? AND kind = ? AND target_id = ?`, userID, kind, targetID)
	return wrap("remove pin", err)
}

// Pins lists what a user pinned, with the names to show, oldest first so the
// list does not reshuffle under the pointer every time something is added.
// A pin whose target is gone is dropped on the way out rather than shown as a
// dead link.
func (s *Store) Pins(ctx context.Context, userID string) ([]Pin, error) {
	rows, err := s.main.QueryContext(ctx, `
		SELECT p.kind, p.target_id, p.pinned_at,
		       COALESCE(t.name, s.name, ''),
		       COALESCE(st.name, '')
		FROM pins p
		LEFT JOIN tenants t ON p.kind = 'tenant' AND t.id = p.target_id
		LEFT JOIN sites   s ON p.kind = 'site'   AND s.id = p.target_id
		LEFT JOIN tenants st ON p.kind = 'site'  AND st.id = s.tenant_id
		WHERE p.user_id = ?
		ORDER BY p.pinned_at, p.target_id`, userID)
	if err != nil {
		return nil, wrap("pins", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Pin{}
	for rows.Next() {
		var p Pin
		var at string
		if err := rows.Scan(&p.Kind, &p.TargetID, &at, &p.Name, &p.Sub); err != nil {
			return nil, wrap("pins", err)
		}
		if p.Name == "" { // the customer or site was deleted meanwhile
			continue
		}
		p.PinnedAt = parseTS(at)
		out = append(out, p)
	}
	return out, wrap("pins", rows.Err())
}

// IsPinned answers the star on a page.
func (s *Store) IsPinned(ctx context.Context, userID, kind, targetID string) (bool, error) {
	var one int
	err := s.main.QueryRowContext(ctx, `SELECT 1 FROM pins WHERE user_id = ? AND kind = ? AND target_id = ?`, userID, kind, targetID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrap("is pinned", err)
	}
	return true, nil
}
