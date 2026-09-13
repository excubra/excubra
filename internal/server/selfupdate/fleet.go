package selfupdate

import (
	"context"
	"time"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// The fleet guard keeps the promise ADR-0002 makes to the boxes.
//
// A server that installs a release more than the compatibility window ahead of
// its boxes answers every one of them with 426 from that moment on. Boxes do
// update themselves, but they look once a day — so between two of their checks
// the server can outrun them. That is what happened on 13.09.2026: the server
// walked from 0.7.4 to 0.10.0 in one morning, the two boxes were still on 0.7.4
// when it arrived, and they were refused before they ever got the offer.
//
// So the server no longer steps outside the window of a box it serves. It asks
// the lagging boxes to update now instead of at their daily tick, waits, and
// installs once they are within reach. The window is a promise in both
// directions, and the side that can wait is the server.
const (
	// staleAfter is how long a box may be silent before it stops holding the
	// server back. A box that was decommissioned must not freeze the server for
	// ever; one that is merely switched off over a long weekend must.
	staleAfter = 14 * 24 * time.Hour
	// holdRetry is how soon the server looks again while it waits for boxes.
	holdRetry = 5 * time.Minute
	// nudgeGoodFor is how long an update task issued by the guard stays valid.
	nudgeGoodFor = 6 * time.Hour
)

// Lagging is a box that the target release would push out of the window.
type Lagging struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// behind lists the boxes target would leave outside the compatibility window.
// Revoked boxes, boxes that never reported a version and boxes nobody has heard
// from in staleAfter do not count.
func (c *Controller) behind(ctx context.Context, target version.Semver) ([]Lagging, error) {
	boxes, err := c.Store.Boxes(ctx, "")
	if err != nil {
		return nil, err
	}
	now := c.Now()
	var out []Lagging
	for _, b := range boxes {
		if b.RevokedAt != nil || b.AgentVersion == "" {
			continue
		}
		if b.LastSeen.IsZero() || now.Sub(b.LastSeen) > staleAfter {
			continue
		}
		av, err := version.Parse(b.AgentVersion)
		if err != nil {
			continue
		}
		if version.Compatible(av, target) {
			continue
		}
		name := b.Name
		if name == "" {
			name = b.ID
		}
		out = append(out, Lagging{ID: b.ID, Name: name, Version: b.AgentVersion})
	}
	return out, nil
}

// nudge asks each lagging box to fetch update metadata at its next heartbeat
// instead of at its daily tick. A box that already has such a task waiting is
// left alone, so a server that waits for hours does not pile up tasks.
func (c *Controller) nudge(ctx context.Context, lagging []Lagging) {
	now := c.Now()
	for _, l := range lagging {
		pending, err := c.Store.PendingBoxTasks(ctx, l.ID, now)
		if err != nil {
			c.Log.Warn("self-update: pending tasks", "box", l.ID, "err", err)
			continue
		}
		waiting := false
		for _, t := range pending {
			if t.Kind == wire.TaskUpdate {
				waiting = true
				break
			}
		}
		if waiting {
			continue
		}
		t := store.BoxTask{ID: id.New("task"), BoxID: l.ID, Kind: wire.TaskUpdate, IssuedAt: now, IssuedBy: "server", ExpiresAt: now.Add(nudgeGoodFor)}
		if err := c.Store.CreateBoxTask(ctx, t); err != nil {
			c.Log.Warn("self-update: asking a box to update", "box", l.ID, "err", err)
		}
	}
}

// names renders the held-back boxes for a log line or the console.
func names(l []Lagging) []string {
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, x.Name+" ("+x.Version+")")
	}
	return out
}
