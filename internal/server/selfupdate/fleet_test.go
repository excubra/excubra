package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/agent/update"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// The regression of 13.09.2026: the server must not install a release that would
// leave a box outside the compatibility window, because from that moment on it
// would refuse that box every single request. It asks the box to update instead
// and installs once the box is within reach.
func TestServerWaitsForTheBoxes(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	blob := bytes.Repeat([]byte("NEW SERVER "), 200000)
	c := New(w.st, w.upd, filepath.Join(w.dir, "data"), "linux", "amd64", true, nil)
	c.Now = func() time.Time { return now }

	must(t, w.st.PutRelease(ctx, store.Release{Version: "9.9.9", OS: "linux", Arch: "amd64", URL: w.srv.URL + "/amd", SHA256: sha256Of(blob), Signature: "good", CreatedAt: now}))
	must(t, w.st.SetChannelVersion(ctx, "stable", "9.9.9"))

	// four boxes: one far behind, one within the window, one long silent and one
	// revoked — only the first may hold the server back.
	must(t, w.st.CreateBox(ctx, store.Box{ID: "box_behind", Name: "Geschäftsstelle", HWID: "a", AgentVersion: "9.6.0", OS: "linux", Arch: "amd64", LastSeen: now.Add(-time.Minute), EnrolledAt: now}))
	must(t, w.st.CreateBox(ctx, store.Box{ID: "box_near", Name: "Außenposten", HWID: "b", AgentVersion: "9.8.0", OS: "linux", Arch: "amd64", LastSeen: now.Add(-time.Minute), EnrolledAt: now}))
	must(t, w.st.CreateBox(ctx, store.Box{ID: "box_gone", Name: "Alt", HWID: "c", AgentVersion: "1.0.0", OS: "linux", Arch: "amd64", LastSeen: now.Add(-30 * 24 * time.Hour), EnrolledAt: now}))
	must(t, w.st.CreateBox(ctx, store.Box{ID: "box_revoked", Name: "Ersetzt", HWID: "d", AgentVersion: "1.0.0", OS: "linux", Arch: "amd64", LastSeen: now.Add(-time.Minute), EnrolledAt: now}))
	must(t, w.st.RevokeBox(ctx, "box_revoked", now))

	// held back, and the lagging box was asked to update
	if err := c.Check(ctx); err != nil {
		t.Fatalf("held-back check should not error: %v", err)
	}
	s := c.Status(ctx)
	if len(s.HeldBack) != 1 || s.HeldBack[0].ID != "box_behind" {
		t.Fatalf("held back should name exactly the lagging box: %+v", s.HeldBack)
	}
	if s.Available != "9.9.9" {
		t.Fatalf("the release is still available, only postponed: %+v", s)
	}
	tasks, err := w.st.PendingBoxTasks(ctx, "box_behind", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 1 || tasks[0].Kind != wire.TaskUpdate {
		t.Fatalf("the lagging box should have one update task: %+v", tasks)
	}
	if n, _ := w.st.PendingBoxTasks(ctx, "box_near", now); len(n) != 0 {
		t.Fatalf("a box inside the window must not be nudged: %+v", n)
	}
	if n, _ := w.st.PendingBoxTasks(ctx, "box_gone", now); len(n) != 0 {
		t.Fatalf("a box silent for a month must not hold the server back: %+v", n)
	}
	if n, _ := w.st.PendingBoxTasks(ctx, "box_revoked", now); len(n) != 0 {
		t.Fatalf("a revoked box must not hold the server back: %+v", n)
	}
	if w.trials != 0 {
		t.Fatalf("nothing may be installed while boxes are behind, trials=%d", w.trials)
	}
	if d := c.nextDelay(); d != holdRetry {
		t.Fatalf("a held-back server looks again in minutes, not %s", d)
	}

	// a second check does not pile up a second task
	if err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if tasks, _ := w.st.PendingBoxTasks(ctx, "box_behind", now); len(tasks) != 1 {
		t.Fatalf("one waiting task is enough: %+v", tasks)
	}

	// the box catches up: the release lands
	must(t, w.st.UpdateBoxAgent(ctx, "box_behind", "9.8.1", "linux", "amd64"))
	if err := c.Check(ctx); !errors.Is(err, update.ErrRestart) {
		t.Fatalf("expected the install once the fleet is within the window, got %v", err)
	}
	if s := c.Status(ctx); len(s.HeldBack) != 0 {
		t.Fatalf("nothing should be held back any more: %+v", s.HeldBack)
	}
}

// The guard must not become a deadlock. A box that never manages to update would
// otherwise hold the server on an old release for ever, so an operator can say
// "install anyway" — once, on the record, and without taking the boxes' way back
// (/v1/update, /v1/renew stay open outside the window).
func TestOperatorCanInstallAnyway(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	blob := bytes.Repeat([]byte("NEW SERVER "), 200000)
	dataDir := filepath.Join(w.dir, "data")
	c := New(w.st, w.upd, dataDir, "linux", "amd64", true, nil)
	c.Now = func() time.Time { return now }

	must(t, w.st.PutRelease(ctx, store.Release{Version: "9.9.9", OS: "linux", Arch: "amd64", URL: w.srv.URL + "/amd", SHA256: sha256Of(blob), Signature: "good", CreatedAt: now}))
	must(t, w.st.SetChannelVersion(ctx, "stable", "9.9.9"))
	must(t, w.st.CreateBox(ctx, store.Box{ID: "box_stuck", Name: "Hängt", HWID: "a", AgentVersion: "9.0.0", OS: "linux", Arch: "amd64", LastSeen: now.Add(-time.Minute), EnrolledAt: now}))

	if err := c.Check(ctx); err != nil {
		t.Fatalf("held back: %v", err)
	}
	if s := c.Status(ctx); len(s.HeldBack) != 1 {
		t.Fatalf("the stuck box should hold the server: %+v", s.HeldBack)
	}

	// the CLI's side: the trigger file carries the override
	must(t, RequestNowAnyway(dataDir))
	body, err := os.ReadFile(filepath.Join(dataDir, "update", TriggerFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), triggerAnyway) {
		t.Fatalf("the trigger file should carry the override: %q", body)
	}

	// the server's side: one check ignores the guard, the next does not
	c.mu.Lock()
	c.anyway = true
	c.mu.Unlock()
	if err := c.Check(ctx); !errors.Is(err, update.ErrRestart) {
		t.Fatalf("the override should install: %v", err)
	}
	c.mu.Lock()
	stillSet := c.anyway
	c.mu.Unlock()
	if stillSet {
		t.Fatal("the override must be one-shot, not a mode")
	}
}
