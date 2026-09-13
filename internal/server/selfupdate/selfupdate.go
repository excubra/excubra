// Package selfupdate lets the server update itself the way a box does (ADR-0006):
// the same signed release, the same updater, the same rollback. The server follows
// a channel of its own (setting server.channel, default stable), checks daily, and
// right away when the console or the CLI asks. It never signs anything and only
// installs what verifies against the compiled-in release key.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/agent/update"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// SettingChannel is the settings key for the channel the server follows.
const SettingChannel = "server.channel"

// TriggerFile under <datadir>/update asks the running server to check now; the CLI
// writes it, the server removes it.
const TriggerFile = "now"

// triggerAnyway in that file means: install even while boxes are behind.
const triggerAnyway = "anyway"

// Timings.
const (
	firstCheck  = 2 * time.Minute
	checkEvery  = 24 * time.Hour
	checkJitter = time.Hour
	pollTrigger = 30 * time.Second
)

// Status is what the console and the CLI show.
type Status struct {
	Enabled    bool      `json:"enabled"`
	Running    string    `json:"running"`
	Arch       string    `json:"arch"`
	Channel    string    `json:"channel"`   // stable | canary | off
	Target     string    `json:"target"`    // the version the channel points at ("" = none)
	Available  string    `json:"available"` // Target when it is newer than Running and built for this platform
	LastCheck  time.Time `json:"lastCheck"`
	LastError  string    `json:"lastError"`
	RolledBack string    `json:"rolledBack"` // "0.3.0 → 0.2.1" when the last attempt was rolled back
	// HeldBack lists the boxes that Available would push outside the
	// compatibility window. While it is not empty the server stays where it is
	// and asks those boxes to update first (see fleet.go).
	HeldBack []Lagging `json:"heldBack"`
}

// Controller runs the checks for one server.
type Controller struct {
	Store   *store.Store
	Updater *update.Updater
	Log     *slog.Logger
	Now     func() time.Time
	Arch    string
	OS      string
	Enabled bool
	DataDir string

	now chan struct{}
	mu  sync.Mutex
	st  Status
	// anyway skips the fleet guard for exactly one check, after an operator asked
	// for it. Deliberate, audited and one-shot: a guard that can never be overruled
	// is a deadlock waiting for the day a box cannot update at all.
	anyway bool
}

// New returns a controller; Run starts the checks.
func New(st *store.Store, upd *update.Updater, dataDir, osName, arch string, enabled bool, log *slog.Logger) *Controller {
	if log == nil {
		log = slog.Default()
	}
	return &Controller{Store: st, Updater: upd, Log: log, Now: time.Now, Arch: arch, OS: osName, Enabled: enabled, DataDir: dataDir, now: make(chan struct{}, 1)}
}

// Channel returns the channel the server follows.
func (c *Controller) Channel(ctx context.Context) string {
	v, err := c.Store.Setting(ctx, SettingChannel)
	if err != nil || v == "" {
		return wire.ChannelStable
	}
	return v
}

// SetChannel changes it: stable, canary or off.
func (c *Controller) SetChannel(ctx context.Context, ch string) error {
	if ch != wire.ChannelStable && ch != wire.ChannelCanary && ch != "off" {
		return errors.New("selfupdate: channel must be stable, canary or off")
	}
	return c.Store.SetSetting(ctx, SettingChannel, ch)
}

// NoteRollback records that the previous start rolled an update back.
func (c *Controller) NoteRollback(p update.Pending) {
	c.mu.Lock()
	c.st.RolledBack = p.To + " → " + p.From
	c.mu.Unlock()
}

// Status computes the current picture.
func (c *Controller) Status(ctx context.Context) Status {
	c.mu.Lock()
	s := c.st
	c.mu.Unlock()
	s.Enabled, s.Running, s.Arch = c.Enabled, version.Version, c.Arch
	s.Channel = c.Channel(ctx)
	s.Target, s.Available = "", ""
	if s.Channel == "off" {
		s.HeldBack = nil
		return s
	}
	if v, err := c.Store.ChannelVersion(ctx, s.Channel); err == nil && v != "" {
		s.Target = v
		if target, err := version.Parse(v); err == nil && newer(target, version.Current()) {
			if _, err := c.Store.Release(ctx, v, c.OS, c.Arch); err == nil {
				s.Available = v
			}
		}
	}
	if s.Available == "" {
		s.HeldBack = nil
	}
	return s
}

// TriggerAnyway asks for a check that installs even while boxes are behind.
// One check only — the next one guards the fleet again.
func (c *Controller) TriggerAnyway() {
	c.mu.Lock()
	c.anyway = true
	c.mu.Unlock()
	c.TriggerNow()
}

// TriggerNow asks for a check at the next opportunity.
func (c *Controller) TriggerNow() {
	select {
	case c.now <- struct{}{}:
	default:
	}
}

// Check looks once and updates if the channel points at a newer build for this
// platform. It returns update.ErrRestart after a swap, nil otherwise.
func (c *Controller) Check(ctx context.Context) error {
	now := c.Now()
	err := c.check(ctx)
	c.mu.Lock()
	c.st.LastCheck = now
	c.st.LastError = ""
	if err != nil && !errors.Is(err, update.ErrRestart) {
		c.st.LastError = err.Error()
	}
	c.mu.Unlock()
	return err
}

func (c *Controller) check(ctx context.Context) error {
	if !c.Enabled {
		return nil
	}
	ch := c.Channel(ctx)
	if ch == "off" {
		return nil
	}
	v, err := c.Store.ChannelVersion(ctx, ch)
	if err != nil {
		return err
	}
	if v == "" {
		return nil
	}
	target, err := version.Parse(v)
	if err != nil {
		return fmt.Errorf("channel %s points at %q, which is not a version", ch, v)
	}
	if !newer(target, version.Current()) {
		return nil
	}
	rel, err := c.Store.Release(ctx, v, c.OS, c.Arch)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("release %s has no build for %s/%s", v, c.OS, c.Arch)
	}
	if err != nil {
		return err
	}
	// The boxes come first: installing past their window would refuse them.
	lagging, err := c.behind(ctx, target)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.st.HeldBack = lagging
	override := c.anyway
	c.anyway = false
	c.mu.Unlock()
	switch {
	case len(lagging) == 0:
	case override:
		c.Log.Warn("self-update: installing although boxes are behind, as an operator asked", "to", v, "boxes", names(lagging))
		_ = c.Store.Audit(ctx, c.Now(), "operator", "server.update.anyway", v, "installed past the window of: "+strings.Join(names(lagging), ", "))
		c.mu.Lock()
		c.st.HeldBack = nil
		c.mu.Unlock()
	default:
		c.nudge(ctx, lagging)
		c.Log.Info("self-update: waiting for boxes before installing", "to", v, "boxes", names(lagging))
		return nil
	}
	c.Log.Info("self-update: newer release on channel", "channel", ch, "from", version.Version, "to", v)
	err = c.Updater.Apply(ctx, wire.UpdateInfo{Version: rel.Version, URL: rel.URL, SHA256: rel.SHA256, Signature: rel.Signature, MinAgentVersion: rel.MinAgentVersion})
	switch {
	case errors.Is(err, update.ErrRestart):
		_ = c.Store.Audit(ctx, c.Now(), "server", "server.update", v, "installed "+v+" over "+version.Version+", restarting")
		c.mu.Lock()
		c.st.RolledBack = ""
		c.mu.Unlock()
		return err
	case err != nil:
		_ = c.Store.Audit(ctx, c.Now(), "server", "server.update.failed", v, err.Error())
		return err
	}
	return nil
}

// Run checks after a short delay, then daily with jitter, and whenever asked
// through TriggerNow or the trigger file. It returns update.ErrRestart when the
// binary was swapped and nil when ctx ends.
func (c *Controller) Run(ctx context.Context) error {
	t := time.NewTimer(firstCheck)
	defer t.Stop()
	poll := time.NewTicker(pollTrigger)
	defer poll.Stop()
	trigger := filepath.Join(c.DataDir, "update", TriggerFile)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			t.Reset(c.nextDelay())
		case <-c.now:
		case <-poll.C:
			body, err := os.ReadFile(trigger) //nolint:gosec // a flag file the CLI wrote next to our own data
			if err != nil {
				continue
			}
			_ = os.Remove(trigger)
			if strings.Contains(string(body), triggerAnyway) {
				c.mu.Lock()
				c.anyway = true
				c.mu.Unlock()
				c.Log.Warn("self-update: an operator asked to install even if boxes are behind")
			}
			c.Log.Info("self-update: check requested through the trigger file")
		}
		if err := c.Check(ctx); err != nil {
			if errors.Is(err, update.ErrRestart) {
				return err
			}
			c.Log.Warn("self-update", "err", err)
		}
	}
}

// nextDelay is a day with jitter normally, and holdRetry while the server waits
// for boxes to catch up — a release that is held back should land minutes after
// the last box arrives, not the next morning.
func (c *Controller) nextDelay() time.Duration {
	c.mu.Lock()
	held := len(c.st.HeldBack) > 0
	c.mu.Unlock()
	if held {
		return holdRetry
	}
	return checkEvery + time.Duration(rand.IntN(int(checkJitter/time.Second)))*time.Second //nolint:gosec // jitter, not security
}

// RequestNow writes the trigger file for a running server (the CLI's side).
func RequestNow(dataDir string) error { return request(dataDir, "") }

// RequestNowAnyway asks for a check that installs even while boxes are behind.
// It is the operator's answer to the one case the fleet guard cannot solve by
// itself: a box that keeps failing to update would otherwise hold the server on
// an old release for ever. The boxes keep their way back either way, because
// /v1/update and /v1/renew are answered outside the window (ADR-0002).
func RequestNowAnyway(dataDir string) error { return request(dataDir, triggerAnyway) }

func request(dataDir, extra string) error {
	dir := filepath.Join(dataDir, "update")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	body := time.Now().UTC().Format(time.RFC3339)
	if extra != "" {
		body += " " + extra
	}
	return os.WriteFile(filepath.Join(dir, TriggerFile), []byte(body+"\n"), 0o644) //nolint:gosec // a flag file, no secret
}

func newer(a, b version.Semver) bool {
	if a.Major != b.Major {
		return a.Major > b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor > b.Minor
	}
	return a.Patch > b.Patch
}
