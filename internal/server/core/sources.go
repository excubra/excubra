package core

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/rules"
	"github.com/excubra/excubra/internal/server/store"
)

// Sources (ADR-0023): an application reports itself over the API. What it sends
// is kept in its tenant's day files (table logs); the rules make findings of it
// on the source's device; a finding that opens is one security.alert, as for
// live signals.

// Finding sources of what a source reported. Incidents resolve after a quiet
// day; the state findings follow the state.
const (
	SourceApp        = "app"
	SourceAppCert    = "app.cert"
	SourceAppSilence = "app.silence"
)

// Limits of one post.
const (
	MaxSourceEvents = 500
	appLookback     = rules.RefusedWindow // the longest window a counting rule needs
	appFuture       = time.Hour           // a clock that far ahead is wrong, not early
)

// SourceEvent is one event as the source sends it (ADR-0023 §3).
type SourceEvent struct {
	EventID    string    `json:"event_id"`
	OccurredAt time.Time `json:"occurred_at"`
	Kind       string    `json:"kind"`
	Actor      string    `json:"actor,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Target     string    `json:"target,omitempty"`
	Summary    string    `json:"summary,omitempty"`
}

// SourceStatus is what the source says about itself.
type SourceStatus struct {
	Version      string    `json:"version,omitempty"`
	CertNotAfter time.Time `json:"cert_not_after,omitzero"`
}

// SourcePost is one post: events and, optionally, the status.
type SourcePost struct {
	Events []SourceEvent `json:"events"`
	Status *SourceStatus `json:"status,omitempty"`
}

// ErrNotASource says a token is not bound to a source.
var ErrNotASource = errors.New("core: this token belongs to no source")

// SourceReport takes one post of the source the token belongs to: it touches the
// device, keeps the events, judges them, and answers how many were new.
func (e *Engine) SourceReport(ctx context.Context, tok store.APIToken, post SourcePost) (int, error) {
	if tok.DeviceID == "" {
		return 0, ErrNotASource
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	dev, err := e.Store.Device(ctx, tok.DeviceID)
	if err != nil {
		return 0, err
	}
	if err := e.Store.TouchDevice(ctx, dev.ID, now); err != nil {
		return 0, err
	}
	source := "app." + strings.ToLower(strings.Join(strings.Fields(dev.Hostname), "-"))
	entries := make([]store.LogEntry, 0, len(post.Events))
	for _, ev := range post.Events {
		if le, ok := sourceEntry(dev.ID, source, ev, now); ok {
			entries = append(entries, le)
		}
	}
	fresh, err := e.Store.AddLogs(ctx, dev.TenantID, entries)
	if err != nil {
		return 0, err
	}

	var alerts []event.Event
	for _, le := range fresh {
		if f, ok := rules.EvaluateAppEvent(appEvent(le), e.loc()); ok {
			alerts = append(alerts, e.appFinding(ctx, dev, SourceApp, f, true, now)...)
		}
	}
	if len(fresh) > 0 {
		recent, err := e.Store.Logs(ctx, dev.TenantID, dev.ID, now.Add(-appLookback), now.Add(appFuture), "", 10000)
		if err != nil {
			return len(fresh), err
		}
		events := make([]rules.AppEvent, 0, len(recent))
		for _, le := range recent {
			events = append(events, appEvent(le))
		}
		for _, f := range rules.EvaluateAppWindow(events, now) {
			alerts = append(alerts, e.appFinding(ctx, dev, SourceApp, f, false, now)...)
		}
	}

	// It talks, so it is not silent; its certificate is what it says, and a
	// certificate finding that opens alerts once, like every other.
	if resolved, err := e.Store.SyncDeviceFindings(ctx, dev.ID, SourceAppSilence, nil, now); err == nil {
		for _, fid := range resolved {
			_ = e.Store.DeleteAck(ctx, "finding", fid)
		}
	}
	if post.Status != nil {
		var cert []store.Finding
		for _, f := range rules.EvaluateAppState(dev.Hostname, now, post.Status.CertNotAfter, now) {
			if _, err := e.Store.OpenFinding(ctx, dev.ID, f.Rule, f.Key); errors.Is(err, store.ErrNotFound) {
				alerts = append(alerts, e.appAlert(dev, f, now))
			}
			cert = append(cert, e.storeFinding(dev, SourceAppCert, f))
		}
		if resolved, err := e.Store.SyncDeviceFindings(ctx, dev.ID, SourceAppCert, cert, now); err == nil {
			for _, fid := range resolved {
				_ = e.Store.DeleteAck(ctx, "finding", fid)
			}
		}
	}
	e.publish(ctx, alerts)
	return len(fresh), nil
}

// sourceTick is the engine's minute for the sources: a source that went quiet
// gets its finding (and one alert when it opens), refreshed every minute while
// it stays quiet.
func (e *Engine) sourceTick(ctx context.Context, now time.Time) []event.Event {
	var alerts []event.Event
	list, err := e.Store.Sources(ctx)
	if err != nil {
		e.Log.Error("sources", "err", err)
		return nil
	}
	for _, src := range list {
		dev := src.Device
		var silent []store.Finding
		for _, f := range rules.EvaluateAppState(dev.Hostname, dev.LastSeen, time.Time{}, now) {
			if f.Rule != "app.silent" {
				continue
			}
			if _, err := e.Store.OpenFinding(ctx, dev.ID, f.Rule, f.Key); errors.Is(err, store.ErrNotFound) {
				e.Log.Warn("source silent", "device", dev.ID, "name", dev.Hostname, "last", dev.LastSeen)
				alerts = append(alerts, e.appAlert(dev, f, now))
			}
			silent = append(silent, e.storeFinding(dev, SourceAppSilence, f))
		}
		if resolved, err := e.Store.SyncDeviceFindings(ctx, dev.ID, SourceAppSilence, silent, now); err == nil {
			for _, fid := range resolved {
				_ = e.Store.DeleteAck(ctx, "finding", fid)
			}
		}
	}
	// Incidents resolve after a quiet day. So do state findings nobody refreshes
	// any more — those of a source whose token was revoked, which this loop no
	// longer visits.
	for _, source := range []string{SourceApp, SourceAppSilence, SourceAppCert} {
		quiet, err := e.Store.ResolveQuietFindings(ctx, source, now.Add(-signalQuiet), now)
		if err != nil {
			e.Log.Error("sources: quiet findings", "source", source, "err", err)
		}
		for _, fid := range quiet {
			_ = e.Store.DeleteAck(ctx, "finding", fid)
		}
	}
	return alerts
}

// appFinding opens or refreshes a finding from what a source reported. additive
// findings count their events over their life; the counting rules bring their
// own count. The alert goes out once, when the finding opens.
func (e *Engine) appFinding(ctx context.Context, dev store.Device, source string, f rules.Finding, additive bool, now time.Time) []event.Event {
	prev, perr := e.Store.OpenFinding(ctx, dev.ID, f.Rule, f.Key)
	if perr == nil && additive {
		var old struct {
			Count int `json:"count"`
		}
		if json.Unmarshal(prev.Evidence, &old) == nil && old.Count > 0 {
			f.Evidence["count"] = old.Count + 1
		}
	}
	if err := e.Store.UpsertFinding(ctx, e.storeFinding(dev, source, f), now); err != nil {
		e.Log.Error("source: finding", "device", dev.ID, "rule", f.Rule, "err", err)
		return nil
	}
	if perr == nil {
		return nil
	}
	e.Log.Warn("source", "device", dev.ID, "name", dev.Hostname, "rule", f.Rule, "key", f.Key)
	return []event.Event{e.appAlert(dev, f, now)}
}

// appAlert is the one security.alert of a finding that opened.
func (e *Engine) appAlert(dev store.Device, f rules.Finding, now time.Time) event.Event {
	al := event.New(event.SecurityAlert, now)
	al.Source = event.SourceApp
	al.Severity = event.Critical
	if f.Severity != rules.High {
		al.Severity = event.Warning
	}
	al.TenantID, al.SiteID, al.DeviceID = dev.TenantID, dev.SiteID, dev.ID
	al.Device = &event.DeviceRef{IP: dev.IP, Vendor: dev.Vendor, Hostname: dev.Hostname}
	al.Details = map[string]any{"rule": f.Rule, "key": f.Key, "title": f.Title, "info": f.Detail, "source": dev.Hostname}
	return al
}

func (e *Engine) storeFinding(dev store.Device, source string, f rules.Finding) store.Finding {
	ev, _ := json.Marshal(f.Evidence)
	return store.Finding{ID: id.New("fnd"), TenantID: dev.TenantID, SiteID: dev.SiteID, DeviceID: dev.ID, ConnectorID: source,
		Rule: f.Rule, Key: f.Key, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: ev}
}

// loc is the house's time zone; UTC when nobody set one.
func (e *Engine) loc() *time.Location {
	if e.Loc == nil {
		return time.UTC
	}
	return e.Loc
}

// sourceEntry checks one event and makes a log entry of it. An event without an
// id or a kind is not one; a clock far in the future is replaced by the time it
// arrived, so it cannot hide in a day nobody looks at.
func sourceEntry(deviceID, source string, ev SourceEvent, now time.Time) (store.LogEntry, bool) {
	ev.EventID, ev.Kind = strings.TrimSpace(ev.EventID), strings.TrimSpace(ev.Kind)
	if ev.EventID == "" || ev.Kind == "" || len(ev.EventID) > 128 || len(ev.Kind) > 64 {
		return store.LogEntry{}, false
	}
	at := ev.OccurredAt
	if at.IsZero() || at.After(now.Add(appFuture)) {
		at = now
	}
	return store.LogEntry{
		DeviceID: deviceID, EventID: ev.EventID, OccurredAt: at.UTC(), ReceivedAt: now.UTC(), Source: source,
		Kind: ev.Kind, Actor: clip(ev.Actor, 200), IP: clip(ev.IP, 64), Target: clip(ev.Target, 200), Summary: clip(ev.Summary, 500),
	}, true
}

func appEvent(le store.LogEntry) rules.AppEvent {
	return rules.AppEvent{Kind: le.Kind, Actor: le.Actor, IP: le.IP, Target: le.Target, Summary: le.Summary, At: le.OccurredAt}
}

// clip keeps a string to n bytes without cutting a character in half.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
