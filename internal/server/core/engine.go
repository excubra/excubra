// Package core is the engine that every listener talks to: it owns the state
// machine, persists its state through the store, turns transitions into published
// events, and builds the configuration a box pulls. Ingest, console and status API
// are thin layers over it.
package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// Publisher stores an event and fans it out (the webhook package).
type Publisher interface {
	Publish(ctx context.Context, ev event.Event) error
}

// DeviceGoneAfter is how long a device may be unseen before device.gone.
const DeviceGoneAfter = 24 * time.Hour

// Engine is safe for concurrent use; every operation holds the lock for its
// duration, which is fine at one heartbeat per box per minute.
type Engine struct {
	Store *store.Store
	Pub   Publisher
	Log   *slog.Logger
	Now   func() time.Time

	mu      sync.Mutex
	m       *state.Machine
	revoked map[string]bool // certificate serials
	sites   map[string]store.Site
}

// Load builds the engine from the store: boxes, hosts, persisted states, windows.
func Load(ctx context.Context, st *store.Store, pub Publisher, log *slog.Logger) (*Engine, error) {
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{Store: st, Pub: pub, Log: log, Now: time.Now, m: state.New(), revoked: map[string]bool{}, sites: map[string]store.Site{}}
	sites, err := st.Sites(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, s := range sites {
		e.sites[s.ID] = s
	}
	boxStates, err := st.BoxStates(ctx)
	if err != nil {
		return nil, err
	}
	boxes, err := st.Boxes(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, b := range boxes {
		if b.RevokedAt != nil {
			e.revoked[b.CertSerial] = true
			continue
		}
		mb := state.Box{ID: b.ID}
		if site, ok := e.sites[b.SiteID]; ok {
			mb.SiteID, mb.TenantID = site.ID, site.TenantID
		}
		if bs, ok := boxStates[b.ID]; ok {
			mb.Status, mb.LastHeartbeat, mb.SilentSince = bs.Status, bs.LastHeartbeat, bs.SilentSince
		}
		mb.AgentVersion = b.AgentVersion
		e.m.PutBox(mb)
	}
	serials, err := st.RevokedSerials(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range serials {
		e.revoked[s] = true
	}
	hostStates, err := st.HostStates(ctx)
	if err != nil {
		return nil, err
	}
	hosts, err := st.Hosts(ctx, "", "")
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		mh := machineHost(h)
		if hs, ok := hostStates[h.ID]; ok {
			mh.Observed, mh.Reported = hs.Observed, hs.Reported
			mh.Failures, mh.Successes = hs.Failures, hs.Successes
			mh.Since, mh.RunStart, mh.DownSince = hs.Since, hs.RunStart, hs.DownSince
			mh.LastFailedChecks, mh.LastBoxTime = hs.LastFailedChecks, hs.LastBoxTime
		}
		e.m.PutHost(mh)
	}
	windows, err := st.Maintenances(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, w := range windows {
		e.m.PutMaintenance(machineWindow(w))
	}
	return e, nil
}

func machineHost(h store.Host) state.Host {
	return state.Host{ID: h.ID, BoxID: h.BoxID, ParentID: h.ParentID, IsUplink: h.IsUplink,
		Ref: event.HostRef{Name: h.Name, IP: h.Address, MAC: h.MAC, Vendor: h.Vendor}}
}

func machineWindow(w store.Maintenance) state.Maintenance {
	return state.Maintenance{ID: w.ID, Scope: state.Scope(w.Scope), TargetID: w.TargetID, TenantID: w.TenantID, SiteID: w.SiteID,
		Until: w.Until, Reason: w.Reason, SetBy: w.SetBy}
}

// ---- box identity ----------------------------------------------------------------

// IsRevoked reports whether a certificate serial is on the deny list.
func (e *Engine) IsRevoked(serial string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.revoked[serial]
}

// RegisterBox is called after enrollment: the box exists in the store; the engine
// starts tracking it (unassigned).
func (e *Engine) RegisterBox(b store.Box) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.m.PutBox(state.Box{ID: b.ID, AgentVersion: b.AgentVersion})
}

// RevokeBox denies the box's certificate and stops tracking it.
func (e *Engine) RevokeBox(ctx context.Context, boxID, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, err := e.Store.Box(ctx, boxID)
	if err != nil {
		return err
	}
	if err := e.Store.RevokeBox(ctx, boxID, e.Now()); err != nil {
		return err
	}
	e.revoked[b.CertSerial] = true
	e.m.RemoveBox(boxID)
	return e.audit(ctx, actor, "box.revoke", boxID, "")
}

// DeleteBox removes a box, its hosts and state; the serial stays denied.
func (e *Engine) DeleteBox(ctx context.Context, boxID, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, err := e.Store.Box(ctx, boxID)
	if err != nil {
		return err
	}
	if err := e.Store.RevokeBox(ctx, boxID, e.Now()); err != nil {
		return err
	}
	e.revoked[b.CertSerial] = true
	if err := e.Store.DeleteBox(ctx, boxID); err != nil {
		return err
	}
	e.m.RemoveBox(boxID)
	return e.audit(ctx, actor, "box.delete", boxID, "")
}

// AssignBox binds a box to a site ("" unassigns). Host states are reset.
func (e *Engine) AssignBox(ctx context.Context, boxID, siteID, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if siteID != "" {
		site, err := e.Store.Site(ctx, siteID)
		if err != nil {
			return err
		}
		e.sites[site.ID] = site
		if err := e.Store.AssignBox(ctx, boxID, siteID); err != nil {
			return err
		}
		e.m.AssignBox(boxID, site.TenantID, siteID)
	} else {
		if err := e.Store.AssignBox(ctx, boxID, ""); err != nil {
			return err
		}
		e.m.UnassignBox(boxID)
	}
	if err := e.persistDirty(ctx); err != nil {
		return err
	}
	return e.audit(ctx, actor, "box.assign", boxID, siteID)
}

// ---- sites ---------------------------------------------------------------------------

// CreateSite creates a site and caches it.
func (e *Engine) CreateSite(ctx context.Context, s store.Site, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.Store.CreateSite(ctx, s); err != nil {
		return err
	}
	e.sites[s.ID] = s
	return e.audit(ctx, actor, "site.create", s.ID, s.Name)
}

// ---- hosts ---------------------------------------------------------------------------

// CreateHost starts monitoring a host.
func (e *Engine) CreateHost(ctx context.Context, h store.Host, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := validateHost(h); err != nil {
		return err
	}
	if err := e.Store.CreateHost(ctx, h); err != nil {
		return err
	}
	e.m.PutHost(machineHost(h))
	return e.audit(ctx, actor, "host.create", h.ID, h.Name+" "+h.Address)
}

// UpdateHost changes a host's editable fields; topology changes are reconciled.
func (e *Engine) UpdateHost(ctx context.Context, h store.Host, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := validateHost(h); err != nil {
		return err
	}
	if err := e.Store.UpdateHost(ctx, h); err != nil {
		return err
	}
	cur, ok := e.m.Host(h.ID)
	if ok {
		cur.Ref = event.HostRef{Name: h.Name, IP: h.Address, MAC: h.MAC, Vendor: h.Vendor}
		e.m.PutHost(cur)
	}
	events := e.m.SetHostTopology(h.ID, h.ParentID, h.IsUplink, e.Now())
	if err := e.persistDirty(ctx); err != nil {
		return err
	}
	e.publish(ctx, events)
	return e.audit(ctx, actor, "host.update", h.ID, h.Name)
}

// DeleteHost stops monitoring a host.
func (e *Engine) DeleteHost(ctx context.Context, hostID, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.Store.DeleteHost(ctx, hostID); err != nil {
		return err
	}
	e.m.RemoveHost(hostID)
	for _, h := range e.m.Hosts() {
		if h.ParentID == hostID {
			h.ParentID = ""
			e.m.PutHost(h)
		}
	}
	return e.audit(ctx, actor, "host.delete", hostID, "")
}

func validateHost(h store.Host) error {
	if h.ID == "" || h.BoxID == "" || h.TenantID == "" || h.SiteID == "" || h.Address == "" {
		return errors.New("core: host needs id, box, tenant, site and address")
	}
	if h.ParentID == h.ID {
		return errors.New("core: a host cannot be its own parent")
	}
	for _, c := range h.Checks {
		switch c.Type {
		case wire.CheckICMP:
		case wire.CheckTCP:
			if c.Port < 1 || c.Port > 65535 {
				return fmt.Errorf("core: tcp check needs a port (got %d)", c.Port)
			}
		case wire.CheckHTTP:
			if c.URL == "" {
				return errors.New("core: http check needs a url")
			}
		default:
			return fmt.Errorf("core: unknown check type %q", c.Type)
		}
	}
	return nil
}

// HostView is a host with its live state, for console and API.
type HostView struct {
	store.Host
	State      state.Host
	Suppressed string
}

// HostViews returns hosts of a tenant (or all) with their states.
func (e *Engine) HostViews(ctx context.Context, tenantID string) ([]HostView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	hosts, err := e.Store.Hosts(ctx, tenantID, "")
	if err != nil {
		return nil, err
	}
	out := make([]HostView, 0, len(hosts))
	for _, h := range hosts {
		v := HostView{Host: h}
		if st, ok := e.m.Host(h.ID); ok {
			v.State = st
			v.Suppressed = e.m.Suppressed(h.ID)
		}
		out = append(out, v)
	}
	return out, nil
}

// HostView returns one host with state.
func (e *Engine) HostView(ctx context.Context, hostID string) (HostView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	h, err := e.Store.Host(ctx, hostID)
	if err != nil {
		return HostView{}, err
	}
	v := HostView{Host: h}
	if st, ok := e.m.Host(h.ID); ok {
		v.State = st
		v.Suppressed = e.m.Suppressed(h.ID)
	}
	return v, nil
}

// BoxState returns the live state of a box.
func (e *Engine) BoxState(boxID string) (state.Box, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.m.Box(boxID)
}

// ---- maintenance -----------------------------------------------------------------------

// StartMaintenance opens a window and publishes maintenance.started.
func (e *Engine) StartMaintenance(ctx context.Context, w store.Maintenance, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if w.ID == "" {
		w.ID = id.New("mnt")
	}
	if w.CreatedAt.IsZero() {
		w.CreatedAt = e.Now()
	}
	if w.SetBy == "" {
		w.SetBy = actor
	}
	switch state.Scope(w.Scope) {
	case state.ScopeTenant, state.ScopeSite, state.ScopeHost:
	default:
		return fmt.Errorf("core: bad maintenance scope %q", w.Scope)
	}
	if !w.Until.After(e.Now()) {
		return errors.New("core: maintenance must end in the future")
	}
	if err := e.Store.CreateMaintenance(ctx, w); err != nil {
		return err
	}
	events := e.m.StartMaintenance(machineWindow(w), e.Now())
	e.publish(ctx, events)
	return e.audit(ctx, actor, "maintenance.start", w.ID, w.Scope+" "+w.TargetID+" until "+w.Until.UTC().Format(time.RFC3339))
}

// EndMaintenance clears a window early and publishes what that releases.
func (e *Engine) EndMaintenance(ctx context.Context, maintID, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.Store.DeleteMaintenance(ctx, maintID); err != nil {
		return err
	}
	events := e.m.EndMaintenance(maintID, e.Now())
	if err := e.persistDirty(ctx); err != nil {
		return err
	}
	e.publish(ctx, events)
	return e.audit(ctx, actor, "maintenance.end", maintID, "")
}

// MaintenanceFor finds active windows covering a target (host, site or tenant id).
func (e *Engine) MaintenanceFor(targetID string) []state.Maintenance {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []state.Maintenance
	for _, w := range e.m.Maintenances() {
		if w.TargetID == targetID {
			out = append(out, w)
		}
	}
	return out
}

// ---- heartbeat, config, tick -------------------------------------------------------------

// Heartbeat processes one heartbeat of a known, unrevoked box.
func (e *Engine) Heartbeat(ctx context.Context, box store.Box, hb wire.Heartbeat) (wire.HeartbeatResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()

	if _, ok := e.m.Box(box.ID); !ok {
		e.m.PutBox(state.Box{ID: box.ID})
		if site, ok := e.sites[box.SiteID]; ok {
			e.m.AssignBox(box.ID, site.TenantID, site.ID)
		}
	}
	events := e.m.Heartbeat(box.ID, now, hb.Agent.Version, hb.Hosts)
	if err := e.persistDirty(ctx); err != nil {
		return wire.HeartbeatResponse{}, err
	}
	if err := e.Store.UpdateBoxHeartbeat(ctx, box.ID, hb, now); err != nil {
		return wire.HeartbeatResponse{}, err
	}

	site, assigned := e.sites[box.SiteID]
	if assigned {
		e.rollups(ctx, site.TenantID, hb)
		events = append(events, e.sightings(ctx, site, box.ID, hb.Discovery.Seen, now)...)
	}
	e.publish(ctx, events)

	cfg, err := e.config(ctx, box)
	if err != nil {
		return wire.HeartbeatResponse{}, err
	}
	return wire.HeartbeatResponse{ServerTime: now, ConfigVersion: cfg.Version, Assigned: assigned}, nil
}

func (e *Engine) rollups(ctx context.Context, tenantID string, hb wire.Heartbeat) {
	now := e.Now()
	for _, hr := range hb.Hosts {
		if _, ok := e.m.Host(hr.HostID); !ok {
			continue
		}
		for _, r := range hr.Rounds {
			for _, c := range r.Checks {
				if err := e.Store.AddRollup(ctx, tenantID, hr.HostID, now, c.Type, c.OK, c.LatencyMS); err != nil {
					e.Log.Error("rollup", "host", hr.HostID, "err", err)
				}
			}
		}
	}
}

func (e *Engine) sightings(ctx context.Context, site store.Site, boxID string, seen []wire.Sighting, now time.Time) []event.Event {
	var events []event.Event
	if len(seen) > wire.MaxSightings {
		seen = seen[:wire.MaxSightings]
	}
	for _, sg := range seen {
		if sg.MAC == "" {
			continue
		}
		d, isNew, wasGone, err := e.Store.UpsertSighting(ctx, site.TenantID, site.ID, sg, now)
		if err != nil {
			e.Log.Warn("sighting", "mac", sg.MAC, "err", err)
			continue
		}
		if isNew || wasGone {
			ev := event.New(event.DeviceNew, now)
			ev.Source = event.SourceDiscovery
			ev.TenantID, ev.SiteID, ev.BoxID, ev.DeviceID = site.TenantID, site.ID, boxID, d.ID
			first := d.FirstSeen
			ev.Since = &first
			ev.Device = &event.DeviceRef{IP: d.IP, MAC: d.MAC, Vendor: d.Vendor, Hostname: d.Hostname, FirstSeen: &first}
			events = append(events, ev)
		}
	}
	return events
}

// TestPing publishes a test.ping event addressed to one webhook target.
func (e *Engine) TestPing(ctx context.Context, tenantID, targetID, actor string) (event.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.Store.Tenant(ctx, tenantID); err != nil {
		return event.Event{}, err
	}
	ev := event.New(event.TestPing, e.Now())
	ev.Source = event.SourceConsole
	ev.TenantID = tenantID
	ev.Details = map[string]any{"target_id": targetID, "triggered_by": actor}
	if err := e.Pub.Publish(ctx, ev); err != nil {
		return ev, err
	}
	return ev, e.audit(ctx, actor, "webhook.test", targetID, tenantID)
}

// Config returns the configuration document a box pulls.
func (e *Engine) Config(ctx context.Context, box store.Box) (wire.Config, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.config(ctx, box)
}

func (e *Engine) config(ctx context.Context, box store.Box) (wire.Config, error) {
	cfg := wire.Config{
		Intervals: wire.DefaultIntervals,
		Hosts:     []wire.HostConfig{},
		Discovery: wire.DiscoveryConfig{Mode: wire.DiscoveryPassive, SweepIntervalS: 900, MaxPPS: 50},
		Update:    wire.UpdateConfig{Channel: box.Channel},
	}
	if cfg.Update.Channel == "" {
		cfg.Update.Channel = wire.ChannelStable
	}
	if _, ok := e.sites[box.SiteID]; ok && box.RevokedAt == nil {
		cfg.Assigned = true
		hosts, err := e.Store.Hosts(ctx, "", box.ID)
		if err != nil {
			return wire.Config{}, err
		}
		for _, h := range hosts {
			checks := h.Checks
			if len(checks) == 0 {
				checks = []wire.CheckConfig{{Type: wire.CheckICMP}}
			}
			cfg.Hosts = append(cfg.Hosts, wire.HostConfig{HostID: h.ID, Address: h.Address, Checks: checks})
		}
		sort.Slice(cfg.Hosts, func(i, j int) bool { return cfg.Hosts[i].HostID < cfg.Hosts[j].HostID })
		if box.DiscoveryMode == wire.DiscoverySweep {
			cfg.Discovery.Mode = wire.DiscoverySweep
			cfg.Discovery.Subnets = box.DiscoverySubnets
		}
		nk, err := e.Store.NetbirdKey(ctx, box.ID)
		if err == nil && nk.ClaimedAt == nil {
			cfg.NetbirdPending = true
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return wire.Config{}, err
		}
	}
	cfg.Version = configVersion(cfg)
	return cfg, nil
}

// configVersion hashes the canonical document without its version field.
func configVersion(cfg wire.Config) string {
	cfg.Version = ""
	b, _ := json.Marshal(cfg)
	sum := sha256.Sum256(b)
	return "cfg_" + hex.EncodeToString(sum[:8])
}

// Tick runs silence detection, maintenance expiry and device.gone.
func (e *Engine) Tick(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	events := e.m.Tick(now)
	if err := e.persistDirty(ctx); err != nil {
		return err
	}
	// windows the machine expired are deleted from the store
	live := map[string]bool{}
	for _, w := range e.m.Maintenances() {
		live[w.ID] = true
	}
	stored, err := e.Store.Maintenances(ctx, "")
	if err != nil {
		return err
	}
	for _, w := range stored {
		if !live[w.ID] {
			if err := e.Store.DeleteMaintenance(ctx, w.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
		}
	}
	gone, err := e.Store.MarkDevicesGone(ctx, now.Add(-DeviceGoneAfter), now)
	if err != nil {
		return err
	}
	for _, d := range gone {
		ev := event.New(event.DeviceGone, now)
		ev.Source = event.SourceDiscovery
		ev.TenantID, ev.SiteID, ev.DeviceID = d.TenantID, d.SiteID, d.ID
		last := d.LastSeen
		ev.Since = &last
		ev.Device = &event.DeviceRef{IP: d.IP, MAC: d.MAC, Vendor: d.Vendor, Hostname: d.Hostname, LastSeen: &last}
		events = append(events, ev)
	}
	e.publish(ctx, events)
	return nil
}

// RunTicker calls Tick every interval until ctx ends.
func (e *Engine) RunTicker(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.Tick(ctx); err != nil {
				e.Log.Error("tick", "err", err)
			}
		}
	}
}

// ---- internals ------------------------------------------------------------------------------

func (e *Engine) persistDirty(ctx context.Context) error {
	hosts, boxes := e.m.Dirty()
	now := e.Now()
	for _, hid := range hosts {
		h, ok := e.m.Host(hid)
		if !ok {
			continue
		}
		if err := e.Store.SaveHostState(ctx, h, now); err != nil {
			return err
		}
	}
	for _, bid := range boxes {
		b, ok := e.m.Box(bid)
		if !ok {
			continue
		}
		if err := e.Store.SaveBoxState(ctx, b, now); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) publish(ctx context.Context, events []event.Event) {
	for _, ev := range events {
		if err := e.Pub.Publish(ctx, ev); err != nil {
			e.Log.Error("publish", "type", ev.Type, "event", ev.ID, "err", err)
		}
	}
}

func (e *Engine) audit(ctx context.Context, actor, action, target, summary string) error {
	return e.Store.Audit(ctx, e.Now(), actor, action, target, summary)
}
