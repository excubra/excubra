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
	"github.com/excubra/excubra/internal/server/feed"
	"github.com/excubra/excubra/internal/server/rules"
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
	Feed  *feed.Service // end-of-life data for the version rules (ADR-0018); nil means no version findings

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
			mh.LastFailedChecks, mh.LastChecks, mh.LastBoxTime = hs.LastFailedChecks, hs.LastChecks, hs.LastBoxTime
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
	_ = e.Store.DeleteAck(ctx, "box_silent", boxID)
	_ = e.Store.DeleteAck(ctx, "box_unassigned", boxID)
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
		_ = e.Store.DeleteAck(ctx, "box_unassigned", boxID)
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
	_ = e.Store.DeleteAck(ctx, "host_down", hostID)
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

// Maintenances returns every active window.
func (e *Engine) Maintenances() []state.Maintenance {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.m.Maintenances()
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
	e.absorbNotesAndResults(ctx, box.ID, hb, now)
	if hb.Agent.SealKey != "" {
		if err := e.Store.SetBoxSealKey(ctx, box.ID, hb.Agent.SealKey); err != nil {
			e.Log.Error("seal key", "box", box.ID, "err", err)
		}
	}
	e.absorbConnectors(ctx, box, hb.Connectors, now)

	site, assigned := e.sites[box.SiteID]
	if assigned {
		e.rollups(ctx, site.TenantID, hb)
		events = append(events, e.sightings(ctx, site, box.ID, hb.Discovery.Seen, now)...)
		if hb.Scan != nil {
			e.absorbScan(ctx, site, box, hb.Scan, now)
		}
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
		if sg.MAC == "" && sg.IP == "" {
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
		// the scan switch is read fresh: the CLI flips it in the store, not in this cache
		if site, err := e.Store.Site(ctx, box.SiteID); err == nil && site.ScanEnabled && box.Role != store.RoleOutpost {
			cfg.Scan = wire.ScanConfig{Enabled: true, IntervalS: 24 * 3600, MaxPPS: 20}
		}
		if box.Role == store.RoleOutpost {
			// an outpost looks at the sites' public addresses every hour
			if targets, err := e.Store.ScanTargets(ctx); err == nil {
				cfg.Scan = wire.ScanConfig{Enabled: len(targets) > 0, IntervalS: 3600, MaxPPS: 20}
				for _, t := range targets {
					cfg.Scan.External = append(cfg.Scan.External, wire.ScanTarget{SiteID: t.SiteID, IP: t.IP})
				}
			}
		}
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
		ok, err := e.Store.NetbirdKeyProfile(ctx, box.ID, wire.NetbirdProfileOperator)
		if err == nil && ok.ClaimedAt == nil {
			cfg.NetbirdOperatorPending = true
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			return wire.Config{}, err
		}
	}
	if box.RevokedAt == nil {
		pending, err := e.Store.PendingBoxTasks(ctx, box.ID, e.Now())
		if err != nil {
			return wire.Config{}, err
		}
		for _, t := range pending {
			cfg.Tasks = append(cfg.Tasks, wire.Task{ID: t.ID, Kind: t.Kind, IssuedAt: t.IssuedAt})
		}
		if cfg.Assigned {
			cons, err := e.Store.ConnectorsForBox(ctx, box.ID)
			if err != nil {
				return wire.Config{}, err
			}
			for _, c := range cons {
				if c.Disabled || len(cfg.Connectors) >= wire.MaxConnectors {
					continue
				}
				cfg.Connectors = append(cfg.Connectors, wire.ConnectorConfig{ID: c.ID, DeviceID: c.DeviceID, Kind: c.Kind, URL: c.URL, Sealed: c.Sealed,
					IntervalS: c.IntervalS, TLSFingerprint: c.TLSFingerprint, Version: c.Version()})
			}
		}
	}
	if box.Role == store.RoleOutpost {
		// and leaves the network it stands in alone: no hosts, no sweep
		cfg.Hosts, cfg.Discovery.Mode, cfg.Discovery.Subnets = []wire.HostConfig{}, wire.DiscoveryPassive, nil
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
	expired, err := e.Store.ExpireBoxTasks(ctx, now)
	if err != nil {
		return err
	}
	for _, t := range expired {
		_ = e.audit(ctx, "server", "box.task.expired", t.ID, t.Kind+" for "+t.BoxID)
	}
	if err := e.Store.PruneBoxTasks(ctx, now.Add(-taskHistory)); err != nil {
		return err
	}
	if err := e.Store.PruneFindings(ctx, now.Add(-taskHistory)); err != nil {
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
		switch ev.Type { // a recovery ends the acknowledged problem
		case event.HostUp:
			_ = e.Store.DeleteAck(ctx, "host_down", ev.HostID)
		case event.BoxBack:
			_ = e.Store.DeleteAck(ctx, "box_silent", ev.BoxID)
		}
		if err := e.Pub.Publish(ctx, ev); err != nil {
			e.Log.Error("publish", "type", ev.Type, "event", ev.ID, "err", err)
		}
	}
}

func (e *Engine) audit(ctx context.Context, actor, action, target, summary string) error {
	return e.Store.Audit(ctx, e.Now(), actor, action, target, summary)
}

// ---- tasks (ADR-0014) ------------------------------------------------------------------------

// TaskTTL is how long a queued task waits for the box before it expires as failed.
const TaskTTL = time.Hour

// taskHistory is how long finished tasks stay visible on the box page.
const taskHistory = 30 * 24 * time.Hour

// Bounds on what a box may write into the console through notes and results.
const (
	maxNotesPerHeartbeat = 20
	maxNoteLen           = 500
)

// ErrTaskPending says a task of that kind is already waiting for the box.
var ErrTaskPending = errors.New("core: a task of this kind is already waiting for the box")

// ErrBadTask says the kind is not on the closed list.
var ErrBadTask = errors.New("core: unknown task kind")

// QueueTask queues one task for a box: the kind must be on the closed list, the box
// must exist and not be revoked, and at most one task per kind waits at a time. The
// box sees it with its next config pull; nothing is pushed.
func (e *Engine) QueueTask(ctx context.Context, boxID, kind, actor string) (store.BoxTask, error) {
	if !wire.ValidTaskKind(kind) {
		return store.BoxTask{}, fmt.Errorf("%w: %q", ErrBadTask, kind)
	}
	box, err := e.Store.Box(ctx, boxID)
	if err != nil {
		return store.BoxTask{}, err
	}
	if box.RevokedAt != nil {
		return store.BoxTask{}, errors.New("core: the box is revoked")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Now()
	pending, err := e.Store.PendingBoxTasks(ctx, boxID, now)
	if err != nil {
		return store.BoxTask{}, err
	}
	for _, t := range pending {
		if t.Kind == kind {
			return t, ErrTaskPending
		}
	}
	t := store.BoxTask{ID: id.New("task"), BoxID: boxID, Kind: kind, IssuedAt: now, IssuedBy: actor, ExpiresAt: now.Add(TaskTTL)}
	if err := e.Store.CreateBoxTask(ctx, t); err != nil {
		return store.BoxTask{}, err
	}
	return t, e.audit(ctx, actor, "box.task", boxID, kind+" "+t.ID)
}

// absorbNotesAndResults stores what the box wants an operator to see and closes the
// tasks it reports. Delivery is at-least-once, so a repeated result is ignored.
func (e *Engine) absorbNotesAndResults(ctx context.Context, boxID string, hb wire.Heartbeat, now time.Time) {
	notes := hb.Notes
	if len(notes) > maxNotesPerHeartbeat {
		notes = notes[:maxNotesPerHeartbeat]
	}
	for _, n := range notes {
		if len(n) > maxNoteLen {
			n = n[:maxNoteLen]
		}
		if err := e.Store.AddBoxNote(ctx, boxID, now, n); err != nil {
			e.Log.Error("box note", "box", boxID, "err", err)
		}
	}
	for _, r := range hb.TaskResults {
		detail := r.Detail
		if len(detail) > maxNoteLen {
			detail = detail[:maxNoteLen]
		}
		err := e.Store.CompleteBoxTask(ctx, boxID, r.ID, r.OK, detail, now)
		switch {
		case errors.Is(err, store.ErrNotFound):
			// already recorded, expired, or not this box's task: nothing changes
		case err != nil:
			e.Log.Error("task result", "box", boxID, "task", r.ID, "err", err)
		default:
			outcome := "ok"
			if !r.OK {
				outcome = "failed"
			}
			_ = e.audit(ctx, "box:"+boxID, "box.task.done", r.ID, fmt.Sprintf("%s %s: %s", r.Kind, outcome, detail))
		}
	}
}

// absorbConnectors stores connector readings and their numbers (ADR-0015).
func (e *Engine) absorbConnectors(ctx context.Context, box store.Box, reports []wire.ConnectorReport, now time.Time) {
	if len(reports) > wire.MaxConnectors {
		reports = reports[:wire.MaxConnectors]
	}
	site, assigned := e.sites[box.SiteID]
	for _, r := range reports {
		if len(r.Facts) > wire.MaxConnectorFactsSize {
			r.Facts = nil
		}
		err := e.Store.UpdateConnectorReading(ctx, box.ID, r, now)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue // not this box's connector, or deleted meanwhile
		case err != nil:
			e.Log.Error("connector reading", "box", box.ID, "connector", r.ID, "err", err)
			continue
		}
		if r.OK && assigned && len(r.Metrics) > 0 {
			if err := e.Store.AddConnectorSamples(ctx, site.TenantID, r.ID, now, r.Metrics); err != nil {
				e.Log.Error("connector samples", "connector", r.ID, "err", err)
			}
		}
		if r.OK {
			e.evaluateRules(ctx, r.ID, r.Metrics, now)
		}
		if r.TokenSealed != "" && len(r.TokenSealed) <= 16*1024 {
			if err := e.Store.ReplaceConnectorSealed(ctx, box.ID, r.ID, r.TokenSealed, now); err != nil && !errors.Is(err, store.ErrNotFound) {
				e.Log.Error("connector bootstrap credential", "connector", r.ID, "err", err)
			} else if err == nil {
				_ = e.audit(ctx, "box:"+box.ID, "connector.bootstrap", r.ID, "device credential replaced by the box's own API token")
			}
		}
	}
}

// evaluateRules runs the prevention rules over the connector's stored facts and the
// metrics of this reading, and syncs the findings (open, still open, resolved).
func (e *Engine) evaluateRules(ctx context.Context, connectorID string, metrics map[string]float64, now time.Time) {
	c, err := e.Store.Connector(ctx, connectorID)
	if err != nil {
		return
	}
	facts := map[string]any{}
	if len(c.Facts) > 0 {
		_ = json.Unmarshal(c.Facts, &facts)
	}
	found := rules.Evaluate(rules.Input{Kind: c.Kind, Facts: facts, Metrics: metrics, Pinned: c.TLSFingerprint != "", Now: now})
	if v, _ := facts["version"].(string); v != "" && c.Kind == "fortigate" && c.DeviceID != "" {
		e.versionFindings(ctx, c.TenantID, c.SiteID, c.DeviceID, []rules.Service{{Proto: "connector", Product: "FortiOS", Version: v, Name: c.Kind}}, now)
	}
	current := make([]store.Finding, 0, len(found))
	for _, f := range found {
		ev, _ := json.Marshal(f.Evidence)
		current = append(current, store.Finding{ID: id.New("fnd"), TenantID: c.TenantID, SiteID: c.SiteID, DeviceID: c.DeviceID, ConnectorID: c.ID,
			Rule: f.Rule, Key: f.Key, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: ev})
	}
	resolved, err := e.Store.SyncFindings(ctx, c.ID, current, now)
	if err != nil {
		e.Log.Error("findings", "connector", c.ID, "err", err)
	}
	for _, fid := range resolved { // a resolved finding takes its acknowledgement with it
		_ = e.Store.DeleteAck(ctx, "finding", fid)
	}
}

// ---- the service scan (ADR-0018) --------------------------------------------------------

// absorbScan stores what a scan round saw on each device and lets the scan rules
// speak: services that appeared or disappeared are logged, findings are synced per
// device, the round is bookkept for "when did we last look".
func (e *Engine) absorbScan(ctx context.Context, site store.Site, box store.Box, rep *wire.ScanReport, now time.Time) {
	if rep.Round == "" || len(rep.Hosts) > wire.MaxScanHosts {
		return
	}
	round, err := e.Store.ScanRound(ctx, rep.Round)
	if err != nil {
		round = store.ScanRound{ID: rep.Round, BoxID: box.ID, SiteID: site.ID, StartedAt: rep.StartedAt}
	}
	for _, h := range rep.Hosts {
		if h.SiteID != "" {
			e.absorbExternal(ctx, box, rep, h, now)
			continue
		}
		dev, err := e.Store.DeviceByAddress(ctx, site.ID, h.MAC, h.IP)
		if err != nil {
			continue // the scan knows a device the inventory does not have yet; the next round will
		}
		svcs, facts := scanServices(dev.ID, h.Services)
		added, gone, err := e.Store.UpsertServices(ctx, dev.ID, svcs, now)
		if err != nil {
			e.Log.Error("scan: services", "device", dev.ID, "err", err)
			continue
		}
		if len(added) > 0 || len(gone) > 0 {
			e.Log.Info("scan: services changed", "site", site.ID, "device", dev.ID, "ip", h.IP, "appeared", len(added), "gone", len(gone))
		}
		round.Hosts++
		round.Services += len(svcs)
		found := rules.EvaluateScan(rules.ScanInput{Services: facts, Now: now})
		current := make([]store.Finding, 0, len(found))
		for _, f := range found {
			ev, _ := json.Marshal(f.Evidence)
			current = append(current, store.Finding{ID: id.New("fnd"), TenantID: site.TenantID, SiteID: site.ID, DeviceID: dev.ID, ConnectorID: "scan",
				Rule: f.Rule, Key: f.Key, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: ev})
		}
		resolved, err := e.Store.SyncDeviceFindings(ctx, dev.ID, "scan", current, now)
		if err != nil {
			e.Log.Error("scan: findings", "device", dev.ID, "err", err)
		}
		for _, fid := range resolved {
			_ = e.Store.DeleteAck(ctx, "finding", fid)
		}
		e.versionFindings(ctx, site.TenantID, site.ID, dev.ID, facts, now)
	}
	if rep.Final {
		fin := now
		round.FinishedAt, round.Errors = &fin, rep.Errors
	}
	if err := e.Store.SetScanRound(ctx, round); err != nil {
		e.Log.Error("scan: round", "round", rep.Round, "err", err)
	}
}

// scanServices converts a report's services for the store and for the rules.
func scanServices(deviceID string, in []wire.ScanService) ([]store.Service, []rules.Service) {
	svcs := make([]store.Service, 0, len(in))
	facts := make([]rules.Service, 0, len(in))
	for i, sv := range in {
		if i >= wire.MaxScanServices {
			break
		}
		var tlsJSON json.RawMessage
		var rt *rules.TLS
		if sv.TLS != nil {
			tlsJSON, _ = json.Marshal(sv.TLS)
			rt = &rules.TLS{Subject: sv.TLS.Subject, Issuer: sv.TLS.Issuer, NotAfter: sv.TLS.NotAfter, SelfSigned: sv.TLS.SelfSigned, Version: sv.TLS.Version}
		}
		svcs = append(svcs, store.Service{DeviceID: deviceID, Port: sv.Port, Proto: sv.Proto, Name: sv.Name, Product: sv.Product, Version: sv.Version, Banner: sv.Banner, Title: sv.Title, TLS: tlsJSON})
		facts = append(facts, rules.Service{Port: sv.Port, Proto: sv.Proto, Name: sv.Name, Product: sv.Product, Version: sv.Version, Banner: sv.Banner, Title: sv.Title, TLS: rt})
	}
	return svcs, facts
}

// absorbExternal stores what an outpost saw on a site's public address: the
// outside view. Only an outpost may report it, only for an address the site's own
// box reported, and it hangs on the device that stands for the site's public
// address. The stricter external rules apply.
func (e *Engine) absorbExternal(ctx context.Context, outpost store.Box, rep *wire.ScanReport, h wire.ScanHost, now time.Time) {
	if outpost.Role != store.RoleOutpost {
		return
	}
	target, ok := e.sites[h.SiteID]
	if !ok {
		return
	}
	known := false
	if boxes, err := e.Store.Boxes(ctx, h.SiteID); err == nil {
		for _, b := range boxes {
			if b.RevokedAt == nil && b.PublicIP == h.IP {
				known = true
			}
		}
	}
	if !known {
		return
	}
	dev, err := e.Store.EnsureExternalDevice(ctx, target.TenantID, target.ID, h.IP, now)
	if err != nil {
		e.Log.Error("scan: outside view device", "site", h.SiteID, "err", err)
		return
	}
	svcs, facts := scanServices(dev.ID, h.Services)
	added, gone, err := e.Store.UpsertServices(ctx, dev.ID, svcs, now)
	if err != nil {
		e.Log.Error("scan: outside services", "site", h.SiteID, "err", err)
		return
	}
	if len(added) > 0 || len(gone) > 0 {
		e.Log.Info("scan: outside view changed", "site", h.SiteID, "ip", h.IP, "appeared", len(added), "gone", len(gone))
	}
	found := rules.EvaluateExternal(rules.ScanInput{Services: facts, Now: now})
	current := make([]store.Finding, 0, len(found))
	for _, f := range found {
		ev, _ := json.Marshal(f.Evidence)
		current = append(current, store.Finding{ID: id.New("fnd"), TenantID: target.TenantID, SiteID: target.ID, DeviceID: dev.ID, ConnectorID: "wan",
			Rule: f.Rule, Key: f.Key, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: ev})
	}
	resolved, err := e.Store.SyncDeviceFindings(ctx, dev.ID, "wan", current, now)
	if err != nil {
		e.Log.Error("scan: outside findings", "site", h.SiteID, "err", err)
	}
	for _, fid := range resolved {
		_ = e.Store.DeleteAck(ctx, "finding", fid)
	}
	e.versionFindings(ctx, target.TenantID, target.ID, dev.ID, facts, now)
	fin := now
	if err := e.Store.SetScanRound(ctx, store.ScanRound{ID: rep.Round + ":" + h.SiteID, BoxID: outpost.ID, SiteID: h.SiteID, StartedAt: rep.StartedAt, FinishedAt: &fin, Hosts: 1, Services: len(svcs), External: true}); err != nil {
		e.Log.Error("scan: outside round", "site", h.SiteID, "err", err)
	}
}

// versionFindings lets the feed judge the versions the scan or a connector saw and
// syncs them under the source "version".
func (e *Engine) versionFindings(ctx context.Context, tenantID, siteID, deviceID string, facts []rules.Service, now time.Time) {
	if e.Feed == nil {
		return
	}
	found := e.Feed.Findings(facts, now)
	current := make([]store.Finding, 0, len(found))
	for _, f := range found {
		ev, _ := json.Marshal(f.Evidence)
		current = append(current, store.Finding{ID: id.New("fnd"), TenantID: tenantID, SiteID: siteID, DeviceID: deviceID, ConnectorID: "version",
			Rule: f.Rule, Key: f.Key, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: ev})
	}
	resolved, err := e.Store.SyncDeviceFindings(ctx, deviceID, "version", current, now)
	if err != nil {
		e.Log.Error("version findings", "device", deviceID, "err", err)
	}
	for _, fid := range resolved {
		_ = e.Store.DeleteAck(ctx, "finding", fid)
	}
}

// ReassessVersions takes a fresh look at every device's services after the feed
// changed: a line that just reached its end becomes a finding without waiting for
// the next scan round.
func (e *Engine) ReassessVersions(ctx context.Context) {
	if e.Feed == nil {
		return
	}
	svcs, err := e.Store.OpenServices(ctx)
	if err != nil {
		return
	}
	byDevice := map[string][]rules.Service{}
	var order []string
	for _, sv := range svcs {
		if _, ok := byDevice[sv.DeviceID]; !ok {
			order = append(order, sv.DeviceID)
		}
		byDevice[sv.DeviceID] = append(byDevice[sv.DeviceID], rules.Service{Port: sv.Port, Proto: sv.Proto, Name: sv.Name, Product: sv.Product, Version: sv.Version})
	}
	now := e.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, devID := range order {
		dev, err := e.Store.Device(ctx, devID)
		if err != nil {
			continue
		}
		e.versionFindings(ctx, dev.TenantID, dev.SiteID, dev.ID, byDevice[devID], now)
	}
}

// SetSiteScan switches the service scan of a site; the box picks it up with its
// next config pull.
func (e *Engine) SetSiteScan(ctx context.Context, siteID string, enabled bool, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	site, ok := e.sites[siteID]
	if !ok {
		return store.ErrNotFound
	}
	if err := e.Store.SetSiteScan(ctx, siteID, enabled); err != nil {
		return err
	}
	site.ScanEnabled = enabled
	e.sites[siteID] = site
	state := "off"
	if enabled {
		state = "on"
	}
	return e.audit(ctx, actor, "site.scan", siteID, state)
}
