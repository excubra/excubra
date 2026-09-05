// Package state is the pure state machine of EX0 (ADR-0004): boxes go online/silent,
// hosts go unknown/up/down, maintenance windows and uplink dependencies suppress
// events, and every emitted event is a transition. No I/O, no timers — the caller
// feeds heartbeats and ticks and persists what Dirty() reports.
package state

import (
	"sort"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/wire"
)

// HostState is the observed or reported state of a host.
type HostState string

// Host states.
const (
	Unknown HostState = "unknown"
	Up      HostState = "up"
	Down    HostState = "down"
)

// BoxStatus is online or silent.
type BoxStatus string

// Box statuses.
const (
	Online BoxStatus = "online"
	Silent BoxStatus = "silent"
)

// Thresholds from the concept: 3 failed rounds → down, 2 ok rounds → up, 3 missed
// heartbeats (+ grace) → silent.
const (
	FailuresToDown           = 3
	SuccessesToUp            = 2
	MissedHeartbeatsToSilent = 3
	SilenceGrace             = 30 * time.Second
	DefaultHeartbeatInterval = 60 * time.Second
)

// Box is the per-box state. TenantID/SiteID are empty while unassigned.
type Box struct {
	ID                string
	TenantID          string
	SiteID            string
	HeartbeatInterval time.Duration
	Status            BoxStatus
	LastHeartbeat     time.Time
	SilentSince       time.Time
	AgentVersion      string
}

// Assigned reports whether the box belongs to a site (and therefore a tenant).
func (b *Box) Assigned() bool { return b.SiteID != "" && b.TenantID != "" }

func (b *Box) silenceAfter() time.Duration {
	hb := b.HeartbeatInterval
	if hb <= 0 {
		hb = DefaultHeartbeatInterval
	}
	return MissedHeartbeatsToSilent*hb + SilenceGrace
}

// Host is the per-host state. Observed follows the checks; Reported is what the
// outside world was last told. Both are persisted.
type Host struct {
	ID       string
	BoxID    string
	ParentID string // uplink ancestor, empty for none
	IsUplink bool
	Ref      event.HostRef

	Observed  HostState
	Reported  HostState
	Failures  int       // consecutive failed rounds
	Successes int       // consecutive ok rounds
	Since     time.Time // when Observed was entered (server time)
	RunStart  time.Time // first round of the current consecutive run
	DownSince time.Time // when Observed last became Down

	LastFailedChecks []string           // labels of the checks that failed in the last failed round
	LastChecks       []wire.CheckResult // results of the last round applied, for console and API
	LastBoxTime      time.Time          // box time of the last round applied
}

// Scope of a maintenance window.
type Scope string

// Maintenance scopes.
const (
	ScopeTenant Scope = "tenant"
	ScopeSite   Scope = "site"
	ScopeHost   Scope = "host"
)

// Maintenance is a window; TenantID/SiteID are the envelope scope of its events.
type Maintenance struct {
	ID       string
	Scope    Scope
	TargetID string // tenant, site or host id depending on Scope
	TenantID string
	SiteID   string
	Until    time.Time
	Reason   string
	SetBy    string
}

// Machine holds every box, host and window. Not safe for concurrent use; the
// caller serialises.
type Machine struct {
	boxes map[string]*Box
	hosts map[string]*Host
	maint map[string]*Maintenance

	dirtyHosts map[string]struct{}
	dirtyBoxes map[string]struct{}
}

// New returns an empty machine.
func New() *Machine {
	return &Machine{
		boxes:      map[string]*Box{},
		hosts:      map[string]*Host{},
		maint:      map[string]*Maintenance{},
		dirtyHosts: map[string]struct{}{},
		dirtyBoxes: map[string]struct{}{},
	}
}

// ---- loading and topology -----------------------------------------------------

// PutBox adds or replaces a box with the given state (use zero state for a new box).
func (m *Machine) PutBox(b Box) {
	if b.Status == "" {
		b.Status = Online
	}
	if b.HeartbeatInterval <= 0 {
		b.HeartbeatInterval = DefaultHeartbeatInterval
	}
	m.boxes[b.ID] = &b
}

// RemoveBox drops a box and all its hosts. No events.
func (m *Machine) RemoveBox(id string) {
	delete(m.boxes, id)
	for hid, h := range m.hosts {
		if h.BoxID == id {
			delete(m.hosts, hid)
		}
	}
}

// PutHost adds or replaces a host with the given state (zero state = new host).
func (m *Machine) PutHost(h Host) {
	if h.Observed == "" {
		h.Observed = Unknown
	}
	if h.Reported == "" {
		h.Reported = Unknown
	}
	m.hosts[h.ID] = &h
}

// RemoveHost drops a host. No events; children keep their ParentID (dangling
// parents count as no parent).
func (m *Machine) RemoveHost(id string) {
	delete(m.hosts, id)
}

// PutMaintenance loads a window without emitting maintenance.started.
func (m *Machine) PutMaintenance(w Maintenance) {
	m.maint[w.ID] = &w
}

// AssignBox binds a box to a site and tenant and resets the state of its hosts.
func (m *Machine) AssignBox(boxID, tenantID, siteID string) {
	b, ok := m.boxes[boxID]
	if !ok {
		return
	}
	b.TenantID, b.SiteID = tenantID, siteID
	m.dirtyBoxes[boxID] = struct{}{}
	for _, h := range m.hosts {
		if h.BoxID == boxID {
			m.resetHost(h)
		}
	}
}

// UnassignBox detaches a box; its hosts' states are dropped. No events.
func (m *Machine) UnassignBox(boxID string) {
	b, ok := m.boxes[boxID]
	if !ok {
		return
	}
	b.TenantID, b.SiteID = "", ""
	m.dirtyBoxes[boxID] = struct{}{}
	for _, h := range m.hosts {
		if h.BoxID == boxID {
			m.resetHost(h)
		}
	}
}

// SetHostTopology changes parent/uplink of a host and reconciles the box, because
// suppression may have changed for the host and its descendants.
func (m *Machine) SetHostTopology(hostID, parentID string, isUplink bool, at time.Time) []event.Event {
	h, ok := m.hosts[hostID]
	if !ok {
		return nil
	}
	h.ParentID, h.IsUplink = parentID, isUplink
	m.dirtyHosts[hostID] = struct{}{}
	return m.reconcileBox(h.BoxID, at)
}

func (m *Machine) resetHost(h *Host) {
	*h = Host{ID: h.ID, BoxID: h.BoxID, ParentID: h.ParentID, IsUplink: h.IsUplink, Ref: h.Ref,
		Observed: Unknown, Reported: Unknown}
	m.dirtyHosts[h.ID] = struct{}{}
}

// ---- reading -------------------------------------------------------------------

// Box returns a copy of a box's state.
func (m *Machine) Box(id string) (Box, bool) {
	b, ok := m.boxes[id]
	if !ok {
		return Box{}, false
	}
	return *b, true
}

// Host returns a copy of a host's state.
func (m *Machine) Host(id string) (Host, bool) {
	h, ok := m.hosts[id]
	if !ok {
		return Host{}, false
	}
	return *h, true
}

// Hosts returns copies of all hosts, ordered by id.
func (m *Machine) Hosts() []Host {
	out := make([]Host, 0, len(m.hosts))
	for _, h := range m.hosts {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Maintenances returns copies of all active windows, ordered by id.
func (m *Machine) Maintenances() []Maintenance {
	out := make([]Maintenance, 0, len(m.maint))
	for _, w := range m.maint {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// InMaintenance reports whether a host is covered by a window. A window counts
// until Tick or EndMaintenance removes it — never by comparing clocks here — so
// maintenance.ended always precedes the host events it releases.
func (m *Machine) InMaintenance(hostID string) bool {
	h, ok := m.hosts[hostID]
	if !ok {
		return false
	}
	return m.inMaintenance(h)
}

// Suppressed reports whether events for a host are currently suppressed and why
// ("box_silent", "maintenance", "uplink:<id>" or "").
func (m *Machine) Suppressed(hostID string) string {
	h, ok := m.hosts[hostID]
	if !ok {
		return ""
	}
	return m.suppressed(h)
}

// Dirty returns the hosts and boxes whose state changed since the last call and
// clears the record. The caller persists them.
func (m *Machine) Dirty() (hosts, boxes []string) {
	for id := range m.dirtyHosts {
		hosts = append(hosts, id)
	}
	for id := range m.dirtyBoxes {
		boxes = append(boxes, id)
	}
	sort.Strings(hosts)
	sort.Strings(boxes)
	m.dirtyHosts = map[string]struct{}{}
	m.dirtyBoxes = map[string]struct{}{}
	return hosts, boxes
}

// ---- inputs ------------------------------------------------------------------

// Heartbeat applies a heartbeat received at `at` (server time). Rounds are applied
// in order, then every host of the box is reconciled, ancestors first.
func (m *Machine) Heartbeat(boxID string, at time.Time, agentVersion string, reports []wire.HostReport) []event.Event {
	b, ok := m.boxes[boxID]
	if !ok {
		return nil
	}
	var events []event.Event
	if b.Status == Silent {
		b.Status = Online
		if b.Assigned() {
			silentFor := at.Sub(b.SilentSince)
			since := b.SilentSince
			ev := event.New(event.BoxBack, at)
			ev.Source = event.SourceState
			ev.TenantID, ev.SiteID, ev.BoxID = b.TenantID, b.SiteID, b.ID
			ev.Since = &since
			ev.Details = map[string]any{
				"silent_for_s":  int64(silentFor / time.Second),
				"agent_version": agentVersion,
			}
			events = append(events, ev)
		}
		b.SilentSince = time.Time{}
	}
	b.LastHeartbeat = at
	b.AgentVersion = agentVersion
	m.dirtyBoxes[boxID] = struct{}{}

	for _, rep := range reports {
		h, ok := m.hosts[rep.HostID]
		if !ok || h.BoxID != boxID {
			continue // unknown host or a host of another box: ignored, never trusted
		}
		for _, r := range rep.Rounds {
			m.applyRound(h, r, at)
		}
	}
	events = append(events, m.reconcileBox(boxID, at)...)
	return events
}

// Tick advances time: silence detection and maintenance expiry.
func (m *Machine) Tick(at time.Time) []event.Event {
	var events []event.Event
	touched := map[string]struct{}{}

	// Expire maintenance windows.
	for _, w := range m.sortedMaint() {
		if !w.Until.After(at) {
			delete(m.maint, w.ID)
			events = append(events, maintenanceEnded(w, at, "expired"))
			for _, h := range m.hosts {
				if m.windowCovers(w, h) {
					touched[h.BoxID] = struct{}{}
				}
			}
		}
	}

	// Silence detection.
	for _, b := range m.sortedBoxes() {
		if b.Status != Online || b.LastHeartbeat.IsZero() {
			continue
		}
		if at.Sub(b.LastHeartbeat) < b.silenceAfter() {
			continue
		}
		b.Status = Silent
		b.SilentSince = b.LastHeartbeat
		m.dirtyBoxes[b.ID] = struct{}{}
		if !b.Assigned() {
			continue
		}
		since := b.LastHeartbeat
		ev := event.New(event.BoxSilent, at)
		ev.Source = event.SourceState
		ev.TenantID, ev.SiteID, ev.BoxID = b.TenantID, b.SiteID, b.ID
		ev.Since = &since
		hb := b.HeartbeatInterval
		ev.Details = map[string]any{
			"missed_heartbeats": int64(at.Sub(b.LastHeartbeat) / hb),
			"last_heartbeat_at": b.LastHeartbeat.UTC(),
		}
		events = append(events, ev)
	}

	for boxID := range touched {
		events = append(events, m.reconcileBox(boxID, at)...)
	}
	return events
}

// StartMaintenance opens a window (or updates an existing one with the same id —
// no second started event) and emits maintenance.started.
func (m *Machine) StartMaintenance(w Maintenance, at time.Time) []event.Event {
	if _, exists := m.maint[w.ID]; exists {
		m.maint[w.ID] = &w
		return nil
	}
	m.maint[w.ID] = &w
	ev := event.New(event.MaintenanceStarted, at)
	ev.Source = event.SourceMaintenance
	ev.TenantID, ev.SiteID = w.TenantID, w.SiteID
	if w.Scope == ScopeHost {
		ev.HostID = w.TargetID
		if h, ok := m.hosts[w.TargetID]; ok {
			ev.BoxID = h.BoxID
			ref := h.Ref
			ev.Host = &ref
		}
	}
	until := w.Until
	ev.Maintenance = &event.MaintenanceRef{Scope: string(w.Scope), Until: &until, Reason: w.Reason, SetBy: w.SetBy}
	return []event.Event{ev}
}

// EndMaintenance clears a window early, emits maintenance.ended and reconciles the
// hosts it covered.
func (m *Machine) EndMaintenance(id string, at time.Time) []event.Event {
	w, ok := m.maint[id]
	if !ok {
		return nil
	}
	delete(m.maint, id)
	events := []event.Event{maintenanceEnded(w, at, "cleared")}
	touched := map[string]struct{}{}
	for _, h := range m.hosts {
		if m.windowCovers(w, h) {
			touched[h.BoxID] = struct{}{}
		}
	}
	for boxID := range touched {
		events = append(events, m.reconcileBox(boxID, at)...)
	}
	return events
}

// ---- internals -----------------------------------------------------------------

func (m *Machine) applyRound(h *Host, r wire.Round, at time.Time) {
	m.dirtyHosts[h.ID] = struct{}{}
	h.LastBoxTime = r.At
	h.LastChecks = append([]wire.CheckResult(nil), r.Checks...)
	if r.OK {
		if h.Successes == 0 {
			h.RunStart = at
		}
		h.Successes++
		h.Failures = 0
		if h.Observed != Up && h.Successes >= SuccessesToUp {
			h.Observed = Up
			h.Since = h.RunStart
		}
		return
	}
	if h.Failures == 0 {
		h.RunStart = at
	}
	h.Failures++
	h.Successes = 0
	h.LastFailedChecks = h.LastFailedChecks[:0]
	for _, c := range r.Checks {
		if !c.OK {
			h.LastFailedChecks = append(h.LastFailedChecks, c.Type)
		}
	}
	if h.Observed != Down && h.Failures >= FailuresToDown {
		h.Observed = Down
		h.Since = h.RunStart
		h.DownSince = h.RunStart
	}
}

// reconcileBox reconciles every host of a box, ancestors before descendants, so an
// uplink that just went down suppresses its children in the same pass.
func (m *Machine) reconcileBox(boxID string, at time.Time) []event.Event {
	b, ok := m.boxes[boxID]
	if !ok {
		return nil
	}
	var hosts []*Host
	for _, h := range m.hosts {
		if h.BoxID == boxID {
			hosts = append(hosts, h)
		}
	}
	sort.Slice(hosts, func(i, j int) bool {
		di, dj := m.depth(hosts[i]), m.depth(hosts[j])
		if di != dj {
			return di < dj
		}
		return hosts[i].ID < hosts[j].ID
	})
	var events []event.Event
	for _, h := range hosts {
		if ev, ok := m.reconcile(b, h, at); ok {
			events = append(events, ev)
		}
	}
	return events
}

// reconcile implements the table in ADR-0004.
func (m *Machine) reconcile(b *Box, h *Host, at time.Time) (event.Event, bool) {
	if !b.Assigned() || m.suppressed(h) != "" || h.Observed == Unknown {
		return event.Event{}, false
	}
	switch {
	case h.Observed == Up && h.Reported == Down:
		h.Reported = Up
		m.dirtyHosts[h.ID] = struct{}{}
		return m.hostEvent(b, h, event.HostUp, at), true
	case h.Observed == Up:
		if h.Reported != Up {
			h.Reported = Up
			m.dirtyHosts[h.ID] = struct{}{}
		}
		return event.Event{}, false
	case h.Observed == Down && h.Reported != Down:
		h.Reported = Down
		m.dirtyHosts[h.ID] = struct{}{}
		return m.hostEvent(b, h, event.HostDown, at), true
	}
	return event.Event{}, false
}

func (m *Machine) hostEvent(b *Box, h *Host, t event.Type, at time.Time) event.Event {
	ev := event.New(t, at)
	ev.Source = event.SourceState
	ev.TenantID, ev.SiteID, ev.BoxID, ev.HostID = b.TenantID, b.SiteID, b.ID, h.ID
	ref := h.Ref
	ev.Host = &ref
	since := h.Since
	ev.Since = &since
	switch t {
	case event.HostDown:
		failed := append([]string(nil), h.LastFailedChecks...)
		ev.Details = map[string]any{
			"checks_failed":        failed,
			"consecutive_failures": h.Failures,
			"box_time":             h.LastBoxTime.UTC(),
		}
	case event.HostUp:
		var downFor int64
		if !h.DownSince.IsZero() {
			downFor = int64(h.Since.Sub(h.DownSince) / time.Second)
		}
		ev.Details = map[string]any{
			"down_for_s":            downFor,
			"consecutive_successes": h.Successes,
			"box_time":              h.LastBoxTime.UTC(),
		}
	}
	return ev
}

// suppressed returns the reason a host's events are suppressed, or "".
func (m *Machine) suppressed(h *Host) string {
	if b, ok := m.boxes[h.BoxID]; ok && b.Status == Silent {
		return "box_silent"
	}
	if m.inMaintenance(h) {
		return "maintenance"
	}
	if id := m.downAncestor(h); id != "" {
		return "uplink:" + id
	}
	return ""
}

func (m *Machine) inMaintenance(h *Host) bool {
	for _, w := range m.maint {
		if m.windowCovers(w, h) {
			return true
		}
	}
	return false
}

func (m *Machine) windowCovers(w *Maintenance, h *Host) bool {
	switch w.Scope {
	case ScopeHost:
		return w.TargetID == h.ID
	case ScopeSite:
		b, ok := m.boxes[h.BoxID]
		return ok && b.SiteID == w.TargetID
	case ScopeTenant:
		b, ok := m.boxes[h.BoxID]
		return ok && b.TenantID == w.TargetID
	}
	return false
}

// downAncestor walks the parent chain (cycle-safe) and returns the first ancestor
// whose observed state is Down.
func (m *Machine) downAncestor(h *Host) string {
	seen := map[string]bool{h.ID: true}
	for pid := h.ParentID; pid != "" && !seen[pid]; {
		seen[pid] = true
		p, ok := m.hosts[pid]
		if !ok {
			return ""
		}
		if p.Observed == Down {
			return p.ID
		}
		pid = p.ParentID
	}
	return ""
}

func (m *Machine) depth(h *Host) int {
	d := 0
	seen := map[string]bool{h.ID: true}
	for pid := h.ParentID; pid != "" && !seen[pid]; {
		seen[pid] = true
		p, ok := m.hosts[pid]
		if !ok {
			break
		}
		d++
		pid = p.ParentID
	}
	return d
}

func (m *Machine) sortedMaint() []*Maintenance {
	out := make([]*Maintenance, 0, len(m.maint))
	for _, w := range m.maint {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *Machine) sortedBoxes() []*Box {
	out := make([]*Box, 0, len(m.boxes))
	for _, b := range m.boxes {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func maintenanceEnded(w *Maintenance, at time.Time, how string) event.Event {
	ev := event.New(event.MaintenanceEnded, at)
	ev.Source = event.SourceMaintenance
	ev.TenantID, ev.SiteID = w.TenantID, w.SiteID
	if w.Scope == ScopeHost {
		ev.HostID = w.TargetID
	}
	ev.Maintenance = &event.MaintenanceRef{Scope: string(w.Scope), Reason: w.Reason, Ended: how}
	return ev
}
