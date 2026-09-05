package state

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/wire"
)

var t0 = time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

const (
	boxA  = "box_a"
	fw    = "host_fw"  // uplink
	srv   = "host_srv" // child of fw
	nas   = "host_nas" // independent
	tenA  = "ten_a"
	siteA = "site_a"
)

type fixture struct {
	t   *testing.T
	m   *Machine
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	m := New()
	m.PutBox(Box{ID: boxA, TenantID: tenA, SiteID: siteA})
	m.PutHost(Host{ID: fw, BoxID: boxA, IsUplink: true, Ref: event.HostRef{Name: "FortiGate", IP: "192.168.1.1"}})
	m.PutHost(Host{ID: srv, BoxID: boxA, ParentID: fw, Ref: event.HostRef{Name: "srv01", IP: "192.168.1.10"}})
	m.PutHost(Host{ID: nas, BoxID: boxA, Ref: event.HostRef{Name: "nas", IP: "192.168.1.20"}})
	f := &fixture{t: t, m: m, now: t0}
	// first heartbeat with no rounds: box is online from t0
	f.m.Heartbeat(boxA, f.now, "0.1.0", nil)
	f.m.Dirty()
	return f
}

// hb advances 60 s and delivers one heartbeat; rounds maps host id → ok flags.
func (f *fixture) hb(rounds map[string][]bool) []event.Event {
	f.now = f.now.Add(60 * time.Second)
	ids := make([]string, 0, len(rounds))
	for id := range rounds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var reports []wire.HostReport
	for _, id := range ids {
		var rs []wire.Round
		for i, ok := range rounds[id] {
			at := f.now.Add(-30 * time.Second * time.Duration(len(rounds[id])-i))
			if ok {
				rs = append(rs, wire.Round{At: at, OK: true, Checks: []wire.CheckResult{{Type: "icmp", OK: true}}})
			} else {
				rs = append(rs, wire.Round{At: at, OK: false, Checks: []wire.CheckResult{
					{Type: "icmp", OK: false, Error: "timeout"}, {Type: "tcp:443", OK: false, Error: "refused"}}})
			}
		}
		reports = append(reports, wire.HostReport{HostID: id, Rounds: rs})
	}
	return f.m.Heartbeat(boxA, f.now, "0.1.0", reports)
}

// tick advances by d and ticks.
func (f *fixture) tick(d time.Duration) []event.Event {
	f.now = f.now.Add(d)
	return f.m.Tick(f.now)
}

func types(evs []event.Event) string {
	var s []string
	for _, e := range evs {
		id := e.HostID
		if id == "" {
			id = e.BoxID
		}
		s = append(s, string(e.Type)+"("+id+")")
	}
	return strings.Join(s, " ")
}

func (f *fixture) want(evs []event.Event, want string) {
	f.t.Helper()
	if got := types(evs); got != want {
		f.t.Fatalf("at %s: events = [%s], want [%s]", f.now.Format("15:04:05"), got, want)
	}
}

func (f *fixture) none(evs []event.Event) { f.t.Helper(); f.want(evs, "") }

func (f *fixture) host(id string) Host {
	f.t.Helper()
	h, ok := f.m.Host(id)
	if !ok {
		f.t.Fatalf("host %s missing", id)
	}
	return h
}

// ---- host transitions -----------------------------------------------------------

func TestHostDownAfterThreeFailures(t *testing.T) {
	f := newFixture(t)
	f.none(f.hb(map[string][]bool{nas: {false}}))
	firstFail := f.now
	f.none(f.hb(map[string][]bool{nas: {false}}))
	evs := f.hb(map[string][]bool{nas: {false}})
	f.want(evs, "host.down(host_nas)")
	f.none(f.hb(map[string][]bool{nas: {false}})) // stays down, no repeat

	e := evs[0]
	if e.Severity != event.Warning || e.TenantID != tenA || e.SiteID != siteA || e.BoxID != boxA {
		t.Fatalf("envelope wrong: %+v", e)
	}
	if e.Since == nil || !e.Since.Equal(firstFail) {
		t.Fatalf("since = %v, want %v (first failed heartbeat)", e.Since, firstFail)
	}
	if e.Details["consecutive_failures"] != 3 {
		t.Fatalf("consecutive_failures = %v", e.Details["consecutive_failures"])
	}
	if got := e.Details["checks_failed"].([]string); len(got) != 2 || got[0] != "icmp" || got[1] != "tcp:443" {
		t.Fatalf("checks_failed = %v", got)
	}
	if e.Host == nil || e.Host.Name != "nas" {
		t.Fatalf("host ref missing: %+v", e.Host)
	}
	h := f.host(nas)
	if h.Observed != Down || h.Reported != Down || h.Failures != 4 {
		t.Fatalf("host state: %+v", h)
	}
}

func TestHostUpAfterTwoSuccesses(t *testing.T) {
	f := newFixture(t)
	f.want(f.hb(map[string][]bool{nas: {false, false, false}}), "host.down(host_nas)")
	f.none(f.hb(map[string][]bool{nas: {true}}))
	evs := f.hb(map[string][]bool{nas: {true}})
	f.want(evs, "host.up(host_nas)")
	if evs[0].Severity != event.Info {
		t.Fatalf("severity = %s", evs[0].Severity)
	}
	if evs[0].Details["down_for_s"] != int64(60) { // down since hb1, up since hb2
		t.Fatalf("down_for_s = %v", evs[0].Details["down_for_s"])
	}
	f.none(f.hb(map[string][]bool{nas: {true}}))
}

func TestFlappingProducesOneEvent(t *testing.T) {
	f := newFixture(t)
	f.none(f.hb(map[string][]bool{nas: {false, false, true}}))
	f.none(f.hb(map[string][]bool{nas: {false, false}}))
	f.want(f.hb(map[string][]bool{nas: {false}}), "host.down(host_nas)")

	g := newFixture(t)
	for i := 0; i < 5; i++ {
		g.none(g.hb(map[string][]bool{nas: {true, false}}))
	}
	if h := g.host(nas); h.Observed != Unknown {
		t.Fatalf("a host that never had 2 ok or 3 failed in a row must stay unknown, got %s", h.Observed)
	}
}

func TestNewHostUpIsSilent(t *testing.T) {
	f := newFixture(t)
	f.none(f.hb(map[string][]bool{nas: {true, true}}))
	if h := f.host(nas); h.Observed != Up || h.Reported != Up {
		t.Fatalf("host state: %+v", h)
	}
}

func TestNewHostDownReports(t *testing.T) {
	f := newFixture(t)
	f.want(f.hb(map[string][]bool{nas: {false, false, false}}), "host.down(host_nas)")
}

func TestDownUpAlternate(t *testing.T) {
	f := newFixture(t)
	var all []event.Event
	pattern := []bool{false, false, false, true, true, false, false, false, true, true, false, false, false}
	for _, ok := range pattern {
		all = append(all, f.hb(map[string][]bool{nas: {ok}})...)
	}
	f.want(all, "host.down(host_nas) host.up(host_nas) host.down(host_nas) host.up(host_nas) host.down(host_nas)")
}

// ---- box silence ----------------------------------------------------------------

func TestSilence(t *testing.T) {
	f := newFixture(t)
	f.none(f.tick(200 * time.Second))
	evs := f.tick(10 * time.Second) // 210 s = 3×60 + 30 grace
	f.want(evs, "box.silent(box_a)")
	if evs[0].Severity != event.Critical || evs[0].Details["missed_heartbeats"] != int64(3) {
		t.Fatalf("box.silent details: %+v", evs[0])
	}
	f.none(f.tick(300 * time.Second))
	if b, _ := f.m.Box(boxA); b.Status != Silent {
		t.Fatalf("box status = %s", b.Status)
	}
	f.now = f.now.Add(100 * time.Second)
	evs = f.m.Heartbeat(boxA, f.now, "0.2.0", nil)
	f.want(evs, "box.back(box_a)")
	if evs[0].Details["silent_for_s"] != int64(610) || evs[0].Details["agent_version"] != "0.2.0" {
		t.Fatalf("box.back details: %+v", evs[0].Details)
	}
	if b, _ := f.m.Box(boxA); b.Status != Online {
		t.Fatalf("box status = %s", b.Status)
	}
}

func TestSilenceFreezesHostsAndCountersContinue(t *testing.T) {
	f := newFixture(t)
	f.none(f.hb(map[string][]bool{nas: {false, false}}))
	f.want(f.tick(210*time.Second), "box.silent(box_a)")
	f.none(f.tick(600 * time.Second))
	// the box returns and reports the third failure: exactly box.back + host.down
	f.want(f.hb(map[string][]bool{nas: {false}}), "box.back(box_a) host.down(host_nas)")
}

func TestSilentBoxSuppressesEverything(t *testing.T) {
	f := newFixture(t)
	f.want(f.hb(map[string][]bool{nas: {false, false, false}}), "host.down(host_nas)")
	f.want(f.tick(210*time.Second), "box.silent(box_a)")
	if got := f.m.Suppressed(nas); got != "box_silent" {
		t.Fatalf("suppressed = %q", got)
	}
	// maintenance expiring while silent must not emit host events
	f.m.PutMaintenance(Maintenance{ID: "m1", Scope: ScopeHost, TargetID: nas, TenantID: tenA, SiteID: siteA, Until: f.now.Add(time.Second)})
	f.want(f.tick(10*time.Second), "maintenance.ended(host_nas)")
}

func TestUnassignedBoxNeverEmits(t *testing.T) {
	m := New()
	m.PutBox(Box{ID: "box_new"})
	m.PutHost(Host{ID: "host_x", BoxID: "box_new"})
	now := t0
	if evs := m.Heartbeat("box_new", now, "0.1.0", []wire.HostReport{{HostID: "host_x", Rounds: []wire.Round{
		{At: now, OK: false}, {At: now, OK: false}, {At: now, OK: false}}}}); len(evs) != 0 {
		t.Fatalf("unassigned box emitted %s", types(evs))
	}
	if evs := m.Tick(now.Add(time.Hour)); len(evs) != 0 {
		t.Fatalf("unassigned box emitted %s", types(evs))
	}
	if b, _ := m.Box("box_new"); b.Status != Silent {
		t.Fatalf("status still tracked for unassigned boxes, got %s", b.Status)
	}
	if evs := m.Heartbeat("box_new", now.Add(2*time.Hour), "0.1.0", nil); len(evs) != 0 {
		t.Fatalf("unassigned box emitted %s", types(evs))
	}
}

// ---- uplink ---------------------------------------------------------------------

func TestUplinkDownSuppressesChildren(t *testing.T) {
	f := newFixture(t)
	f.none(f.hb(map[string][]bool{fw: {true, true}, srv: {true, true}}))
	evs := f.hb(map[string][]bool{fw: {false, false, false}, srv: {false, false, false}})
	f.want(evs, "host.down(host_fw)")
	if got := f.m.Suppressed(srv); got != "uplink:host_fw" {
		t.Fatalf("suppressed = %q", got)
	}
	if h := f.host(srv); h.Observed != Down || h.Reported != Up {
		t.Fatalf("child state: observed=%s reported=%s", h.Observed, h.Reported)
	}
	f.none(f.hb(map[string][]bool{fw: {false}, srv: {false}}))
	// uplink recovers, child is still dead: up for the uplink, then one down for the child
	f.want(f.hb(map[string][]bool{fw: {true, true}, srv: {false}}), "host.up(host_fw) host.down(host_srv)")
}

func TestChildFailingBeforeUplinkIsReported(t *testing.T) {
	f := newFixture(t)
	f.none(f.hb(map[string][]bool{fw: {true, true}, srv: {true, true}}))
	f.want(f.hb(map[string][]bool{fw: {true}, srv: {false, false, false}}), "host.down(host_srv)")
	f.want(f.hb(map[string][]bool{fw: {false, false, false}, srv: {false}}), "host.down(host_fw)")
	f.want(f.hb(map[string][]bool{fw: {true, true}, srv: {true, true}}), "host.up(host_fw) host.up(host_srv)")
}

func TestUplinkChain(t *testing.T) {
	f := newFixture(t)
	f.m.PutHost(Host{ID: "host_leaf", BoxID: boxA, ParentID: srv})
	f.none(f.hb(map[string][]bool{fw: {true, true}, srv: {true, true}, "host_leaf": {true, true}}))
	f.want(f.hb(map[string][]bool{fw: {false, false, false}, srv: {false, false, false}, "host_leaf": {false, false, false}}),
		"host.down(host_fw)")
	if got := f.m.Suppressed("host_leaf"); got != "uplink:host_srv" { // nearest down ancestor
		t.Fatalf("leaf suppressed = %q", got)
	}
}

func TestParentCycleDoesNotHang(t *testing.T) {
	m := New()
	m.PutBox(Box{ID: boxA, TenantID: tenA, SiteID: siteA})
	m.PutHost(Host{ID: "host_a", BoxID: boxA, ParentID: "host_b"})
	m.PutHost(Host{ID: "host_b", BoxID: boxA, ParentID: "host_a"})
	rounds := []wire.Round{{At: t0, OK: false}, {At: t0, OK: false}, {At: t0, OK: false}}
	done := make(chan struct{})
	go func() {
		m.Heartbeat(boxA, t0, "0.1.0", []wire.HostReport{{HostID: "host_a", Rounds: rounds}, {HostID: "host_b", Rounds: rounds}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("parent cycle hangs the machine")
	}
}

func TestSetHostTopologyReconciles(t *testing.T) {
	f := newFixture(t)
	f.none(f.hb(map[string][]bool{fw: {true, true}, nas: {true, true}}))
	f.want(f.hb(map[string][]bool{fw: {false, false, false}, nas: {false, false, false}}), "host.down(host_fw) host.down(host_nas)")
	// nas was independent; making fw its parent changes nothing now (already reported)
	f.none(f.m.SetHostTopology(nas, fw, false, f.now))
	// fw recovers; nas stays down and was already reported: only fw up
	f.want(f.hb(map[string][]bool{fw: {true, true}, nas: {false}}), "host.up(host_fw)")
}

// ---- maintenance ----------------------------------------------------------------

func TestMaintenanceCoversFailure(t *testing.T) {
	f := newFixture(t)
	w := Maintenance{ID: "m1", Scope: ScopeHost, TargetID: nas, TenantID: tenA, SiteID: siteA,
		Until: f.now.Add(10 * time.Minute), Reason: "reboot", SetBy: "jeremia"}
	evs := f.m.StartMaintenance(w, f.now)
	f.want(evs, "maintenance.started(host_nas)")
	if evs[0].Maintenance == nil || evs[0].Maintenance.Scope != "host" || evs[0].Maintenance.Reason != "reboot" {
		t.Fatalf("maintenance ref: %+v", evs[0].Maintenance)
	}
	f.none(f.m.StartMaintenance(w, f.now)) // same id: update, no second event
	f.none(f.hb(map[string][]bool{nas: {false, false, false}}))
	if got := f.m.Suppressed(nas); got != "maintenance" {
		t.Fatalf("suppressed = %q", got)
	}
	for i := 0; i < 9; i++ { // the box keeps heartbeating, the host keeps failing
		f.none(f.hb(map[string][]bool{nas: {false, false}}))
	}
	f.want(f.tick(0), "maintenance.ended(host_nas) host.down(host_nas)") // window ends at +10 min
	f.none(f.hb(map[string][]bool{nas: {false}}))
}

func TestMaintenanceCoversRecovery(t *testing.T) {
	f := newFixture(t)
	f.want(f.hb(map[string][]bool{nas: {false, false, false}}), "host.down(host_nas)")
	f.want(f.m.StartMaintenance(Maintenance{ID: "m1", Scope: ScopeHost, TargetID: nas, TenantID: tenA, SiteID: siteA,
		Until: f.now.Add(time.Hour)}, f.now), "maintenance.started(host_nas)")
	f.none(f.hb(map[string][]bool{nas: {true, true}}))
	f.want(f.m.EndMaintenance("m1", f.now), "maintenance.ended(host_nas) host.up(host_nas)")
	f.none(f.m.EndMaintenance("m1", f.now)) // already gone
}

func TestMaintenanceNoChangeNoEvent(t *testing.T) {
	f := newFixture(t)
	f.none(f.hb(map[string][]bool{nas: {true, true}}))
	f.want(f.m.StartMaintenance(Maintenance{ID: "m1", Scope: ScopeHost, TargetID: nas, TenantID: tenA, SiteID: siteA,
		Until: f.now.Add(time.Hour)}, f.now), "maintenance.started(host_nas)")
	f.none(f.hb(map[string][]bool{nas: {false, false, false}}))
	f.none(f.hb(map[string][]bool{nas: {true, true}})) // died and recovered inside the window
	f.want(f.m.EndMaintenance("m1", f.now), "maintenance.ended(host_nas)")
}

func TestSiteAndTenantScope(t *testing.T) {
	for _, tc := range []struct {
		scope  Scope
		target string
	}{{ScopeSite, siteA}, {ScopeTenant, tenA}} {
		f := newFixture(t)
		evs := f.m.StartMaintenance(Maintenance{ID: "m1", Scope: tc.scope, TargetID: tc.target, TenantID: tenA, SiteID: siteA,
			Until: f.now.Add(time.Hour)}, f.now)
		if len(evs) != 1 || evs[0].Type != event.MaintenanceStarted || evs[0].HostID != "" {
			t.Fatalf("%s: started = %s", tc.scope, types(evs))
		}
		f.none(f.hb(map[string][]bool{fw: {false, false, false}, srv: {false, false, false}, nas: {false, false, false}}))
		evs = f.m.EndMaintenance("m1", f.now)
		// fw down is reported, srv suppressed by fw, nas reported
		f.want(evs, "maintenance.ended() host.down(host_fw) host.down(host_nas)")
	}
}

func TestNestedMaintenance(t *testing.T) {
	f := newFixture(t)
	f.m.StartMaintenance(Maintenance{ID: "site", Scope: ScopeSite, TargetID: siteA, TenantID: tenA, SiteID: siteA,
		Until: f.now.Add(20 * time.Minute)}, f.now)
	f.m.StartMaintenance(Maintenance{ID: "host", Scope: ScopeHost, TargetID: nas, TenantID: tenA, SiteID: siteA,
		Until: f.now.Add(10 * time.Minute)}, f.now)
	f.none(f.hb(map[string][]bool{nas: {false, false, false}}))
	for i := 0; i < 9; i++ {
		f.none(f.hb(map[string][]bool{nas: {false, false}}))
	}
	f.want(f.tick(0), "maintenance.ended(host_nas)") // +10 min: still covered by the site window
	for i := 0; i < 10; i++ {
		f.none(f.hb(map[string][]bool{nas: {false, false}}))
	}
	f.want(f.tick(0), "maintenance.ended() host.down(host_nas)") // +20 min
}

// ---- configuration changes --------------------------------------------------------

func TestUnassignAndReassignResetsHosts(t *testing.T) {
	f := newFixture(t)
	f.want(f.hb(map[string][]bool{nas: {false, false, false}}), "host.down(host_nas)")
	f.m.UnassignBox(boxA)
	if h := f.host(nas); h.Observed != Unknown || h.Reported != Unknown || h.Failures != 0 {
		t.Fatalf("host not reset: %+v", h)
	}
	f.none(f.hb(map[string][]bool{nas: {false, false, false}})) // unassigned: silent
	f.m.AssignBox(boxA, tenA, siteA)
	f.want(f.hb(map[string][]bool{nas: {false, false, false}}), "host.down(host_nas)")
}

func TestRemovedAndForeignHostsIgnored(t *testing.T) {
	f := newFixture(t)
	f.m.RemoveHost(nas)
	f.none(f.hb(map[string][]bool{nas: {false, false, false}}))
	f.m.PutBox(Box{ID: "box_other", TenantID: "ten_b", SiteID: "site_b"})
	f.m.PutHost(Host{ID: "host_foreign", BoxID: "box_other"})
	f.none(f.hb(map[string][]bool{"host_foreign": {false, false, false}})) // reported by box_a: ignored
	if h := f.host("host_foreign"); h.Failures != 0 {
		t.Fatalf("foreign host touched: %+v", h)
	}
	f.m.RemoveBox("box_other")
	if _, ok := f.m.Host("host_foreign"); ok {
		t.Fatal("RemoveBox left a host behind")
	}
}

func TestDirtyTracking(t *testing.T) {
	f := newFixture(t)
	f.hb(map[string][]bool{nas: {true}})
	hosts, boxes := f.m.Dirty()
	if len(hosts) != 1 || hosts[0] != nas || len(boxes) != 1 || boxes[0] != boxA {
		t.Fatalf("dirty = %v %v", hosts, boxes)
	}
	if hosts, boxes = f.m.Dirty(); len(hosts) != 0 || len(boxes) != 0 {
		t.Fatalf("dirty not cleared: %v %v", hosts, boxes)
	}
}

func TestHostsAndMaintenancesAreSortedCopies(t *testing.T) {
	f := newFixture(t)
	hs := f.m.Hosts()
	if len(hs) != 3 || hs[0].ID != fw || hs[1].ID != nas || hs[2].ID != srv {
		t.Fatalf("hosts = %+v", hs)
	}
	hs[0].Observed = Down
	if h := f.host(fw); h.Observed == Down {
		t.Fatal("Hosts() returned a reference, not a copy")
	}
	f.m.PutMaintenance(Maintenance{ID: "b"})
	f.m.PutMaintenance(Maintenance{ID: "a"})
	ms := f.m.Maintenances()
	if len(ms) != 2 || ms[0].ID != "a" {
		t.Fatalf("maintenances = %+v", ms)
	}
}
