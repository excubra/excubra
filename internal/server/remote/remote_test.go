package remote

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/netbird"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

type world struct {
	st   *store.Store
	fake *netbird.Fake
	srv  *httptest.Server
	svc  *Service
	now  time.Time
}

func newWorld(t *testing.T) *world {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fake := netbird.NewFake("tok")
	fake.Groups = []netbird.Group{{ID: "grp_viico", Name: "viico"}}
	srv := httptest.NewServer(fake.Handler())
	t.Cleanup(srv.Close)
	w := &world{st: st, fake: fake, srv: srv, now: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)}
	w.svc = New(st, nil)
	w.svc.Now = func() time.Time { return w.now }
	ctx := context.Background()
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Muster GmbH", CreatedAt: w.now}))
	must(t, st.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "Werk", CreatedAt: w.now}))
	must(t, st.CreateSite(ctx, store.Site{ID: "site_b", TenantID: "ten_a", Name: "Lager", CreatedAt: w.now}))
	must(t, st.CreateBox(ctx, store.Box{ID: "box_a", SiteID: "site_a", Name: "muster-box", HWID: "hw", CertSerial: "1", CertNotAfter: w.now.Add(time.Hour), EnrolledAt: w.now}))
	must(t, st.CreateBox(ctx, store.Box{ID: "box_b", SiteID: "site_b", Name: "lager-box", HWID: "hw2", CertSerial: "2", CertNotAfter: w.now.Add(time.Hour), EnrolledAt: w.now}))
	return w
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// the box reports its operator daemon in the heartbeat; that is all the server sees of it
func (w *world) report(t *testing.T, boxID, status, ip string) {
	t.Helper()
	must(t, w.st.UpdateBoxHeartbeat(context.Background(), boxID, wire.Heartbeat{Agent: wire.AgentInfo{Version: "0.2.7"}, NetbirdOperator: &wire.NetbirdInfo{Status: status, IP: ip}}, w.now))
}

func (w *world) operatorKey(t *testing.T, boxID string) (store.NetbirdKey, error) {
	t.Helper()
	return w.st.NetbirdKeyProfile(context.Background(), boxID, wire.NetbirdProfileOperator)
}

func TestEnableWiresTheLANOnceTheBoxJoined(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()

	// not configured yet: a clear error, nothing created
	if _, err := w.svc.Enable(ctx, "site_a", "192.168.10.0/24", "jeremia"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unconfigured: %v", err)
	}
	must(t, w.svc.SaveSettings(ctx, w.srv.URL, "tok", "", "", ""))
	if s := w.svc.Settings(ctx); !s.HasToken || s.TechGroup != "viico" || s.LANGroup != "kunden-lan" {
		t.Fatalf("settings %+v", s)
	}
	if n, err := w.svc.Test(ctx); err != nil || n != 1 {
		t.Fatalf("test: %d %v", n, err)
	}

	// bad and overlapping LANs are refused
	for _, bad := range []string{"8.8.8.0/24", "192.168.10.5", "fe80::/64", "10.0.0.0/7"} {
		if _, err := w.svc.Enable(ctx, "site_a", bad, "jeremia"); !errors.Is(err, ErrBadCIDR) {
			t.Fatalf("%s accepted: %v", bad, err)
		}
	}

	// a LAN somebody already routes by hand in our stack is refused
	w.fake.Networks = append(w.fake.Networks, netbird.Network{ID: "net_bridge", Name: "KfT LAN (Bridge)"})
	w.fake.Res["net_bridge"] = []netbird.Resource{{ID: "res_b", Name: "lan", Address: "192.168.10.0/24", Enabled: true}}
	if _, err := w.svc.Enable(ctx, "site_a", "192.168.10.0/24", "jeremia"); !errors.Is(err, ErrOverlap) || !strings.Contains(err.Error(), "Bridge") {
		t.Fatalf("hand-built bridge not refused: %v", err)
	}
	w.fake.Networks = nil
	delete(w.fake.Res, "net_bridge")

	// enable before the box ever reported an operator daemon: the row waits, no key is minted
	ra, err := w.svc.Enable(ctx, "site_a", "192.168.10.0/24", "jeremia")
	must(t, err)
	if ra.State != store.RemoteKey || ra.CIDR != "192.168.10.0/24" || len(w.fake.Keys) != 0 || !strings.Contains(ra.Detail, "Operator-Daemon") {
		t.Fatalf("after enable: %+v keys=%d", ra, len(w.fake.Keys))
	}
	if _, err := w.svc.Enable(ctx, "site_b", "192.168.10.128/25", "jeremia"); !errors.Is(err, ErrOverlap) {
		t.Fatalf("overlap not refused: %v", err)
	}

	// the box reports an idle operator daemon: the next reconcile mints its key, the other box gets none
	w.report(t, "box_a", wire.NetbirdNotConfigured, "")
	w.svc.Reconcile(ctx)
	k, err := w.operatorKey(t, "box_a")
	if err != nil || len(w.fake.Keys) != 1 || k.SetupKey != w.fake.Keys[0].Key || k.ManagementURL != w.srv.URL || k.ClaimedAt != nil {
		t.Fatalf("operator key: %+v %v keys=%d", k, err, len(w.fake.Keys))
	}
	if _, err := w.operatorKey(t, "box_b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a box without the daemon got a key: %v", err)
	}
	if !strings.Contains(w.fake.Keys[0].Name, "Muster GmbH · Werk · muster-box") {
		t.Fatalf("key name %q", w.fake.Keys[0].Name)
	}

	// the box claims the key: joining
	_, err = w.st.ClaimNetbirdKeyProfile(ctx, "box_a", wire.NetbirdProfileOperator, w.now)
	must(t, err)
	w.svc.Reconcile(ctx)
	ra, _ = w.st.RemoteAccess(ctx, "site_a")
	if ra.State != store.RemoteJoining {
		t.Fatalf("after claim: %+v", ra)
	}

	// the box reports its operator peer; the API knows the peer: network, resource, router
	w.report(t, "box_a", wire.NetbirdConnected, "100.90.0.7")
	w.fake.Peers = []netbird.Peer{{ID: "peer_box_a", Hostname: "muster-box", IP: "100.90.0.7", Connected: true}}
	w.svc.Reconcile(ctx)
	ra, _ = w.st.RemoteAccess(ctx, "site_a")
	if ra.State != store.RemoteActive || ra.PeerID != "peer_box_a" || ra.NetworkID == "" || ra.ResourceID == "" || ra.RouterID == "" {
		t.Fatalf("after wiring: %+v", ra)
	}
	if len(w.fake.Networks) != 1 || w.fake.Networks[0].Name != "Muster GmbH · Werk" {
		t.Fatalf("network: %+v", w.fake.Networks)
	}
	res := w.fake.Res[ra.NetworkID]
	if len(res) != 1 || res[0].Address != "192.168.10.0/24" || !res[0].Enabled {
		t.Fatalf("resource: %+v", res)
	}
	if rt := w.fake.Routers[ra.NetworkID]; len(rt) != 1 || rt[0].Peer != "peer_box_a" || !rt[0].Masquerade {
		t.Fatalf("router: %+v", rt)
	}
	if len(w.fake.Policies) != 2 || w.fake.Policies[0].Name != PolicyName || w.fake.Policies[1].Name != PolicyBoxName {
		t.Fatalf("policies: %+v", w.fake.Policies)
	}
	var names []string
	for _, g := range w.fake.Groups {
		names = append(names, g.Name)
	}
	if got := strings.Join(names, " "); got != "viico kunden-lan kunden-box" {
		t.Fatalf("groups: %q", got)
	}

	// a second reconcile changes nothing but the peer state text
	w.fake.Peers[0].Connected = false
	w.svc.Reconcile(ctx)
	ra, _ = w.st.RemoteAccess(ctx, "site_a")
	if ra.State != store.RemoteActive || !strings.Contains(ra.Detail, "nicht verbunden") || len(w.fake.Networks) != 1 || len(w.fake.Policies) != 2 {
		t.Fatalf("refresh: %+v networks=%d", ra, len(w.fake.Networks))
	}

	// disable switches the resource off; enable again reuses everything without a new key
	ra, err = w.svc.Disable(ctx, "site_a", "jeremia")
	must(t, err)
	if ra.State != store.RemoteOff || ra.Enabled || w.fake.Res[ra.NetworkID][0].Enabled {
		t.Fatalf("after disable: %+v", ra)
	}
	w.fake.Peers[0].Connected = true
	ra, err = w.svc.Enable(ctx, "site_a", "192.168.10.0/24", "jeremia")
	must(t, err)
	if ra.State != store.RemoteActive || len(w.fake.Keys) != 1 || len(w.fake.Networks) != 1 || !w.fake.Res[ra.NetworkID][0].Enabled {
		t.Fatalf("re-enable: %+v keys=%d", ra, len(w.fake.Keys))
	}

	// remove deletes the network and the row; the box stays a peer, its key record stays
	must(t, w.svc.Remove(ctx, "site_a", "jeremia"))
	if _, err := w.st.RemoteAccess(ctx, "site_a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("row survived remove")
	}
	if len(w.fake.Networks) != 0 {
		t.Fatal("network survived remove")
	}
	if _, err := w.operatorKey(t, "box_a"); err != nil {
		t.Fatalf("remove took the box out of the stack: %v", err)
	}
}

// The box image is one package: a box that reports its operator daemon becomes a
// peer in our stack without anyone switching a LAN on, and keys that go nowhere are
// replaced — but not while the daemon is connecting on its own.
func TestBoxesBecomePeersOnTheirOwn(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	must(t, w.svc.SaveSettings(ctx, w.srv.URL, "tok", "", "", ""))
	keys := func(n int, what string) {
		t.Helper()
		if len(w.fake.Keys) != n {
			t.Fatalf("%s: %d keys, want %d", what, len(w.fake.Keys), n)
		}
	}

	w.svc.Reconcile(ctx)
	keys(0, "nothing reported")

	w.report(t, "box_a", wire.NetbirdNotConfigured, "")
	w.svc.Reconcile(ctx)
	keys(1, "idle daemon reported")
	w.svc.Reconcile(ctx)
	keys(1, "key still waiting")

	// nobody fetched it within its lifetime: replaced, and the record carries the new one
	w.now = w.now.Add(keyTTL + time.Minute)
	w.svc.Reconcile(ctx)
	keys(2, "expired unfetched")
	if k, _ := w.operatorKey(t, "box_a"); k.SetupKey != w.fake.Keys[1].Key || k.ClaimedAt != nil {
		t.Fatalf("record not renewed: %+v", k)
	}

	// fetched, daemon still idle: patience for two hours, then a new key
	_, err := w.st.ClaimNetbirdKeyProfile(ctx, "box_a", wire.NetbirdProfileOperator, w.now)
	must(t, err)
	w.now = w.now.Add(time.Hour)
	w.svc.Reconcile(ctx)
	keys(2, "fetched an hour ago")
	w.now = w.now.Add(2 * time.Hour)
	w.svc.Reconcile(ctx)
	keys(3, "fetched, still unconfigured after the timeout")

	// fetched and the daemon has its config (disconnected while it connects): left alone
	_, err = w.st.ClaimNetbirdKeyProfile(ctx, "box_a", wire.NetbirdProfileOperator, w.now)
	must(t, err)
	w.report(t, "box_a", wire.NetbirdDisconnected, "")
	w.now = w.now.Add(5 * time.Hour)
	w.svc.Reconcile(ctx)
	keys(3, "connecting on its own")

	w.report(t, "box_a", wire.NetbirdConnected, "100.90.0.7")
	w.svc.Reconcile(ctx)
	keys(3, "connected")

	// a box that never reports a daemon never gets one; the listing says so
	if _, err := w.operatorKey(t, "box_b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("box_b: %v", err)
	}
	ps, err := w.svc.PeerStates(ctx)
	must(t, err)
	if len(ps) != 2 || ps[0].BoxID != "box_a" || ps[0].Status != wire.NetbirdConnected || ps[0].IP != "100.90.0.7" || !strings.HasPrefix(ps[0].Key, "fetched") {
		t.Fatalf("peer states: %+v", ps)
	}
	if ps[1].BoxID != "box_b" || ps[1].Status != "no operator daemon" || ps[1].Key != "none" {
		t.Fatalf("peer states: %+v", ps)
	}
	if len(w.fake.Policies) != 2 {
		t.Fatalf("policies: %+v", w.fake.Policies)
	}
}

func TestKeyNobodyFetchesExpires(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	must(t, w.svc.SaveSettings(ctx, w.srv.URL, "tok", "", "", ""))
	w.report(t, "box_a", wire.NetbirdNotConfigured, "")
	_, err := w.svc.Enable(ctx, "site_a", "10.1.0.0/16", "jeremia")
	must(t, err)
	if len(w.fake.Keys) != 1 {
		t.Fatalf("enable did not mint the key right away: %d", len(w.fake.Keys))
	}
	w.now = w.now.Add(3 * time.Hour)
	w.svc.Reconcile(ctx)
	ra, _ := w.st.RemoteAccess(ctx, "site_a")
	if ra.State != store.RemoteError || !strings.Contains(ra.Detail, "Operator-Daemon") {
		t.Fatalf("expected a timeout error: %+v", ra)
	}
}
