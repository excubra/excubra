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

	// enable: key minted in the box group, handed to the box, state key
	ra, err := w.svc.Enable(ctx, "site_a", "192.168.10.0/24", "jeremia")
	must(t, err)
	if ra.State != store.RemoteKey || ra.CIDR != "192.168.10.0/24" || len(w.fake.Keys) != 1 {
		t.Fatalf("after enable: %+v keys=%d", ra, len(w.fake.Keys))
	}
	k, err := w.st.NetbirdKeyProfile(ctx, "box_a", wire.NetbirdProfileOperator)
	if err != nil || k.SetupKey != w.fake.Keys[0].Key || k.ManagementURL != w.srv.URL || k.ClaimedAt != nil {
		t.Fatalf("operator key: %+v %v", k, err)
	}
	if _, err := w.svc.Enable(ctx, "site_b", "192.168.10.128/25", "jeremia"); !errors.Is(err, ErrOverlap) {
		t.Fatalf("overlap not refused: %v", err)
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
	must(t, w.st.UpdateBoxHeartbeat(ctx, "box_a", wire.Heartbeat{Agent: wire.AgentInfo{Version: "0.2.3"}, NetbirdOperator: &wire.NetbirdInfo{Status: wire.NetbirdConnected, IP: "100.90.0.7"}}, w.now))
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
	if len(w.fake.Policies) != 1 || w.fake.Policies[0].Name != PolicyName {
		t.Fatalf("policy: %+v", w.fake.Policies)
	}
	var names []string
	for _, g := range w.fake.Groups {
		names = append(names, g.Name)
	}
	if got := strings.Join(names, " "); got != "viico kunden-box kunden-lan" {
		t.Fatalf("groups: %q", got)
	}

	// a second reconcile changes nothing but the peer state text
	w.fake.Peers[0].Connected = false
	w.svc.Reconcile(ctx)
	ra, _ = w.st.RemoteAccess(ctx, "site_a")
	if ra.State != store.RemoteActive || !strings.Contains(ra.Detail, "nicht verbunden") || len(w.fake.Networks) != 1 {
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

	// remove deletes the network and the row
	must(t, w.svc.Remove(ctx, "site_a", "jeremia"))
	if _, err := w.st.RemoteAccess(ctx, "site_a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("row survived remove")
	}
	if len(w.fake.Networks) != 0 {
		t.Fatal("network survived remove")
	}
}

func TestKeyNobodyFetchesExpires(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	must(t, w.svc.SaveSettings(ctx, w.srv.URL, "tok", "", "", ""))
	_, err := w.svc.Enable(ctx, "site_a", "10.1.0.0/16", "jeremia")
	must(t, err)
	w.now = w.now.Add(3 * time.Hour)
	w.svc.Reconcile(ctx)
	ra, _ := w.st.RemoteAccess(ctx, "site_a")
	if ra.State != store.RemoteError || !strings.Contains(ra.Detail, "Operator-Daemon") {
		t.Fatalf("expected a timeout error: %+v", ra)
	}
}
