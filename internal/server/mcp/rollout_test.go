package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/console"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/netbird"
	"github.com/excubra/excubra/internal/server/remote"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

type nopPub struct{}

func (nopPub) Publish(context.Context, event.Event) error { return nil }

// rollout is a server with everything a session's set-up tools reach: the
// engine, the console's watch rule, remote access against a pretend NetBird.
type rollout struct {
	t    *testing.T
	st   *store.Store
	eng  *core.Engine
	rem  *remote.Service
	fake *netbird.Fake
	s    *Server
	now  time.Time
}

func newRollout(t *testing.T) *rollout {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	must(t, err)
	t.Cleanup(func() { _ = st.Close() })
	ca, err := pki.LoadOrCreateCA(dir + "/ca")
	must(t, err)
	r := &rollout{t: t, st: st, now: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)}
	now := func() time.Time { return r.now }
	r.eng, err = core.Load(context.Background(), st, nopPub{}, slog.New(slog.DiscardHandler))
	must(t, err)
	r.eng.Now = now
	con, err := console.New(r.eng, st, ca, slog.New(slog.DiscardHandler), time.UTC, "ingest.example.test", 443)
	must(t, err)
	con.Now = now
	r.fake = netbird.NewFake("tok")
	r.fake.Groups = []netbird.Group{{ID: "grp_viico", Name: "viico"}}
	srv := httptest.NewServer(r.fake.Handler())
	t.Cleanup(srv.Close)
	r.rem = remote.New(st, slog.New(slog.DiscardHandler))
	r.rem.Now = now
	r.rem.SetLocalNets = r.eng.SetSiteLocalNets
	must(t, r.rem.SaveSettings(context.Background(), srv.URL, "tok", "", "", ""))
	r.s = &Server{Store: st, Now: now, Actor: "claude-kunde", CAFingerprint: ca.Fingerprint(), Ingest: "ingest.example.test", IngestPt: 443,
		Engine: r.eng, Remote: r.rem, Watch: con}
	return r
}

func (r *rollout) call(name string, args map[string]any) map[string]any {
	r.t.Helper()
	out, err := r.s.call(context.Background(), name, args)
	if err != nil {
		r.t.Fatalf("%s: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		r.t.Fatalf("%s: %v in %s", name, err, out)
	}
	return m
}

func (r *rollout) fails(name string, args map[string]any, want string) {
	r.t.Helper()
	_, err := r.s.call(context.Background(), name, args)
	if err == nil || !strings.Contains(err.Error(), want) {
		r.t.Fatalf("%s must be refused with %q: %v", name, want, err)
	}
}

// status returns the checklist as step → state, and whether the site is done.
func (r *rollout) status(siteID string) (map[string]string, map[string]string, bool) {
	r.t.Helper()
	m := r.call("ex0_rollout_status", map[string]any{"site_id": siteID})
	states, details := map[string]string{}, map[string]string{}
	for _, v := range m["steps"].([]any) {
		st := v.(map[string]any)
		states[st["step"].(string)] = st["state"].(string)
		details[st["step"].(string)], _ = st["detail"].(string)
	}
	done, _ := m["done"].(bool)
	return states, details, done
}

// box plays the box: it enrolled with the site's key and sends a heartbeat.
func (r *rollout) box(boxID, siteID string, hb wire.Heartbeat) {
	r.t.Helper()
	ctx := context.Background()
	if _, err := r.st.Box(ctx, boxID); err != nil {
		b := store.Box{ID: boxID, HWID: "hw-" + boxID, CertSerial: boxID, CertNotAfter: r.now.Add(90 * 24 * time.Hour), EnrolledAt: r.now}
		must(r.t, r.st.CreateBox(ctx, b))
		r.eng.RegisterBox(b)
		must(r.t, r.eng.AssignBox(ctx, boxID, siteID, "key"))
	}
	if hb.Agent.Version == "" {
		hb.Agent.Version = "0.0.0-dev"
	}
	must(r.t, r.st.UpdateBoxHeartbeat(ctx, boxID, hb, r.now))
}

// A customer in one session: from nothing to a site that is watched and
// reachable, with one question after every step — how far is it — and an
// answer that names what is missing. Nobody clicks anything.
func TestARolloutInOneSession(t *testing.T) {
	r := newRollout(t)
	ctx := context.Background()

	r.call("ex0_create_tenant", map[string]any{"slug": "muster", "name": "Muster GmbH"})
	r.call("ex0_create_site", map[string]any{"tenant_id": "ten_muster", "slug": "werk", "name": "Werk"})
	// the site went through the engine: a box that enrolls finds it at once
	if st, _, done := r.status("site_werk"); st["box"] != "open" || done {
		t.Fatalf("an empty site: %v", st)
	}
	nb := r.call("ex0_new_box", map[string]any{"site_id": "site_werk", "ctid": float64(200), "ip": "192.168.10.60/24", "gw": "192.168.10.1"})
	if nb["hostname"] != "ex0-muster-werk" {
		t.Fatalf("hostname: %v", nb["hostname"])
	}
	if st, d, _ := r.status("site_werk"); st["box"] != "waiting" || !strings.Contains(d["box"], "wartet") {
		t.Fatalf("a key that waits for its command: %v %v", st, d)
	}
	// set-up that needs a box says so instead of failing oddly
	r.fails("ex0_site_lan", map[string]any{"site_id": "site_werk"}, "noch keine Box")
	r.fails("ex0_customer_vpn", map[string]any{"site_id": "site_werk", "management_url": "https://muster.vpn.example.test", "setup_key": "0123456789abcdef0123"}, "noch keine Box")

	// the box enrolls and reports; its operator peer is still joining
	r.box("box_werk", "site_werk", wire.Heartbeat{Box: wire.BoxInfo{LAN: []string{"192.168.10.0/24"}, LANIP: "192.168.10.60"}, NetbirdOperator: &wire.NetbirdInfo{Status: wire.NetbirdDisconnected}})
	st, _, _ := r.status("site_werk")
	if st["box"] != "ok" || st["lan"] != "ok" || st["operator_vpn"] != "waiting" || st["remote_access"] != "waiting" || st["devices"] != "waiting" || st["watch"] != "open" || st["customer_vpn"] != "optional" || st["scan"] != "optional" {
		t.Fatalf("a box that just arrived: %v", st)
	}

	// the peer joins; the server wires the LAN by itself
	r.box("box_werk", "site_werk", wire.Heartbeat{Box: wire.BoxInfo{LAN: []string{"192.168.10.0/24"}, LANIP: "192.168.10.60"}, NetbirdOperator: &wire.NetbirdInfo{Status: wire.NetbirdConnected, IP: "100.90.0.7"}})
	r.fake.Peers = []netbird.Peer{{ID: "peer_werk", Hostname: "ex0-muster-werk", IP: "100.90.0.7", Connected: true}}
	r.rem.Reconcile(ctx)
	st, d, _ := r.status("site_werk")
	if st["operator_vpn"] != "ok" || st["remote_access"] != "ok" || !strings.Contains(d["operator_vpn"], "ssh root@100.90.0.7") || !strings.Contains(d["remote_access"], "192.168.10.0/24") {
		t.Fatalf("remote access: %v %v", st, d)
	}

	// what the box sees in the LAN
	seen := func(mac, ip, vendor, host string) string {
		dev, _, _, err := r.st.UpsertSighting(ctx, "ten_muster", "site_werk", wire.Sighting{MAC: mac, IP: ip, Vendor: vendor, Hostname: host, LastSeen: r.now}, r.now)
		must(t, err)
		return dev.ID
	}
	fw := seen("00:09:0f:00:00:01", "192.168.10.1", "Fortinet, Inc.", "")
	dc := seen("94:40:c9:00:00:02", "192.168.10.5", "Hewlett Packard Enterprise", "MUSTER-DC")
	seen("80:5e:c0:00:00:03", "192.168.10.80", "Yealink", "")
	lap := seen("f8:75:a4:00:00:04", "192.168.10.120", "LCFC(HeFei) Electronics", "LAPTOP-7")

	sug := r.call("ex0_watch_suggestion", map[string]any{"site_id": "site_werk"})
	if add := sug["would_add"].([]any); len(add) != 3 {
		t.Fatalf("the rule proposes what stays put (firewall, server, phone), not the laptop: %v", sug)
	}
	// the proposal, and the domain controller asked the way that matters: its DNS port
	w := r.call("ex0_watch", map[string]any{"site_id": "site_werk", "suggested": true, "devices": []any{
		map[string]any{"device_id": dc, "checks": []any{"icmp", "tcp:53"}},
	}})
	if added := w["suggested"].(map[string]any)["added"].([]any); len(added) != 3 {
		t.Fatalf("suggested: %v", w)
	}
	if upd := w["devices"].(map[string]any)["updated"].([]any); len(upd) != 1 {
		t.Fatalf("the watched server gets its checks changed, not a second host: %v", w)
	}
	hosts, _ := r.st.Hosts(ctx, "ten_muster", "box_werk")
	if len(hosts) != 3 {
		t.Fatalf("hosts: %+v", hosts)
	}
	for _, h := range hosts {
		switch h.DeviceID {
		case fw:
			if !h.IsUplink {
				t.Fatal("the firewall is the uplink: one cut line is one outage")
			}
		case dc:
			if len(h.Checks) != 2 || h.Checks[1].Type != wire.CheckTCP || h.Checks[1].Port != 53 || h.IsUplink {
				t.Fatalf("dc: %+v", h)
			}
		}
	}
	// the engine knows the hosts: the box gets them with its next config
	b, _ := r.st.Box(ctx, "box_werk")
	cfg, err := r.eng.Config(ctx, b)
	must(t, err)
	if len(cfg.Hosts) != 3 {
		t.Fatalf("the box's config carries %d hosts, want 3", len(cfg.Hosts))
	}
	// what the box cannot ask is refused, a foreign device too; a laptop can be picked on purpose
	r.fails("ex0_watch", map[string]any{"site_id": "site_werk", "devices": []any{map[string]any{"device_id": dc, "checks": []any{"snmp:161"}}}}, "andere Prüfungen kennt die Box nicht")
	r.fails("ex0_watch", map[string]any{"site_id": "site_werk"}, "suggested")
	w = r.call("ex0_watch", map[string]any{"site_id": "site_werk", "devices": []any{map[string]any{"device_id": "dev_gibtesnicht"}, map[string]any{"device_id": lap, "uplink": false}}})
	out := w["devices"].(map[string]any)
	if len(out["failed"].([]any)) != 1 || len(out["added"].([]any)) != 1 {
		t.Fatalf("picked by hand: %v", w)
	}

	// the customer's own VPN: handed to the box, claimed once, forgotten by the server
	r.fails("ex0_customer_vpn", map[string]any{"site_id": "site_werk", "management_url": "http://muster.vpn.example.test", "setup_key": "0123456789abcdef0123"}, "https://")
	r.call("ex0_customer_vpn", map[string]any{"site_id": "site_werk", "management_url": "https://muster.vpn.example.test/", "setup_key": "0123456789ABCDEF-0123"})
	if st, _, _ := r.status("site_werk"); st["customer_vpn"] != "waiting" {
		t.Fatalf("handed over, not fetched: %v", st)
	}
	nk, err := r.st.ClaimNetbirdKey(ctx, "box_werk", r.now)
	if err != nil || nk.ManagementURL != "https://muster.vpn.example.test" || nk.SetupKey != "0123456789ABCDEF-0123" {
		t.Fatalf("what the box claims: %+v %v", nk, err)
	}
	r.box("box_werk", "site_werk", wire.Heartbeat{Box: wire.BoxInfo{LAN: []string{"192.168.10.0/24"}, LANIP: "192.168.10.60"}, Netbird: wire.NetbirdInfo{Status: wire.NetbirdConnected, IP: "100.77.0.9"},
		NetbirdOperator: &wire.NetbirdInfo{Status: wire.NetbirdConnected, IP: "100.90.0.7"}})

	// the scan: not without the consent on the record
	r.fails("ex0_site_scan", map[string]any{"site_id": "site_werk", "on": true}, "Einwilligung")
	r.fails("ex0_site_scan", map[string]any{"site_id": "site_werk", "on": true, "consent": "ja"}, "Einwilligung")
	r.call("ex0_site_scan", map[string]any{"site_id": "site_werk", "on": true, "consent": "Herr Muster am 01.10.2026 per Mail, Vertrag §7"})
	if site, _ := r.st.Site(ctx, "site_werk"); !site.ScanEnabled {
		t.Fatal("scan not switched on")
	}

	st, _, done := r.status("site_werk")
	for _, step := range []string{"box", "version", "operator_vpn", "lan", "remote_access", "customer_vpn", "devices", "watch", "scan"} {
		if st[step] != "ok" {
			t.Fatalf("%s: %s — all steps: %v", step, st[step], st)
		}
	}
	if !done {
		t.Fatalf("every step is ok or optional, so the site is done: %v", st)
	}

	// everything the session did is on the record under its name
	audit, _ := r.st.AuditEntries(ctx, 100, 0)
	did := map[string]bool{}
	for _, a := range audit {
		if a.Actor == "claude-kunde" {
			did[a.Action] = true
		}
	}
	for _, action := range []string{"tenant.create", "site.create", "key.new", "host.create", "host.update", "site.watch.suggested", "netbird.set", "site.scan.consent", "site.scan"} {
		if !did[action] {
			t.Fatalf("no audit entry %q under the session's actor: %v", action, did)
		}
	}
}

// A LAN numbered with public addresses, as the second customer's was
// (29.09.2026). The status names the problem and the way out; the declaration
// takes a person's confirmation.
func TestALANOutsideRFC1918TakesAConfirmation(t *testing.T) {
	r := newRollout(t)
	ctx := context.Background()
	r.call("ex0_create_tenant", map[string]any{"slug": "kanzlei", "name": "Kanzlei"})
	r.call("ex0_create_site", map[string]any{"tenant_id": "ten_kanzlei", "slug": "buero", "name": "Büro"})
	r.box("box_k", "site_buero", wire.Heartbeat{Box: wire.BoxInfo{LANOther: []string{"192.0.2.0/24"}, LANIP: "192.0.2.79"}, NetbirdOperator: &wire.NetbirdInfo{Status: wire.NetbirdConnected, IP: "100.90.0.9"}})
	r.fake.Peers = []netbird.Peer{{ID: "peer_k", Hostname: "ex0-kanzlei-buero", IP: "100.90.0.9", Connected: true}}
	r.rem.Reconcile(ctx)

	st, d, done := r.status("site_buero")
	if st["lan"] != "open" || st["remote_access"] != "open" || done || !strings.Contains(d["lan"], "192.0.2.0/24") || !strings.Contains(d["remote_access"], "kein privater Adressbereich") {
		t.Fatalf("the status must name the network and the reason: %v %v", st, d)
	}
	// without the confirmation: refused, with the consequence spelled out
	r.fails("ex0_site_lan", map[string]any{"site_id": "site_buero"}, "confirm_public")
	r.fails("ex0_site_lan", map[string]any{"site_id": "site_buero", "lan": "198.51.100.0/24", "confirm_public": true}, "in dem die Box selbst steht")

	out := r.call("ex0_site_lan", map[string]any{"site_id": "site_buero", "confirm_public": true})
	if out["lan"] != "192.0.2.0/24" || out["state"] != store.RemoteActive {
		t.Fatalf("declared: %v", out)
	}
	st, _, _ = r.status("site_buero")
	if st["lan"] != "ok" || st["remote_access"] != "ok" {
		t.Fatalf("after the declaration: %v", st)
	}
	// the engine heard it: the rules count that network as inside from now on
	site, _ := r.st.Site(ctx, "site_buero")
	if len(site.LocalNets) != 1 || site.LocalNets[0] != "192.0.2.0/24" {
		t.Fatalf("local nets: %v", site.LocalNets)
	}
}

// Without a server on the socket the command answers from the files. What reads
// still works; what needs the engine says so instead of writing past it.
func TestSetUpToolsNeedTheRunningServer(t *testing.T) {
	st, err := store.Open(t.TempDir())
	must(t, err)
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "A", CreatedAt: now}))
	must(t, st.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "A", CreatedAt: now}))
	must(t, st.CreateBox(ctx, store.Box{ID: "box_a", SiteID: "site_a", HWID: "hw", CertSerial: "1", CertNotAfter: now.Add(time.Hour), EnrolledAt: now, LastSeen: now}))
	s := &Server{Store: st, Now: func() time.Time { return now }, Actor: "x"}
	for name, args := range map[string]map[string]any{
		"ex0_site_lan":         {"site_id": "site_a", "lan": "192.168.1.0/24"},
		"ex0_watch_suggestion": {"site_id": "site_a"},
		"ex0_watch":            {"site_id": "site_a", "suggested": true},
		"ex0_site_scan":        {"site_id": "site_a", "on": false},
	} {
		if _, err := s.call(ctx, name, args); err == nil || !strings.Contains(err.Error(), "laufenden Server") {
			t.Fatalf("%s without a server: %v", name, err)
		}
	}
	if out, err := s.call(ctx, "ex0_rollout_status", map[string]any{"site_id": "site_a"}); err != nil || !strings.Contains(out, "\"step\": \"box\"") {
		t.Fatalf("reading works from the files: %v %s", err, out)
	}
}
