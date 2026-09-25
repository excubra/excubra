//go:build preview

package console_test

// Design preview for the single-page console: seeds pilot-like data, logs in, and keeps a
// local server running for a while. It prints the URL and the raw session cookie so a
// browser can be pointed at the app without typing a password.
//
//	EX0_PREVIEW_SERVE=20m go test -tags preview -run TestPreviewServe -timeout 1h ./internal/server/console/ -v
//
// The httptest server listens on a random port. EX0_PREVIEW_ADDR additionally exposes
// it on a fixed address (127.0.0.1:18080 is what web/vite.config.ts proxies to).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/api"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

func TestPreviewServe(t *testing.T) {
	dur := os.Getenv("EX0_PREVIEW_SERVE")
	if dur == "" {
		t.Skip("EX0_PREVIEW_SERVE not set")
	}
	d, err := time.ParseDuration(dur)
	if err != nil {
		t.Fatal(err)
	}
	f := seedPreview(t)
	u, _ := url.Parse(f.srv.URL)
	var raw string
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == "excubra_session" {
			raw = c.Value
		}
	}
	if addr := os.Getenv("EX0_PREVIEW_ADDR"); addr != "" {
		proxy := httputil.NewSingleHostReverseProxy(u)
		go func() { _ = http.ListenAndServe(addr, proxy) }()
		t.Logf("PREVIEW_ADDR=http://%s/", addr)
	}
	t.Logf("PREVIEW_URL=%s/", f.srv.URL)
	t.Logf("PREVIEW_COOKIE=excubra_session=%s", raw)
	time.Sleep(d)
}

// seedPreview builds a logged-in fixture with a customer whose box sees a few
// devices, and an application that reports itself (ADR-0023) with a day of events.
func seedPreview(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.login(t)
	ctx := context.Background()
	now := time.Now()
	post := func(path string, form url.Values) string {
		t.Helper()
		status, body := f.postJSON(path, form, f.csrf)
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", path, status, body)
		}
		return body
	}

	post("/api/tenants", url.Values{"slug": {"muster"}, "name": {"Muster Sport e.V."}})
	post("/api/tenants/ten_muster/sites", url.Values{"slug": {"geschaeftsstelle"}, "name": {"Geschäftsstelle"}})
	box := store.Box{ID: "box_wns7sxvzvnrc", HWID: "ff65b128111ed14d", CertSerial: "bb055137284f7ab04745abbf7ee06237",
		CertNotAfter: now.Add(89 * 24 * time.Hour), EnrolledAt: now.Add(-2 * time.Hour), Channel: "stable", DiscoveryMode: "sweep", OS: "linux", Arch: "amd64"}
	must(t, f.st.CreateBox(ctx, box))
	f.eng.RegisterBox(store.Box{ID: box.ID})
	post("/api/boxes/"+box.ID+"/assign", url.Values{"site_id": {"site_geschaeftsstelle"}})
	box, err := f.st.Box(ctx, box.ID)
	must(t, err)
	var seen []wire.Sighting
	for _, d := range []struct{ ip, mac, vendor, host string }{
		{"192.168.100.254", "02:00:00:da:1c:4b", "Fortinet, Inc.", ""},
		{"192.168.100.25", "02:00:00:de:1e:2f", "Proxmox Server Solutions GmbH", ""},
		{"192.168.100.19", "02:00:00:61:d0:70", "Proxmox Server Solutions GmbH", "MUSTER-RDS"},
		{"192.168.100.15", "02:00:00:cd:b7:34", "Proxmox Server Solutions GmbH", "truenas"},
		{"192.168.100.36", "02:00:00:e7:38:66", "INNOVAPHONE AG", ""},
		{"192.168.100.8", "02:00:00:7e:5d:d1", "Brother Industries, LTD.", "BRNB422004535AB"},
	} {
		seen = append(seen, wire.Sighting{MAC: d.mac, IP: d.ip, Vendor: d.vendor, Hostname: d.host, LastSeen: now.Add(-40 * time.Second)})
	}
	if _, err := f.eng.Heartbeat(ctx, box, wire.Heartbeat{SentAt: now.Add(-30 * time.Second), Agent: wire.AgentInfo{Version: "v0.18.0", UptimeS: 25000},
		Box: wire.BoxInfo{DiskTotalBytes: 4_100_000_000, DiskFreeBytes: 3_000_000_000}, Discovery: wire.DiscoveryReport{Seen: seen}}); err != nil {
		t.Fatal(err)
	}

	// VIIDOC reports itself from the private network.
	post("/api/tenants", url.Values{"slug": {"viico"}, "name": {"VIICO GmbH"}})
	post("/api/tenants/ten_viico/sites", url.Values{"slug": {"rechenzentrum"}, "name": {"Rechenzentrum"}})
	var created struct {
		Token string `json:"token"`
	}
	must(t, json.Unmarshal([]byte(post("/api/sources", url.Values{"site": {"site_rechenzentrum"}, "name": {"VIIDOC"}, "address": {"10.100.10.3"}})), &created))
	tok, err := f.st.APITokenByHash(ctx, api.HashToken(created.Token))
	must(t, err)
	var events []core.SourceEvent
	add := func(ago time.Duration, kind, actor, ip, target, summary string) {
		events = append(events, core.SourceEvent{EventID: fmt.Sprintf("preview-%03d", len(events)), OccurredAt: now.Add(-ago),
			Kind: kind, Actor: actor, IP: ip, Target: target, Summary: summary})
	}
	add(26*time.Hour, "auth.login", "anna@viico.test", "198.51.100.7", "", "Anmeldung über Microsoft")
	add(25*time.Hour, "ticket.create", "anna@viico.test", "", "T-2026-0412", "Drucker im Empfang druckt nicht")
	add(19*time.Hour, "hr.viewed", "chef@viico.test", "198.51.100.7", "Personalakte Tim Beispiel", "")
	add(6*time.Hour, "auth.device.new", "tim@viico.test", "198.51.100.23", "", "Safari auf einem iPhone")
	add(5*time.Hour, "settings.bank", "chef@viico.test", "198.51.100.7", "company.bank1_iban", "DE02 1203 … → DE89 3704 …")
	add(3*time.Hour, "download", "anna@viico.test", "198.51.100.7", "Angebot A-2026-118.pdf", "")
	add(2*time.Hour, "user.admin", "chef@viico.test", "198.51.100.7", "tim@viico.test", "Technik → Verwaltung")
	add(90*time.Minute, "auth.emergency", "chef@viico.test", "192.0.2.10", "", "Notzugang über SSH ausgestellt")
	for i := range 12 {
		add(time.Duration(12-i)*time.Minute, "auth.refused", "", "203.0.113.9", "", "Microsoft: Konto unbekannt")
	}
	add(time.Minute, "ticket.close", "tim@viico.test", "", "T-2026-0412", "Treiber neu installiert")
	if _, err := f.eng.SourceReport(ctx, tok, core.SourcePost{Events: events, Status: &core.SourceStatus{Version: "v1.9.0", CertNotAfter: now.AddDate(0, 0, 11)}}); err != nil {
		t.Fatal(err)
	}
	return f
}
