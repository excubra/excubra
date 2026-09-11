//go:build preview

package console_test

// Design preview: renders the console pages with data that looks like the KfT pilot
// into a directory, so the pages can be opened in a browser without a login.
//
//	EX0_PREVIEW_DIR=/tmp/ex0-preview go test -tags preview -run TestPreviewDump ./internal/server/console/
//
// Then serve that directory (it gets a copy of static/) and open status.html & co.

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

func TestPreviewDump(t *testing.T) {
	out := os.Getenv("EX0_PREVIEW_DIR")
	if out == "" {
		t.Skip("EX0_PREVIEW_DIR not set")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	f := seedPreview(t)
	ctx := context.Background()
	hosts, err := f.st.Hosts(ctx, "ten_kft", "")
	must(t, err)
	dumpPreview(t, f, out, hosts)
}

// seedPreview builds a logged-in fixture with data that looks like the KfT pilot.
func seedPreview(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.login(t)
	ctx := context.Background()
	now := time.Now()

	f.post("/tenants", url.Values{"slug": {"kft"}, "name": {"Klub für Terrier von 1894 e.V."}}, true)
	f.post("/tenants/ten_kft/sites", url.Values{"slug": {"geschaeftsstelle"}, "name": {"Geschäftsstelle"}}, true)
	must(t, f.st.CreateBox(ctx, store.Box{ID: "box_wns7sxvzvnrc", HWID: "ff65b128111ed14d", CertSerial: "bb055137284f7ab04745abbf7ee06237",
		CertNotAfter: now.Add(89 * 24 * time.Hour), EnrolledAt: now.Add(-2 * time.Hour), Channel: "stable", DiscoveryMode: "sweep", OS: "linux", Arch: "amd64"}))
	f.eng.RegisterBox(store.Box{ID: "box_wns7sxvzvnrc"})
	f.post("/boxes/box_wns7sxvzvnrc/assign", url.Values{"site_id": {"site_geschaeftsstelle"}}, true)
	f.post("/boxes/box_wns7sxvzvnrc/settings", url.Values{"name": {"kft-box"}, "channel": {"stable"}, "discovery_mode": {"sweep"}}, true)
	box, err := f.st.Box(ctx, "box_wns7sxvzvnrc")
	must(t, err)

	type dev struct{ ip, mac, ven, host string }
	devs := []dev{
		{"192.168.100.254", "84:39:8f:74:63:48", "Fortinet, Inc.", ""},
		{"192.168.100.24", "5c:ba:2c:55:11:08", "Hewlett Packard Enterprise", ""},
		{"192.168.100.25", "bc:24:11:a1:3b:15", "Proxmox Server Solutions GmbH", ""},
		{"192.168.100.19", "bc:24:11:b5:fa:53", "Proxmox Server Solutions GmbH", "KFT-RDS"},
		{"192.168.100.15", "bc:24:11:bc:9a:c2", "Proxmox Server Solutions GmbH", "truenas"},
		{"192.168.100.3", "bc:24:11:88:c4:a7", "Proxmox Server Solutions GmbH", ""},
		{"192.168.100.60", "bc:24:11:80:c7:71", "Proxmox Server Solutions GmbH", "kft-box.local"},
		{"192.168.100.21", "44:4e:6d:72:8d:ab", "AVM Audiovisuelles Marketing und Computersysteme GmbH", ""},
		{"192.168.100.36", "00:90:33:4c:ea:e4", "INNOVAPHONE AG", ""},
		{"192.168.100.41", "00:90:33:4c:cc:29", "INNOVAPHONE AG", ""},
		{"192.168.100.42", "00:90:33:47:02:95", "INNOVAPHONE AG", ""},
		{"192.168.100.121", "00:90:33:4c:eb:83", "INNOVAPHONE AG", ""},
		{"192.168.100.122", "00:90:33:4c:4a:4b", "INNOVAPHONE AG", ""},
		{"192.168.100.153", "00:90:33:4c:cb:ec", "INNOVAPHONE AG", ""},
		{"192.168.100.8", "b4:22:00:45:35:ab", "Brother Industries, LTD.", "BRNB422004535AB"},
		{"192.168.100.35", "b4:22:00:c2:e3:3b", "Brother Industries, LTD.", "BRNB42200C2E33B"},
		{"192.168.100.20", "6c:f2:d8:80:b2:a3", "CANON INC.", ""},
		{"192.168.100.33", "00:1a:fd:15:01:b2", "EVOLIS", ""},
		{"192.168.100.157", "00:07:4d:6c:7e:76", "Zebra Technologies Corp.", ""},
		{"192.168.100.38", "c4:ef:bb:59:06:28", "LCFC(Hefei) Electronics Technology co., ltd", ""},
		{"192.168.100.39", "c4:c6:e6:02:ce:c1", "LCFC(Hefei) Electronics Technology co., ltd", ""},
		{"", "18:3d:2d:4d:40:d6", "LCFC(Hefei) Electronics Technology co., ltd", ""},
		{"", "d0:ad:08:a1:59:c2", "HP Inc.", ""},
		{"", "78:99:87:08:d7:6a", "Xiaomi Communications Co Ltd", ""},
		{"192.168.100.2", "a2:98:9f:a7:3e:1c", "", ""},
		{"", "8e:3c:02:41:86:27", "", ""},
	}
	var seen []wire.Sighting
	for _, d := range devs {
		seen = append(seen, wire.Sighting{MAC: d.mac, IP: d.ip, Vendor: d.ven, Hostname: d.host, LastSeen: now.Add(-40 * time.Second)})
	}
	hb := wire.Heartbeat{SentAt: now.Add(-30 * time.Second), Agent: wire.AgentInfo{Version: "v0.1.0", UptimeS: 25000},
		Box:       wire.BoxInfo{DiskTotalBytes: 4_100_000_000, DiskFreeBytes: 3_000_000_000},
		Netbird:   wire.NetbirdInfo{Status: "connected", IP: "100.112.91.255", Version: "0.78.1"},
		Discovery: wire.DiscoveryReport{Seen: seen}}
	if _, err := f.eng.Heartbeat(ctx, box, hb); err != nil {
		t.Fatal(err)
	}

	stored, err := f.st.Devices(ctx, "ten_kft", "site_geschaeftsstelle", time.Time{})
	must(t, err)
	byIP := map[string]store.Device{}
	for _, d := range stored {
		byIP[d.IP] = d
	}
	for _, ip := range []string{"192.168.100.254", "192.168.100.24", "192.168.100.25", "192.168.100.19", "192.168.100.15"} {
		form := url.Values{}
		if ip == "192.168.100.254" {
			form.Set("uplink", "1")
		}
		if status, _, _ := f.post("/devices/"+byIP[ip].ID+"/watch", form, true); status != 303 {
			t.Fatalf("watch %s: %d", ip, status)
		}
	}
	hosts, err := f.st.Hosts(ctx, "ten_kft", "")
	must(t, err)
	var reports []wire.HostReport
	for _, h := range hosts {
		ok := h.Address != "192.168.100.15" // TrueNAS is down in the preview
		lat := int64(2)
		var rounds []wire.Round
		for i := 0; i < 3; i++ {
			cr := wire.CheckResult{Type: "icmp", OK: ok, LatencyMS: &lat}
			if !ok {
				cr.Error = "timeout"
				cr.LatencyMS = nil
			}
			rounds = append(rounds, wire.Round{At: now.Add(-time.Duration(3-i) * time.Minute), OK: ok, Checks: []wire.CheckResult{cr}})
		}
		reports = append(reports, wire.HostReport{HostID: h.ID, Rounds: rounds})
	}
	hb2 := hb
	hb2.SentAt = now.Add(-2 * time.Second)
	hb2.Hosts = reports
	hb2.Discovery = wire.DiscoveryReport{}
	if _, err := f.eng.Heartbeat(ctx, box, hb2); err != nil {
		t.Fatal(err)
	}
	// a second customer without a box yet, and an unassigned test box
	f.post("/tenants", url.Values{"slug": {"viico"}, "name": {"VIICO GmbH"}}, true)
	f.post("/tenants/ten_viico/sites", url.Values{"slug": {"buero"}, "name": {"Büro Ludwigshafen"}}, true)
	must(t, f.st.CreateBox(ctx, store.Box{ID: "box_rn4ebjmtknby", HWID: "e3b0c44298fc1c14", CertSerial: "2", CertNotAfter: now.Add(89 * 24 * time.Hour),
		EnrolledAt: now.Add(-5 * time.Hour), AgentVersion: "0.0.0-dev+83953d0", OS: "linux", Arch: "arm64", Channel: "stable"}))
	f.eng.RegisterBox(store.Box{ID: "box_rn4ebjmtknby"})
	seedActions(t, f)
	return f
}

// seedActions adds what the action features show: tasks with results, heartbeat
// notes, an acknowledged outage, releases and channel pointers.
func seedActions(t *testing.T, f *fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	const box = "box_wns7sxvzvnrc"
	for _, n := range []string{"update to 0.2.0 not installed: sig: no release key embedded", "netbird up failed: management unreachable"} {
		if err := f.st.AddBoxNote(ctx, box, now.Add(-3*time.Hour), n); err != nil {
			t.Fatal(err)
		}
	}
	done, err := f.eng.QueueTask(ctx, box, wire.TaskRecheck, "jeremia")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.CompleteBoxTask(ctx, box, done.ID, true, "26 hosts checked, 1 failed", now.Add(-40*time.Minute)); err != nil {
		t.Fatal(err)
	}
	failed, err := f.eng.QueueTask(ctx, box, wire.TaskUpdate, "jeremia")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.CompleteBoxTask(ctx, box, failed.ID, false, "update check failed: 204 no release for channel stable", now.Add(-20*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.eng.QueueTask(ctx, box, wire.TaskSweep, "jeremia"); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		if err := f.st.PutRelease(ctx, store.Release{Version: "0.2.0", OS: "linux", Arch: arch, URL: "https://github.com/excubra/excubra/releases/download/v0.2.0/excubra_linux_" + arch, SHA256: "9f2c…", Signature: "MEUCIQ…", MinAgentVersion: "0.1.0", CreatedAt: now.Add(-24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.st.SetChannelVersion(ctx, "canary", "0.2.0"); err != nil {
		t.Fatal(err)
	}
	// a FortiGate connector with a reading, so the device page has something to show
	if err := f.st.SetBoxSealKey(ctx, box, "TzzOyQfgRGO42lA8akZ+KD6gNw7wrOUoWromV7sS/Sw="); err != nil {
		t.Fatal(err)
	}
	devs, err := f.st.Devices(ctx, "ten_kft", "site_geschaeftsstelle", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.IP != "192.168.100.254" {
			continue
		}
		c := store.Connector{ID: "con_fgt01", TenantID: "ten_kft", SiteID: "site_geschaeftsstelle", BoxID: box, DeviceID: d.ID, Kind: wire.ConnectorFortiGate, URL: "https://192.168.100.254",
			Sealed: strings.Repeat("A", 120), SealedBy: "console:jeremia", SealedAt: now.Add(-2 * time.Hour), IntervalS: 300, CreatedAt: now.Add(-2 * time.Hour)}
		if err := f.st.CreateConnector(ctx, c); err != nil {
			t.Fatal(err)
		}
		facts := `{"serial":"FGT60FTK21012345","version":"v7.2.8","build":1639,"hostname":"KFT-FW01","model":"FortiGate 60F","log_disk":"available","ha_mode":"standalone",
			"admin_https_port":8443,"admin_ssh_port":22,"admin_timeout_min":5,"timezone":"Europe/Berlin",
			"interfaces":[{"name":"wan1","alias":"Telekom","link":true,"ip":"217.0.0.12","speed":1000},{"name":"internal","alias":"LAN","link":true,"ip":"192.168.100.254","speed":1000},{"name":"dmz","alias":"","link":false,"ip":"","speed":0}],
			"ipsec":[{"name":"to-viico","gateway":"144.76.67.109","up":true,"phase2":[{"name":"to-viico-p2","status":"up","in_bytes":1284211,"out_bytes":934102}]},{"name":"to-hq","gateway":"198.51.100.1","up":false,"phase2":[{"name":"hq-p2","status":"down"}]}],
			"licenses":{"forticare":{"status":"registered"},"antivirus":{"status":"licensed","expires":1790000000},"ips":{"status":"licensed","expires":1790000000},"web_filter":{"status":"expired","expires":1750000000}}}`
		rep := wire.ConnectorReport{ID: c.ID, DeviceID: d.ID, Kind: wire.ConnectorFortiGate, OK: true, CollectedAt: now.Add(-3 * time.Minute), Facts: json.RawMessage(facts),
			Metrics:        map[string]float64{"cpu_pct": 6, "mem_pct": 38, "sessions": 1240, "disk_pct": 3, "interfaces_up": 2, "interfaces_down": 1, "ipsec_up": 1, "ipsec_down": 1, "licenses_expired": 1},
			TLSFingerprint: "3c9a0f4d7b1e2a5c6d8f9e0b1a2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4"}
		if err := f.st.UpdateConnectorReading(ctx, box, rep, now.Add(-3*time.Minute)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 24; i++ {
			at := now.Add(-time.Duration(i) * time.Hour)
			_ = f.st.AddConnectorSamples(ctx, "ten_kft", c.ID, at, map[string]float64{"cpu_pct": float64(4 + i%7), "sessions": float64(900 + (i*137)%600)})
		}
	}
	views, err := f.eng.HostViews(ctx, "ten_kft")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range views {
		if string(v.State.Observed) == "down" {
			if err := f.st.SetAck(ctx, store.Ack{Kind: "host_down", TargetID: v.ID, Since: v.State.Since, Actor: "jeremia", At: now.Add(-25 * time.Minute), Note: "Ticket 4711, Techniker unterwegs"}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func dumpPreview(t *testing.T, f *fixture, out string, hosts []store.Host) {
	t.Helper()
	var fwHost string
	for _, h := range hosts {
		if h.Address == "192.168.100.254" {
			fwHost = h.ID
		}
	}
	pages := map[string]string{
		"status.html":            "/status",
		"site-netz.html":         "/sites/site_geschaeftsstelle?tab=netz",
		"site-ueberwachung.html": "/sites/site_geschaeftsstelle?tab=ueberwachung",
		"site-ereignisse.html":   "/sites/site_geschaeftsstelle?tab=ereignisse",
		"site-technik.html":      "/sites/site_geschaeftsstelle?tab=technik",
		"events.html":            "/events",
		"boxes.html":             "/boxes",
		"tenants.html":           "/tenants",
		"users.html":             "/users",
		"keys.html":              "/keys",
		"webhooks.html":          "/webhooks",
		"tokens.html":            "/tokens",
		"audit.html":             "/audit",
		"maintenance.html":       "/maintenance",
		"host.html":              "/hosts/" + fwHost,
		"login.html":             "/login",
	}
	for file, path := range pages {
		status, body := f.get(path)
		if status != 200 {
			t.Fatalf("%s: %d", path, status)
		}
		must(t, os.WriteFile(filepath.Join(out, file), []byte(body), 0o644))
	}
	// step two of the login, reached with a pending first step
	f.post("/login", url.Values{"user": {userName}, "password": {password}}, false)
	if status, body := f.get("/login/code"); status == 200 {
		must(t, os.WriteFile(filepath.Join(out, "login-code.html"), []byte(body), 0o644))
	}
	// the static assets, so the pages render from the directory
	must(t, filepath.WalkDir("static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(out, p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	}))
	t.Logf("preview written to %s", out)
}
