//go:build preview

package console_test

// Design preview: renders the console pages with data that looks like the pilot customer
// into a directory, so the pages can be opened in a browser without a login.
//
//	EX0_PREVIEW_DIR=/tmp/ex0-preview go test -tags preview -run TestPreviewDump ./internal/server/console/
//
// Then serve that directory (it gets a copy of static/) and open status.html & co.

import (
	"context"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
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
	hosts, err := f.st.Hosts(ctx, "ten_muster", "")
	must(t, err)
	dumpPreview(t, f, out, hosts)
}

// seedPreview builds a logged-in fixture with data that looks like the pilot customer.
func seedPreview(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.login(t)
	ctx := context.Background()
	now := time.Now()

	f.post("/tenants", url.Values{"slug": {"muster"}, "name": {"Muster Sport e.V."}}, true)
	f.post("/tenants/ten_muster/sites", url.Values{"slug": {"geschaeftsstelle"}, "name": {"Geschäftsstelle"}}, true)
	must(t, f.st.CreateBox(ctx, store.Box{ID: "box_x4m7q2n9c5td", HWID: "3d9a41c07be25f68", CertSerial: "5e1f0a9c3b7d42e68a1c5f09d2b7e314",
		CertNotAfter: now.Add(89 * 24 * time.Hour), EnrolledAt: now.Add(-2 * time.Hour), Channel: "stable", DiscoveryMode: "sweep", OS: "linux", Arch: "amd64"}))
	f.eng.RegisterBox(store.Box{ID: "box_x4m7q2n9c5td"})
	f.post("/boxes/box_x4m7q2n9c5td/assign", url.Values{"site_id": {"site_geschaeftsstelle"}}, true)
	f.post("/boxes/box_x4m7q2n9c5td/settings", url.Values{"name": {"muster-box"}, "channel": {"stable"}, "discovery_mode": {"sweep"}}, true)
	box, err := f.st.Box(ctx, "box_x4m7q2n9c5td")
	must(t, err)

	type dev struct{ ip, mac, ven, host string }
	devs := []dev{
		{"192.168.20.254", "02:00:00:da:1c:4b", "Fortinet, Inc.", ""},
		{"192.168.20.24", "02:00:00:6e:63:b6", "Hewlett Packard Enterprise", ""},
		{"192.168.20.25", "02:00:00:de:1e:2f", "Proxmox Server Solutions GmbH", ""},
		{"192.168.20.19", "02:00:00:61:d0:70", "Proxmox Server Solutions GmbH", "MUSTER-RDS"},
		{"192.168.20.15", "02:00:00:cd:b7:34", "Proxmox Server Solutions GmbH", "truenas"},
		{"192.168.20.3", "02:00:00:dd:13:4b", "Proxmox Server Solutions GmbH", ""},
		{"192.168.20.60", "02:00:00:b4:37:5d", "Proxmox Server Solutions GmbH", "muster-box.local"},
		{"192.168.20.21", "02:00:00:e0:db:14", "AVM Audiovisuelles Marketing und Computersysteme GmbH", ""},
		{"192.168.20.36", "02:00:00:e7:38:66", "INNOVAPHONE AG", ""},
		{"192.168.20.41", "02:00:00:b4:74:96", "INNOVAPHONE AG", ""},
		{"192.168.20.42", "02:00:00:ea:4d:9b", "INNOVAPHONE AG", ""},
		{"192.168.20.121", "02:00:00:5c:77:dd", "INNOVAPHONE AG", ""},
		{"192.168.20.122", "02:00:00:2b:55:94", "INNOVAPHONE AG", ""},
		{"192.168.20.153", "02:00:00:b2:e5:2a", "INNOVAPHONE AG", ""},
		{"192.168.20.8", "02:00:00:7e:5d:d1", "Brother Industries, LTD.", "BRN0200007E5DD1"},
		{"192.168.20.35", "02:00:00:3c:27:2e", "Brother Industries, LTD.", "BRN0200003C272E"},
		{"192.168.20.20", "02:00:00:83:14:e0", "CANON INC.", ""},
		{"192.168.20.33", "02:00:00:a5:52:81", "EVOLIS", ""},
		{"192.168.20.157", "02:00:00:a3:05:8f", "Zebra Technologies Corp.", ""},
		{"192.168.20.38", "02:00:00:76:ee:cb", "LCFC(Hefei) Electronics Technology co., ltd", ""},
		{"192.168.20.39", "02:00:00:a9:d9:31", "LCFC(Hefei) Electronics Technology co., ltd", ""},
		{"", "02:00:00:d6:ae:a8", "LCFC(Hefei) Electronics Technology co., ltd", ""},
		{"", "02:00:00:c4:07:ed", "HP Inc.", ""},
		{"", "02:00:00:35:49:ad", "Xiaomi Communications Co Ltd", ""},
		{"192.168.20.2", "02:00:00:e6:2c:1c", "", ""},
		{"", "02:00:00:48:d3:4e", "", ""},
	}
	var seen []wire.Sighting
	for _, d := range devs {
		seen = append(seen, wire.Sighting{MAC: d.mac, IP: d.ip, Vendor: d.ven, Hostname: d.host, LastSeen: now.Add(-40 * time.Second)})
	}
	hb := wire.Heartbeat{SentAt: now.Add(-30 * time.Second), Agent: wire.AgentInfo{Version: "v0.1.0", UptimeS: 25000},
		Box:       wire.BoxInfo{DiskTotalBytes: 4_100_000_000, DiskFreeBytes: 3_000_000_000},
		Netbird:   wire.NetbirdInfo{Status: "connected", IP: "100.64.0.99", Version: "0.78.1"},
		Discovery: wire.DiscoveryReport{Seen: seen}}
	if _, err := f.eng.Heartbeat(ctx, box, hb); err != nil {
		t.Fatal(err)
	}

	stored, err := f.st.Devices(ctx, "ten_muster", "site_geschaeftsstelle", time.Time{})
	must(t, err)
	byIP := map[string]store.Device{}
	for _, d := range stored {
		byIP[d.IP] = d
	}
	for _, ip := range []string{"192.168.20.254", "192.168.20.24", "192.168.20.25", "192.168.20.19", "192.168.20.15"} {
		form := url.Values{}
		if ip == "192.168.20.254" {
			form.Set("uplink", "1")
		}
		if status, _, _ := f.post("/devices/"+byIP[ip].ID+"/watch", form, true); status != 303 {
			t.Fatalf("watch %s: %d", ip, status)
		}
	}
	hosts, err := f.st.Hosts(ctx, "ten_muster", "")
	must(t, err)
	var reports []wire.HostReport
	for _, h := range hosts {
		ok := h.Address != "192.168.20.15" // TrueNAS is down in the preview
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
	must(t, f.st.CreateBox(ctx, store.Box{ID: "box_h3w8k6v2y9fb", HWID: "e3b0c44298fc1c14", CertSerial: "2", CertNotAfter: now.Add(89 * 24 * time.Hour),
		EnrolledAt: now.Add(-5 * time.Hour), AgentVersion: "0.0.0-dev+83953d0", OS: "linux", Arch: "arm64", Channel: "stable"}))
	f.eng.RegisterBox(store.Box{ID: "box_h3w8k6v2y9fb"})
	seedActions(t, f)
	return f
}

// seedActions adds what the action features show: tasks with results, heartbeat
// notes, an acknowledged outage, releases and channel pointers.
func seedActions(t *testing.T, f *fixture) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	const box = "box_x4m7q2n9c5td"
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
	views, err := f.eng.HostViews(ctx, "ten_muster")
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
		if h.Address == "192.168.20.254" {
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
