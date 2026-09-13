// Command demo fills a data directory with realistic sample data so the console
// can be looked at and developed without a real box: two tenants, sites, boxes,
// hosts with state, a day of check rollups, devices, events and a webhook target.
//
//	go run ./tools/demo /tmp/ex0-demo
package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/server/webhook"
	"github.com/excubra/excubra/internal/wire"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: demo <data-dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	ctx := context.Background()
	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()
	now := time.Now()
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	must(st.CreateTenant(ctx, store.Tenant{ID: "ten_viico", Name: "VIICO GmbH", CreatedAt: now.Add(-30 * 24 * time.Hour)}))
	must(st.CreateTenant(ctx, store.Tenant{ID: "ten_muster", Name: "Muster Hebezeugservice GmbH", CreatedAt: now.Add(-20 * 24 * time.Hour)}))
	must(st.CreateWebhookTarget(ctx, store.WebhookTarget{ID: "tgt_crm", Name: "VIICO-CRM", URL: "https://crm.viico.internal/ex0/webhook", Secret: id.Secret(32), TenantScope: "*", Enabled: true, CreatedAt: now.Add(-30 * 24 * time.Hour)}))
	must(st.CreateAPIToken(ctx, store.APIToken{ID: "tok_crm", Name: "crm", TokenHash: "demo", Tenants: []string{"*"}, CreatedAt: now.Add(-30 * 24 * time.Hour)}))
	must(st.CreateEnrollmentKey(ctx, store.EnrollmentKey{ID: "key_charge01", SecretHash: "demo1", Note: "Charge September", CreatedAt: now.Add(-3 * 24 * time.Hour), ExpiresAt: now.Add(27 * 24 * time.Hour)}))

	deliverer := webhook.New(st, "demo", slog.Default())
	eng, err := core.Load(ctx, st, deliverer, slog.Default())
	if err != nil {
		return err
	}
	must(eng.CreateSite(ctx, store.Site{ID: "site_buero", TenantID: "ten_viico", Name: "Büro Ludwigshafen", CreatedAt: now.Add(-30 * 24 * time.Hour), Address: "Musterstraße 1, 67059 Ludwigshafen"}, "demo"))
	must(eng.CreateSite(ctx, store.Site{ID: "site_werk", TenantID: "ten_muster", Name: "Werk Frankenthal", CreatedAt: now.Add(-20 * 24 * time.Hour), Address: "Beispielweg 7, 67227 Frankenthal"}, "demo"))
	must(eng.CreateSite(ctx, store.Site{ID: "site_lager", TenantID: "ten_muster", Name: "Lager Worms", CreatedAt: now.Add(-10 * 24 * time.Hour), Address: "Beispielallee 22, 67547 Worms"}, "demo"))

	// Coordinates as an operator would have looked them up once; the demo must not
	// call a geocoder. Town centres, not real customer doorsteps.
	must(st.SetSiteLocation(ctx, "site_buero", "Musterstraße 1, 67059 Ludwigshafen", 49.4775, 8.4450, true))
	must(st.SetSiteLocation(ctx, "site_werk", "Beispielweg 7, 67227 Frankenthal", 49.5386, 8.3543, true))
	must(st.SetSiteLocation(ctx, "site_lager", "Beispielallee 22, 67547 Worms", 49.6319, 8.3592, true))

	boxes := []store.Box{
		{ID: "box_buero", SiteID: "site_buero", Name: "Büro", HWID: "3f1a9c2e77b04d1a", AgentVersion: "0.1.0", OS: "linux", Arch: "amd64", CertSerial: "1a2b3c", CertNotAfter: now.Add(80 * 24 * time.Hour), Channel: "canary", DiscoveryMode: "sweep", NetbirdStatus: "connected", NetbirdIP: "100.85.12.4", DiskTotalBytes: 250e9, DiskFreeBytes: 212e9, UptimeS: 864000, LastSeen: now, EnrolledAt: now.Add(-28 * 24 * time.Hour)},
		{ID: "box_werk", SiteID: "site_werk", Name: "Werk", HWID: "9c0d44e1aa3b7f52", AgentVersion: "0.1.0", OS: "linux", Arch: "arm64", CertSerial: "4d5e6f", CertNotAfter: now.Add(75 * 24 * time.Hour), Channel: "stable", DiscoveryMode: "sweep", NetbirdStatus: "connected", NetbirdIP: "100.85.30.9", DiskTotalBytes: 120e9, DiskFreeBytes: 101e9, UptimeS: 1728000, LastSeen: now, EnrolledAt: now.Add(-19 * 24 * time.Hour)},
		{ID: "box_lager", SiteID: "site_lager", Name: "Lager", HWID: "b7e2f00c5d6a1933", AgentVersion: "0.1.0", OS: "linux", Arch: "arm64", CertSerial: "7a8b9c", CertNotAfter: now.Add(85 * 24 * time.Hour), Channel: "stable", DiscoveryMode: "passive", NetbirdStatus: "disconnected", NetbirdIP: "", DiskTotalBytes: 120e9, DiskFreeBytes: 99e9, UptimeS: 420, LastSeen: now.Add(-6 * time.Minute), EnrolledAt: now.Add(-9 * 24 * time.Hour)},
		{ID: "box_neu", HWID: "e4c1d2a3b4f50011", AgentVersion: "0.1.0", OS: "linux", Arch: "arm64", CertSerial: "0a0b0c", CertNotAfter: now.Add(89 * 24 * time.Hour), EnrolledAt: now.Add(-40 * time.Minute)},
	}
	for _, b := range boxes {
		must(st.CreateBox(ctx, b))
		eng.RegisterBox(b)
		if b.SiteID != "" {
			must(eng.AssignBox(ctx, b.ID, b.SiteID, "demo"))
		}
	}
	must(st.SetNetbirdKey(ctx, store.NetbirdKey{BoxID: "box_lager", ManagementURL: "https://muster.vpn.example.test", SetupKey: "demo", CreatedAt: now.Add(-1 * time.Hour)}))

	type h struct {
		id, site, box, name, ip, mac, vendor, parent string
		uplink                                       bool
		checks                                       []wire.CheckConfig
		down                                         bool
	}
	hosts := []h{
		{"host_fw_buero", "site_buero", "box_buero", "FortiGate 60F", "192.168.1.1", "00:09:0f:aa:bb:cc", "Fortinet, Inc.", "", true, []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 443}}, false},
		{"host_pve1", "site_buero", "box_buero", "pve-01", "192.168.1.10", "b4:2e:99:11:22:33", "Giga-Byte Technology", "host_fw_buero", false, []wire.CheckConfig{{Type: "icmp"}, {Type: "https", URL: "https://192.168.1.10:8006/"}}, false},
		{"host_starface", "site_buero", "box_buero", "Starface PBX", "192.168.1.20", "00:50:56:9a:1b:2c", "VMware, Inc.", "host_fw_buero", false, []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 5060}}, false},
		{"host_nas", "site_buero", "box_buero", "Synology NAS", "192.168.1.30", "00:11:32:aa:bb:01", "Synology Incorporated", "host_fw_buero", false, []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 5001}}, false},
		{"host_printer", "site_buero", "box_buero", "Brother HL-L6400", "192.168.1.77", "3c:2a:f4:11:22:33", "Brother Industries, LTD.", "host_fw_buero", false, []wire.CheckConfig{{Type: "icmp"}}, true},
		{"host_fw_werk", "site_werk", "box_werk", "OPNsense", "10.20.0.1", "00:0c:29:44:55:66", "VMware, Inc.", "", true, []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 443}}, false},
		{"host_dc", "site_werk", "box_werk", "DC01", "10.20.0.5", "00:0c:29:77:88:99", "VMware, Inc.", "host_fw_werk", false, []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 389}}, false},
		{"host_rds", "site_werk", "box_werk", "RDS01", "10.20.0.6", "00:0c:29:aa:bb:cc", "VMware, Inc.", "host_fw_werk", false, []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 3389}}, true},
		{"host_plc", "site_werk", "box_werk", "Siemens S7-1200", "10.20.5.40", "", "", "host_fw_werk", false, []wire.CheckConfig{{Type: "icmp"}}, false},
		{"host_lager_fw", "site_lager", "box_lager", "FRITZ!Box 7590", "192.168.178.1", "dc:39:6f:12:34:56", "AVM Audiovisuelles Marketing und Computersysteme GmbH", "", true, []wire.CheckConfig{{Type: "icmp"}}, false},
	}
	for _, x := range hosts {
		if x.site == "" {
			continue
		}
		tenant := "ten_viico"
		if x.site != "site_buero" {
			tenant = "ten_muster"
		}
		checks := x.checks
		for i := range checks {
			if checks[i].Type == "https" {
				checks[i].Type = "http"
			}
		}
		must(eng.CreateHost(ctx, store.Host{ID: x.id, TenantID: tenant, SiteID: x.site, BoxID: x.box, Name: x.name, Address: x.ip, MAC: x.mac, Vendor: x.vendor, ParentID: x.parent, IsUplink: x.uplink, Checks: checks, CreatedAt: now.Add(-15 * 24 * time.Hour)}, "demo"))
		// a day of rollups with the occasional failed round
		for hour := 0; hour < 24; hour++ {
			at := now.Add(-time.Duration(23-hour) * time.Hour)
			for _, c := range checks {
				for round := 0; round < 120; round++ {
					lat := int64(2 + rand.IntN(9)) //nolint:gosec
					ok := true
					if x.down && hour >= 21 {
						ok = false
					} else if hour == 9 && round < 6 && x.id == "host_pve1" {
						ok = false
					}
					must(st.AddRollup(ctx, tenant, x.id, at, c.Label(), ok, &lat))
				}
			}
		}
	}
	// heartbeats drive the state machine: hosts up, two down
	for _, b := range boxes[:3] {
		var reports []wire.HostReport
		for _, x := range hosts {
			if x.box != b.ID {
				continue
			}
			var rounds []wire.Round
			for i := 0; i < 3; i++ {
				ok := !x.down
				var cr []wire.CheckResult
				for _, c := range x.checks {
					lat := int64(3)
					r := wire.CheckResult{Type: c.Label(), OK: ok, LatencyMS: &lat}
					if !ok {
						r.Error, r.LatencyMS = "timeout", nil
					}
					cr = append(cr, r)
				}
				rounds = append(rounds, wire.Round{At: now.Add(-time.Duration(3-i) * 30 * time.Second), OK: ok, Checks: cr})
			}
			reports = append(reports, wire.HostReport{HostID: x.id, Rounds: rounds})
		}
		seen := []wire.Sighting{}
		switch b.ID {
		case "box_buero":
			seen = []wire.Sighting{
				{MAC: "00:09:0f:aa:bb:cc", IP: "192.168.1.1", Vendor: "Fortinet, Inc.", Hostname: "fw01", LastSeen: now},
				{MAC: "b4:2e:99:11:22:33", IP: "192.168.1.10", Vendor: "Giga-Byte Technology", Hostname: "pve-01", LastSeen: now},
				{MAC: "00:50:56:9a:1b:2c", IP: "192.168.1.20", Vendor: "VMware, Inc.", Hostname: "starface", LastSeen: now},
				{MAC: "00:11:32:aa:bb:01", IP: "192.168.1.30", Vendor: "Synology Incorporated", Hostname: "nas", LastSeen: now},
				{MAC: "3c:2a:f4:11:22:33", IP: "192.168.1.77", Vendor: "Brother Industries, LTD.", Hostname: "BRW3C2AF4112233", LastSeen: now.Add(-3 * time.Hour)},
				{MAC: "a4:cf:12:8d:3e:01", IP: "192.168.1.101", Vendor: "Espressif Inc.", Hostname: "", LastSeen: now},
				{MAC: "f0:9f:c2:5a:6b:7c", IP: "192.168.1.102", Vendor: "Ubiquiti Inc", Hostname: "U6-Pro-Buero", LastSeen: now},
				{MAC: "98:da:c4:aa:11:22", IP: "192.168.1.150", Vendor: "TP-Link Corporation Limited", Hostname: "", LastSeen: now.Add(-20 * time.Minute)},
				{MAC: "d8:3a:dd:12:34:56", IP: "192.168.1.151", Vendor: "Raspberry Pi Trading Ltd", Hostname: "ex0-box-buero", LastSeen: now},
			}
		case "box_werk":
			seen = []wire.Sighting{
				{MAC: "00:0c:29:44:55:66", IP: "10.20.0.1", Vendor: "VMware, Inc.", Hostname: "opnsense", LastSeen: now},
				{MAC: "00:0c:29:77:88:99", IP: "10.20.0.5", Vendor: "VMware, Inc.", Hostname: "dc01", LastSeen: now},
				{MAC: "00:0c:29:aa:bb:cc", IP: "10.20.0.6", Vendor: "VMware, Inc.", Hostname: "rds01", LastSeen: now.Add(-2 * time.Hour)},
				{IP: "10.20.5.40", LastSeen: now}, {IP: "10.20.5.41", LastSeen: now}, {IP: "10.20.5.42", LastSeen: now.Add(-40 * time.Minute)},
				{MAC: "00:1b:1b:aa:bb:cc", IP: "10.20.0.60", Vendor: "Siemens AG", Hostname: "hmi-halle2", LastSeen: now},
			}
		}
		if _, err := eng.Heartbeat(ctx, b, wire.Heartbeat{SentAt: now, Agent: wire.AgentInfo{Version: b.AgentVersion, OS: b.OS, Arch: b.Arch, UptimeS: b.UptimeS},
			Box: wire.BoxInfo{DiskTotalBytes: b.DiskTotalBytes, DiskFreeBytes: b.DiskFreeBytes}, Netbird: wire.NetbirdInfo{Status: b.NetbirdStatus, IP: b.NetbirdIP}, Hosts: reports, Discovery: wire.DiscoveryReport{Seen: seen}}); err != nil {
			return err
		}
	}
	// a maintenance window and a few older events for the timeline
	must(eng.StartMaintenance(ctx, store.Maintenance{TenantID: "ten_muster", SiteID: "site_lager", Scope: "site", TargetID: "site_lager", Until: now.Add(90 * time.Minute), Reason: "Umzug Serverschrank"}, "jeremia"))
	older := []struct {
		t    event.Type
		ago  time.Duration
		host string
		name string
	}{
		{event.HostDown, 5 * time.Hour, "host_pve1", "pve-01"}, {event.HostUp, 4*time.Hour + 50*time.Minute, "host_pve1", "pve-01"},
		{event.BoxSilent, 16 * time.Hour, "", ""}, {event.BoxBack, 15*time.Hour + 40*time.Minute, "", ""},
	}
	for _, o := range older {
		ev := event.New(o.t, now.Add(-o.ago))
		ev.Source, ev.TenantID, ev.SiteID, ev.BoxID = event.SourceState, "ten_viico", "site_buero", "box_buero"
		if o.host != "" {
			ev.HostID = o.host
			ev.Host = &event.HostRef{Name: o.name, IP: "192.168.1.10"}
			ev.Details = map[string]any{"checks_failed": []string{"icmp"}, "consecutive_failures": 3}
		}
		must(deliverer.Publish(ctx, ev))
	}
	_ = state.Up
	fmt.Println("demo data written to", dir)
	return nil
}
