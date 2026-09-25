package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestASourceIsADeviceWithItsOwnToken(t *testing.T) {
	s := open(t)
	seed(t, s)
	site, err := s.Site(ctx, "site_a")
	must(t, err)
	src, err := s.CreateSource(ctx, site, "VIIDOC", "10.100.10.3", SourceTokenName("VIIDOC"), "hash-1", t0)
	must(t, err)
	if src.Device.Hostname != "VIIDOC" || src.Device.Vendor != SourceVendor || src.Device.MAC != "" || src.Device.TenantID != "ten_a" {
		t.Fatalf("device: %+v", src.Device)
	}
	tok, err := s.APITokenByHash(ctx, "hash-1")
	must(t, err)
	if tok.DeviceID != src.Device.ID || len(tok.Tenants) != 1 || tok.Tenants[0] != "ten_a" {
		t.Fatalf("token: %+v", tok)
	}
	// a source needs a name and an IP address, not a host name
	for _, bad := range [][2]string{{"", "10.100.10.9"}, {"VIIDOC", "viidoc.example"}, {strings.Repeat("x", 65), "10.100.10.9"}} {
		if _, err := s.CreateSource(ctx, site, bad[0], bad[1], SourceTokenName(bad[0]), "hash-x", t0); !errors.Is(err, ErrSourceInvalid) {
			t.Fatalf("source %q at %q: %v", bad[0], bad[1], err)
		}
	}
	// the same address on the same site is one device, not two
	if _, err := s.CreateSource(ctx, site, "VIIDOC", "10.100.10.3", SourceTokenName("VIIDOC"), "hash-2", t0); !errors.Is(err, ErrSourceExists) {
		t.Fatalf("second source at the same address: %v", err)
	}
	list, err := s.Sources(ctx)
	must(t, err)
	if len(list) != 1 || list[0].Device.ID != src.Device.ID {
		t.Fatalf("sources: %+v", list)
	}
	must(t, s.RevokeAPIToken(ctx, tok.ID, t0.Add(time.Hour)))
	if list, _ := s.Sources(ctx); len(list) != 0 {
		t.Fatalf("a revoked source is still listed: %+v", list)
	}
}

func TestLogsAreStoredOnceAndReadNewestFirst(t *testing.T) {
	s := open(t)
	seed(t, s)
	entry := func(id, kind string, at time.Time) LogEntry {
		return LogEntry{DeviceID: "dev_1", EventID: id, OccurredAt: at, ReceivedAt: at.Add(time.Second),
			Source: "app.viidoc", Kind: kind, Actor: "anna", IP: "198.51.100.7", Target: "t", Summary: "s"}
	}
	late := t0.Add(23*time.Hour + 59*time.Minute) // the evening of t0's day
	fresh, err := s.AddLogs(ctx, "ten_a", []LogEntry{
		entry("e1", "auth.login", t0),
		entry("e2", "auth.device.new", t0.Add(time.Minute)),
		entry("e3", "settings.bank", late),
		entry("e4", "auth.login", late.Add(2*time.Minute)), // the next day
	})
	must(t, err)
	if len(fresh) != 4 {
		t.Fatalf("stored %d of 4", len(fresh))
	}
	// a retry of the same batch stores nothing new
	fresh, err = s.AddLogs(ctx, "ten_a", []LogEntry{entry("e1", "auth.login", t0), entry("e4", "auth.login", late.Add(2*time.Minute))})
	must(t, err)
	if len(fresh) != 0 {
		t.Fatalf("a retry stored %d again", len(fresh))
	}

	all, err := s.Logs(ctx, "ten_a", "dev_1", t0.Add(-time.Hour), late.Add(time.Hour), "", 0)
	must(t, err)
	if len(all) != 4 || all[0].EventID != "e4" || all[3].EventID != "e1" {
		t.Fatalf("newest first across two days: %+v", all)
	}
	auth, err := s.Logs(ctx, "ten_a", "dev_1", t0.Add(-time.Hour), late.Add(time.Hour), "auth", 0)
	must(t, err)
	if len(auth) != 3 {
		t.Fatalf("kind auth keeps its sub-kinds: %d", len(auth))
	}
	limited, err := s.Logs(ctx, "ten_a", "dev_1", t0.Add(-time.Hour), late.Add(time.Hour), "", 2)
	must(t, err)
	if len(limited) != 2 || limited[0].EventID != "e4" {
		t.Fatalf("limit: %+v", limited)
	}

	// reading a day without a file creates none
	if _, err := s.Logs(ctx, "ten_a", "dev_1", t0.AddDate(0, 0, -10), t0.AddDate(0, 0, -9), "", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "tenants", "ten_a", DayOf(t0.AddDate(0, 0, -9))+".db")); err == nil {
		t.Fatal("a read created a day file")
	}
}
