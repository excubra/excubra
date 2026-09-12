package feed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/rules"
)

func TestAssessPicksTheCycleAndJudgesIt(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	nginx := &Product{Slug: "nginx", Cycles: []Cycle{
		{Cycle: "1.29", Latest: "1.29.2", EOL: false},
		{Cycle: "1.28", Latest: "1.28.1", EOL: false},
		{Cycle: "1.26", Latest: "1.26.3", EOL: "2026-11-01"},
		{Cycle: "1.24", Latest: "1.24.0", EOL: "2025-05-29"},
		{Cycle: "1.18", Latest: "1.18.0", EOL: "2021-04-20"},
	}}
	cases := []struct{ version, state, cycle string }{
		{"1.29.2", "current", "1.29"}, {"1.29.0", "outdated", "1.29"}, {"1.26.3", "eol_soon", "1.26"}, {"1.24.0", "eol", "1.24"}, {"1.18.0", "eol", "1.18"}, {"2.0.1", "unknown", ""}, {"", "unknown", ""},
	}
	for _, c := range cases {
		v := Assess(nginx, c.version, now)
		if v.State != c.state || v.Cycle != c.cycle {
			t.Errorf("%q: %+v, want %s/%s", c.version, v, c.state, c.cycle)
		}
	}
	// the longest matching cycle wins; a "p" suffix and a leading v are fine
	pg := &Product{Slug: "postgresql", Cycles: []Cycle{{Cycle: "16", Latest: "16.4", EOL: "2028-11-09"}, {Cycle: "1", Latest: "1.0", EOL: "2000-01-01"}}}
	if v := Assess(pg, "v16.2", now); v.State != "outdated" || v.Cycle != "16" {
		t.Fatalf("postgres: %+v", v)
	}
	if Assess(nil, "1.0", now).State != "unknown" {
		t.Fatal("nil product")
	}
	if compareVersions("9.2p1", "9.2") != 0 || compareVersions("10.11.6-MariaDB", "10.11.7") != -1 || compareVersions("8.4", "8.4.1") != -1 {
		t.Fatal("version comparison")
	}
}

func TestFindingsFromTheCacheAndTheFetchLoop(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/mariadb.json" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`[{"cycle":"11.4","latest":"11.4.5","eol":"2029-05-29"},{"cycle":"10.11","latest":"10.11.11","eol":"2028-02-16"},{"cycle":"10.5","latest":"10.5.28","eol":"2025-06-24"}]`))
	}))
	defer srv.Close()
	s := New(nil, nil)
	s.URL, s.Now = srv.URL, func() time.Time { return now }
	services := []rules.Service{
		{Port: 3306, Proto: "tcp", Name: "mysql", Product: "MariaDB", Version: "10.5.20-MariaDB"},
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.2p1"}, // no feed for it
		{Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: ""},       // no version
	}
	if got := s.Findings(services, now); len(got) != 0 {
		t.Fatalf("findings before the feed is fetched: %+v", got)
	}
	if n := s.Refresh(context.Background()); n != 1 || calls != 1 {
		t.Fatalf("refresh: changed=%d calls=%d", n, calls)
	}
	got := s.Findings(services, now)
	if len(got) != 1 || got[0].Rule != "version.eol" || got[0].Key != "tcp/3306" || got[0].Severity != rules.High {
		t.Fatalf("findings: %+v", got)
	}
	if got[0].Detail == "" || got[0].Evidence["latest"] != "10.5.28" || got[0].Evidence["cycle"] != "10.5" {
		t.Fatalf("finding detail: %+v", got[0])
	}
	// fresh: nothing to refresh; a day later it is wanted again
	if n := s.Refresh(context.Background()); n != 0 {
		t.Fatalf("second refresh fetched again: %d", n)
	}
	s.Now = func() time.Time { return now.Add(25 * time.Hour) }
	_ = s.Findings(services, now.Add(25*time.Hour))
	if n := s.Refresh(context.Background()); n != 1 {
		t.Fatalf("stale product not refreshed: %d", n)
	}
	// an outdated version within a supported line is a note
	s.Put(&Product{Slug: "mariadb", FetchedAt: now, Cycles: []Cycle{{Cycle: "11.4", Latest: "11.4.5", EOL: "2029-05-29"}}})
	got = s.Findings([]rules.Service{{Port: 3306, Proto: "tcp", Product: "MariaDB", Version: "11.4.2"}}, now)
	if len(got) != 1 || got[0].Rule != "version.outdated" || got[0].Severity != rules.Low {
		t.Fatalf("outdated: %+v", got)
	}
	if Slug("Apache") != "apache-http-server" || Slug("FortiGate") != "fortios" || Slug("lighttpd") != "" {
		t.Fatal("slugs")
	}
}

func TestIISVersionNamesTheWindowsServer(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	s := New(nil, nil)
	s.Now = func() time.Time { return now }
	s.Put(&Product{Slug: "windows-server", FetchedAt: now, Cycles: []Cycle{{Cycle: "2025", Latest: "10.0.26100", EOL: "2034-10-10"}, {Cycle: "2012", Latest: "6.2.9200", EOL: "2023-10-10"}}})
	got := s.Findings([]rules.Service{{Port: 80, Proto: "tcp", Product: "Microsoft-IIS", Version: "8.0"}, {Port: 443, Proto: "tcp", Product: "Microsoft-IIS", Version: "10.0"}}, now)
	if len(got) != 1 || got[0].Rule != "version.eol" || !strings.Contains(got[0].Title, "Windows Server 2012") {
		t.Fatalf("iis: %+v", got)
	}
	if slug, v := derive("nginx", "1.24.0"); slug != "nginx" || v != "1.24.0" {
		t.Fatal("derive passes other products through")
	}
}
