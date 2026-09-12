package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSourcesAreParsedMergedAndVersioned(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.URL.Path {
		case "/hosts":
			_, _ = w.Write([]byte("# URLhaus hosts\n127.0.0.1\tevil.test\n127.0.0.1\tBad.Example.\n127.0.0.1\tlocalhost\n127.0.0.1 10.0.0.1\n"))
		case "/tf":
			_, _ = w.Write([]byte(`# ThreatFox
"2026-09-12 10:00:00","1","c2.example","domain","botnet_cc","x","y","Cobalt Strike","","75","","","0","r"
"2026-09-12 10:00:00","2","http://dl.example:8080/payload.exe","url","payload_delivery","x","y","Emotet","","50","","","0","r"
"2026-09-12 10:00:00","3","203.0.113.5:443","ip:port","botnet_cc","x","y","z","","50","","","0","r"
"2026-09-12 10:00:00","4","evil.test","domain","botnet_cc","x","y","z","","50","","","0","r"
`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	s := New(nil, nil)
	s.URLhaus, s.ThreatFox, s.Now = srv.URL+"/hosts", srv.URL+"/tf", func() time.Time { return now }
	changed, err := s.Refresh(context.Background(), false)
	if err != nil || !changed || calls != 2 {
		t.Fatalf("refresh: changed=%v err=%v calls=%d", changed, err, calls)
	}
	body, version := s.Body()
	if string(body) != "bad.example\nc2.example\ndl.example\nevil.test\n" || len(version) != 16 {
		t.Fatalf("body %q version %q", body, version)
	}
	st := s.Status()
	if st.Domains != 4 || st.Sources["urlhaus"] != 2 || st.Sources["threatfox"] != 2 {
		t.Fatalf("status: %+v", st)
	}
	if src, ok := s.Contains("www.evil.test"); !ok || src != "urlhaus" {
		t.Fatal("contains")
	}
	if _, ok := s.Contains("notevil.test"); ok {
		t.Fatal("suffix match too loose")
	}
	// fresh: no fetch; a day later it is fetched again and the version stays put
	if changed, _ := s.Refresh(context.Background(), false); changed || calls != 2 {
		t.Fatalf("refetched while fresh: %v %d", changed, calls)
	}
	s.Now = func() time.Time { return now.Add(25 * time.Hour) }
	if changed, _ := s.Refresh(context.Background(), false); changed || calls != 4 {
		t.Fatalf("stale refresh: changed=%v calls=%d", changed, calls)
	}
	if _, v := s.Body(); v != version {
		t.Fatal("the same list got a new version")
	}
	if got := parseHosts([]byte("0.0.0.0 x.y\nbad entry with space\nUPPER.CASE\n1.2.3.4\n")); strings.Join(got, ",") != "x.y,upper.case" {
		t.Fatalf("parseHosts: %v", got)
	}
}

func TestNoSourceIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	s := New(nil, nil)
	s.URLhaus, s.ThreatFox = srv.URL, srv.URL
	if _, err := s.Refresh(context.Background(), true); err == nil {
		t.Fatal("no error")
	}
	if _, v := s.Body(); v != "" {
		t.Fatal("a version without a list")
	}
}
