package vuln

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/rules"
	"github.com/excubra/excubra/internal/server/store"
)

func TestIdentify(t *testing.T) {
	cases := []struct {
		sv   rules.Service
		ok   bool
		cpe  string
		eco  string
		pkgv string
	}{
		{rules.Service{Product: "OpenSSH", Version: "9.2p1", Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u9"}, true, "cpe:2.3:a:openbsd:openssh:9.2:p1:*:*:*:*:*:*", "Debian:12", "1:9.2p1-2+deb12u9"},
		{rules.Service{Product: "OpenSSH", Version: "9.6p1", Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.19"}, true, "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*", "Ubuntu:24.04:LTS", "1:9.6p1-3ubuntu13.19"},
		{rules.Service{Product: "OpenSSH", Version: "10.0p2", Banner: "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4"}, true, "cpe:2.3:a:openbsd:openssh:10.0:p2:*:*:*:*:*:*", "Debian:13", "1:10.0p2-7+deb13u4"},
		{rules.Service{Product: "OpenSSH", Version: "8.4p1", Banner: "SSH-2.0-OpenSSH_8.4p1 Raspbian-5+deb11u3"}, true, "cpe:2.3:a:openbsd:openssh:8.4:p1:*:*:*:*:*:*", "Debian:11", "1:8.4p1-5+deb11u3"},
		{rules.Service{Product: "OpenSSH", Version: "9.9", Banner: "SSH-2.0-OpenSSH_9.9"}, true, "cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*", "", ""},
		{rules.Service{Product: "nginx", Version: "1.24.0"}, true, "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", "", ""},
		{rules.Service{Product: "FortiOS", Version: "v7.4.3"}, true, "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*", "", ""},
		{rules.Service{Product: "Apache", Version: ""}, false, "", "", ""},
		{rules.Service{Product: "Microsoft-IIS", Version: "10.0"}, false, "", "", ""},
		{rules.Service{Product: "nginx", Version: "1.24.0 (evil)"}, false, "", "", ""},
	}
	for _, c := range cases {
		q, ok := Identify(c.sv)
		if ok != c.ok {
			t.Fatalf("%s %s: ok=%v", c.sv.Product, c.sv.Version, ok)
		}
		if !ok {
			continue
		}
		if q.CPEs[0] != c.cpe || q.Ecosystem != c.eco || q.PkgVersion != c.pkgv {
			t.Fatalf("%s %s: %+v", c.sv.Product, c.sv.Version, q)
		}
	}
	if q, _ := Identify(rules.Service{Product: "nginx", Version: "1.24.0"}); len(q.CPEs) != 2 || !strings.HasPrefix(q.Key(), "cpe|") {
		t.Fatalf("nginx asks both vendors: %+v", q)
	}
}

func TestScoreFromVector(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1, // CVE-2024-6387
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N": 6.4,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N": 3.3,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for v, want := range cases {
		got, ok := ScoreFromVector(v)
		if !ok || got != want {
			t.Fatalf("%s: got %.1f ok=%v want %.1f", v, got, ok, want)
		}
	}
	if _, ok := ScoreFromVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"); ok {
		t.Fatal("v4 vectors are not computed")
	}
}

// NVD lists upstream's CVEs, OSV says which of them Debian still has open (and
// which package version fixes them), KEV marks the exploited one. The finding
// carries all three.
func TestLookupMergesTheDatabases(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	nvdCalls, osvCalls, kevCalls := 0, 0, 0
	var osvBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nvd":
			nvdCalls++
			if !strings.Contains(r.URL.RawQuery, "cpeName=cpe:2.3:a:openbsd:openssh:9.2:p1") {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(`{"vulnerabilities":[
				{"cve":{"id":"CVE-2024-6387","published":"2024-07-01T13:15:06.557","descriptions":[{"lang":"en","value":"A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition."}],"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":8.1}}]},"cisaExploitAdd":"2024-07-01"}},
				{"cve":{"id":"CVE-2023-51385","published":"2023-12-18T19:15:08.000","descriptions":[{"lang":"en","value":"In ssh in OpenSSH before 9.6, OS command injection might occur."}],"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":6.5}}]}}},
				{"cve":{"id":"CVE-2020-0001","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"rejected"}]}}
			]}`))
		case "/osv":
			osvCalls++
			b, _ := io.ReadAll(r.Body)
			osvBody = string(b)
			_, _ = w.Write([]byte(`{"vulns":[
				{"id":"DEBIAN-CVE-2024-6387","aliases":["CVE-2024-6387"],"details":"regreSSHion","affected":[{"package":{"ecosystem":"Debian:12","name":"openssh"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:9.2p1-2+deb12u3"}]}]}]},
				{"id":"DEBIAN-CVE-2025-0001","aliases":["CVE-2025-0001"],"summary":"Made-up unfixed issue","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"}],"affected":[{"package":{"ecosystem":"Debian:12","name":"openssh"},"ecosystem_specific":{"urgency":"not yet assigned"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]},
				{"id":"DEBIAN-CVE-2007-2768","summary":"Debian says it does not matter","affected":[{"package":{"ecosystem":"Debian:12","name":"openssh"},"ecosystem_specific":{"urgency":"unimportant"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}
			]}`))
		case "/kev":
			kevCalls++
			_, _ = w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2024-6387"},{"cveID":"CVE-2021-44228"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	s := New(nil, nil)
	s.NVD, s.OSV, s.KEV = srv.URL+"/nvd", srv.URL+"/osv", srv.URL+"/kev"
	s.Now = func() time.Time { return now }
	s.gapNVD = func(bool) time.Duration { return 0 }
	services := []rules.Service{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.2p1", Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"},
		{Port: 80, Proto: "tcp", Name: "http", Product: "Apache", Version: ""},
	}
	if got := s.Findings(services, now); len(got) != 0 {
		t.Fatalf("findings before any lookup: %+v", got)
	}
	if n := s.Refresh(context.Background()); n != 2 || nvdCalls != 1 || osvCalls != 1 || kevCalls != 1 {
		t.Fatalf("refresh: changed=%d nvd=%d osv=%d kev=%d", n, nvdCalls, osvCalls, kevCalls)
	}
	var q map[string]any
	_ = json.Unmarshal([]byte(osvBody), &q)
	if q["version"] != "1:9.2p1-2+deb12u2" || q["package"].(map[string]any)["ecosystem"] != "Debian:12" {
		t.Fatalf("osv query: %s", osvBody)
	}
	got := s.Findings(services, now)
	if len(got) != 1 {
		t.Fatalf("findings: %+v", got)
	}
	f := got[0]
	if f.Rule != "vuln.known" || f.Key != "tcp/22" || f.Severity != rules.High || !strings.Contains(f.Title, "2 bekannte Schwachstellen, eine wird aktiv ausgenutzt") {
		t.Fatalf("finding: %+v", f)
	}
	if !strings.Contains(f.Detail, "CVE-2024-6387 (CVSS 8.1)") || !strings.Contains(f.Detail, "1:9.2p1-2+deb12u3") || strings.Contains(f.Detail, "CVE-2023-51385") {
		t.Fatalf("detail: %s", f.Detail)
	}
	cves := f.Evidence["cves"].([]CVE)
	if cves[0].ID != "CVE-2024-6387" || !cves[0].Exploited || cves[0].Untriaged || cves[1].ID != "CVE-2025-0001" || cves[1].Score != 6.4 || !cves[1].Untriaged {
		t.Fatalf("cves: %+v", cves)
	}
	if !strings.Contains(f.Detail, "1 davon hat die Distribution noch nicht eingestuft") {
		t.Fatalf("untriaged note missing: %s", f.Detail)
	}
	// fresh: nothing to fetch; a day later it is wanted again
	if n := s.Refresh(context.Background()); n != 0 {
		t.Fatalf("second refresh fetched again: %d", n)
	}
	s.Now = func() time.Time { return now.Add(25 * time.Hour) }
	_ = s.Findings(services, now.Add(25*time.Hour))
	if n := s.Refresh(context.Background()); n != 2 {
		t.Fatalf("stale result not refreshed: %d", n)
	}
	// an upstream-only query (no distribution) takes NVD as it is, minus the rejected one
	up := []rules.Service{{Port: 2222, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.2p1", Banner: "SSH-2.0-OpenSSH_9.2p1"}}
	_ = s.Findings(up, now)
	_ = s.Refresh(context.Background())
	got = s.Findings(up, now)
	if len(got) != 1 || got[0].Evidence["count"] != 2 || !strings.Contains(got[0].Detail, "zurückportiert") {
		t.Fatalf("upstream finding: %+v", got)
	}
}

// A database that fails leaves no finding behind and is retried later, not
// hammered.
func TestFailedLookupsPause(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(503) }))
	defer srv.Close()
	s := New(nil, nil)
	s.NVD, s.OSV, s.KEV = srv.URL, srv.URL, srv.URL
	s.Now = func() time.Time { return now }
	s.gapNVD = func(bool) time.Duration { return 0 }
	services := []rules.Service{{Port: 22, Proto: "tcp", Product: "OpenSSH", Version: "9.2p1"}}
	_ = s.Findings(services, now)
	if n := s.Refresh(context.Background()); n != 0 || calls != 3 { // kev (cisa, then nvd) + the query
		t.Fatalf("refresh: changed=%d calls=%d", n, calls)
	}
	if n := s.Refresh(context.Background()); n != 0 || calls != 5 { // kev again, the query paused
		t.Fatalf("paused query retried at once: changed=%d calls=%d", n, calls)
	}
	s.Now = func() time.Time { return now.Add(20 * time.Minute) }
	_ = s.Refresh(context.Background())
	if calls != 8 {
		t.Fatalf("retry after the pause: calls=%d", calls)
	}
	if got := s.Findings(services, now); len(got) != 0 {
		t.Fatalf("finding without data: %+v", got)
	}
}

// A version whose open CVEs are all still unjudged by the distribution is reported
// as such and never becomes urgent on scores alone; the KEV list falls back to
// NVD when CISA refuses.
func TestUntriagedStaysMediumAndKEVFallsBackToNVD(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/kev":
			w.WriteHeader(403)
		case r.URL.Path == "/nvd" && strings.Contains(r.URL.RawQuery, "hasKev"):
			_, _ = w.Write([]byte(`{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228"}},{"cve":{"id":"CVE-2024-6387"}}]}`))
		case r.URL.Path == "/nvd":
			_, _ = w.Write([]byte(`{"vulnerabilities":[]}`))
		case r.URL.Path == "/osv":
			_, _ = w.Write([]byte(`{"vulns":[
				{"id":"DEBIAN-CVE-2026-59998","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"package":{"ecosystem":"Debian:13","name":"openssh"},"ecosystem_specific":{"urgency":"not yet assigned"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]},
				{"id":"DEBIAN-CVE-2026-59999","affected":[{"package":{"ecosystem":"Debian:13","name":"openssh"},"ecosystem_specific":{"urgency":"not yet assigned"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}
			]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	s := New(nil, nil)
	s.NVD, s.OSV, s.KEV = srv.URL+"/nvd", srv.URL+"/osv", srv.URL+"/kev"
	s.Now = func() time.Time { return now }
	s.gapNVD = func(bool) time.Duration { return 0 }
	services := []rules.Service{{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "10.0p2", Banner: "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4"}}
	_ = s.Findings(services, now)
	if n := s.Refresh(context.Background()); n != 2 || !s.Exploited("CVE-2021-44228") {
		t.Fatalf("refresh: %d exploited=%v", n, s.Exploited("CVE-2021-44228"))
	}
	got := s.Findings(services, now)
	if len(got) != 1 || got[0].Severity != rules.Medium || !strings.Contains(got[0].Title, "2 gemeldete Schwachstellen, Fix der Distribution steht aus") || got[0].Evidence["untriaged"] != 2 {
		t.Fatalf("untriaged finding: %+v", got)
	}
}

// A cached result built by an older judgement is not trusted after an upgrade:
// it is fetched again.
func TestOldJudgementsAreFetchedAgain(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	old, _ := json.Marshal(Result{Product: "OpenSSH", Version: "9.2p1", CVEs: []CVE{{ID: "CVE-2007-2768"}}, Judged: resultVersion - 1})
	must(t, st.SetVuln(ctx, "cpe|cpe:2.3:a:openbsd:openssh:9.2:p1:*:*:*:*:*:*", old, now))
	fresh, _ := json.Marshal(Result{Product: "nginx", Version: "1.24.0", CVEs: []CVE{}, Judged: resultVersion})
	must(t, st.SetVuln(ctx, "cpe|cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*,cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", fresh, now))
	s := New(st, nil)
	s.Now = func() time.Time { return now }
	if _, ok := s.cache["cpe|cpe:2.3:a:openbsd:openssh:9.2:p1:*:*:*:*:*:*"]; ok {
		t.Fatal("an old judgement was loaded")
	}
	if _, ok := s.cache["cpe|cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*,cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"]; !ok {
		t.Fatal("a current judgement was dropped")
	}
	_ = s.Findings([]rules.Service{{Port: 22, Proto: "tcp", Product: "OpenSSH", Version: "9.2p1"}}, now)
	s.mu.Lock()
	_, wanted := s.want["cpe|cpe:2.3:a:openbsd:openssh:9.2:p1:*:*:*:*:*:*"]
	s.mu.Unlock()
	if !wanted {
		t.Fatal("the old result is not wanted again")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
