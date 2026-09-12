package ingest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/blocklist"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/feed"
	"github.com/excubra/excubra/internal/server/ingest"
	"github.com/excubra/excubra/internal/server/rules"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/server/vuln"
	"github.com/excubra/excubra/internal/wire"
)

var t0 = time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

// pub captures published events.
type pub struct {
	mu     sync.Mutex
	events []event.Event
}

func (p *pub) Publish(_ context.Context, ev event.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, ev)
	return nil
}

func (p *pub) types() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var s []string
	for _, e := range p.events {
		s = append(s, string(e.Type))
	}
	return strings.Join(s, " ")
}

func (p *pub) reset() {
	p.mu.Lock()
	p.events = nil
	p.mu.Unlock()
}

type fixture struct {
	t      *testing.T
	st     *store.Store
	ca     *pki.CA
	eng    *core.Engine
	srv    *httptest.Server
	host   string
	pub    *pub
	now    time.Time
	key    pki.EnrollmentKey
	client *http.Client // pinned, anonymous
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := pki.LoadOrCreateCA(dir + "/ca")
	if err != nil {
		t.Fatal(err)
	}
	p := &pub{}
	eng, err := core.Load(context.Background(), st, p, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, st: st, ca: ca, eng: eng, pub: p, now: t0}
	eng.Now = func() time.Time { return f.now }
	is := ingest.New(eng, st, ca, slog.Default())
	is.Now = func() time.Time { return f.now }

	srvCert, err := ca.LoadOrCreateServerCert(dir+"/ca", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewUnstartedServer(is.Handler())
	f.srv.TLS = pki.IngestTLSConfig(ca, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil })
	f.srv.TLS.Certificates = []tls.Certificate{srvCert}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.host, _, _ = net.SplitHostPort(strings.TrimPrefix(f.srv.URL, "https://"))

	ctx := context.Background()
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "A", CreatedAt: t0}))
	must(t, eng.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "HQ", CreatedAt: t0}, "test"))
	f.key, _ = pki.NewEnrollmentKey(f.host, 443, ca.Fingerprint())
	must(t, st.CreateEnrollmentKey(ctx, store.EnrollmentKey{ID: "key_1", SecretHash: f.key.SecretHash(), CreatedAt: t0, ExpiresAt: t0.Add(30 * 24 * time.Hour)}))
	f.client = f.httpClient(nil)
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) httpClient(cert *tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: pki.AgentTLSConfig(f.ca.Fingerprint(), f.host, cert)}, Timeout: 5 * time.Second}
}

func (f *fixture) do(c *http.Client, method, path string, body any, headers map[string]string) (int, []byte) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(wire.HeaderAgentVersion, "0.0.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// enroll runs the enrollment flow and returns the box id and a client with its certificate.
func (f *fixture) enroll(keyStr string) (string, *http.Client, int) {
	f.t.Helper()
	key, _ := pki.GenerateKey()
	csr, _ := pki.CSRPEM(key, "hw-test")
	status, body := f.do(f.client, "POST", "/v1/enroll", wire.EnrollRequest{Key: keyStr, HWID: "hw-test", CSR: string(csr), AgentVersion: "0.0.0", OS: "linux", Arch: "arm64"}, nil)
	if status != 200 {
		return "", nil, status
	}
	var resp wire.EnrollResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		f.t.Fatal(err)
	}
	keyPEM, _ := pki.KeyPEM(key)
	cert, err := tls.X509KeyPair([]byte(resp.Certificate), keyPEM)
	if err != nil {
		f.t.Fatal(err)
	}
	return resp.BoxID, f.httpClient(&cert), status
}

func TestEnrollmentAndKeyIsOneTime(t *testing.T) {
	f := newFixture(t)
	boxID, boxClient, status := f.enroll(f.key.String())
	if status != 200 || !strings.HasPrefix(boxID, "box_") {
		t.Fatalf("enroll: %d %s", status, boxID)
	}
	if _, _, status := f.enroll(f.key.String()); status != 401 {
		t.Fatalf("second use of the key: %d", status)
	}
	if _, _, status := f.enroll("EX0:1:h:443:" + strings.Repeat("0", 32) + ":" + strings.Repeat("0", 32)); status != 401 {
		t.Fatalf("unknown key: %d", status)
	}
	if status, _ := f.do(f.client, "POST", "/v1/enroll", wire.EnrollRequest{Key: "garbage"}, nil); status != 400 {
		t.Fatalf("malformed key: %d", status)
	}
	// anonymous client on a box route
	if status, _ := f.do(f.client, "POST", "/v1/heartbeat", wire.Heartbeat{}, nil); status != 401 {
		t.Fatalf("anonymous heartbeat: %d", status)
	}
	// unknown route: 404 without a body
	if status, body := f.do(boxClient, "GET", "/", nil, nil); status != 404 || len(body) != 0 {
		t.Fatalf("root: %d %q", status, body)
	}
	b, err := f.st.Box(context.Background(), boxID)
	must(t, err)
	if b.SiteID != "" || b.HWID != "hw-test" || b.OS != "linux" {
		t.Fatalf("box: %+v", b)
	}
	// unassigned box: heartbeat accepted, config says unassigned
	status, body := f.do(boxClient, "POST", "/v1/heartbeat", wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.0.0", OS: "linux", Arch: "arm64"}}, nil)
	if status != 200 {
		t.Fatalf("heartbeat: %d %s", status, body)
	}
	var hr wire.HeartbeatResponse
	_ = json.Unmarshal(body, &hr)
	if hr.Assigned || !strings.HasPrefix(hr.ConfigVersion, "cfg_") {
		t.Fatalf("heartbeat response: %+v", hr)
	}
	status, body = f.do(boxClient, "GET", "/v1/config", nil, nil)
	var cfg wire.Config
	_ = json.Unmarshal(body, &cfg)
	if status != 200 || cfg.Assigned || len(cfg.Hosts) != 0 || cfg.Discovery.Mode != wire.DiscoveryPassive || cfg.Version != hr.ConfigVersion {
		t.Fatalf("config: %d %+v", status, cfg)
	}
	if status, _ := f.do(boxClient, "POST", "/v1/netbird/claim", nil, nil); status != 409 {
		t.Fatalf("claim while unassigned: %d", status)
	}
}

// A key made for a site: the box is assigned the moment it enrolls, nobody clicks.
func TestSiteBoundKeyAssignsTheBox(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	k2, _ := pki.NewEnrollmentKey(f.host, 443, f.ca.Fingerprint())
	must(t, f.st.CreateEnrollmentKey(ctx, store.EnrollmentKey{ID: "key_site", SecretHash: k2.SecretHash(), SiteID: "site_a", CreatedAt: f.now, ExpiresAt: f.now.Add(24 * time.Hour)}))
	boxID, boxClient, status := f.enroll(k2.String())
	if status != 200 {
		t.Fatalf("enroll: %d", status)
	}
	b, err := f.st.Box(ctx, boxID)
	must(t, err)
	if b.SiteID != "site_a" {
		t.Fatalf("box not assigned by its key: %+v", b)
	}
	status, body := f.do(boxClient, "POST", "/v1/heartbeat", wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.0.0", OS: "linux", Arch: "amd64"}, Box: wire.BoxInfo{LAN: []string{"192.168.10.0/24", "10.9.0.0/16"}}}, nil)
	var hr wire.HeartbeatResponse
	_ = json.Unmarshal(body, &hr)
	if status != 200 || !hr.Assigned {
		t.Fatalf("heartbeat after pre-assignment: %d %+v", status, hr)
	}
	b, _ = f.st.Box(ctx, boxID)
	if len(b.LAN) != 2 || b.LAN[0] != "192.168.10.0/24" {
		t.Fatalf("LAN not stored from the heartbeat: %+v", b.LAN)
	}
	keys, _ := f.st.EnrollmentKeys(ctx)
	for _, k := range keys {
		if k.ID == "key_site" && (k.SiteID != "site_a" || k.UsedByBox != boxID) {
			t.Fatalf("key record: %+v", k)
		}
	}
}

func TestAssignedBoxLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, boxClient, _ := f.enroll(f.key.String())
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))
	must(t, f.eng.CreateHost(ctx, store.Host{ID: "host_fw", TenantID: "ten_a", SiteID: "site_a", BoxID: boxID, Name: "fw", Address: "192.168.1.1", IsUplink: true,
		Checks: []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 443}}, CreatedAt: t0}, "test"))
	must(t, f.eng.CreateHost(ctx, store.Host{ID: "host_srv", TenantID: "ten_a", SiteID: "site_a", BoxID: boxID, Name: "srv", Address: "192.168.1.10", ParentID: "host_fw", CreatedAt: t0}, "test"))
	must(t, f.st.SetNetbirdKey(ctx, store.NetbirdKey{BoxID: boxID, ManagementURL: "https://a.vpn.example", SetupKey: "sk-1", CreatedAt: t0}))

	// config now lists both hosts, sweep discovery, pending netbird
	status, body := f.do(boxClient, "GET", "/v1/config", nil, nil)
	var cfg wire.Config
	_ = json.Unmarshal(body, &cfg)
	if status != 200 || !cfg.Assigned || len(cfg.Hosts) != 2 || cfg.Hosts[0].HostID != "host_fw" || len(cfg.Hosts[0].Checks) != 2 ||
		len(cfg.Hosts[1].Checks) != 1 || cfg.Hosts[1].Checks[0].Type != "icmp" || !cfg.NetbirdPending || cfg.Discovery.Mode != wire.DiscoverySweep {
		t.Fatalf("config: %d %+v", status, cfg)
	}
	// ETag round trip
	if status, _ := f.do(boxClient, "GET", "/v1/config", nil, map[string]string{"If-None-Match": `"` + cfg.Version + `"`}); status != 304 {
		t.Fatalf("If-None-Match: %d", status)
	}
	// netbird claim exactly once
	status, body = f.do(boxClient, "POST", "/v1/netbird/claim", nil, nil)
	var claim wire.NetbirdClaimResponse
	_ = json.Unmarshal(body, &claim)
	if status != 200 || claim.SetupKey != "sk-1" {
		t.Fatalf("claim: %d %+v", status, claim)
	}
	if status, _ := f.do(boxClient, "POST", "/v1/netbird/claim", nil, nil); status != 404 {
		t.Fatalf("second claim: %d", status)
	}
	_, body = f.do(boxClient, "GET", "/v1/config", nil, nil)
	_ = json.Unmarshal(body, &cfg)
	if cfg.NetbirdPending {
		t.Fatal("netbird still pending after claim")
	}

	// heartbeats: fw ok, srv fails three rounds → host.down(srv); plus a sighting → device.new
	hb := func(fwOK, srvOK bool, seen []wire.Sighting) wire.HeartbeatResponse {
		t.Helper()
		f.now = f.now.Add(60 * time.Second)
		req := wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.0.0", OS: "linux", Arch: "arm64"}, ConfigVersion: cfg.Version,
			Hosts: []wire.HostReport{
				{HostID: "host_fw", Rounds: []wire.Round{{At: f.now, OK: fwOK, Checks: []wire.CheckResult{{Type: "icmp", OK: fwOK}, {Type: "tcp:443", OK: fwOK}}}}},
				{HostID: "host_srv", Rounds: []wire.Round{{At: f.now, OK: srvOK, Checks: []wire.CheckResult{{Type: "icmp", OK: srvOK, Error: "timeout"}}}}},
				{HostID: "host_foreign", Rounds: []wire.Round{{At: f.now, OK: false}}},
			},
			Discovery: wire.DiscoveryReport{Seen: seen},
		}
		status, body := f.do(boxClient, "POST", "/v1/heartbeat", req, nil)
		if status != 200 {
			t.Fatalf("heartbeat: %d %s", status, body)
		}
		var resp wire.HeartbeatResponse
		_ = json.Unmarshal(body, &resp)
		return resp
	}
	hb(true, true, []wire.Sighting{{MAC: "00:11:22:33:44:55", IP: "192.168.1.50", Vendor: "Acme", LastSeen: f.now}})
	hb(true, false, nil)
	hb(true, false, nil)
	hb(true, false, nil)
	if got := f.pub.types(); got != "device.new host.down" {
		t.Fatalf("events: %s", got)
	}
	f.pub.reset()
	hv, err := f.eng.HostView(ctx, "host_srv")
	must(t, err)
	if hv.State.Observed != state.Down || hv.State.Reported != state.Down || hv.Suppressed != "" {
		t.Fatalf("srv view: %+v", hv.State)
	}
	// maintenance on the site, srv recovers inside it: nothing until the window ends
	must(t, f.eng.StartMaintenance(ctx, store.Maintenance{ID: "mnt_1", TenantID: "ten_a", SiteID: "site_a", Scope: "site", TargetID: "site_a", Until: f.now.Add(10 * time.Minute), Reason: "patch"}, "jeremia"))
	for i := 0; i < 10; i++ { // the box keeps heartbeating through the window
		hb(true, true, nil)
	}
	if got := f.pub.types(); got != "maintenance.started" {
		t.Fatalf("events during maintenance: %s", got)
	}
	f.pub.reset()
	must(t, f.eng.Tick(ctx)) // now == until: the window expires
	if got := f.pub.types(); got != "maintenance.ended host.up" {
		t.Fatalf("events after maintenance: %s", got)
	}
	if ms, _ := f.st.Maintenances(ctx, ""); len(ms) != 0 {
		t.Fatal("expired window still stored")
	}
	f.pub.reset()

	// silence: no heartbeat for 4 minutes → box.silent; device gone after 24 h
	f.now = f.now.Add(4 * time.Minute)
	must(t, f.eng.Tick(ctx))
	f.now = f.now.Add(24 * time.Hour)
	must(t, f.eng.Tick(ctx))
	if got := f.pub.types(); got != "box.silent device.gone" {
		t.Fatalf("events: %s", got)
	}
	f.pub.reset()
	hb(true, true, nil)
	if got := f.pub.types(); got != "box.back" {
		t.Fatalf("events: %s", got)
	}

	// persisted state survives a restart of the engine
	eng2, err := core.Load(ctx, f.st, f.pub, slog.Default())
	must(t, err)
	if hv, _ := eng2.HostView(ctx, "host_srv"); hv.State.Observed != state.Up || hv.State.Reported != state.Up {
		t.Fatalf("state after reload: %+v", hv.State)
	}
	if bs, ok := eng2.BoxState(boxID); !ok || bs.Status != state.Online || bs.TenantID != "ten_a" {
		t.Fatalf("box state after reload: %+v", bs)
	}

	// rollups were written
	rs, err := f.st.Rollups(ctx, "ten_a", "host_srv", t0, f.now.Add(time.Hour))
	must(t, err)
	if len(rs) == 0 {
		t.Fatal("no rollups")
	}

	// update metadata: nothing configured → 204; configured → info
	if status, _ := f.do(boxClient, "GET", "/v1/update?os=linux&arch=arm64", nil, nil); status != 204 {
		t.Fatalf("update without release: %d", status)
	}
	must(t, f.st.PutRelease(ctx, store.Release{Version: "0.2.0", OS: "linux", Arch: "arm64", URL: "https://dl/excubra", SHA256: "abc", Signature: "sig", CreatedAt: t0}))
	must(t, f.st.SetChannelVersion(ctx, "stable", "0.2.0"))
	status, body = f.do(boxClient, "GET", "/v1/update?os=linux&arch=arm64", nil, nil)
	var info wire.UpdateInfo
	_ = json.Unmarshal(body, &info)
	if status != 200 || info.Version != "0.2.0" || info.Signature != "sig" {
		t.Fatalf("update: %d %+v", status, info)
	}
	if status, _ := f.do(boxClient, "GET", "/v1/update?os=windows&arch=arm64", nil, nil); status != 400 {
		t.Fatalf("bad os: %d", status)
	}

	// renew, then revoke: the old and the new certificate are both refused afterwards
	key2, _ := pki.GenerateKey()
	csr2, _ := pki.CSRPEM(key2, "hw")
	status, body = f.do(boxClient, "POST", "/v1/renew", wire.RenewRequest{CSR: string(csr2)}, nil)
	var rr wire.RenewResponse
	_ = json.Unmarshal(body, &rr)
	if status != 200 || rr.Certificate == "" {
		t.Fatalf("renew: %d %s", status, body)
	}
	keyPEM2, _ := pki.KeyPEM(key2)
	cert2, _ := tls.X509KeyPair([]byte(rr.Certificate), keyPEM2)
	client2 := f.httpClient(&cert2)
	if status, _ := f.do(client2, "GET", "/v1/config", nil, nil); status != 200 {
		t.Fatalf("renewed cert refused: %d", status)
	}
	must(t, f.eng.RevokeBox(ctx, boxID, "jeremia"))
	if status, _ := f.do(client2, "GET", "/v1/config", nil, nil); status != 403 {
		t.Fatalf("revoked box accepted: %d", status)
	}
	if status, _ := f.do(boxClient, "GET", "/v1/config", nil, nil); status != 403 {
		t.Fatalf("revoked box (old cert) accepted: %d", status)
	}
}

// The service scan (ADR-0018): the switch reaches the box through its config, a
// report becomes services on the device and findings from the scan rules, and a
// later round that no longer sees a service marks it gone and resolves its finding.
func TestScanReportBecomesServicesAndFindings(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, boxClient, _ := f.enroll(f.key.String())
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))
	beat := func(hb wire.Heartbeat) wire.HeartbeatResponse {
		t.Helper()
		f.now = f.now.Add(60 * time.Second)
		hb.SentAt, hb.Agent = f.now, wire.AgentInfo{Version: "0.3.0", OS: "linux", Arch: "amd64"}
		status, body := f.do(boxClient, "POST", "/v1/heartbeat", hb, nil)
		if status != 200 {
			t.Fatalf("heartbeat: %d %s", status, body)
		}
		var resp wire.HeartbeatResponse
		_ = json.Unmarshal(body, &resp)
		return resp
	}
	// the device appears through discovery; the scan is off by default
	beat(wire.Heartbeat{Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "00:11:22:33:44:55", IP: "192.168.1.50", Vendor: "Acme", LastSeen: f.now}}}})
	_, body := f.do(boxClient, "GET", "/v1/config", nil, nil)
	var cfg wire.Config
	_ = json.Unmarshal(body, &cfg)
	if cfg.Scan.Enabled {
		t.Fatal("scan on without anyone switching it on")
	}
	must(t, f.eng.SetSiteScan(ctx, "site_a", true, "test"))
	_, body = f.do(boxClient, "GET", "/v1/config", nil, nil)
	_ = json.Unmarshal(body, &cfg)
	if !cfg.Scan.Enabled || cfg.Scan.MaxPPS != 20 || cfg.Scan.IntervalS != 86400 {
		t.Fatalf("scan config: %+v", cfg.Scan)
	}
	devs, err := f.st.Devices(ctx, "ten_a", "site_a", time.Time{})
	must(t, err)
	var devID string
	for _, d := range devs {
		if d.IP == "192.168.1.50" {
			devID = d.ID
		}
	}
	if devID == "" {
		t.Fatalf("device not in the inventory: %+v", devs)
	}

	// a round: telnet and an https service with an expired certificate
	expired := &wire.TLSInfo{Subject: "CN=old.example.test", Issuer: "CN=old.example.test", NotAfter: f.now.Add(-48 * time.Hour), SelfSigned: true, Version: "1.2"}
	beat(wire.Heartbeat{Scan: &wire.ScanReport{Round: "scan_1", StartedAt: f.now, Final: true, Scanned: 1, Hosts: []wire.ScanHost{{IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Services: []wire.ScanService{
		{Port: 23, Proto: "tcp", Name: "telnet"},
		{Port: 443, Proto: "tcp", Name: "https", Product: "nginx", Version: "1.24.0", Title: "Kamera", TLS: expired},
	}}}}})
	svcs, err := f.st.ServicesForDevice(ctx, devID)
	must(t, err)
	if len(svcs) != 2 || svcs[0].Port != 23 || svcs[1].Port != 443 || svcs[1].Product != "nginx" || len(svcs[1].TLS) == 0 || svcs[0].GoneAt != nil {
		t.Fatalf("services: %+v", svcs)
	}
	open, err := f.st.OpenFindings(ctx, "ten_a")
	must(t, err)
	rules := map[string]string{}
	for _, fd := range open {
		if fd.DeviceID == devID && fd.ConnectorID == "scan" {
			rules[fd.Rule] = fd.Severity
		}
	}
	if rules["scan.telnet"] != "high" || rules["scan.cert_expired"] != "high" || rules["scan.cert_selfsigned"] != "low" || len(rules) != 3 {
		t.Fatalf("scan findings: %v", rules)
	}
	rounds, err := f.st.ScanRounds(ctx, "site_a", 5)
	must(t, err)
	if len(rounds) != 1 || rounds[0].FinishedAt == nil || rounds[0].Hosts != 1 || rounds[0].Services != 2 || rounds[0].BoxID != boxID {
		t.Fatalf("rounds: %+v", rounds)
	}

	// the next round no longer sees telnet: the service is gone, its finding resolved
	beat(wire.Heartbeat{Scan: &wire.ScanReport{Round: "scan_2", StartedAt: f.now, Final: true, Scanned: 1, Hosts: []wire.ScanHost{{IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Services: []wire.ScanService{
		{Port: 443, Proto: "tcp", Name: "https", Product: "nginx", Version: "1.24.0", Title: "Kamera", TLS: expired},
	}}}}})
	svcs, _ = f.st.ServicesForDevice(ctx, devID)
	if len(svcs) != 2 || svcs[0].Port != 443 || svcs[1].Port != 23 || svcs[1].GoneAt == nil {
		t.Fatalf("after second round: %+v", svcs)
	}
	open, _ = f.st.OpenFindings(ctx, "ten_a")
	for _, fd := range open {
		if fd.DeviceID == devID && fd.Rule == "scan.telnet" {
			t.Fatalf("telnet finding survived: %+v", fd)
		}
	}
	// switched off again: the config says so
	must(t, f.eng.SetSiteScan(ctx, "site_a", false, "test"))
	_, body = f.do(boxClient, "GET", "/v1/config", nil, nil)
	_ = json.Unmarshal(body, &cfg)
	if cfg.Scan.Enabled {
		t.Fatal("scan still on after switching it off")
	}
}

// The outside view (ADR-0018): the server learns a site's public address from the
// box's heartbeat, an outpost gets it as a target, and what the outpost sees hangs
// on the device that stands for the address, judged by the stricter rules.
func TestOutpostScansTheSitesPublicAddress(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, boxClient, _ := f.enroll(f.key.String())
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))
	must(t, f.eng.SetSiteScan(ctx, "site_a", true, "test"))
	// the customer box heartbeats: its source address becomes the site's public address
	f.now = f.now.Add(time.Minute)
	if status, _ := f.do(boxClient, "POST", "/v1/heartbeat", wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.3.2", OS: "linux", Arch: "amd64"}}, nil); status != 200 {
		t.Fatalf("heartbeat: %d", status)
	}
	b, _ := f.st.Box(ctx, boxID)
	if b.PublicIP != "127.0.0.1" || b.Role != store.RoleBox {
		t.Fatalf("box after heartbeat: public=%q role=%q", b.PublicIP, b.Role)
	}

	// the outpost: a second box in a site of our own, made an outpost
	k2, _ := pki.NewEnrollmentKey(f.host, 443, f.ca.Fingerprint())
	must(t, f.st.CreateEnrollmentKey(ctx, store.EnrollmentKey{ID: "key_out", SecretHash: k2.SecretHash(), SiteID: "site_b", CreatedAt: f.now, ExpiresAt: f.now.Add(24 * time.Hour)}))
	must(t, f.eng.CreateSite(ctx, store.Site{ID: "site_b", TenantID: "ten_a", Name: "Außenposten", CreatedAt: f.now}, "test"))
	outID, outClient, status := f.enroll(k2.String())
	if status != 200 {
		t.Fatalf("outpost enroll: %d", status)
	}
	must(t, f.st.SetBoxRole(ctx, outID, store.RoleOutpost))
	_, body := f.do(outClient, "GET", "/v1/config", nil, nil)
	var cfg wire.Config
	_ = json.Unmarshal(body, &cfg)
	if !cfg.Scan.Enabled || len(cfg.Scan.External) != 1 || cfg.Scan.External[0].SiteID != "site_a" || cfg.Scan.External[0].IP != "127.0.0.1" || cfg.Scan.IntervalS != 3600 || cfg.Discovery.Mode != wire.DiscoveryPassive || len(cfg.Hosts) != 0 {
		t.Fatalf("outpost config: %+v discovery=%+v hosts=%d", cfg.Scan, cfg.Discovery, len(cfg.Hosts))
	}

	// the outpost reports: RDP and a FortiGate login page on the site's address
	f.now = f.now.Add(time.Minute)
	rep := &wire.ScanReport{Round: "scan_out_1", StartedAt: f.now, Final: true, Scanned: 1, Hosts: []wire.ScanHost{{IP: "127.0.0.1", SiteID: "site_a", Services: []wire.ScanService{
		{Port: 3389, Proto: "tcp", Name: "rdp"},
		{Port: 443, Proto: "tcp", Name: "https", Title: "FortiGate", TLS: &wire.TLSInfo{Subject: "CN=FGT", Issuer: "CN=FGT", SelfSigned: true, NotAfter: f.now.Add(300 * 24 * time.Hour), Version: "1.2"}},
	}}}}
	if status, body := f.do(outClient, "POST", "/v1/heartbeat", wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.3.2", OS: "linux", Arch: "amd64"}, Scan: rep}, nil); status != 200 {
		t.Fatalf("outpost heartbeat: %d %s", status, body)
	}
	ext, err := f.st.ExternalDevice(ctx, "site_a")
	must(t, err)
	if !ext.External || ext.IP != "127.0.0.1" || ext.SiteID != "site_a" {
		t.Fatalf("external device: %+v", ext)
	}
	svcs, _ := f.st.ServicesForDevice(ctx, ext.ID)
	if len(svcs) != 2 {
		t.Fatalf("outside services: %+v", svcs)
	}
	open, _ := f.st.OpenFindings(ctx, "ten_a")
	got := map[string]string{}
	for _, fd := range open {
		if fd.DeviceID == ext.ID && fd.ConnectorID == "wan" {
			got[fd.Rule] = fd.Severity
		}
	}
	if got["wan.rdp"] != "high" || got["wan.admin_ui"] != "high" || got["wan.cert_selfsigned"] != "medium" || len(got) != 3 {
		t.Fatalf("outside findings: %v", got)
	}
	// the inventory does not list the address as a LAN device; the round is marked external
	devs, _ := f.st.Devices(ctx, "ten_a", "site_a", time.Time{})
	for _, d := range devs {
		if d.External {
			t.Fatalf("external device in the LAN inventory: %+v", d)
		}
	}
	rounds, _ := f.st.ScanRounds(ctx, "site_a", 5)
	if len(rounds) != 1 || !rounds[0].External || rounds[0].BoxID != outID || rounds[0].Services != 2 {
		t.Fatalf("rounds: %+v", rounds)
	}
	// a report for an address the site never had is ignored
	f.now = f.now.Add(time.Minute)
	rep2 := &wire.ScanReport{Round: "scan_out_2", StartedAt: f.now, Final: true, Scanned: 1, Hosts: []wire.ScanHost{{IP: "203.0.113.9", SiteID: "site_a", Services: []wire.ScanService{{Port: 23, Proto: "tcp", Name: "telnet"}}}}}
	_, _ = f.do(outClient, "POST", "/v1/heartbeat", wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.3.2", OS: "linux", Arch: "amd64"}, Scan: rep2}, nil)
	if rounds, _ := f.st.ScanRounds(ctx, "site_a", 5); len(rounds) != 1 {
		t.Fatalf("unknown address accepted: %+v", rounds)
	}
	// a plain box may not report an outside view
	rep3 := &wire.ScanReport{Round: "scan_fake", StartedAt: f.now, Final: true, Scanned: 1, Hosts: []wire.ScanHost{{IP: "127.0.0.1", SiteID: "site_a", Services: []wire.ScanService{{Port: 23, Proto: "tcp", Name: "telnet"}}}}}
	_, _ = f.do(boxClient, "POST", "/v1/heartbeat", wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.3.2", OS: "linux", Arch: "amd64"}, Scan: rep3}, nil)
	if svcs, _ := f.st.ServicesForDevice(ctx, ext.ID); len(svcs) != 2 {
		t.Fatalf("a box reported an outside view: %+v", svcs)
	}
}

// Version rules (ADR-0018): what the scan identifies is judged against the
// end-of-life feed; a line past its end is urgent, and a new feed re-judges
// every device without waiting for the next round.
func TestVersionsAreJudgedAgainstTheFeed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, boxClient, _ := f.enroll(f.key.String())
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))
	must(t, f.eng.SetSiteScan(ctx, "site_a", true, "test"))
	fd := feed.New(nil, nil)
	fd.Now = func() time.Time { return f.now }
	fd.Put(&feed.Product{Slug: "nginx", FetchedAt: f.now, Cycles: []feed.Cycle{{Cycle: "1.28", Latest: "1.28.1", EOL: false}, {Cycle: "1.18", Latest: "1.18.0", EOL: "2021-04-20"}}})
	f.eng.Feed = fd
	beat := func(hb wire.Heartbeat) {
		t.Helper()
		f.now = f.now.Add(60 * time.Second)
		hb.SentAt, hb.Agent = f.now, wire.AgentInfo{Version: "0.3.3", OS: "linux", Arch: "amd64"}
		if status, body := f.do(boxClient, "POST", "/v1/heartbeat", hb, nil); status != 200 {
			t.Fatalf("heartbeat: %d %s", status, body)
		}
	}
	beat(wire.Heartbeat{Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "00:11:22:33:44:66", IP: "192.168.1.51", LastSeen: f.now}}}})
	beat(wire.Heartbeat{Scan: &wire.ScanReport{Round: "scan_v1", StartedAt: f.now, Final: true, Scanned: 1, Hosts: []wire.ScanHost{{IP: "192.168.1.51", MAC: "00:11:22:33:44:66", Services: []wire.ScanService{
		{Port: 80, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.18.0", Banner: "nginx/1.18.0"},
		{Port: 8080, Proto: "tcp", Name: "http", Product: "nginx", Version: "1.28.0", Banner: "nginx/1.28.0"},
	}}}}})
	open, _ := f.st.OpenFindings(ctx, "ten_a")
	got := map[string]string{}
	for _, fd := range open {
		if fd.ConnectorID == "version" {
			got[fd.Rule+"/"+fd.Key] = fd.Severity
		}
	}
	if got["version.eol/tcp/80"] != "high" || got["version.outdated/tcp/8080"] != "low" || len(got) != 2 {
		t.Fatalf("version findings: %v", got)
	}
	// the feed moves on: 1.28 reaches its end → re-assessed without a new scan
	fd.Put(&feed.Product{Slug: "nginx", FetchedAt: f.now, Cycles: []feed.Cycle{{Cycle: "1.30", Latest: "1.30.0", EOL: false}, {Cycle: "1.28", Latest: "1.28.1", EOL: "2026-01-01"}, {Cycle: "1.18", Latest: "1.18.0", EOL: "2021-04-20"}}})
	f.eng.ReassessVersions(ctx)
	open, _ = f.st.OpenFindings(ctx, "ten_a")
	got = map[string]string{}
	for _, fd := range open {
		if fd.ConnectorID == "version" {
			got[fd.Rule+"/"+fd.Key] = fd.Severity
		}
	}
	if got["version.eol/tcp/80"] != "high" || got["version.eol/tcp/8080"] != "high" || len(got) != 2 {
		t.Fatalf("after the feed changed: %v", got)
	}
}

// CVE matching (ADR-0018 §8): a version with known vulnerabilities in the cache
// becomes a finding of the source "vuln" when the scan reports it, and is
// re-assessed when the databases answer.
func TestKnownVulnerabilitiesBecomeFindings(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, boxClient, _ := f.enroll(f.key.String())
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))
	must(t, f.eng.SetSiteScan(ctx, "site_a", true, "test"))
	vs := vuln.New(nil, nil)
	vs.Now = func() time.Time { return f.now }
	q, _ := vuln.Identify(rules.Service{Product: "OpenSSH", Version: "9.2p1", Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"})
	vs.Put(&vuln.Result{Key: q.Key(), Product: "OpenSSH", Version: "9.2p1", FetchedAt: f.now, CVEs: []vuln.CVE{{ID: "CVE-2024-6387", Score: 8.1, Exploited: true, Summary: "regreSSHion", Fixed: "1:9.2p1-2+deb12u3"}}})
	f.eng.Vuln = vs
	beat := func(hb wire.Heartbeat) {
		t.Helper()
		f.now = f.now.Add(60 * time.Second)
		hb.SentAt, hb.Agent = f.now, wire.AgentInfo{Version: "0.5.1", OS: "linux", Arch: "amd64"}
		if status, body := f.do(boxClient, "POST", "/v1/heartbeat", hb, nil); status != 200 {
			t.Fatalf("heartbeat: %d %s", status, body)
		}
	}
	beat(wire.Heartbeat{Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "00:11:22:33:44:77", IP: "192.168.1.52", LastSeen: f.now}}}})
	beat(wire.Heartbeat{Scan: &wire.ScanReport{Round: "scan_c1", StartedAt: f.now, Final: true, Scanned: 1, Hosts: []wire.ScanHost{{IP: "192.168.1.52", MAC: "00:11:22:33:44:77", Services: []wire.ScanService{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.2p1", Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"},
	}}}}})
	open, _ := f.st.OpenFindings(ctx, "ten_a")
	var got *store.Finding
	for i := range open {
		if open[i].ConnectorID == "vuln" {
			got = &open[i]
		}
	}
	if got == nil || got.Rule != "vuln.known" || got.Key != "tcp/22" || got.Severity != "high" || !strings.Contains(got.Title, "aktiv ausgenutzt") {
		t.Fatalf("vuln finding: %+v", got)
	}
	// the package moves to a fixed revision: the databases say nothing is open → resolved on re-assessment
	q2, _ := vuln.Identify(rules.Service{Product: "OpenSSH", Version: "9.2p1", Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"})
	vs.Put(&vuln.Result{Key: q2.Key(), Product: "OpenSSH", Version: "9.2p1", FetchedAt: f.now, CVEs: []vuln.CVE{}})
	beat(wire.Heartbeat{Scan: &wire.ScanReport{Round: "scan_c2", StartedAt: f.now, Final: true, Scanned: 1, Hosts: []wire.ScanHost{{IP: "192.168.1.52", MAC: "00:11:22:33:44:77", Services: []wire.ScanService{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.2p1", Banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"},
	}}}}})
	f.eng.ReassessVulns(ctx)
	open, _ = f.st.OpenFindings(ctx, "ten_a")
	for _, fd := range open {
		if fd.ConnectorID == "vuln" {
			t.Fatalf("finding survived the fix: %+v", fd)
		}
	}
}

// A firmware version a connector reported is judged like a scanned service, and
// re-assessed when the databases answer, without waiting for the next reading.
func TestConnectorVersionsAreReassessed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, _, _ := f.enroll(f.key.String())
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))
	fw, _, _, err := f.st.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{MAC: "00:09:0f:aa:bb:cc", IP: "192.168.1.1", Hostname: "fw-1", LastSeen: f.now}, f.now)
	must(t, err)
	must(t, f.st.CreateConnector(ctx, store.Connector{ID: "con_fw", TenantID: "ten_a", SiteID: "site_a", BoxID: boxID, DeviceID: fw.ID, Kind: "fortigate", URL: "https://192.168.1.1", Sealed: "x", CreatedAt: f.now}))
	must(t, f.st.UpdateConnectorReading(ctx, boxID, wire.ConnectorReport{ID: "con_fw", DeviceID: fw.ID, Kind: "fortigate", OK: true, CollectedAt: f.now, Facts: json.RawMessage(`{"version":"v7.4.12"}`)}, f.now))
	vs := vuln.New(nil, nil)
	vs.Now = func() time.Time { return f.now }
	f.eng.Vuln = vs
	f.eng.ReassessVulns(ctx)
	if _, err := f.st.OpenFinding(ctx, fw.ID, "vuln.known", "connector"); err == nil {
		t.Fatal("finding without any data")
	}
	q, _ := vuln.Identify(rules.Service{Product: "FortiOS", Version: "v7.4.12"})
	vs.Put(&vuln.Result{Key: q.Key(), Product: "FortiOS", Version: "7.4.12", FetchedAt: f.now, CVEs: []vuln.CVE{{ID: "CVE-2026-1", Score: 6.1, Summary: "something"}}})
	f.eng.ReassessVulns(ctx) // what the loop does after a fetch
	fd, err := f.st.OpenFinding(ctx, fw.ID, "vuln.known", "connector")
	if err != nil || fd.Severity != "medium" || !strings.Contains(fd.Title, "FortiOS 7.4.12") {
		t.Fatalf("firmware finding: %+v %v", fd, err)
	}
}

// The DNS sensor (ADR-0020): off by default; switched on, the config carries the
// switches and the list version, the box fetches the list with an ETag, its
// report lands on the box row and in the day's totals, and what it saw becomes
// findings on the asking device.
func TestDNSSensorConfigListAndReport(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, boxClient, _ := f.enroll(f.key.String())
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))
	bl := blocklist.New(nil, nil)
	bl.Now = func() time.Time { return f.now }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hosts" {
			_, _ = w.Write([]byte("127.0.0.1 evil.test\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	bl.URLhaus, bl.ThreatFox = srv.URL+"/hosts", ""
	f.eng.Blocklist = bl
	beat := func(hb wire.Heartbeat) {
		t.Helper()
		f.now = f.now.Add(60 * time.Second)
		hb.SentAt, hb.Agent = f.now, wire.AgentInfo{Version: "0.7.0", OS: "linux", Arch: "amd64"}
		if status, body := f.do(boxClient, "POST", "/v1/heartbeat", hb, nil); status != 200 {
			t.Fatalf("heartbeat: %d %s", status, body)
		}
	}
	_, body := f.do(boxClient, "GET", "/v1/config", nil, nil)
	var cfg wire.Config
	_ = json.Unmarshal(body, &cfg)
	if cfg.DNS.Enabled {
		t.Fatal("dns sensor on without anyone switching it on")
	}
	if status, _ := f.do(boxClient, "GET", "/v1/blocklist", nil, nil); status != 204 {
		t.Fatalf("empty list must be 204, got %d", status)
	}
	if _, err := bl.Refresh(ctx, true); err != nil {
		t.Fatal(err)
	}
	must(t, f.eng.SetSiteDNS(ctx, "site_a", true, true, []string{"9.9.9.9:53"}, "test"))
	_, body = f.do(boxClient, "GET", "/v1/config", nil, nil)
	_ = json.Unmarshal(body, &cfg)
	if !cfg.DNS.Enabled || !cfg.DNS.Block || len(cfg.DNS.Upstreams) != 1 || cfg.DNS.ListVersion != bl.Version() || cfg.DNS.ListVersion == "" {
		t.Fatalf("dns config: %+v", cfg.DNS)
	}
	status, list := f.do(boxClient, "GET", "/v1/blocklist", nil, nil)
	if status != 200 || string(list) != "evil.test\n" {
		t.Fatalf("blocklist: %d %q", status, list)
	}
	if status, _ := f.do(boxClient, "GET", "/v1/blocklist", nil, map[string]string{"If-None-Match": `"` + bl.Version() + `"`}); status != 304 {
		t.Fatalf("known version must be 304, got %d", status)
	}

	// the box reports: listening, a few queries; the client device asked for a listed domain
	beat(wire.Heartbeat{Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "00:11:22:33:44:88", IP: "192.168.1.60", LastSeen: f.now}}}})
	f.pub.reset()
	beat(wire.Heartbeat{
		Box:     wire.BoxInfo{LANIP: "192.168.1.9"},
		DNS:     &wire.DNSReport{Listening: "192.168.1.9:53", ListVersion: bl.Version(), ListSize: 1, Upstream: "9.9.9.9:53", Queries: 120, Blocked: 1, NXDomain: 4, Clients: 7},
		Signals: []wire.Signal{{Kind: wire.SignalDNSBlock, IP: "192.168.1.60", Count: 1, Detail: "evil.test|www.evil.test|blocked", FirstAt: f.now, LastAt: f.now}},
	})
	box, err := f.st.Box(ctx, boxID)
	must(t, err)
	if box.DNS == nil || box.DNS.Listening != "192.168.1.9:53" || box.DNS.Queries != 120 || box.LANIP != "192.168.1.9" {
		t.Fatalf("box report: %+v lan=%s", box.DNS, box.LANIP)
	}
	days, err := f.st.DNSDays(ctx, "site_a", 5)
	must(t, err)
	if len(days) != 1 || days[0].Queries != 120 || days[0].Blocked != 1 || days[0].NXDomain != 4 {
		t.Fatalf("day totals: %+v", days)
	}
	if got := f.pub.types(); got != "security.alert" {
		t.Fatalf("events: %q", got)
	}
	dev, err := f.st.DeviceByAddress(ctx, "site_a", "", "192.168.1.60")
	must(t, err)
	fd, err := f.st.OpenFinding(ctx, dev.ID, "signal.dns_block", "evil.test")
	if err != nil || fd.Severity != "high" || !strings.Contains(fd.Title, "evil.test") {
		t.Fatalf("dns finding: %+v %v", fd, err)
	}
	// a second report adds to the day, a box that reports nothing keeps its last report
	beat(wire.Heartbeat{DNS: &wire.DNSReport{Listening: "192.168.1.9:53", Queries: 30}})
	beat(wire.Heartbeat{})
	days, _ = f.st.DNSDays(ctx, "site_a", 5)
	box, _ = f.st.Box(ctx, boxID)
	if days[0].Queries != 150 || box.DNS == nil || box.DNS.Queries != 30 {
		t.Fatalf("after more reports: %+v %+v", days, box.DNS)
	}
	must(t, f.eng.SetSiteDNS(ctx, "site_a", false, false, nil, "test"))
	_, body = f.do(boxClient, "GET", "/v1/config", nil, nil)
	_ = json.Unmarshal(body, &cfg)
	if cfg.DNS.Enabled {
		t.Fatal("dns still on after switching it off")
	}
}

// Live detection (ADR-0018 §7): the canary is on by default and off on request; a
// signal becomes a finding on its source device and, when it opens, one
// security.alert; the same signal again only grows the count; a quiet day
// resolves it.
func TestSignalsBecomeAlertsAndFindings(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	boxID, boxClient, _ := f.enroll(f.key.String())
	must(t, f.eng.AssignBox(ctx, boxID, "site_a", "test"))
	beat := func(hb wire.Heartbeat) {
		t.Helper()
		f.now = f.now.Add(60 * time.Second)
		hb.SentAt, hb.Agent = f.now, wire.AgentInfo{Version: "0.5.0", OS: "linux", Arch: "amd64"}
		if status, body := f.do(boxClient, "POST", "/v1/heartbeat", hb, nil); status != 200 {
			t.Fatalf("heartbeat: %d %s", status, body)
		}
	}
	_, body := f.do(boxClient, "GET", "/v1/config", nil, nil)
	var cfg wire.Config
	_ = json.Unmarshal(body, &cfg)
	if !cfg.Canary.Enabled {
		t.Fatal("canary off by default")
	}
	beat(wire.Heartbeat{Box: wire.BoxInfo{Canary: []int{445, 3389}}, Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "00:11:22:33:44:55", IP: "192.168.1.50", Vendor: "Acme", LastSeen: f.now}}}})
	box, err := f.st.Box(ctx, boxID)
	must(t, err)
	if len(box.Canary) != 2 || box.Canary[0] != 445 {
		t.Fatalf("armed ports not stored: %+v", box.Canary)
	}
	f.pub.reset()

	// two touches of the SMB decoy and a network search, both from the known device
	beat(wire.Heartbeat{Signals: []wire.Signal{
		{Kind: wire.SignalCanary, IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Port: 445, Count: 2, FirstAt: f.now, LastAt: f.now},
		{Kind: wire.SignalARPScan, IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Count: 254, FirstAt: f.now, LastAt: f.now},
	}})
	if got := f.pub.types(); got != "security.alert security.alert" {
		t.Fatalf("events: %q", got)
	}
	al := f.pub.events[0]
	if al.Severity != event.Critical || al.Source != event.SourceSignals || al.SiteID != "site_a" || al.BoxID != boxID || al.DeviceID == "" || al.Device == nil || al.Device.IP != "192.168.1.50" || al.Details["kind"] != wire.SignalCanary {
		t.Fatalf("alert: %+v", al)
	}
	open, err := f.st.OpenFindings(ctx, "ten_a")
	must(t, err)
	byRule := map[string]store.Finding{}
	for _, fd := range open {
		if fd.ConnectorID == "signal" {
			byRule[fd.Rule] = fd
		}
	}
	if len(byRule) != 2 || byRule["signal.canary"].Severity != "high" || byRule["signal.canary"].Key != "445" || byRule["signal.canary"].DeviceID != al.DeviceID || byRule["signal.arp_scan"].Severity != "high" {
		t.Fatalf("findings: %+v", byRule)
	}

	// the same touch again: no second alert, the count adds up
	f.pub.reset()
	beat(wire.Heartbeat{Signals: []wire.Signal{{Kind: wire.SignalCanary, IP: "192.168.1.50", MAC: "00:11:22:33:44:55", Port: 445, Count: 3, FirstAt: f.now, LastAt: f.now}}})
	if got := f.pub.types(); got != "" {
		t.Fatalf("repeated signal alerted again: %q", got)
	}
	fd, err := f.st.OpenFinding(ctx, al.DeviceID, "signal.canary", "445")
	must(t, err)
	var ev struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(fd.Evidence, &ev)
	if ev.Count != 5 || !strings.Contains(fd.Detail, "5 Versuche") {
		t.Fatalf("count did not add up: %d %s", ev.Count, fd.Detail)
	}

	// a source the inventory does not know is put there so the finding has a device
	beat(wire.Heartbeat{Signals: []wire.Signal{{Kind: wire.SignalARPSpoof, IP: "192.168.1.1", MAC: "de:ad:be:ef:00:01", Count: 1, Detail: "gateway 00:09:0f:aa:bb:cc → de:ad:be:ef:00:01", FirstAt: f.now, LastAt: f.now}}})
	dev, err := f.st.DeviceByAddress(ctx, "site_a", "de:ad:be:ef:00:01", "")
	must(t, err)
	if _, err := f.st.OpenFinding(ctx, dev.ID, "signal.arp_spoof", "192.168.1.1"); err != nil {
		t.Fatalf("spoof finding on the new device: %v", err)
	}

	// a signal a connector read from its device's logs hangs on that device, the source stays remote
	fgt, _, _, err := f.st.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{MAC: "00:09:0f:aa:bb:cc", IP: "192.168.1.1", Hostname: "fw-1", LastSeen: f.now}, f.now)
	must(t, err)
	f.pub.reset()
	beat(wire.Heartbeat{Signals: []wire.Signal{{Kind: wire.SignalFGTAdminFail, DeviceID: fgt.ID, IP: "203.0.113.9", Count: 7, Detail: "admin", FirstAt: f.now, LastAt: f.now}}})
	if got := f.pub.types(); got != "security.alert" {
		t.Fatalf("log signal event: %q", got)
	}
	if fd, err := f.st.OpenFinding(ctx, fgt.ID, "signal.fgt_admin_fail", "203.0.113.9"); err != nil || fd.Severity != "high" {
		t.Fatalf("finding on the firewall: %+v %v", fd, err)
	}
	if _, err := f.st.DeviceByAddress(ctx, "site_a", "", "203.0.113.9"); err == nil {
		t.Fatal("the remote source became a device of the LAN")
	}

	// a quiet day resolves the incidents, the switch turns the decoys off
	f.now = f.now.Add(25 * time.Hour)
	must(t, f.eng.Tick(ctx))
	open, _ = f.st.OpenFindings(ctx, "ten_a")
	for _, fd := range open {
		if fd.ConnectorID == "signal" {
			t.Fatalf("signal finding survived a quiet day: %+v", fd)
		}
	}
	must(t, f.eng.SetSiteCanary(ctx, "site_a", false, "test"))
	_, body = f.do(boxClient, "GET", "/v1/config", nil, nil)
	_ = json.Unmarshal(body, &cfg)
	if cfg.Canary.Enabled {
		t.Fatal("canary still on after switching it off")
	}
}

func TestVersionWindowAndRateLimit(t *testing.T) {
	f := newFixture(t)
	_, boxClient, _ := f.enroll(f.key.String())
	if status, body := f.do(boxClient, "GET", "/v1/config", nil, map[string]string{wire.HeaderAgentVersion: "9.9.9"}); status != 426 || !strings.Contains(string(body), "upgrade_required") {
		t.Fatalf("incompatible version: %d %s", status, body)
	}
	if status, _ := f.do(boxClient, "GET", "/v1/config", nil, map[string]string{wire.HeaderAgentVersion: "not-a-version"}); status != 400 {
		t.Fatalf("bad version header: %d", status)
	}
	limited := false
	for i := 0; i < 40; i++ {
		if status, _ := f.do(boxClient, "GET", "/v1/config", nil, nil); status == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("box rate limit never triggered")
	}
	f.now = f.now.Add(10 * time.Minute)
	if status, _ := f.do(boxClient, "GET", "/v1/config", nil, nil); status != 200 {
		t.Fatalf("rate limit did not recover: %d", status)
	}
}
