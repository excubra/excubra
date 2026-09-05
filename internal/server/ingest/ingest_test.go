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
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/ingest"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
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
