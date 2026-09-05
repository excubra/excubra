package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/server/api"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

var t0 = time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

// pub records events and stores them like the real deliverer would.
type pub struct {
	st     *store.Store
	events []event.Event
}

func (p *pub) Publish(ctx context.Context, ev event.Event) error {
	p.events = append(p.events, ev)
	body, _ := json.Marshal(ev)
	return p.st.InsertEvent(ctx, ev, body, nil, ev.OccurredAt)
}

type fixture struct {
	t   *testing.T
	st  *store.Store
	eng *core.Engine
	srv *httptest.Server
	pub *pub
	now time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	p := &pub{st: st}
	eng, err := core.Load(context.Background(), st, p, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, st: st, eng: eng, pub: p, now: t0}
	eng.Now = func() time.Time { return f.now }
	a := api.New(eng, st, slog.Default())
	a.Now = func() time.Time { return f.now }
	f.srv = httptest.NewServer(a.Handler())
	t.Cleanup(f.srv.Close)

	ctx := context.Background()
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Kunde A", CreatedAt: t0}))
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_b", Name: "Kunde B", CreatedAt: t0}))
	must(t, eng.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "Ludwigshafen", CreatedAt: t0}, "test"))
	must(t, st.CreateBox(ctx, store.Box{ID: "box_1", SiteID: "site_a", HWID: "hw", CertSerial: "1", CertNotAfter: t0.Add(time.Hour), EnrolledAt: t0}))
	must(t, eng.CreateHost(ctx, store.Host{ID: "host_fw", TenantID: "ten_a", SiteID: "site_a", BoxID: "box_1", Name: "FortiGate", Address: "192.168.1.1", MAC: "00:09:0f:aa:bb:cc", IsUplink: true,
		Checks: []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 443}}, CreatedAt: t0}, "test"))
	must(t, eng.CreateHost(ctx, store.Host{ID: "host_srv", TenantID: "ten_a", SiteID: "site_a", BoxID: "box_1", Name: "srv", Address: "192.168.1.10", ParentID: "host_fw", CreatedAt: t0}, "test"))
	must(t, st.CreateAPIToken(ctx, store.APIToken{ID: "tok_crm", Name: "crm", TokenHash: api.HashToken("crm-secret"), Tenants: []string{"*"}, CreatedAt: t0}))
	must(t, st.CreateAPIToken(ctx, store.APIToken{ID: "tok_b", Name: "b", TokenHash: api.HashToken("b-secret"), Tenants: []string{"ten_b"}, CreatedAt: t0}))
	must(t, st.CreateWebhookTarget(ctx, store.WebhookTarget{ID: "tgt_crm", Name: "crm", URL: "https://crm.example/hook", Secret: "s", TenantScope: "*", Enabled: true, CreatedAt: t0}))
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) do(token, method, path string, body any) (int, map[string]any) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			f.t.Fatalf("%s %s: bad json %q", method, path, raw)
		}
	}
	return resp.StatusCode, out
}

// heartbeat feeds rounds straight into the engine (the ingest layer is tested elsewhere).
func (f *fixture) heartbeat(fwOK, srvOK bool) {
	f.t.Helper()
	f.now = f.now.Add(60 * time.Second)
	box, err := f.st.Box(context.Background(), "box_1")
	must(f.t, err)
	lat := int64(3)
	hb := wire.Heartbeat{SentAt: f.now, Agent: wire.AgentInfo{Version: "0.1.0", OS: "linux", Arch: "arm64", UptimeS: 100},
		Netbird: wire.NetbirdInfo{Status: wire.NetbirdConnected, IP: "100.64.0.9"},
		Hosts: []wire.HostReport{
			{HostID: "host_fw", Rounds: []wire.Round{{At: f.now, OK: fwOK, Checks: []wire.CheckResult{{Type: "icmp", OK: fwOK, LatencyMS: &lat}, {Type: "tcp:443", OK: fwOK, LatencyMS: &lat}}}}},
			{HostID: "host_srv", Rounds: []wire.Round{{At: f.now, OK: srvOK, Checks: []wire.CheckResult{{Type: "icmp", OK: srvOK, Error: errIf(!srvOK, "timeout")}}}}},
		},
		Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "00:09:0f:aa:bb:cc", IP: "192.168.1.1", Vendor: "Fortinet", LastSeen: f.now}, {MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.77", Hostname: "printer", LastSeen: f.now}}},
	}
	if _, err := f.eng.Heartbeat(context.Background(), box, hb); err != nil {
		f.t.Fatal(err)
	}
}

func TestAuthAndScope(t *testing.T) {
	f := newFixture(t)
	if status, _ := f.do("", "GET", "/v1/tenants", nil); status != 401 {
		t.Fatalf("no token: %d", status)
	}
	if status, _ := f.do("wrong", "GET", "/v1/tenants", nil); status != 401 {
		t.Fatalf("wrong token: %d", status)
	}
	_, out := f.do("crm-secret", "GET", "/v1/tenants", nil)
	if len(out["tenants"].([]any)) != 2 {
		t.Fatalf("tenants for *: %v", out)
	}
	_, out = f.do("b-secret", "GET", "/v1/tenants", nil)
	if ts := out["tenants"].([]any); len(ts) != 1 || ts[0].(map[string]any)["tenant_id"] != "ten_b" {
		t.Fatalf("tenants for b: %v", out)
	}
	if status, _ := f.do("b-secret", "GET", "/v1/tenants/ten_a/hosts", nil); status != 404 {
		t.Fatalf("scope leak: %d", status)
	}
	if status, _ := f.do("b-secret", "GET", "/v1/hosts/host_fw", nil); status != 404 {
		t.Fatalf("scope leak on host: %d", status)
	}
	if status, _ := f.do("crm-secret", "GET", "/v1/nope", nil); status != 404 {
		t.Fatalf("unknown route: %d", status)
	}
	tok, _ := f.st.APITokenByHash(context.Background(), api.HashToken("crm-secret"))
	if tok.LastUsedAt == nil {
		t.Fatal("last_used_at not touched")
	}
}

func TestSitesHostsDevicesEvents(t *testing.T) {
	f := newFixture(t)
	f.heartbeat(true, true)
	f.heartbeat(true, false)
	f.heartbeat(true, false)
	f.heartbeat(true, false) // srv down

	_, out := f.do("crm-secret", "GET", "/v1/tenants/ten_a/sites", nil)
	sites := out["sites"].([]any)
	site := sites[0].(map[string]any)
	box := site["box"].(map[string]any)
	if site["site_id"] != "site_a" || box["state"] != "online" || box["netbird_status"] != "connected" || box["agent_version"] != "0.1.0" || box["last_heartbeat"] == nil {
		t.Fatalf("sites: %v", out)
	}

	_, out = f.do("crm-secret", "GET", "/v1/tenants/ten_a/hosts", nil)
	hosts := out["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("hosts: %v", out)
	}
	byID := map[string]map[string]any{}
	for _, h := range hosts {
		m := h.(map[string]any)
		byID[m["host_id"].(string)] = m
	}
	fw, srv := byID["host_fw"], byID["host_srv"]
	if fw["state"] != "up" || fw["is_uplink"] != true || len(fw["checks"].([]any)) != 2 || fw["mac"] != "00:09:0f:aa:bb:cc" {
		t.Fatalf("fw: %v", fw)
	}
	if srv["state"] != "down" || srv["parent_host_id"] != "host_fw" || srv["since"] == nil || srv["last_check"] == nil {
		t.Fatalf("srv: %v", srv)
	}
	if c := srv["checks"].([]any)[0].(map[string]any); c["ok"] != false || c["error"] != "timeout" {
		t.Fatalf("srv checks: %v", srv["checks"])
	}

	// host detail with the outage
	f.heartbeat(true, true)
	f.heartbeat(true, true) // srv up again
	_, out = f.do("crm-secret", "GET", "/v1/hosts/host_srv", nil)
	last := out["last_24h"].(map[string]any)
	outages := last["outages"].([]any)
	if len(outages) != 1 || outages[0].(map[string]any)["to"] == nil || last["rounds"].(float64) != 6 || last["failed_rounds"].(float64) != 3 {
		t.Fatalf("host detail: %v", out)
	}
	if avail := last["availability_percent"].(float64); avail != 50 {
		t.Fatalf("availability: %v", avail)
	}

	// devices: the FortiGate is monitored (mac), the printer is not
	_, out = f.do("crm-secret", "GET", "/v1/tenants/ten_a/devices", nil)
	devs := out["devices"].([]any)
	if len(devs) != 2 {
		t.Fatalf("devices: %v", out)
	}
	mon := map[string]bool{}
	for _, d := range devs {
		m := d.(map[string]any)
		mon[m["mac"].(string)] = m["monitored"].(bool)
	}
	if !mon["00:09:0f:aa:bb:cc"] || mon["aa:bb:cc:dd:ee:ff"] {
		t.Fatalf("monitored flags: %v", mon)
	}
	if status, _ := f.do("crm-secret", "GET", "/v1/tenants/ten_a/devices?since=yesterday", nil); status != 400 {
		t.Fatalf("bad since: %d", status)
	}

	_, out = f.do("crm-secret", "GET", "/v1/tenants/ten_a/events?since="+t0.Format(time.RFC3339), nil)
	evs := out["events"].([]any)
	var types []string
	for _, e := range evs {
		types = append(types, e.(map[string]any)["type"].(string))
	}
	if got := strings.Join(types, " "); got != "device.new device.new host.down host.up" {
		t.Fatalf("events: %s", got)
	}
}

func TestMaintenanceAndTestPing(t *testing.T) {
	f := newFixture(t)
	f.heartbeat(true, true)
	until := f.now.Add(time.Hour)
	if status, _ := f.do("crm-secret", "PUT", "/v1/hosts/host_srv/maintenance", map[string]any{"until": until, "reason": "patchday"}); status != 204 {
		t.Fatalf("put maintenance: %d", status)
	}
	if status, _ := f.do("crm-secret", "PUT", "/v1/hosts/host_srv/maintenance", map[string]any{"until": f.now.Add(-time.Hour)}); status != 400 {
		t.Fatalf("maintenance in the past: %d", status)
	}
	_, out := f.do("crm-secret", "GET", "/v1/tenants/ten_a/hosts", nil)
	for _, h := range out["hosts"].([]any) {
		m := h.(map[string]any)
		if m["host_id"] == "host_srv" && m["state"] != "maintenance" {
			t.Fatalf("srv state during maintenance: %v", m["state"])
		}
	}
	if last := f.pub.events[len(f.pub.events)-1]; last.Type != event.MaintenanceStarted || last.Maintenance.Reason != "patchday" {
		t.Fatalf("events: %+v", f.pub.events)
	}
	if status, _ := f.do("crm-secret", "DELETE", "/v1/hosts/host_srv/maintenance", nil); status != 204 {
		t.Fatalf("delete maintenance: %d", status)
	}
	if ms, _ := f.st.Maintenances(context.Background(), ""); len(ms) != 0 {
		t.Fatal("window not removed")
	}
	if status, _ := f.do("crm-secret", "PUT", "/v1/sites/site_a/maintenance", map[string]any{"until": until}); status != 204 {
		t.Fatalf("site maintenance: %d", status)
	}
	if status, _ := f.do("b-secret", "DELETE", "/v1/sites/site_a/maintenance", nil); status != 404 {
		t.Fatalf("scope on site maintenance: %d", status)
	}
	if status, _ := f.do("crm-secret", "DELETE", "/v1/sites/site_a/maintenance", nil); status != 204 {
		t.Fatalf("site maintenance end: %d", status)
	}

	status, out := f.do("crm-secret", "POST", "/v1/webhooks/tgt_crm/test", nil)
	if status != 202 || !strings.HasPrefix(out["event_id"].(string), "evt_") {
		t.Fatalf("test ping: %d %v", status, out)
	}
	last := f.pub.events[len(f.pub.events)-1]
	if last.Type != event.TestPing || last.TenantID != "ten_a" || last.Details["target_id"] != "tgt_crm" {
		t.Fatalf("test ping event: %+v", last)
	}
	if status, _ := f.do("crm-secret", "POST", "/v1/webhooks/tgt_nope/test", nil); status != 404 {
		t.Fatalf("unknown target: %d", status)
	}
	entries, _ := f.st.AuditEntries(context.Background(), 20, 0)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	if got := strings.Join(actions, " "); !strings.Contains(got, "webhook.test") || !strings.Contains(got, "maintenance.start") {
		t.Fatalf("audit: %s", got)
	}
}

func errIf(cond bool, msg string) string {
	if cond {
		return msg
	}
	return ""
}
