package console_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/auth"
	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/console"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

const (
	userName = "jeremia"
	password = "correct horse battery"
)

type pub struct{ st *store.Store }

func (p *pub) Publish(ctx context.Context, ev event.Event) error {
	return p.st.InsertEvent(ctx, ev, []byte("{}"), nil, ev.OccurredAt)
}

type fixture struct {
	t      *testing.T
	st     *store.Store
	eng    *core.Engine
	srv    *httptest.Server
	client *http.Client
	secret string
	csrf   string
	con    *console.Server
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
	eng, err := core.Load(context.Background(), st, &pub{st: st}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	con, err := console.New(eng, st, ca, slog.Default(), time.UTC, "ingest.example.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, st: st, eng: eng, secret: auth.NewTOTPSecret(), con: con}
	f.srv = httptest.NewServer(con.Handler())
	t.Cleanup(f.srv.Close)
	jar, _ := cookiejar.New(nil)
	f.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(context.Background(), store.User{ID: "usr_1", Name: userName, PasswordHash: hash, TOTPSecret: f.secret, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) get(path string) (int, string) {
	f.t.Helper()
	resp, err := f.client.Get(f.srv.URL + path)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (f *fixture) post(path string, form url.Values, withCSRF bool) (int, string, string) {
	f.t.Helper()
	if withCSRF {
		form.Set("csrf", f.csrf)
	}
	resp, err := f.client.PostForm(f.srv.URL+path, form)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Location")
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (f *fixture) login(t *testing.T) {
	t.Helper()
	status, _, loc := f.post("/login", url.Values{"user": {userName}, "password": {password}}, false)
	if status != 303 || loc != "/login/code" {
		t.Fatalf("login step one: %d %s", status, loc)
	}
	if status, body := f.get("/login/code"); status != 200 || !strings.Contains(body, "Zweiter Faktor") {
		t.Fatalf("code page: %d", status)
	}
	code, _ := auth.TOTPCode(f.secret, auth.Counter(time.Now()))
	status, _, loc = f.post("/login/code", url.Values{"totp": {code}}, false)
	if status != 303 || loc != "/status" {
		t.Fatalf("login step two: %d %s", status, loc)
	}
	_, body := f.get("/status")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token on the status page:\n%s", body[:min(len(body), 800)])
	}
	f.csrf = m[1]
}

func TestLoginLogoutAndLockout(t *testing.T) {
	f := newFixture(t)
	if status, _ := f.get("/status"); status != 302 {
		t.Fatalf("anonymous status: %d", status)
	}
	status, body, _ := f.post("/login", url.Values{"user": {userName}, "password": {"wrong password!"}}, false)
	if status != 200 || !strings.Contains(body, "Anmeldung fehlgeschlagen") {
		t.Fatalf("wrong login: %d", status)
	}
	// the code page is not reachable without a passed first step
	if status, _ := f.get("/login/code"); status != 302 {
		t.Fatalf("code page without step one: %d", status)
	}
	f.login(t)
	status, body = f.get("/status")
	if status != 200 || !strings.Contains(body, "Abmelden") {
		t.Fatalf("status after login: %d", status)
	}
	// CSRF is enforced
	if status, _, _ := f.post("/tenants", url.Values{"slug": {"x"}, "name": {"X"}}, false); status != 403 {
		t.Fatalf("post without csrf: %d", status)
	}
	if status, _, _ := f.post("/logout", url.Values{}, true); status != 303 {
		t.Fatalf("logout: %d", status)
	}
	if status, _ := f.get("/status"); status != 302 {
		t.Fatal("still logged in after logout")
	}
	// lockout after five failures, even with the right code afterwards
	for i := 0; i < 5; i++ {
		f.post("/login", url.Values{"user": {userName}, "password": {"nope nope nope"}}, false)
	}
	if status, _, _ := f.post("/login", url.Values{"user": {userName}, "password": {password}}, false); status != 200 {
		t.Fatalf("locked account passed step one: %d", status)
	}
	u, _ := f.st.UserByName(context.Background(), userName)
	if u.LockedUntil == nil {
		t.Fatal("account not locked")
	}
}

func TestPagesAndWorkflows(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	ctx := context.Background()

	for _, p := range []string{"/status", "/status/table", "/boxes", "/tenants", "/maintenance", "/webhooks", "/keys", "/tokens", "/audit"} {
		if status, body := f.get(p); status != 200 || strings.Contains(body, "nicht gerendert") {
			t.Fatalf("GET %s: %d", p, status)
		}
	}

	// tenant and site
	if status, _, loc := f.post("/tenants", url.Values{"slug": {"kundea"}, "name": {"Kunde A"}}, true); status != 303 || loc != "/tenants" {
		t.Fatalf("create tenant: %d %s", status, loc)
	}
	if status, _, _ := f.post("/tenants/ten_kundea/sites", url.Values{"slug": {"lu"}, "name": {"Ludwigshafen"}}, true); status != 303 {
		t.Fatal("create site")
	}
	_, body := f.get("/tenants")
	if !strings.Contains(body, "Ludwigshafen") || !strings.Contains(body, "Kunde A") {
		t.Fatal("tenants page misses the new rows")
	}

	// keys, tokens, webhook target are shown once
	status, body, _ := f.post("/keys", url.Values{"count": {"2"}, "note": {"test"}}, true)
	if status != 200 || strings.Count(body, "EX0:1:ingest.example.test:443:") != 2 {
		t.Fatalf("create keys: %d", status)
	}
	status, body, _ = f.post("/tokens", url.Values{"name": {"crm"}}, true)
	if status != 200 || !strings.Contains(body, "ex0_") {
		t.Fatalf("create token: %d", status)
	}
	status, body, _ = f.post("/webhooks", url.Values{"name": {"CRM"}, "url": {"https://crm.example/hook"}}, true)
	if status != 200 || !strings.Contains(body, "nur einmal angezeigt") {
		t.Fatalf("create webhook: %d", status)
	}
	targets, _ := f.st.WebhookTargets(ctx)
	if len(targets) != 1 || targets[0].Secret == "" {
		t.Fatal("target not stored")
	}
	if status, _, _ := f.post("/webhooks/"+targets[0].ID+"/test", url.Values{"tenant_id": {"ten_kundea"}}, true); status != 303 {
		t.Fatal("test ping")
	}

	// a box appears, gets assigned, reports a device; the device becomes a host
	must(t, f.st.CreateBox(ctx, store.Box{ID: "box_1", HWID: "hw", CertSerial: "1", CertNotAfter: time.Now().Add(time.Hour), EnrolledAt: time.Now()}))
	f.eng.RegisterBox(store.Box{ID: "box_1"})
	_, body = f.get("/boxes")
	if !strings.Contains(body, "box_1") {
		t.Fatal("unassigned box missing")
	}
	if status, _, _ := f.post("/boxes/box_1/assign", url.Values{"site_id": {"site_lu"}}, true); status != 303 {
		t.Fatal("assign box")
	}
	if status, _, _ := f.post("/boxes/box_1/settings", url.Values{"name": {"Büro"}, "channel": {"canary"}, "discovery_mode": {"sweep"}, "discovery_subnets": {"192.168.10.0/24"}}, true); status != 303 {
		t.Fatal("box settings")
	}
	if status, _, _ := f.post("/boxes/box_1/netbird", url.Values{"management_url": {"https://a.vpn.example"}, "setup_key": {"sk"}}, true); status != 303 {
		t.Fatal("netbird key")
	}
	status, body = f.get("/boxes/box_1")
	if status != 200 || !strings.Contains(body, "Büro") || !strings.Contains(body, "a.vpn.example") || !strings.Contains(body, "192.168.10.0/24") {
		t.Fatalf("box page: %d", status)
	}
	box, _ := f.st.Box(ctx, "box_1")
	hb := wire.Heartbeat{SentAt: time.Now(), Agent: wire.AgentInfo{Version: "0.1.0", OS: "linux", Arch: "amd64"},
		Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "00:11:22:33:44:55", IP: "192.168.1.9", Vendor: "Acme", Hostname: "nas", LastSeen: time.Now()}}}}
	if _, err := f.eng.Heartbeat(ctx, box, hb); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.get("/sites/site_lu/inventory"); status != 302 {
		t.Fatalf("old inventory url should redirect: %d", status)
	}
	status, body = f.get("/sites/site_lu")
	if status != 200 || !strings.Contains(body, "00:11:22:33:44:55") || !strings.Contains(body, "beobachten") || !strings.Contains(body, "Acme") {
		t.Fatalf("site page: %d", status)
	}
	devs, _ := f.st.Devices(ctx, "ten_kundea", "site_lu", time.Time{})
	if len(devs) != 1 {
		t.Fatal("device not stored")
	}
	status, _, loc := f.post("/devices/"+devs[0].ID+"/monitor", url.Values{"box_id": {"box_1"}, "icmp": {"1"}, "tcp_port": {"445"}, "slug": {"nas"}}, true)
	if status != 303 || loc != "/hosts/host_nas" {
		t.Fatalf("monitor: %d %s", status, loc)
	}
	status, body = f.get("/hosts/host_nas")
	if status != 200 || !strings.Contains(body, "192.168.1.9") || !strings.Contains(body, `value="445"`) {
		t.Fatalf("host page: %d", status)
	}
	if status, _, _ := f.post("/hosts/host_nas", url.Values{"name": {"NAS"}, "address": {"192.168.1.9"}, "icmp": {"1"}, "is_uplink": {"1"}}, true); status != 303 {
		t.Fatal("host update")
	}
	h, _ := f.st.Host(ctx, "host_nas")
	if h.Name != "NAS" || !h.IsUplink || len(h.Checks) != 1 {
		t.Fatalf("host after update: %+v", h)
	}
	if status, _, _ := f.post("/hosts/host_nas", url.Values{"name": {"NAS"}, "address": {"192.168.1.9"}}, true); status != 303 {
		t.Fatal("host update without checks must redirect with a message")
	}
	if h, _ := f.st.Host(ctx, "host_nas"); len(h.Checks) != 1 {
		t.Fatal("host update without checks was saved")
	}
	_, body = f.get("/sites/site_lu?tab=ueberwachung")
	if !strings.Contains(body, "NAS") || !strings.Contains(body, "Uplink") {
		t.Fatal("site page misses the host")
	}
	_, body = f.get("/status")
	if !strings.Contains(body, `href="/sites/site_lu"`) || !strings.Contains(body, "Beobachtet") {
		t.Fatal("overview misses the site card")
	}

	// maintenance through the host page and the maintenance page
	until := time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04")
	if status, _, _ := f.post("/hosts/host_nas/maintenance", url.Values{"until": {until}, "reason": {"patch"}}, true); status != 303 {
		t.Fatal("host maintenance")
	}
	_, body = f.get("/maintenance")
	if !strings.Contains(body, "patch") {
		t.Fatal("window not listed")
	}
	if status, _, _ := f.post("/hosts/host_nas/maintenance", url.Values{"action": {"end"}}, true); status != 303 {
		t.Fatal("end maintenance")
	}
	if status, _, _ := f.post("/maintenance", url.Values{"scope": {"site"}, "target_id": {"site_lu"}, "until": {until}}, true); status != 303 {
		t.Fatal("site maintenance")
	}
	ws := f.eng.Maintenances()
	if len(ws) != 1 || ws[0].Scope != "site" {
		t.Fatalf("windows: %+v", ws)
	}
	if status, _, _ := f.post("/maintenance/"+ws[0].ID+"/end", url.Values{}, true); status != 303 {
		t.Fatal("end site maintenance")
	}

	// delete host, revoke box, audit shows it all
	if status, _, _ := f.post("/hosts/host_nas/delete", url.Values{}, true); status != 303 {
		t.Fatal("delete host")
	}
	// one-click watch from the device card, and back
	status, _, loc = f.post("/devices/"+devs[0].ID+"/watch", url.Values{"uplink": {"1"}}, true)
	if status != 303 || loc != "/sites/site_lu?tab=netz" {
		t.Fatalf("watch: %d %s", status, loc)
	}
	hosts, _ := f.st.Hosts(ctx, "ten_kundea", "")
	if len(hosts) != 1 || !hosts[0].IsUplink || hosts[0].Address != "192.168.1.9" || len(hosts[0].Checks) != 1 || hosts[0].Checks[0].Type != wire.CheckICMP {
		t.Fatalf("watched host: %+v", hosts)
	}
	if status, _, _ := f.post("/hosts/"+hosts[0].ID+"/uplink", url.Values{}, true); status != 303 {
		t.Fatal("uplink toggle")
	}
	if h, _ := f.st.Host(ctx, hosts[0].ID); h.IsUplink {
		t.Fatal("uplink not toggled off")
	}
	if status, _, loc := f.post("/hosts/"+hosts[0].ID+"/unwatch", url.Values{}, true); status != 303 || loc != "/sites/site_lu?tab=netz" {
		t.Fatalf("unwatch: %d %s", status, loc)
	}
	if hosts, _ := f.st.Hosts(ctx, "ten_kundea", ""); len(hosts) != 0 {
		t.Fatal("host still there after unwatch")
	}
	for _, path := range []string{"/events", "/events?range=7d&tenant=ten_kundea", "/users", "/sites/site_lu?tab=technik", "/sites/site_lu?tab=ereignisse"} {
		if status, body := f.get(path); status != 200 || !strings.Contains(body, "Abmelden") {
			t.Fatalf("%s: %d", path, status)
		}
	}
	if status, _, _ := f.post("/boxes/box_1/revoke", url.Values{}, true); status != 303 {
		t.Fatal("revoke box")
	}
	_, body = f.get("/audit")
	for _, want := range []string{"tenant.create", "site.create", "key.new", "token.new", "webhook.create", "box.assign", "host.create", "maintenance.start", "host.delete", "box.revoke"} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit misses %s", want)
		}
	}
	if status, _ := f.get("/static/htmx.min.js"); status != 200 {
		t.Fatal("static asset missing")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
