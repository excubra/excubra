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

// The CSRF token now comes from /api/me, like the app reads it.
var csrfRe = regexp.MustCompile(`"csrf":"([^"]+)"`)

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
	if status != 303 || loc != "/" {
		t.Fatalf("login step two: %d %s", status, loc)
	}
	_, body := f.get("/api/me")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token from /api/me:\n%s", body[:min(len(body), 400)])
	}
	f.csrf = m[1]
}

func TestLoginLogoutAndLockout(t *testing.T) {
	f := newFixture(t)
	if status, _ := f.get("/api/me"); status != 401 && status != 302 {
		t.Fatalf("anonymous api: %d", status)
	}
	if status, _ := f.get("/"); status != 302 {
		t.Fatalf("anonymous console: %d", status)
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
	status, body = f.get("/api/me")
	if status != 200 || !strings.Contains(body, userName) {
		t.Fatalf("me after login: %d", status)
	}
	// CSRF is enforced
	if status, _, _ := f.post("/api/tenants", url.Values{"slug": {"x"}, "name": {"X"}}, false); status != 403 {
		t.Fatalf("post without csrf: %d", status)
	}
	if status, _, _ := f.post("/logout", url.Values{}, true); status != 303 {
		t.Fatalf("logout: %d", status)
	}
	if status, _ := f.get("/"); status != 302 {
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

// The whole operator workflow over the endpoints the console app uses: customer,
// site, keys, tokens, webhook, box, device, host, maintenance, audit.
func TestWorkflowsOverTheAPI(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	ctx := context.Background()

	for _, p := range []string{"/api/overview", "/api/sites", "/api/boxes", "/api/tenants", "/api/maintenance", "/api/webhooks", "/api/keys", "/api/tokens", "/api/audit", "/api/events", "/api/users", "/api/findings", "/api/updates"} {
		status, body := f.get(p)
		if status != 200 || body == "" {
			t.Fatalf("GET %s: %d", p, status)
		}
	}

	// tenant and site
	if status, body, _ := f.post("/api/tenants", url.Values{"slug": {"kundea"}, "name": {"Kunde A"}}, true); status != 200 || !strings.Contains(body, `"to":"/tenants"`) {
		t.Fatalf("create tenant: %d %s", status, body)
	}
	if status, _, _ := f.post("/api/tenants/ten_kundea/sites", url.Values{"slug": {"lu"}, "name": {"Ludwigshafen"}}, true); status != 200 {
		t.Fatal("create site")
	}
	_, body := f.get("/api/sites")
	if !strings.Contains(body, "Ludwigshafen") || !strings.Contains(body, "Kunde A") {
		t.Fatal("the flat site list misses the new site")
	}

	// keys, tokens and the webhook secret are shown exactly once
	status, body, _ := f.post("/api/keys", url.Values{"count": {"2"}, "note": {"test"}}, true)
	if status != 200 || strings.Count(body, "EX0:1:ingest.example.test:443:") != 2 {
		t.Fatalf("create keys: %d %s", status, body)
	}
	status, body, _ = f.post("/api/tokens", url.Values{"name": {"crm"}}, true)
	if status != 200 || !strings.Contains(body, "ex0_") {
		t.Fatalf("create token: %d", status)
	}
	if status, _, _ := f.post("/api/webhooks", url.Values{"name": {"CRM"}, "url": {"https://crm.example/hook"}}, true); status != 200 {
		t.Fatalf("create webhook: %d", status)
	}
	targets, _ := f.st.WebhookTargets(ctx)
	if len(targets) != 1 || targets[0].Secret == "" {
		t.Fatal("target not stored")
	}
	if status, _, _ := f.post("/api/webhooks/"+targets[0].ID+"/test", url.Values{"tenant_id": {"ten_kundea"}}, true); status != 200 {
		t.Fatal("test ping")
	}

	// a box appears, gets assigned, reports a device; the device becomes a host
	must(t, f.st.CreateBox(ctx, store.Box{ID: "box_1", HWID: "hw", CertSerial: "1", CertNotAfter: time.Now().Add(time.Hour), EnrolledAt: time.Now()}))
	f.eng.RegisterBox(store.Box{ID: "box_1"})
	_, body = f.get("/api/boxes")
	if !strings.Contains(body, "box_1") {
		t.Fatal("unassigned box missing")
	}
	if status, _, _ := f.post("/api/boxes/box_1/assign", url.Values{"site_id": {"site_lu"}}, true); status != 200 {
		t.Fatal("assign box")
	}
	if status, _, _ := f.post("/api/boxes/box_1/settings", url.Values{"name": {"Büro"}, "channel": {"canary"}, "discovery_mode": {"sweep"}, "discovery_subnets": {"192.168.10.0/24"}}, true); status != 200 {
		t.Fatal("box settings")
	}
	if status, _, _ := f.post("/api/boxes/box_1/netbird", url.Values{"management_url": {"https://a.vpn.example"}, "setup_key": {"sk"}}, true); status != 200 {
		t.Fatal("netbird key")
	}
	status, body = f.get("/api/boxes/box_1")
	if status != 200 || !strings.Contains(body, "Büro") || !strings.Contains(body, "a.vpn.example") || !strings.Contains(body, "192.168.10.0/24") {
		t.Fatalf("box detail: %d", status)
	}
	box, _ := f.st.Box(ctx, "box_1")
	hb := wire.Heartbeat{SentAt: time.Now(), Agent: wire.AgentInfo{Version: "0.1.0", OS: "linux", Arch: "amd64"},
		Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "00:11:22:33:44:55", IP: "192.168.1.9", Vendor: "Acme", Hostname: "nas", LastSeen: time.Now()}}}}
	if _, err := f.eng.Heartbeat(ctx, box, hb); err != nil {
		t.Fatal(err)
	}
	status, body = f.get("/api/sites/site_lu")
	if status != 200 || !strings.Contains(body, "00:11:22:33:44:55") || !strings.Contains(body, "Acme") {
		t.Fatalf("site detail: %d", status)
	}
	devs, _ := f.st.Devices(ctx, "ten_kundea", "site_lu", time.Time{})
	if len(devs) != 1 {
		t.Fatal("device not stored")
	}
	status, body, _ = f.post("/api/devices/"+devs[0].ID+"/monitor", url.Values{"box_id": {"box_1"}, "icmp": {"1"}, "tcp_port": {"445"}, "slug": {"nas"}}, true)
	if status != 200 || !strings.Contains(body, `"to":"/hosts/host_nas"`) {
		t.Fatalf("monitor: %d %s", status, body)
	}
	status, body = f.get("/api/hosts/host_nas")
	if status != 200 || !strings.Contains(body, "192.168.1.9") || !strings.Contains(body, "445") {
		t.Fatalf("host detail: %d", status)
	}
	if status, _, _ := f.post("/api/hosts/host_nas", url.Values{"name": {"NAS"}, "address": {"192.168.1.9"}, "icmp": {"1"}, "is_uplink": {"1"}}, true); status != 200 {
		t.Fatal("host update")
	}
	h, _ := f.st.Host(ctx, "host_nas")
	if h.Name != "NAS" || !h.IsUplink || len(h.Checks) != 1 {
		t.Fatalf("host after update: %+v", h)
	}
	// no check selected: the app gets a 400 and a message, and nothing is saved
	if status, body, _ := f.post("/api/hosts/host_nas", url.Values{"name": {"NAS"}, "address": {"192.168.1.9"}}, true); status != 400 || !strings.Contains(body, `"ok":false`) {
		t.Fatalf("host update without checks: %d %s", status, body)
	}
	if h, _ := f.st.Host(ctx, "host_nas"); len(h.Checks) != 1 {
		t.Fatal("host update without checks was saved")
	}
	_, body = f.get("/api/overview")
	if !strings.Contains(body, "site_lu") {
		t.Fatal("overview misses the site card")
	}

	// maintenance from the host and from the maintenance page
	until := time.Now().Add(time.Hour).UTC().Format("2006-01-02T15:04")
	if status, _, _ := f.post("/api/hosts/host_nas/maintenance", url.Values{"until": {until}, "reason": {"patch"}}, true); status != 200 {
		t.Fatal("host maintenance")
	}
	_, body = f.get("/api/maintenance")
	if !strings.Contains(body, "patch") {
		t.Fatal("window not listed")
	}
	if status, _, _ := f.post("/api/hosts/host_nas/maintenance", url.Values{"action": {"end"}}, true); status != 200 {
		t.Fatal("end maintenance")
	}
	if status, _, _ := f.post("/api/maintenance", url.Values{"scope": {"site"}, "target_id": {"site_lu"}, "until": {until}}, true); status != 200 {
		t.Fatal("site maintenance")
	}
	ws := f.eng.Maintenances()
	if len(ws) != 1 || ws[0].Scope != "site" {
		t.Fatalf("windows: %+v", ws)
	}
	if status, _, _ := f.post("/api/maintenance/"+ws[0].ID+"/end", url.Values{}, true); status != 200 {
		t.Fatal("end site maintenance")
	}

	// delete host, watch straight from the device, revoke the box, audit shows it all
	if status, _, _ := f.post("/api/hosts/host_nas/delete", url.Values{}, true); status != 200 {
		t.Fatal("delete host")
	}
	status, body, _ = f.post("/api/devices/"+devs[0].ID+"/watch", url.Values{"uplink": {"1"}}, true)
	if status != 200 || !strings.Contains(body, `"to":"/sites/site_lu?tab=netz"`) {
		t.Fatalf("watch: %d %s", status, body)
	}
	hosts, _ := f.st.Hosts(ctx, "ten_kundea", "")
	if len(hosts) != 1 || !hosts[0].IsUplink || hosts[0].Address != "192.168.1.9" || len(hosts[0].Checks) != 1 || hosts[0].Checks[0].Type != wire.CheckICMP {
		t.Fatalf("watched host: %+v", hosts)
	}
	if status, _, _ := f.post("/api/hosts/"+hosts[0].ID+"/uplink", url.Values{}, true); status != 200 {
		t.Fatal("uplink toggle")
	}
	if h, _ := f.st.Host(ctx, hosts[0].ID); h.IsUplink {
		t.Fatal("uplink not toggled off")
	}
	if status, body, _ := f.post("/api/hosts/"+hosts[0].ID+"/unwatch", url.Values{}, true); status != 200 || !strings.Contains(body, `"to":"/sites/site_lu?tab=netz"`) {
		t.Fatalf("unwatch: %d %s", status, body)
	}
	if hosts, _ := f.st.Hosts(ctx, "ten_kundea", ""); len(hosts) != 0 {
		t.Fatal("host still there after unwatch")
	}
	if status, _, _ := f.post("/api/boxes/box_1/revoke", url.Values{}, true); status != 200 {
		t.Fatal("revoke box")
	}
	_, body = f.get("/api/audit")
	for _, want := range []string{"tenant.create", "site.create", "key.new", "token.new", "webhook.create", "box.assign", "host.create", "maintenance.start", "host.delete", "box.revoke"} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit misses %s", want)
		}
	}
	// the login page keeps its own assets
	if status, _ := f.get("/static/style.css"); status != 200 {
		t.Fatal("login stylesheet missing")
	}
	if status, _ := f.get("/static/mark.svg"); status != 200 {
		t.Fatal("mark missing")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
