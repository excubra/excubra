package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/agent/checks"
	"github.com/excubra/excubra/internal/agent/update"
	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/ingest"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// pub records what the server would deliver by webhook.
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

type fakePinger struct {
	mu   sync.Mutex
	down map[string]bool
}

func (f *fakePinger) Ping(_ context.Context, address string) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down[address] {
		return 0, errors.New("i/o timeout")
	}
	return 2 * time.Millisecond, nil
}

// world is a complete server plus one agent, in one process.
type world struct {
	t       *testing.T
	st      *store.Store
	eng     *core.Engine
	pub     *pub
	srv     *httptest.Server
	is      *ingest.Server
	host    string
	port    int
	ca      *pki.CA
	dir     string
	keyFile string
	pinger  *fakePinger
	nbCalls []string
	nbKeys  []string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "server"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ca, err := pki.LoadOrCreateCA(filepath.Join(dir, "server", "ca"))
	if err != nil {
		t.Fatal(err)
	}
	p := &pub{}
	eng, err := core.Load(context.Background(), st, p, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	is := ingest.New(eng, st, ca, slog.Default())
	srvCert, err := ca.LoadOrCreateServerCert(filepath.Join(dir, "server", "ca"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(is.Handler())
	srv.TLS = pki.IngestTLSConfig(ca, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil })
	srv.TLS.Certificates = []tls.Certificate{srvCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)

	ctx := context.Background()
	if err := st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "A", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := eng.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "HQ", CreatedAt: time.Now()}, "test"); err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, st: st, eng: eng, pub: p, srv: srv, is: is, host: host, port: port, ca: ca, dir: dir, pinger: &fakePinger{down: map[string]bool{}}}
	w.keyFile = filepath.Join(dir, "enroll")
	key, _ := pki.NewEnrollmentKey(host, port, ca.Fingerprint())
	if err := st.CreateEnrollmentKey(ctx, store.EnrollmentKey{ID: "key_1", SecretHash: key.SecretHash(), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.keyFile, []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return w
}

// agent enrolls from the key file and returns a ready agent with fakes wired in.
func (w *world) agent() *Agent {
	w.t.Helper()
	stateDir := filepath.Join(w.dir, "state")
	st, err := OpenState(stateDir)
	if err != nil {
		w.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := waitForEnrollment(ctx, st, w.keyFile, slog.Default()); err != nil {
		w.t.Fatal(err)
	}
	if _, err := os.Stat(w.keyFile); !os.IsNotExist(err) {
		w.t.Fatal("used enrollment key file was not deleted")
	}
	if !st.Enrolled() || !strings.HasPrefix(st.BoxID, "box_") {
		w.t.Fatalf("not enrolled: %+v", st)
	}
	upd, err := update.New(stateDir, slog.Default())
	if err != nil {
		w.t.Fatal(err)
	}
	a, err := newAgent(st, slog.Default(), upd)
	if err != nil {
		w.t.Fatal(err)
	}
	a.checker = checks.NewRunner(w.pinger)
	a.disc.Names.Lookup = func(_ context.Context, ip string) string { return "name-of-" + ip }
	a.netbird.Binary = "true" // exists on PATH, so Status/Up reach the fake Exec
	a.netbird.Exec = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		w.nbCalls = append(w.nbCalls, strings.Join(args, " "))
		if args[0] == "up" {
			for i, arg := range args {
				if arg == "--setup-key-file" {
					b, _ := os.ReadFile(args[i+1])
					w.nbKeys = append(w.nbKeys, string(b))
				}
			}
			return []byte("Connected"), nil
		}
		return []byte(`{"management":{"url":"https://a.vpn.example","connected":true},"netbirdIp":"100.64.0.7/16","daemonVersion":"0.30.0"}`), nil
	}
	return a
}

func TestEndToEnd(t *testing.T) {
	w := newWorld(t)
	a := w.agent()
	ctx := context.Background()

	// 1. unassigned: heartbeat accepted, config says so, box visible server-side
	a.heartbeat(ctx)
	if a.cfg.Assigned || len(a.cfg.Hosts) != 0 || a.cfg.Version == "" {
		t.Fatalf("config after first heartbeat: %+v", a.cfg)
	}
	boxes, _ := w.st.Boxes(ctx, "")
	if len(boxes) != 1 || boxes[0].ID != a.st.BoxID || boxes[0].AgentVersion != version.Version || boxes[0].NetbirdStatus != "connected" {
		t.Fatalf("box server-side: %+v", boxes)
	}
	if a.clockOffset == nil {
		t.Fatal("clock offset not recorded")
	}

	// 2. the operator assigns the box, adds a host and a NetBird key
	must(t, w.eng.AssignBox(ctx, a.st.BoxID, "site_a", "test"))
	must(t, w.eng.CreateHost(ctx, store.Host{ID: "host_fw", TenantID: "ten_a", SiteID: "site_a", BoxID: a.st.BoxID, Name: "fw", Address: "192.168.1.1",
		Checks: []wire.CheckConfig{{Type: "icmp"}}, CreatedAt: time.Now()}, "test"))
	must(t, w.st.SetNetbirdKey(ctx, store.NetbirdKey{BoxID: a.st.BoxID, ManagementURL: "https://a.vpn.example", SetupKey: "sk-secret", CreatedAt: time.Now()}))

	// 3. next heartbeat sees the new config version, pulls, claims netbird once
	a.heartbeat(ctx)
	if !a.cfg.Assigned || len(a.cfg.Hosts) != 1 || a.cfg.Hosts[0].HostID != "host_fw" {
		t.Fatalf("config after assignment: %+v", a.cfg)
	}
	if len(w.nbKeys) != 1 || w.nbKeys[0] != "sk-secret" {
		t.Fatalf("netbird up with key: %v (calls %v)", w.nbKeys, w.nbCalls)
	}
	if _, err := os.Stat(filepath.Join(a.st.Dir, "netbird-setup-key")); !os.IsNotExist(err) {
		t.Fatal("setup key file left on disk")
	}
	a.heartbeat(ctx)
	if len(w.nbKeys) != 1 {
		t.Fatal("netbird key claimed twice")
	}
	if saved, ok := a.st.LoadConfig(); !ok || saved.Version != a.cfg.Version {
		t.Fatal("config not persisted")
	}

	// 4. checks: three failed rounds → host.down, two ok rounds → host.up
	w.pinger.down["192.168.1.1"] = true
	for i := 0; i < 3; i++ {
		a.runRounds(ctx, a.cfg.Hosts)
	}
	a.heartbeat(ctx)
	if got := w.pub.types(); got != "host.down" {
		t.Fatalf("events: %q", got)
	}
	hv, _ := w.eng.HostView(ctx, "host_fw")
	if hv.State.Observed != state.Down || len(hv.State.LastChecks) != 1 || hv.State.LastChecks[0].Error != "timeout" {
		t.Fatalf("host state server-side: %+v", hv.State)
	}
	w.pinger.down["192.168.1.1"] = false
	a.runRounds(ctx, a.cfg.Hosts)
	a.runRounds(ctx, a.cfg.Hosts)
	a.heartbeat(ctx)
	if got := w.pub.types(); got != "host.down host.up" {
		t.Fatalf("events: %q", got)
	}

	// 5. discovery sightings reach the inventory with vendor and name
	a.disc.Table.See("b8:27:eb:12:34:56", "192.168.1.30", "")
	a.disc.Table.See("", "192.168.10.9", "") // icmp-swept, other subnet
	a.heartbeat(ctx)
	devs, _ := w.st.Devices(ctx, "ten_a", "", time.Time{})
	if len(devs) != 2 {
		t.Fatalf("devices: %+v", devs)
	}
	for _, d := range devs {
		switch d.IP {
		case "192.168.1.30":
			if d.Vendor != "Raspberry Pi Foundation" || d.Hostname != "name-of-192.168.1.30" {
				t.Fatalf("pi device: %+v", d)
			}
		case "192.168.10.9":
			if d.MAC != "" {
				t.Fatalf("swept device should have no mac: %+v", d)
			}
		default:
			t.Fatalf("unexpected device %+v", d)
		}
	}
	if got := w.pub.types(); got != "host.down host.up device.new device.new" {
		t.Fatalf("events: %q", got)
	}

	// 6. a downloaded build's selftest talks to the server with the stored identity
	if err := Selftest(a.st.Dir); err != nil {
		t.Fatalf("selftest: %v", err)
	}

	// 7. the server demands a newer agent: the loop queues an update check, rounds are kept
	// (server and agent share the version package in this process, so pin the server side)
	w.is.Version, _ = version.Parse("0.1.0")
	old := version.Version
	version.Version = "0.4.0"
	a.runRounds(ctx, a.cfg.Hosts)
	a.heartbeat(ctx)
	version.Version = old
	w.is.Version = version.Current()
	select {
	case <-a.updateNow:
	default:
		t.Fatal("426 did not trigger an update check")
	}
	if len(a.rounds["host_fw"]) != 1 {
		t.Fatalf("rounds after a failed heartbeat: %+v", a.rounds)
	}

	// 8. revocation: the heartbeat is refused and nothing is lost or crashes
	must(t, w.eng.RevokeBox(ctx, a.st.BoxID, "test"))
	a.heartbeat(ctx)
	if len(a.rounds["host_fw"]) != 1 {
		t.Fatal("rounds dropped after revocation")
	}
	if err := Selftest(a.st.Dir); err == nil {
		t.Fatal("selftest passed for a revoked box")
	}
}

func TestEnrollRefusedKeyIsDropped(t *testing.T) {
	w := newWorld(t)
	// burn the key with a first enrollment, then try again from the same file
	first := w.agent()
	_ = first
	badKey, _ := pki.NewEnrollmentKey(w.host, w.port, w.ca.Fingerprint())
	must(t, os.WriteFile(w.keyFile, []byte(badKey.String()), 0o600)) // never registered server-side
	st, err := OpenState(filepath.Join(w.dir, "state2"))
	must(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = waitForEnrollment(ctx, st, w.keyFile, slog.Default())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected to wait after a refused key, got %v", err)
	}
	if _, err := os.Stat(w.keyFile); !os.IsNotExist(err) {
		t.Fatal("a refused (unusable) key file must be deleted, not retried forever")
	}
	if st.Enrolled() {
		t.Fatal("enrolled with a refused key")
	}
}

func TestEnrollPinsTheCA(t *testing.T) {
	w := newWorld(t)
	otherCA, _ := pki.LoadOrCreateCA(t.TempDir())
	key, _ := pki.NewEnrollmentKey(w.host, w.port, otherCA.Fingerprint()) // pinned to a CA the server does not have
	st, _ := OpenState(filepath.Join(w.dir, "state3"))
	err := Enroll(context.Background(), st, key.String(), "", slog.Default())
	if err == nil || st.Enrolled() {
		t.Fatalf("enrollment against a server with the wrong CA succeeded: %v", err)
	}
}

func TestApplyConfigClampsAndPrunes(t *testing.T) {
	a := &Agent{rounds: map[string][]wire.Round{"host_old": {{OK: true}}, "host_keep": {{OK: true}}}}
	a.disc = discoveryForTest()
	a.applyConfig(wire.Config{Version: "cfg_1", Intervals: wire.Intervals{HeartbeatS: 5, CheckS: 1, ConfigMaxAgeS: 99999},
		Hosts:     []wire.HostConfig{{HostID: "host_keep", Address: "10.0.0.1", Checks: []wire.CheckConfig{{Type: "snmp"}}}},
		Discovery: wire.DiscoveryConfig{Mode: "sweep", Subnets: []string{"10.0.0.0/8"}}})
	if a.hbInterval != minHeartbeat || a.checkEvery != minCheck || a.configMaxAge != maxConfigAge {
		t.Fatalf("clamped intervals: %v %v %v", a.hbInterval, a.checkEvery, a.configMaxAge)
	}
	if _, ok := a.rounds["host_old"]; ok {
		t.Fatal("rounds of a removed host kept")
	}
	joined := strings.Join(a.cfgErrors, "\n")
	if !strings.Contains(joined, "snmp") || !strings.Contains(joined, "larger than") {
		t.Fatalf("config errors: %v", a.cfgErrors)
	}
	a.applyConfig(wire.Config{Version: "cfg_2"})
	if a.hbInterval != 60*time.Second || a.checkEvery != 30*time.Second || a.configMaxAge != 15*time.Minute {
		t.Fatalf("defaults: %v %v %v", a.hbInterval, a.checkEvery, a.configMaxAge)
	}
}

func TestRoundsAreBounded(t *testing.T) {
	a := &Agent{rounds: map[string][]wire.Round{}}
	for i := 0; i < wire.MaxRoundsPerHost+5; i++ {
		a.addRound("host_x", wire.Round{OK: i%2 == 0})
	}
	reports, dropped := a.takeRounds()
	if len(reports) != 1 || len(reports[0].Rounds) != wire.MaxRoundsPerHost || dropped != 5 {
		t.Fatalf("take: %d rounds, dropped %d", len(reports[0].Rounds), dropped)
	}
	if len(a.rounds) != 0 {
		t.Fatal("take did not clear")
	}
	a.addRound("host_x", wire.Round{OK: true})
	a.putRounds(reports) // heartbeat failed: old rounds go back in front of the new one
	if rs := a.rounds["host_x"]; len(rs) != wire.MaxRoundsPerHost || !rs[len(rs)-1].OK {
		t.Fatalf("put: %d rounds, last ok=%v", len(rs), rs[len(rs)-1].OK)
	}
}

func TestHeartbeatJSONShape(t *testing.T) {
	// the wire format the server parses: a quick guard against accidental renames
	hb := wire.Heartbeat{Notes: []string{"n"}, Discovery: wire.DiscoveryReport{Seen: []wire.Sighting{{MAC: "aa:bb:cc:dd:ee:ff", IP: "1.2.3.4"}}}}
	b, _ := json.Marshal(hb)
	for _, key := range []string{`"sent_at"`, `"agent"`, `"box"`, `"netbird"`, `"config_version"`, `"notes"`, `"discovery"`, `"buffer"`, `"mac"`, `"last_seen"`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("heartbeat json misses %s: %s", key, b)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
