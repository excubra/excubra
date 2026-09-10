package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/wire"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seed(t *testing.T, s *Store) {
	t.Helper()
	must(t, s.CreateTenant(ctx, Tenant{ID: "ten_a", Name: "Kunde A", CreatedAt: t0}))
	must(t, s.CreateSite(ctx, Site{ID: "site_a", TenantID: "ten_a", Name: "Ludwigshafen", CreatedAt: t0}))
	must(t, s.CreateBox(ctx, Box{ID: "box_1", HWID: "hw1", CertSerial: "1", CertNotAfter: t0.Add(90 * 24 * time.Hour), EnrolledAt: t0}))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenReopenMigrations(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	must(t, err)
	seed(t, s)
	must(t, s.Close())
	s2, err := Open(dir) // migrations must be idempotent
	must(t, err)
	defer s2.Close()
	if _, err := s2.Tenant(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Tenant(ctx, "ten_x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestBoxesAndAssignment(t *testing.T) {
	s := open(t)
	seed(t, s)
	b, err := s.Box(ctx, "box_1")
	must(t, err)
	if b.SiteID != "" || b.Channel != "stable" || b.RevokedAt != nil {
		t.Fatalf("fresh box: %+v", b)
	}
	must(t, s.AssignBox(ctx, "box_1", "site_a"))
	must(t, s.UpdateBoxAgent(ctx, "box_1", "0.1.0", "linux", "arm64"))
	b, _ = s.Box(ctx, "box_1")
	if b.SiteID != "site_a" || b.AgentVersion != "0.1.0" {
		t.Fatalf("assigned box: %+v", b)
	}
	if bs, _ := s.Boxes(ctx, "site_a"); len(bs) != 1 {
		t.Fatalf("boxes by site: %d", len(bs))
	}
	must(t, s.AssignBox(ctx, "box_1", ""))
	b, _ = s.Box(ctx, "box_1")
	if b.SiteID != "" {
		t.Fatal("unassign failed")
	}
	if err := s.AssignBox(ctx, "box_nope", "site_a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	must(t, s.RevokeBox(ctx, "box_1", t0))
	b, _ = s.Box(ctx, "box_1")
	serials, _ := s.RevokedSerials(ctx)
	if b.RevokedAt == nil || len(serials) != 1 || serials[0] != "1" {
		t.Fatalf("revoke: %+v %v", b, serials)
	}
	must(t, s.CreateHost(ctx, Host{ID: "host_x", TenantID: "ten_a", SiteID: "site_a", BoxID: "box_1", Name: "x", Address: "10.0.0.1", CreatedAt: t0}))
	must(t, s.DeleteBox(ctx, "box_1"))
	if _, err := s.Host(ctx, "host_x"); !errors.Is(err, ErrNotFound) {
		t.Fatal("hosts of a deleted box survived")
	}
	if serials, _ := s.RevokedSerials(ctx); len(serials) != 1 {
		t.Fatal("deny list must survive box deletion")
	}
}

func TestEnrollmentKeyLifecycle(t *testing.T) {
	s := open(t)
	must(t, s.CreateEnrollmentKey(ctx, EnrollmentKey{ID: "key_1", SecretHash: "h1", CreatedAt: t0, ExpiresAt: t0.Add(30 * 24 * time.Hour)}))
	must(t, s.CreateEnrollmentKey(ctx, EnrollmentKey{ID: "key_2", SecretHash: "h2", CreatedAt: t0, ExpiresAt: t0.Add(30 * 24 * time.Hour)}))
	must(t, s.CreateEnrollmentKey(ctx, EnrollmentKey{ID: "key_3", SecretHash: "h3", CreatedAt: t0, ExpiresAt: t0.Add(time.Hour)}))

	k, err := s.UseEnrollmentKey(ctx, "h1", "box_1", t0.Add(time.Minute))
	must(t, err)
	if k.UsedAt == nil || k.UsedByBox != "box_1" {
		t.Fatalf("used key: %+v", k)
	}
	if _, err := s.UseEnrollmentKey(ctx, "h1", "box_2", t0.Add(2*time.Minute)); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("second use: %v", err)
	}
	if _, err := s.UseEnrollmentKey(ctx, "unknown", "box_2", t0); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("unknown: %v", err)
	}
	must(t, s.RevokeEnrollmentKey(ctx, "key_2", t0))
	if _, err := s.UseEnrollmentKey(ctx, "h2", "box_2", t0); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := s.UseEnrollmentKey(ctx, "h3", "box_2", t0.Add(2*time.Hour)); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("expired: %v", err)
	}
	keys, _ := s.EnrollmentKeys(ctx)
	if len(keys) != 3 {
		t.Fatalf("keys: %d", len(keys))
	}
}

func TestNetbirdClaimOnce(t *testing.T) {
	s := open(t)
	seed(t, s)
	must(t, s.SetNetbirdKey(ctx, NetbirdKey{BoxID: "box_1", ManagementURL: "https://a.vpn.example", SetupKey: "sk", CreatedAt: t0}))
	k, err := s.ClaimNetbirdKey(ctx, "box_1", t0)
	must(t, err)
	if k.SetupKey != "sk" || k.ClaimedAt == nil {
		t.Fatalf("claim: %+v", k)
	}
	if _, err := s.ClaimNetbirdKey(ctx, "box_1", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second claim: %v", err)
	}
	must(t, s.SetNetbirdKey(ctx, NetbirdKey{BoxID: "box_1", ManagementURL: "https://a.vpn.example", SetupKey: "sk2", CreatedAt: t0})) // re-issue
	if _, err := s.ClaimNetbirdKey(ctx, "box_1", t0); err != nil {
		t.Fatalf("re-issued claim: %v", err)
	}
}

func TestDevices(t *testing.T) {
	s := open(t)
	seed(t, s)
	sg := wire.Sighting{MAC: "00:09:0F:AA:BB:CC", IP: "192.168.1.1", Vendor: "Fortinet"}
	d, isNew, wasGone, err := s.UpsertSighting(ctx, "ten_a", "site_a", sg, t0)
	must(t, err)
	if !isNew || wasGone || d.MAC != "00:09:0f:aa:bb:cc" || d.Vendor != "Fortinet" {
		t.Fatalf("first sighting: %+v %v %v", d, isNew, wasGone)
	}
	d2, isNew, _, err := s.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{MAC: "00:09:0f:aa:bb:cc", Hostname: "fw"}, t0.Add(time.Hour))
	must(t, err)
	if isNew || d2.ID != d.ID || d2.Hostname != "fw" || d2.IP != "192.168.1.1" || !d2.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Fatalf("second sighting: %+v", d2)
	}
	gone, err := s.MarkDevicesGone(ctx, t0.Add(2*time.Hour), t0.Add(25*time.Hour))
	must(t, err)
	if len(gone) != 1 || gone[0].GoneAt == nil {
		t.Fatalf("gone: %+v", gone)
	}
	if again, _ := s.MarkDevicesGone(ctx, t0.Add(2*time.Hour), t0.Add(26*time.Hour)); len(again) != 0 {
		t.Fatal("device marked gone twice")
	}
	_, isNew, wasGone, err = s.UpsertSighting(ctx, "ten_a", "site_a", sg, t0.Add(30*time.Hour))
	must(t, err)
	if isNew || !wasGone {
		t.Fatalf("return: new=%v gone=%v", isNew, wasGone)
	}
	devs, _ := s.Devices(ctx, "ten_a", "", time.Time{})
	if len(devs) != 1 || devs[0].GoneAt != nil {
		t.Fatalf("devices: %+v", devs)
	}
	if devs, _ := s.Devices(ctx, "ten_a", "", t0.Add(40*time.Hour)); len(devs) != 0 {
		t.Fatal("since filter ignored")
	}
	must(t, s.SetDeviceIgnored(ctx, d.ID, true))
	if _, _, _, err := s.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{}, t0); err == nil {
		t.Fatal("sighting without MAC and IP accepted")
	}
	// ICMP-swept devices in other subnets have no MAC and are keyed by IP
	d1, isNew, _, err := s.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{IP: "192.168.10.5"}, t0)
	must(t, err)
	d2, isNew2, _, err := s.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{IP: "192.168.10.5", Hostname: "plc"}, t0.Add(time.Minute))
	must(t, err)
	d3, isNew3, _, err := s.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{IP: "192.168.10.6"}, t0)
	must(t, err)
	if !isNew || isNew2 || !isNew3 || d1.ID != d2.ID || d1.ID == d3.ID || d2.Hostname != "plc" || d2.MAC != "" {
		t.Fatalf("ip-keyed devices: %+v %+v %+v", d1, d2, d3)
	}
	// a device with a MAC keeps its row when its IP changes
	m1, _, _, err := s.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{MAC: "aa:aa:aa:aa:aa:01", IP: "192.168.1.50"}, t0)
	must(t, err)
	m2, isNewM, _, err := s.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{MAC: "aa:aa:aa:aa:aa:01", IP: "192.168.1.51"}, t0.Add(time.Hour))
	must(t, err)
	if isNewM || m1.ID != m2.ID || m2.IP != "192.168.1.51" {
		t.Fatalf("mac-keyed device across ip change: %+v %+v", m1, m2)
	}
}

func TestHostsAndState(t *testing.T) {
	s := open(t)
	seed(t, s)
	h := Host{ID: "host_fw", TenantID: "ten_a", SiteID: "site_a", BoxID: "box_1", Name: "FortiGate", Address: "192.168.1.1", IsUplink: true,
		Checks: []wire.CheckConfig{{Type: "icmp"}, {Type: "tcp", Port: 443}}, CreatedAt: t0}
	must(t, s.CreateHost(ctx, h))
	must(t, s.CreateHost(ctx, Host{ID: "host_srv", TenantID: "ten_a", SiteID: "site_a", BoxID: "box_1", Name: "srv", Address: "192.168.1.10", ParentID: "host_fw", CreatedAt: t0}))
	got, err := s.Host(ctx, "host_fw")
	must(t, err)
	if len(got.Checks) != 2 || got.Checks[1].Port != 443 || !got.IsUplink {
		t.Fatalf("host: %+v", got)
	}
	got.Name = "FG-60F"
	got.Checks = nil
	must(t, s.UpdateHost(ctx, got))
	got, _ = s.Host(ctx, "host_fw")
	if got.Name != "FG-60F" || got.Checks == nil || len(got.Checks) != 0 {
		t.Fatalf("updated host: %+v", got)
	}
	if hs, _ := s.Hosts(ctx, "ten_a", ""); len(hs) != 2 {
		t.Fatalf("hosts by tenant: %d", len(hs))
	}

	st := state.Host{ID: "host_fw", Observed: state.Down, Reported: state.Up, Failures: 3, Since: t0, RunStart: t0, DownSince: t0, LastFailedChecks: []string{"icmp"}, LastBoxTime: t0}
	must(t, s.SaveHostState(ctx, st, t0))
	must(t, s.SaveBoxState(ctx, state.Box{ID: "box_1", Status: state.Silent, LastHeartbeat: t0, SilentSince: t0}, t0))
	hs, err := s.HostStates(ctx)
	must(t, err)
	if hs["host_fw"].Observed != state.Down || hs["host_fw"].Failures != 3 || hs["host_fw"].LastFailedChecks[0] != "icmp" || !hs["host_fw"].Since.Equal(t0) {
		t.Fatalf("host state: %+v", hs["host_fw"])
	}
	bs, _ := s.BoxStates(ctx)
	if bs["box_1"].Status != state.Silent || !bs["box_1"].LastHeartbeat.Equal(t0) {
		t.Fatalf("box state: %+v", bs["box_1"])
	}

	must(t, s.DeleteHost(ctx, "host_fw"))
	if _, err := s.HostStates(ctx); err != nil {
		t.Fatal(err)
	}
	if hs, _ := s.HostStates(ctx); len(hs) != 0 {
		t.Fatal("host_state did not cascade")
	}
	child, _ := s.Host(ctx, "host_srv")
	if child.ParentID != "" {
		t.Fatal("child kept a dangling parent")
	}
}

func TestMaintenanceTargetsTokensUsers(t *testing.T) {
	s := open(t)
	seed(t, s)
	must(t, s.CreateMaintenance(ctx, Maintenance{ID: "mnt_1", TenantID: "ten_a", SiteID: "site_a", Scope: "site", TargetID: "site_a", Until: t0.Add(time.Hour), Reason: "patch", SetBy: "j", CreatedAt: t0}))
	ms, _ := s.Maintenances(ctx, "ten_a")
	if len(ms) != 1 || ms[0].Reason != "patch" {
		t.Fatalf("maintenance: %+v", ms)
	}
	must(t, s.DeleteMaintenance(ctx, "mnt_1"))
	if err := s.DeleteMaintenance(ctx, "mnt_1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("double delete")
	}

	must(t, s.CreateWebhookTarget(ctx, WebhookTarget{ID: "tgt_crm", Name: "CRM", URL: "https://crm.example/hook", Secret: "s", TenantScope: "*", Enabled: true, CreatedAt: t0}))
	must(t, s.CreateWebhookTarget(ctx, WebhookTarget{ID: "tgt_b", Name: "B", URL: "https://b.example", Secret: "s", TenantScope: "ten_b", Enabled: true, CreatedAt: t0}))
	must(t, s.CreateWebhookTarget(ctx, WebhookTarget{ID: "tgt_off", Name: "off", URL: "https://off.example", Secret: "s", TenantScope: "ten_a", Enabled: false, CreatedAt: t0}))
	tg, _ := s.TargetsForTenant(ctx, "ten_a")
	if len(tg) != 1 || tg[0].ID != "tgt_crm" {
		t.Fatalf("targets for tenant: %+v", tg)
	}
	tgt, _ := s.WebhookTarget(ctx, "tgt_crm")
	tgt.Name, tgt.Secret = "CRM2", ""
	must(t, s.UpdateWebhookTarget(ctx, tgt))
	tgt, _ = s.WebhookTarget(ctx, "tgt_crm")
	if tgt.Name != "CRM2" || tgt.Secret != "s" {
		t.Fatalf("update kept secret? %+v", tgt)
	}

	must(t, s.CreateAPIToken(ctx, APIToken{ID: "tok_1", Name: "crm", TokenHash: "th", Tenants: []string{"ten_a"}, CreatedAt: t0}))
	tok, err := s.APITokenByHash(ctx, "th")
	must(t, err)
	if len(tok.Tenants) != 1 || tok.Tenants[0] != "ten_a" {
		t.Fatalf("token: %+v", tok)
	}
	must(t, s.TouchAPIToken(ctx, "tok_1", t0))
	must(t, s.RevokeAPIToken(ctx, "tok_1", t0))
	if _, err := s.APITokenByHash(ctx, "th"); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked token still resolves")
	}

	must(t, s.CreateUser(ctx, User{ID: "usr_1", Name: "jeremia", PasswordHash: "ph", TOTPSecret: "ts", CreatedAt: t0}))
	if err := s.CreateUser(ctx, User{ID: "usr_2", Name: "jeremia", PasswordHash: "ph", TOTPSecret: "ts", CreatedAt: t0}); err == nil {
		t.Fatal("duplicate user name accepted")
	}
	lock := t0.Add(15 * time.Minute)
	must(t, s.UpdateUserLoginState(ctx, "usr_1", 5, &lock, 42))
	u, _ := s.UserByName(ctx, "jeremia")
	if u.FailedLogins != 5 || u.LockedUntil == nil || u.TOTPLastCounter != 42 {
		t.Fatalf("user: %+v", u)
	}
	must(t, s.CreateSession(ctx, Session{TokenHash: "sh", UserID: "usr_1", CSRF: "c", CreatedAt: t0, LastSeen: t0}))
	must(t, s.TouchSession(ctx, "sh", t0.Add(time.Hour)))
	sess, _ := s.Session(ctx, "sh")
	if !sess.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Fatalf("session: %+v", sess)
	}
	must(t, s.DeleteStaleSessions(ctx, t0.Add(2*time.Hour), t0.Add(-time.Hour)))
	if _, err := s.Session(ctx, "sh"); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale session survived")
	}
	must(t, s.Audit(ctx, t0, "jeremia", "box.assign", "box_1", "→ site_a"))
	must(t, s.Audit(ctx, t0, "jeremia", "host.monitor", "host_fw", ""))
	entries, _ := s.AuditEntries(ctx, 10, 0)
	if len(entries) != 2 || entries[0].Action != "host.monitor" {
		t.Fatalf("audit: %+v", entries)
	}
	must(t, s.PutRelease(ctx, Release{Version: "0.2.0", OS: "linux", Arch: "arm64", URL: "https://x", SHA256: "s", Signature: "sig", CreatedAt: t0}))
	must(t, s.SetChannelVersion(ctx, "canary", "0.2.0"))
	if v, _ := s.ChannelVersion(ctx, "canary"); v != "0.2.0" {
		t.Fatal("channel version")
	}
	if v, _ := s.ChannelVersion(ctx, "stable"); v != "" {
		t.Fatal("unset channel must be empty")
	}
	if r, err := s.Release(ctx, "0.2.0", "linux", "arm64"); err != nil || r.Signature != "sig" {
		t.Fatalf("release: %+v %v", r, err)
	}
}

func TestEventsDeliveriesAcrossDays(t *testing.T) {
	s := open(t)
	seed(t, s)
	day1 := time.Date(2026, 9, 4, 23, 59, 30, 0, time.UTC)
	day2 := time.Date(2026, 9, 5, 0, 0, 30, 0, time.UTC)
	e1 := event.New(event.HostDown, day1)
	e1.TenantID, e1.SiteID, e1.BoxID, e1.HostID, e1.Source = "ten_a", "site_a", "box_1", "host_fw", event.SourceState
	e2 := event.New(event.HostUp, day2)
	e2.TenantID, e2.SiteID, e2.BoxID, e2.HostID, e2.Source = "ten_a", "site_a", "box_1", "host_fw", event.SourceState
	must(t, s.InsertEvent(ctx, e1, []byte(`{"body":1}`), []string{"tgt_a", "tgt_b"}, day1))
	must(t, s.InsertEvent(ctx, e2, []byte(`{"body":2}`), []string{"tgt_a"}, day2))
	if err := s.InsertEvent(ctx, e2, nil, nil, day2); err == nil {
		t.Fatal("duplicate event id accepted")
	}
	days, _ := s.Days("ten_a")
	if len(days) != 2 || days[0] != "2026-09-04" || days[1] != "2026-09-05" {
		t.Fatalf("days: %v", days)
	}
	got, err := s.Event(ctx, "ten_a", e1.ID)
	must(t, err)
	if got.Type != event.HostDown || got.HostID != "host_fw" {
		t.Fatalf("event: %+v", got)
	}
	if _, err := s.Event(ctx, "ten_a", "evt_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing event: %v", err)
	}
	if _, err := s.Event(ctx, "ten_b", e1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tenant must not see the event: %v", err)
	}
	evs, err := s.Events(ctx, "ten_a", day1.Add(-time.Hour), day2.Add(time.Hour), "", 0)
	must(t, err)
	if len(evs) != 2 || evs[0].ID != e1.ID || evs[1].ID != e2.ID {
		t.Fatalf("events across days: %+v", evs)
	}
	if evs, _ := s.Events(ctx, "ten_a", day1.Add(-time.Hour), day2.Add(time.Hour), "", 1); len(evs) != 1 {
		t.Fatal("limit ignored")
	}
	if evs, _ := s.Events(ctx, "ten_a", day2, day2.Add(time.Hour), "host_fw", 0); len(evs) != 1 || evs[0].ID != e2.ID {
		t.Fatalf("since/host filter: %+v", evs)
	}

	due, err := s.DueDeliveries(ctx, day2, 10)
	must(t, err)
	if len(due) != 3 {
		t.Fatalf("due: %d", len(due))
	}
	d := due[0]
	d.State, d.Attempts, d.LastStatus, d.DeliveredAt = DeliveryDelivered, 1, 200, day2
	must(t, s.UpdateDelivery(ctx, d))
	d = due[1]
	d.Attempts, d.LastStatus, d.LastError, d.NextAttemptAt = 1, 503, "unavailable", day2.Add(30*time.Second)
	must(t, s.UpdateDelivery(ctx, d))
	if due, _ := s.DueDeliveries(ctx, day2, 10); len(due) != 1 {
		t.Fatalf("due after updates: %d", len(due))
	}
	if due, _ := s.DueDeliveries(ctx, day2.Add(time.Minute), 10); len(due) != 2 {
		t.Fatalf("due after backoff: %d", len(due))
	}
	dl, _ := s.Deliveries(ctx, "ten_a", e1.ID)
	if len(dl) != 2 || dl[0].Body != `{"body":1}` {
		t.Fatalf("deliveries: %+v", dl)
	}
	d = due[0]
	d.State = DeliveryFailed
	must(t, s.UpdateDelivery(ctx, d))
	failed, _ := s.DeliveriesByState(ctx, "ten_a", DeliveryFailed, 7, day2)
	if len(failed) != 1 {
		t.Fatalf("failed: %+v", failed)
	}
	// two days later neither file is today or yesterday: nothing is due any more
	if due, _ := s.DueDeliveries(ctx, day2.Add(48*time.Hour), 10); len(due) != 0 {
		t.Fatalf("window: %d", len(due))
	}
	if due, _ := s.DueDeliveries(ctx, day2.Add(20*time.Hour), 10); len(due) != 2 { // e1/tgt_b retry and e2/tgt_a
		t.Fatalf("same day still due: %d", len(due))
	}
}

func TestRollupsPruneBackup(t *testing.T) {
	s := open(t)
	seed(t, s)
	lat := int64(5)
	for i := 0; i < 4; i++ {
		must(t, s.AddRollup(ctx, "ten_a", "host_fw", t0.Add(time.Duration(i)*10*time.Minute), "icmp", i != 2, &lat))
	}
	big := int64(50)
	must(t, s.AddRollup(ctx, "ten_a", "host_fw", t0.Add(time.Hour), "icmp", true, &big))
	rs, err := s.Rollups(ctx, "ten_a", "host_fw", t0, t0.Add(2*time.Hour))
	must(t, err)
	if len(rs) != 2 || rs[0].Rounds != 4 || rs[0].Failed != 1 || rs[0].LatencySumMS != 20 || rs[1].LatencyMaxMS != 50 {
		t.Fatalf("rollups: %+v", rs)
	}

	old := event.New(event.TestPing, t0.Add(-100*24*time.Hour))
	old.TenantID = "ten_a"
	must(t, s.InsertEvent(ctx, old, []byte("{}"), nil, t0))
	removed, err := s.Prune(90*24*time.Hour, t0)
	must(t, err)
	if len(removed) != 1 {
		t.Fatalf("prune removed %v", removed)
	}
	if days, _ := s.Days("ten_a"); len(days) != 1 {
		t.Fatalf("days after prune: %v", days)
	}

	bdir := filepath.Join(t.TempDir(), "backup")
	must(t, os.MkdirAll(filepath.Join(s.Dir(), "ca"), 0o700))
	must(t, os.WriteFile(filepath.Join(s.Dir(), "ca", "ca.key"), []byte("k"), 0o600))
	must(t, s.Backup(ctx, bdir, t0.Add(24*time.Hour)))
	if _, err := os.Stat(filepath.Join(bdir, "main.db")); err != nil {
		t.Fatal("main.db not backed up")
	}
	if _, err := os.Stat(filepath.Join(bdir, "tenants", "ten_a", "2026-09-05.db")); err != nil {
		t.Fatal("day file not backed up")
	}
	if st, err := os.Stat(filepath.Join(bdir, "ca", "ca.key")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal("ca key not backed up with mode 600")
	}
	r, err := Open(bdir)
	must(t, err)
	defer r.Close()
	if _, err := r.Tenant(ctx, "ten_a"); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rs, _ := r.Rollups(ctx, "ten_a", "host_fw", t0, t0.Add(2*time.Hour)); len(rs) != 2 {
		t.Fatal("restored day file incomplete")
	}
}
