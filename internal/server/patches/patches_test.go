package patches

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/action1"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

type fakeReader struct {
	gotID    string
	eps      []action1.Endpoint
	vulns    []action1.Vulnerability
	software map[string][]action1.Software
	swFail   map[string]error
	off      bool
	fail     error
}

func (f *fakeReader) Configure(_, id, _ string) { f.gotID = id; f.off = id == "" }
func (f *fakeReader) Configured() bool          { return !f.off }
func (f *fakeReader) Endpoints(context.Context, string) ([]action1.Endpoint, error) {
	return f.eps, f.fail
}
func (f *fakeReader) Vulnerabilities(context.Context, string) ([]action1.Vulnerability, error) {
	return f.vulns, f.fail
}
func (f *fakeReader) EndpointSoftware(_ context.Context, _, epID string) ([]action1.Software, error) {
	if err := f.swFail[epID]; err != nil {
		return nil, err
	}
	return f.software[epID], nil
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// configure puts credentials in the settings, which is where the service takes
// them from at every run.
func configure(t *testing.T, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	must(t, st.SetSetting(ctx, action1.SettingClientID, "cid"))
	must(t, st.SetSetting(ctx, action1.SettingClientSecret, "sec"))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The pilot customer's shape end to end: the manager knows two machines, the box
// knows one of them, and the hole lands on that one as a single finding.
func TestSyncWritesOneFindingPerMatchedMachine(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Kunde A", CreatedAt: now}))
	must(t, st.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "Haus", CreatedAt: now}))
	dev, _, _, err := st.UpsertSighting(ctx, "ten_a", "site_a",
		wire.Sighting{MAC: "00:11:22:33:44:55", IP: "192.0.2.10", Hostname: "SRV-DC", LastSeen: now}, now)
	must(t, err)

	r := &fakeReader{
		eps: []action1.Endpoint{
			{ID: "ep-dc", Name: "SRV-DC.beispiel.test", Status: "Connected", LastSeen: "2026-09-14_10-00-00"},
			{ID: "ep-rds", Name: "SRV-RDS.beispiel.test", Status: "Connected", LastSeen: "2026-09-14_10-00-00"},
		},
		vulns: []action1.Vulnerability{{
			CVE: "CVE-2026-70465", CVSS: 8.1, Status: "Overdue",
			Deadline: now.AddDate(0, 0, -18),
			Affected: []action1.Affected{{Product: "FortiClient", Versions: []string{"7.4.2.1737"}}},
		}},
		software: map[string][]action1.Software{
			"ep-dc":  {{Name: "FortiClient", Version: "7.4.2.1737", UpdateStatus: "None"}},
			"ep-rds": {{Name: "Microsoft Edge", Version: "153.0", UpdateStatus: "Current"}},
		},
	}
	configure(t, st)
	svc := New(st, r, nil)
	svc.Now = func() time.Time { return now }
	must(t, st.SetPatchOrg(ctx, store.PatchOrg{TenantID: "ten_a", Provider: Provider, OrgID: "org-1", OrgName: "Kunde A"}, now))

	must(t, svc.Sync(ctx))
	got := svc.Status()
	if got.Tenants != 1 || got.Machines != 2 || got.Matched != 1 {
		t.Fatalf("status: %+v", got)
	}
	if len(got.Unmatched) != 1 || got.Unmatched[0] != "SRV-RDS.beispiel.test" {
		t.Fatalf("the machine EX0 does not know should be named, not invented: %+v", got.Unmatched)
	}

	open, err := st.OpenFindings(ctx, "")
	must(t, err)
	if len(open) != 1 {
		t.Fatalf("one machine, one finding: %+v", open)
	}
	f := open[0]
	if f.DeviceID != dev.ID || f.ConnectorID != Source || f.Severity != "high" {
		t.Fatalf("finding: %+v", f)
	}
	var ev map[string]any
	must(t, json.Unmarshal(f.Evidence, &ev))
	if ev["source"] != Provider || ev["worstCVE"] != "CVE-2026-70465" {
		t.Fatalf("evidence should say where it came from and what the worst is: %+v", ev)
	}

	// the hole is closed at the customer: the finding resolves on the next run
	r.vulns = nil
	r.software["ep-dc"] = []action1.Software{{Name: "FortiClient", Version: "7.4.3.0", UpdateStatus: "Current"}}
	must(t, svc.Sync(ctx))
	open, err = st.OpenFindings(ctx, "")
	must(t, err)
	if len(open) != 0 {
		t.Fatalf("a closed hole should close the finding: %+v", open)
	}
}

func TestSyncDoesNothingWithoutCredentialsOrLinks(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()

	svc := New(st, &fakeReader{off: true}, nil)
	must(t, svc.Sync(ctx)) // no credentials is a state, not an error
	if svc.Status().Tenants != 0 {
		t.Fatal("nothing configured, nothing read")
	}

	configure(t, st)
	svc = New(st, &fakeReader{}, nil)
	must(t, svc.Sync(ctx)) // credentials, but nobody linked a customer
	if svc.Status().Tenants != 0 {
		t.Fatal("a customer nobody linked is not read")
	}

	svc = New(st, nil, nil)
	must(t, svc.Sync(ctx)) // no reader at all
}

func TestSyncReportsAFailingProvider(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Kunde A", CreatedAt: now}))
	must(t, st.SetPatchOrg(ctx, store.PatchOrg{TenantID: "ten_a", Provider: Provider, OrgID: "org-1"}, now))

	configure(t, st)
	svc := New(st, &fakeReader{fail: errors.New("boom")}, nil)
	must(t, svc.Sync(ctx))
	if svc.Status().Error == "" {
		t.Fatal("a provider that fails should be visible, not silent")
	}
}

func TestHostKey(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"SRV-DC.beispiel.test", "srv-dc"},
		{"srv-dc", "srv-dc"},
		{" SRV-RDS.BEISPIEL.TEST. ", "srv-rds"},
		{"srv$", "srv"},
		{"", ""},
		{".leading", ""},
	} {
		if got := hostKey(c.in); got != c.want {
			t.Errorf("hostKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Somebody enters the credentials in the console while the server runs. The next
// run must use them; a restart to pick up a setting is the kind of thing nobody
// remembers at the moment it matters.
func TestSyncTakesCredentialsAsTheyStand(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Now()
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Kunde A", CreatedAt: now}))
	must(t, st.SetPatchOrg(ctx, store.PatchOrg{TenantID: "ten_a", Provider: Provider, OrgID: "org-1"}, now))

	r := &fakeReader{off: true}
	svc := New(st, r, nil)
	must(t, svc.Sync(ctx))
	if svc.Status().Tenants != 0 {
		t.Fatal("no credentials in the settings, nothing read")
	}

	must(t, st.SetSetting(ctx, action1.SettingClientID, "cid"))
	must(t, st.SetSetting(ctx, action1.SettingClientSecret, "sec"))
	must(t, svc.Sync(ctx))
	if r.gotID != "cid" {
		t.Fatalf("the reader should have been handed the stored credential, got %q", r.gotID)
	}
	if svc.Status().Tenants != 1 {
		t.Fatal("the linked customer should be read on the next run, without a restart")
	}
}

// A kick makes the loop look again straight away, and two kicks are not two runs.
func TestKickRunsOnceAndSoon(t *testing.T) {
	st := openStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	configure(t, st)
	now := time.Now()
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Kunde A", CreatedAt: now}))
	must(t, st.SetPatchOrg(ctx, store.PatchOrg{TenantID: "ten_a", Provider: Provider, OrgID: "org-1"}, now))

	svc := New(st, &fakeReader{}, nil)
	go svc.Run(ctx, time.Hour)
	svc.Kick()
	svc.Kick() // the second one must not stack a second run

	deadline := time.Now().Add(5 * time.Second)
	for svc.Status().Tenants == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if svc.Status().Tenants != 1 {
		t.Fatal("a kick should have run the sync without waiting for the interval")
	}
}

// The whole point of keeping unplaced machines: a person has to see them to
// assign them, and a decision made by hand must survive every later sync.
func TestAMachineAssignedByHandKeepsItsDevice(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 15, 9, 0, 0, 0, time.UTC)
	configure(t, st)

	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Kunde A", CreatedAt: now}))
	must(t, st.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "Haus", CreatedAt: now}))
	// The box calls it NAS01; the manager calls it FILESERVER. No name match is
	// ever going to bring these two together.
	dev, _, _, err := st.UpsertSighting(ctx, "ten_a", "site_a",
		wire.Sighting{MAC: "00:11:22:33:44:66", IP: "192.0.2.20", Hostname: "NAS01", LastSeen: now}, now)
	must(t, err)

	r := &fakeReader{
		eps: []action1.Endpoint{{ID: "ep-fs", Name: "FILESERVER.beispiel.test", Status: "Connected", LastSeen: "2026-09-15_08-00-00"}},
		vulns: []action1.Vulnerability{{
			CVE: "CVE-2026-1", CVSS: 9.1, Status: "Overdue", Deadline: now.AddDate(0, 0, -3),
			Affected: []action1.Affected{{Product: "Beispiel Backup", Versions: []string{"3.0"}}},
		}},
		software: map[string][]action1.Software{
			"ep-fs": {{Name: "Beispiel Backup", Version: "3.0", Missing: []string{"3.1"}}},
		},
	}
	svc := New(st, r, nil)
	svc.Now = func() time.Time { return now }
	must(t, st.SetPatchOrg(ctx, store.PatchOrg{TenantID: "ten_a", Provider: Provider, OrgID: "org-1"}, now))
	must(t, svc.Sync(ctx))

	// Nothing matched, but the machine is on the page with everything about it.
	rows, err := st.PatchMachines(ctx, "ten_a")
	must(t, err)
	if len(rows) != 1 || rows[0].DeviceID != "" {
		t.Fatalf("an unplaced machine must still be stored: %+v", rows)
	}
	if rows[0].CVECount != 1 || rows[0].WorstCVSS != 9.1 || rows[0].Pending != 1 {
		t.Fatalf("the state should be there even without a device: %+v", rows[0])
	}
	if open, err := st.OpenFindings(ctx, ""); err != nil || len(open) != 0 {
		t.Fatalf("no device, no finding: %+v %v", open, err)
	}

	// A person decides. From now on it is that device, and it stays.
	must(t, st.PinPatchMachine(ctx, Provider, "ep-fs", dev.ID))
	later := now.Add(time.Hour)
	svc.Now = func() time.Time { return later }
	must(t, svc.Sync(ctx))

	rows, err = st.PatchMachines(ctx, "ten_a")
	must(t, err)
	if len(rows) != 1 || rows[0].DeviceID != dev.ID || !rows[0].Pinned {
		t.Fatalf("the sync must not take a decision back: %+v", rows)
	}
	open, err := st.OpenFindings(ctx, "")
	must(t, err)
	if len(open) != 1 || open[0].DeviceID != dev.ID {
		t.Fatalf("the finding belongs on the assigned device: %+v", open)
	}
	m, ok, err := st.PatchMachineForDevice(ctx, dev.ID)
	must(t, err)
	if !ok || len(m.Software) == 0 {
		t.Fatalf("the device page needs the inventory: %+v", m)
	}
}

// A machine that is gone at the customer stops being a row here — but a run
// that could not read everything must not mistake its own gap for a removal.
func TestCleanupOnlyAfterAWholeRun(t *testing.T) {
	st := openStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	configure(t, st)
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Kunde A", CreatedAt: now}))
	must(t, st.SetPatchOrg(ctx, store.PatchOrg{TenantID: "ten_a", Provider: Provider, OrgID: "org-1"}, now))

	r := &fakeReader{
		eps: []action1.Endpoint{
			{ID: "ep-1", Name: "EINS.beispiel.test", Status: "Connected"},
			{ID: "ep-2", Name: "ZWEI.beispiel.test", Status: "Connected"},
		},
		software: map[string][]action1.Software{"ep-1": {{Name: "A", Version: "1"}}, "ep-2": {{Name: "B", Version: "1"}}},
	}
	svc := New(st, r, nil)
	svc.Now = func() time.Time { return now }
	must(t, svc.Sync(ctx))
	if rows, _ := st.PatchMachines(ctx, "ten_a"); len(rows) != 2 {
		t.Fatalf("both machines should be stored: %+v", rows)
	}

	// The provider fails for one of them. Nothing may be deleted.
	r.swFail = map[string]error{"ep-2": errors.New("timeout")}
	svc.Now = func() time.Time { return now.Add(time.Hour) }
	must(t, svc.Sync(ctx))
	if rows, _ := st.PatchMachines(ctx, "ten_a"); len(rows) != 2 {
		t.Fatalf("a partial run must not delete a machine it could not read: %+v", rows)
	}

	// It really is gone: a whole run without it removes it.
	r.swFail = nil
	r.eps = r.eps[:1]
	svc.Now = func() time.Time { return now.Add(2 * time.Hour) }
	must(t, svc.Sync(ctx))
	rows, err := st.PatchMachines(ctx, "ten_a")
	must(t, err)
	if len(rows) != 1 || rows[0].EndpointID != "ep-1" {
		t.Fatalf("a retired machine should be gone: %+v", rows)
	}
}
