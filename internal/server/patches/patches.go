// Package patches brings the endpoint manager's view of a customer's Windows
// machines into EX0's findings.
//
// It closes the one hole the network view cannot: a scan reads what a service
// announces, and a Windows application announces nothing, which is why the CVE
// matching leaves Windows alone (ADR-0018 §8). The manager has an agent on the
// machine and knows exactly. Put together, the two say what neither says alone.
//
// Three rules this package keeps. It only reads — the manager can deploy patches
// and EX0 does not act on customer systems (salt E15, E16). It only looks at
// customers somebody linked by hand, because guessing which organization is
// which customer is how one customer sees another's machines. And a machine the
// manager knows but EX0 does not is reported as unmatched, never invented: a
// finding needs a device, and a device comes from the box.
package patches

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/action1"
	"github.com/excubra/excubra/internal/server/rules"
	"github.com/excubra/excubra/internal/server/store"
)

// Source is the findings source, like "vuln" and "signal" before it.
const Source = "patch"

// Provider is the only endpoint manager there is today. It lives in the mapping
// row so a second one later does not need a migration.
const Provider = "action1"

// Reader is what the service needs from the manager; the real one is
// *action1.Client and a test supplies its own.
type Reader interface {
	// Configure takes the credentials as they stand right now, so entering them
	// in the console works without restarting the server.
	Configure(baseURL, clientID, clientSecret string)
	Configured() bool
	Endpoints(ctx context.Context, orgID string) ([]action1.Endpoint, error)
	Vulnerabilities(ctx context.Context, orgID string) ([]action1.Vulnerability, error)
	EndpointSoftware(ctx context.Context, orgID, endpointID string) ([]action1.Software, error)
}

// Service syncs patch state on a schedule.
type Service struct {
	Store  *store.Store
	Reader Reader
	Log    *slog.Logger
	Now    func() time.Time

	kick chan struct{} // an operator changed something and wants to see it now

	mu     sync.Mutex
	status Status
}

// Status is the last run, for the console.
type Status struct {
	At        time.Time `json:"at"`
	Tenants   int       `json:"tenants"`
	Machines  int       `json:"machines"`
	Matched   int       `json:"matched"`
	Unmatched []string  `json:"unmatched"` // machines the manager knows and EX0 does not
	Findings  int       `json:"findings"`
	Error     string    `json:"error"`
}

// New returns a service. A nil reader or one without credentials makes every run
// a no-op, which is the state before somebody enters a key.
func New(st *store.Store, r Reader, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{Store: st, Reader: r, Log: log, Now: time.Now, kick: make(chan struct{}, 1)}
}

// Status returns the last run.
func (s *Service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Kick asks for a sync now, without waiting for the next hour. It never blocks
// and never stacks: somebody who just linked a customer wants to see the result,
// and somebody who clicks twice should not cause two runs.
func (s *Service) Kick() {
	if s == nil || s.kick == nil {
		return
	}
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run syncs shortly after start and then every interval, or whenever an operator
// changed something.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	t := time.NewTimer(90 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.kick:
			if !t.Stop() {
				<-t.C
			}
		case <-t.C:
		}
		if err := s.Sync(ctx); err != nil {
			s.Log.Warn("patch state", "err", err)
		}
		t.Reset(every)
	}
}

// Sync reads every linked customer and writes the findings.
func (s *Service) Sync(ctx context.Context) error {
	if s.Reader == nil {
		return nil
	}
	base, _ := s.Store.Setting(ctx, action1.SettingBaseURL)
	cid, _ := s.Store.Setting(ctx, action1.SettingClientID)
	sec, _ := s.Store.Setting(ctx, action1.SettingClientSecret)
	s.Reader.Configure(base, cid, sec)
	if !s.Reader.Configured() {
		return nil
	}
	links, err := s.Store.PatchOrgs(ctx)
	if err != nil {
		return err
	}
	now := s.Now()
	st := Status{At: now, Unmatched: []string{}}
	for _, link := range links {
		if link.Provider != Provider {
			continue
		}
		st.Tenants++
		n, matched, unmatched, err := s.syncTenant(ctx, link, now)
		if err != nil {
			st.Error = err.Error()
			s.Log.Warn("patch state", "tenant", link.TenantID, "err", err)
			continue
		}
		st.Machines += n
		st.Matched += matched
		st.Findings += matched
		st.Unmatched = append(st.Unmatched, unmatched...)
	}
	s.mu.Lock()
	s.status = st
	s.mu.Unlock()
	return nil
}

func (s *Service) syncTenant(ctx context.Context, link store.PatchOrg, now time.Time) (machines, matched int, unmatched []string, err error) {
	eps, err := s.Reader.Endpoints(ctx, link.OrgID)
	if err != nil {
		return 0, 0, nil, err
	}
	vulns, err := s.Reader.Vulnerabilities(ctx, link.OrgID)
	if err != nil {
		return 0, 0, nil, err
	}
	devices, err := s.Store.Devices(ctx, link.TenantID, "", time.Time{})
	if err != nil {
		return 0, 0, nil, err
	}
	byName := devicesByName(devices)
	byID := make(map[string]store.Device, len(devices))
	for _, d := range devices {
		byID[d.ID] = d
	}
	// What a person already decided by hand. It beats the name match, because
	// the reason somebody decides by hand is that the names do not agree.
	pinned := map[string]string{}
	if rows, err := s.Store.PatchMachines(ctx, link.TenantID); err == nil {
		for _, r := range rows {
			if r.Pinned && r.DeviceID != "" {
				pinned[r.EndpointID] = r.DeviceID
			}
		}
	}

	whole := true // a partial run must not delete what it did not get to see
	for _, ep := range eps {
		machines++
		// Every machine is read, placed or not. The software inventory is what
		// makes a hole attributable, and it is also what a person needs in front
		// of them when they decide by hand which device this is.
		software, serr := s.Reader.EndpointSoftware(ctx, link.OrgID, ep.ID)
		if serr != nil {
			s.Log.Warn("patch state: software", "endpoint", ep.Name, "err", serr)
			whole = false
			continue
		}
		m := action1.Join(ep, software, vulns)

		dev, ok := byID[pinned[ep.ID]]
		if !ok {
			dev, ok = byName[hostKey(ep.Name)]
		}
		if !ok {
			// The manager knows this machine and EX0 does not. Say so; do not
			// invent a device, because a device is what the box saw.
			unmatched = append(unmatched, ep.Name)
		}
		if err := s.save(ctx, link, m, dev.ID, now); err != nil {
			s.Log.Error("patch machine", "endpoint", ep.Name, "err", err)
		}
		if ok && s.writeFinding(ctx, m, dev, now) {
			matched++
		}
	}
	if whole {
		if err := s.Store.DropPatchMachines(ctx, Provider, link.OrgID, now); err != nil {
			s.Log.Warn("patch state: cleanup", "err", err)
		}
	}
	return machines, matched, unmatched, nil
}

// save stores what the manager knows about one machine, so the console can show
// it without asking the provider again — and so a machine EX0 cannot place is
// still on the page instead of only in a log line.
func (s *Service) save(ctx context.Context, link store.PatchOrg, m action1.Machine, deviceID string, now time.Time) error {
	row := store.PatchMachine{
		Provider: Provider, EndpointID: m.Endpoint.ID, TenantID: link.TenantID, OrgID: link.OrgID,
		Name: m.Endpoint.Name, DeviceID: deviceID, Online: m.Online, LastSeen: m.LastSeen,
		Inventoried: m.Inventoried, Pending: len(m.Pending), CVECount: len(m.CVEs), SyncedAt: now,
	}
	for _, c := range m.CVEs {
		if c.CVSS > row.WorstCVSS {
			row.WorstCVSS = c.CVSS
		}
		if c.KEV {
			row.KEV = true
		}
	}
	cves, _ := json.Marshal(machineCVEs(m))
	updates, _ := json.Marshal(m.Pending)
	sw, _ := json.Marshal(inventory(m))
	return s.Store.SavePatchMachine(ctx, row, cves, updates, sw)
}

// machineCVE is one hole as the console shows it: the CVE, where it sits, and
// whether the manager has a package ready for it.
type machineCVE struct {
	CVE       string    `json:"cve"`
	CVSS      float64   `json:"cvss"`
	KEV       bool      `json:"kev"`
	Status    string    `json:"status"`
	Deadline  time.Time `json:"deadline"`
	Product   string    `json:"product"`
	Version   string    `json:"version"`
	Patchable bool      `json:"patchable"`
}

func machineCVEs(m action1.Machine) []machineCVE {
	out := make([]machineCVE, 0, len(m.CVEs))
	for _, c := range m.CVEs {
		out = append(out, machineCVE{
			CVE: c.CVE, CVSS: c.CVSS, KEV: c.KEV, Status: c.Status, Deadline: c.Deadline,
			Product: c.Product, Version: c.Version, Patchable: c.Patchable,
		})
	}
	return out
}

// app is one installed application, the answer to "what actually runs there".
type app struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor,omitempty"`
	Update  string `json:"update,omitempty"` // the version the manager has ready
}

func inventory(m action1.Machine) []app {
	out := make([]app, 0, len(m.Software))
	for _, s := range m.Software {
		a := app{Name: s.Name, Version: s.Version, Vendor: s.Vendor}
		if len(s.Missing) > 0 {
			a.Update = s.Missing[0]
		}
		out = append(out, a)
	}
	return out
}

// writeFinding turns a machine into at most one finding on its device, and
// resolves what is no longer true. It reports whether a finding is open.
func (s *Service) writeFinding(ctx context.Context, m action1.Machine, dev store.Device, now time.Time) bool {
	in := rules.PatchInput{Endpoint: m.Endpoint.Name, Online: m.Online, LastSeen: m.LastSeen, Missing: m.Pending, Now: now}
	for _, c := range m.CVEs {
		in.CVEs = append(in.CVEs, rules.PatchCVE{
			CVE: c.CVE, CVSS: c.CVSS, KEV: c.KEV, Overdue: c.Overdue(), Deadline: c.Deadline, Product: c.Product,
		})
	}
	var current []store.Finding
	open := false
	if f, has := rules.EvaluatePatch(in); has {
		f.Evidence["source"] = Provider
		f.Evidence["inventoried"] = m.Inventoried.UTC().Format(time.RFC3339)
		ev, _ := json.Marshal(f.Evidence)
		current = append(current, store.Finding{
			ID: id.New("fnd"), TenantID: dev.TenantID, SiteID: dev.SiteID, DeviceID: dev.ID, ConnectorID: Source,
			Rule: f.Rule, Key: f.Key, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: ev,
		})
		open = true
	}
	resolved, err := s.Store.SyncDeviceFindings(ctx, dev.ID, Source, current, now)
	if err != nil {
		s.Log.Error("patch findings", "device", dev.ID, "err", err)
		return open
	}
	for _, fid := range resolved {
		_ = s.Store.DeleteAck(ctx, "finding", fid)
	}
	return open
}

// devicesByName indexes a customer's devices by the name the box learned, so a
// machine the manager calls "SRV-DC.beispiel.test" finds the device the box saw as
// "SRV-DC".
func devicesByName(devices []store.Device) map[string]store.Device {
	out := make(map[string]store.Device, len(devices))
	for _, d := range devices {
		if k := hostKey(d.Hostname); k != "" {
			// first one wins: two devices with one name is a customer's problem to
			// sort out, and picking the later one silently would hide it
			if _, seen := out[k]; !seen {
				out[k] = d
			}
		}
	}
	return out
}

// hostKey is a hostname without its domain, lowercased. The manager reports a
// fully qualified name and the box reports what the machine announces on the
// LAN; the part before the first dot is the piece both agree on.
func hostKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(strings.TrimSuffix(n, "."), "$")
	if host, _, found := strings.Cut(n, "."); found {
		n = host
	}
	// A name whose first character is a dot has no host part; matching on the
	// empty string would make every such machine the same machine.
	return n
}
