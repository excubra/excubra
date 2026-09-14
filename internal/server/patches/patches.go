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

	for _, ep := range eps {
		machines++
		dev, ok := byName[hostKey(ep.Name)]
		if !ok {
			// The manager knows this machine and EX0 does not. Say so; do not
			// invent a device, because a device is what the box saw.
			unmatched = append(unmatched, ep.Name)
			continue
		}
		software, serr := s.Reader.EndpointSoftware(ctx, link.OrgID, ep.ID)
		if serr != nil {
			s.Log.Warn("patch state: software", "endpoint", ep.Name, "err", serr)
			continue
		}
		m := action1.Join(ep, software, vulns)
		in := rules.PatchInput{Endpoint: ep.Name, Online: m.Online, LastSeen: m.LastSeen, Missing: m.Pending, Now: now}
		for _, c := range m.CVEs {
			in.CVEs = append(in.CVEs, rules.PatchCVE{
				CVE: c.CVE, CVSS: c.CVSS, KEV: c.KEV, Overdue: c.Overdue(), Deadline: c.Deadline, Product: c.Product,
			})
		}
		var current []store.Finding
		if f, has := rules.EvaluatePatch(in); has {
			f.Evidence["source"] = Provider
			f.Evidence["inventoried"] = m.Inventoried.UTC().Format(time.RFC3339)
			ev, _ := json.Marshal(f.Evidence)
			current = append(current, store.Finding{
				ID: id.New("fnd"), TenantID: dev.TenantID, SiteID: dev.SiteID, DeviceID: dev.ID, ConnectorID: Source,
				Rule: f.Rule, Key: f.Key, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Evidence: ev,
			})
			matched++
		}
		resolved, serr := s.Store.SyncDeviceFindings(ctx, dev.ID, Source, current, now)
		if serr != nil {
			s.Log.Error("patch findings", "device", dev.ID, "err", serr)
			continue
		}
		for _, fid := range resolved {
			_ = s.Store.DeleteAck(ctx, "finding", fid)
		}
	}
	return machines, matched, unmatched, nil
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
