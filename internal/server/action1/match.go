package action1

import (
	"strings"
	"time"
)

// Which hole sits on which machine.
//
// Action1 answers two different questions in two different shapes: the
// organization knows its CVEs, and each machine knows its software. Neither says
// "this machine has this CVE". The join is local and exact — product name and
// version, both as Action1 itself spells them on both sides, which was checked
// against the pilot customer's data before this was written: a vulnerability
// naming FortiClient 7.4.2.1737 and an inventory row naming FortiClient
// 7.4.2.1737 are the same thing.
//
// Exact on purpose. A fuzzy match here would put one machine's holes on another
// machine's page, and a finding that names the wrong server is worse than no
// finding: somebody patches the wrong thing and believes they are done.

// Machine is one endpoint's patch state, after the join.
type Machine struct {
	Endpoint    Endpoint
	Online      bool
	LastSeen    time.Time
	CVEs        []MachineCVE
	Pending     []string  // applications with an update waiting, by name
	Inventoried time.Time // the newest inventory row; older than the endpoint's last contact means stale data
}

// MachineCVE is one hole on one machine, with the software it sits in.
type MachineCVE struct {
	Vulnerability
	Product string
	Version string
	// Patchable is whether the manager has an update ready for that application.
	// A hole nobody can close with a click is a different job from one that only
	// needs scheduling, and the finding should not pretend otherwise.
	Patchable bool
}

// Overdue reports whether the manager's own remediation deadline has passed.
func (v Vulnerability) Overdue() bool { return strings.EqualFold(v.Status, "Overdue") }

// key normalises a product and version for the join: Action1 writes both sides
// itself, so only surrounding space and case can differ.
func key(product, version string) string {
	return strings.ToLower(strings.TrimSpace(product)) + "\x00" + strings.TrimSpace(version)
}

// Join attributes an organization's vulnerabilities to one machine's software.
func Join(ep Endpoint, software []Software, vulns []Vulnerability) Machine {
	m := Machine{Endpoint: ep, Online: strings.EqualFold(ep.Status, "Connected"), LastSeen: parseTime(ep.LastSeen)}

	installed := map[string]Software{}
	for _, s := range software {
		if s.Version == "" {
			continue // a row without a version cannot be matched, and guessing is worse
		}
		installed[key(s.Name, s.Version)] = s
		if s.Pending() {
			m.Pending = append(m.Pending, s.Name)
		}
		if s.LastRefresh.After(m.Inventoried) {
			m.Inventoried = s.LastRefresh
		}
	}

	seen := map[string]bool{}
	for _, v := range vulns {
		for _, a := range v.Affected {
			for _, ver := range a.Versions {
				sw, ok := installed[key(a.Product, ver)]
				if !ok || seen[v.CVE] {
					continue
				}
				seen[v.CVE] = true
				m.CVEs = append(m.CVEs, MachineCVE{Vulnerability: v, Product: sw.Name, Version: sw.Version, Patchable: sw.Pending()})
			}
		}
	}
	return m
}
