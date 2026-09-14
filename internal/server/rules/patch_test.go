package rules

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluatePatch(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	cve := func(id string, score float64, kev, overdue bool, deadline time.Time, product string) PatchCVE {
		return PatchCVE{CVE: id, CVSS: score, KEV: kev, Overdue: overdue, Deadline: deadline, Product: product}
	}
	aug := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

	for _, c := range []struct {
		name     string
		in       PatchInput
		want     bool
		severity string
		inTitle  []string
	}{
		{
			// what the pilot customer actually looks like today
			name: "overdue and high scores together are urgent",
			in: PatchInput{Endpoint: "SRV-1", Online: true, Now: now, CVEs: []PatchCVE{
				cve("CVE-2026-70465", 8.1, false, true, aug, "FortiClient"),
				cve("CVE-2025-46373", 7.8, false, true, aug.AddDate(0, -8, 0), "FortiClient"),
			}},
			want: true, severity: High,
			inTitle: []string{"FortiClient", "2 bekannte Lücken", "überfällig"},
		},
		{
			name: "actively exploited is urgent whatever the score says",
			in: PatchInput{Endpoint: "SRV-1", Online: true, Now: now, CVEs: []PatchCVE{
				cve("CVE-2026-1", 4.2, true, false, time.Time{}, "Acrobat"),
			}},
			want: true, severity: High,
			inTitle: []string{"Acrobat", "aktiv ausgenutzt"},
		},
		{
			name: "a high score that is not yet due is worth seeing, not urgent",
			in: PatchInput{Endpoint: "SRV-1", Online: true, Now: now, CVEs: []PatchCVE{
				cve("CVE-2026-2", 9.1, false, false, time.Time{}, "Chrome"),
			}},
			want: true, severity: Medium,
		},
		{
			name: "small and not overdue is hygiene",
			in: PatchInput{Endpoint: "SRV-1", Online: true, Now: now, CVEs: []PatchCVE{
				cve("CVE-2026-3", 2.3, false, false, time.Time{}, "7-Zip"),
			}},
			want: true, severity: Low,
		},
		{
			name:    "updates waiting, no holes",
			in:      PatchInput{Endpoint: "SRV-1", Online: true, Now: now, Missing: []string{"Windows Desktop Runtime"}},
			want:    true,
			inTitle: []string{"Ein Update wartet"},
		},
		{
			name: "an agent long out of contact is itself the finding",
			in:   PatchInput{Endpoint: "SRV-1", Online: false, LastSeen: now.AddDate(0, 0, -30), Now: now},
			want: true, severity: Medium,
			inTitle: []string{"Patch-Stand unbekannt", "30 Tagen"},
		},
		{
			name: "a machine offline since this morning is not a finding",
			in:   PatchInput{Endpoint: "SRV-1", Online: false, LastSeen: now.Add(-3 * time.Hour), Now: now},
			want: false,
		},
		{
			name: "nothing to report is no finding",
			in:   PatchInput{Endpoint: "SRV-1", Online: true, Now: now},
			want: false,
		},
	} {
		got, ok := EvaluatePatch(c.in)
		if ok != c.want {
			t.Errorf("%s: finding=%v, want %v", c.name, ok, c.want)
			continue
		}
		if !ok {
			continue
		}
		if c.severity != "" && got.Severity != c.severity {
			t.Errorf("%s: severity %q, want %q", c.name, got.Severity, c.severity)
		}
		if got.Rule != PatchRule {
			t.Errorf("%s: rule %q", c.name, got.Rule)
		}
		for _, want := range c.inTitle {
			if !strings.Contains(got.Title, want) {
				t.Errorf("%s: title %q should contain %q", c.name, got.Title, want)
			}
		}
	}
}

// One finding per machine, never one per CVE: seven rows saying the same thing
// is the list nobody reads (E23).
func TestEvaluatePatchIsOneFindingPerMachine(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	in := PatchInput{Endpoint: "SRV-1", Online: true, Now: now}
	for i := 0; i < 7; i++ {
		in.CVEs = append(in.CVEs, PatchCVE{CVE: "CVE-2026-x", CVSS: 7.5, Overdue: true, Deadline: now.AddDate(0, 0, -20), Product: "FortiClient"})
	}
	f, ok := EvaluatePatch(in)
	if !ok {
		t.Fatal("seven overdue holes should be a finding")
	}
	if f.Evidence["cves"] != 7 || f.Evidence["overdue"] != 7 {
		t.Fatalf("the count belongs in the evidence: %+v", f.Evidence)
	}
	if !strings.Contains(f.Detail, "20 Tagen") {
		t.Fatalf("the detail should say how long the oldest deadline has passed: %q", f.Detail)
	}
	if !strings.Contains(f.Title, "FortiClient") {
		t.Fatalf("the title should name the software to fix: %q", f.Title)
	}
}

// The software the holes sit in is what an operator acts on.
func TestInSoftware(t *testing.T) {
	for _, c := range []struct {
		in   []string
		want string
	}{
		{nil, "Windows-Maschine"},
		{[]string{"FortiClient"}, "FortiClient"},
		{[]string{"FortiClient", "Chrome"}, "FortiClient und Chrome"},
		{[]string{"FortiClient", "Chrome", "7-Zip"}, "FortiClient und 2 weitere"},
	} {
		if got := inSoftware(c.in); got != c.want {
			t.Errorf("inSoftware(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
