package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// What the patch state of a machine means. The numbers come from an endpoint
// manager (today Action1); the judgement lives here, pure and table-tested like
// every other rule.
//
// Two decisions worth stating, both learned the hard way on the CVE matching
// (salt E23). One finding per machine, not per CVE: seven holes in one
// application are one sentence an operator can act on, and seven rows that say
// the same thing are a list nobody reads. And severity comes from whether the
// vendor's own remediation deadline has passed, not from the highest score in
// the pile — a 9.8 published yesterday is a different thing from a 7.1 that has
// been fixable since August, and only the second one is somebody's fault.

// PatchRule is the finding's stable id.
const PatchRule = "patch.endpoint"

// PatchCVE is one hole the endpoint manager found on a machine.
type PatchCVE struct {
	CVE      string
	CVSS     float64
	KEV      bool
	Overdue  bool      // the manager's own remediation deadline has passed
	Deadline time.Time // zero when the manager gave none
	Product  string    // the software it sits in, "" when unknown
}

// PatchInput is one machine's state as the endpoint manager reports it.
type PatchInput struct {
	Endpoint string // what the manager calls the machine
	Online   bool   // its agent is connected
	LastSeen time.Time
	CVEs     []PatchCVE
	Missing  []string // names of patches offered and not installed
	Now      time.Time
}

// highCVSS is where a score alone makes something urgent, the same threshold the
// CVE matching uses (E23).
const highCVSS = 7.0

// staleAgent is how long a managed machine may be out of contact before the
// silence is itself the finding: patch state nobody can confirm is not patch
// state, and a machine that has been off for a fortnight is a machine nobody is
// patching.
const staleAgent = 14 * 24 * time.Hour

// EvaluatePatch turns one machine's patch state into at most one finding.
func EvaluatePatch(in PatchInput) (Finding, bool) {
	if !in.Online && !in.LastSeen.IsZero() && in.Now.Sub(in.LastSeen) > staleAgent {
		return Finding{
			Rule: PatchRule, Key: "offline", Severity: Medium,
			Title:  "Patch-Stand unbekannt: Agent seit " + humanDays(in.Now.Sub(in.LastSeen)) + " ohne Kontakt",
			Detail: "Die Maschine meldet sich nicht mehr beim Endpunkt-Manager. Ob sie gepatcht ist, weiß im Moment niemand — weder ob Updates fehlen noch ob welche installiert wurden.",
			Evidence: map[string]any{
				"endpoint": in.Endpoint,
				"lastSeen": in.LastSeen.UTC().Format(time.RFC3339),
			},
		}, true
	}
	if len(in.CVEs) == 0 && len(in.Missing) == 0 {
		return Finding{}, false
	}

	var overdue, kev int
	var worst float64
	var worstCVE string
	var oldest time.Time
	products := map[string]bool{}
	for _, c := range in.CVEs {
		if c.Overdue {
			overdue++
		}
		if c.KEV {
			kev++
		}
		if c.CVSS > worst {
			worst, worstCVE = c.CVSS, c.CVE
		}
		if c.Overdue && !c.Deadline.IsZero() && (oldest.IsZero() || c.Deadline.Before(oldest)) {
			oldest = c.Deadline
		}
		if c.Product != "" {
			products[c.Product] = true
		}
	}

	sev := Low
	switch {
	case kev > 0:
		sev = High // actively exploited, whatever the score says
	case overdue > 0 && worst >= highCVSS:
		sev = High
	case overdue > 0 || worst >= highCVSS:
		sev = Medium
	case len(in.CVEs) > 0:
		sev = Low
	}

	f := Finding{Rule: PatchRule, Key: "patches", Severity: sev, Evidence: map[string]any{"endpoint": in.Endpoint}}
	f.Title = patchTitle(len(in.CVEs), overdue, kev, len(in.Missing), sortedNames(products))
	f.Detail = patchDetail(worstCVE, worst, kev, oldest, in.Now, in.Missing)
	if len(in.CVEs) > 0 {
		f.Evidence["cves"] = len(in.CVEs)
		f.Evidence["overdue"] = overdue
		f.Evidence["worstCVSS"] = worst
		f.Evidence["worstCVE"] = worstCVE
		f.Evidence["kev"] = kev
		f.Evidence["products"] = sortedNames(products)
	}
	if len(in.Missing) > 0 {
		f.Evidence["missing"] = in.Missing
	}
	return f, true
}

func patchTitle(cves, overdue, kev, missing int, products []string) string {
	switch {
	case kev > 0:
		return fmt.Sprintf("%s: %s, %s aktiv ausgenutzt", inSoftware(products), count(cves, "eine bekannte Lücke", "%d bekannte Lücken"), count(kev, "eine davon wird", "%d davon werden"))
	case overdue > 0:
		return fmt.Sprintf("%s: %s, %s überfällig", inSoftware(products), count(cves, "eine bekannte Lücke", "%d bekannte Lücken"), count(overdue, "eine", "%d"))
	case cves > 0:
		return fmt.Sprintf("%s: %s", inSoftware(products), count(cves, "eine bekannte Lücke", "%d bekannte Lücken"))
	default:
		return count(missing, "Ein Update wartet auf Installation", "%d Updates warten auf Installation")
	}
}

func patchDetail(worstCVE string, worst float64, kev int, oldest, now time.Time, missing []string) string {
	var b strings.Builder
	if worstCVE != "" {
		fmt.Fprintf(&b, "Die schwerste ist %s mit CVSS %.1f.", worstCVE, worst)
	}
	if kev > 0 {
		b.WriteString(" Sie steht auf der Liste der aktiv ausgenutzten Schwachstellen — dafür gibt es keine ruhige Woche.")
	}
	if !oldest.IsZero() {
		fmt.Fprintf(&b, " Die älteste Frist ist seit %s abgelaufen.", humanDays(now.Sub(oldest)))
	}
	if len(missing) > 0 {
		fmt.Fprintf(&b, " Dazu %s: %s.", count(len(missing), "wartet ein Update", "warten %d Updates"), strings.Join(clipList(missing, 3), ", "))
	}
	if b.Len() == 0 {
		return "Der Endpunkt-Manager meldet offene Punkte für diese Maschine."
	}
	return strings.TrimSpace(b.String())
}

// inSoftware names the software the holes sit in, because "FortiClient" tells an
// operator what to do and "7 Lücken" does not.
func inSoftware(products []string) string {
	switch len(products) {
	case 0:
		return "Windows-Maschine"
	case 1:
		return products[0]
	case 2:
		return products[0] + " und " + products[1]
	default:
		return fmt.Sprintf("%s und %d weitere", products[0], len(products)-1)
	}
}

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clipList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(append([]string{}, in[:n]...), fmt.Sprintf("und %d weitere", len(in)-n))
}

// count fills one of two German forms; the many form may carry a single %d.
// Deliberately not named plural: signal.go has one of those with different
// semantics, and two helpers with one name is how a wrong sentence gets shipped.
func count(n int, one, many string) string {
	if n == 1 {
		return one
	}
	if strings.Contains(many, "%d") {
		return fmt.Sprintf(many, n)
	}
	return many
}

// humanDays reads a duration the way a person says it.
func humanDays(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days <= 0:
		return "weniger als einem Tag"
	case days == 1:
		return "einem Tag"
	case days < 60:
		return fmt.Sprintf("%d Tagen", days)
	default:
		return fmt.Sprintf("%d Monaten", days/30)
	}
}
