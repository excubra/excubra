package action1

import (
	"testing"
	"time"
)

// The pilot customer's real shape, checked against the live account before this
// was written: seven FortiClient holes that sit on the domain controller and not
// on the terminal server, because only the domain controller has FortiClient.
func TestJoinAttributesHolesToTheRightMachine(t *testing.T) {
	forti := Vulnerability{
		CVE: "CVE-2026-70465", CVSS: 8.1, Status: "Overdue",
		Deadline: time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
		Affected: []Affected{{Product: "FortiClient", Versions: []string{"7.4.2.1737"}}},
	}
	runtime := Vulnerability{
		CVE: "CVE-2026-1", CVSS: 5.0, Status: "Pending",
		Affected: []Affected{{Product: "Microsoft Windows Desktop Runtime 10 (x64)", Versions: []string{"10.0.10.50000"}}},
	}
	vulns := []Vulnerability{forti, runtime}

	dc := Join(
		Endpoint{ID: "ep-dc", Name: "SRV-DC.beispiel.test", Status: "Connected", LastSeen: "2026-09-14_18-18-36"},
		[]Software{
			{Name: "FortiClient", Version: "7.4.2.1737", UpdateStatus: "None", LastRefresh: time.Date(2026, 7, 20, 6, 28, 35, 0, time.UTC)},
			{Name: "Microsoft Edge", Version: "153.0.4234.32", UpdateStatus: "Current"},
		}, vulns)
	if len(dc.CVEs) != 1 || dc.CVEs[0].CVE != "CVE-2026-70465" {
		t.Fatalf("the domain controller should carry the FortiClient hole: %+v", dc.CVEs)
	}
	if dc.CVEs[0].Product != "FortiClient" || dc.CVEs[0].Version != "7.4.2.1737" {
		t.Fatalf("the finding should name the software and version: %+v", dc.CVEs[0])
	}
	if dc.CVEs[0].Patchable {
		t.Fatal("Action1 has no package for FortiClient, so this is hand work and must not look like a click")
	}
	if !dc.Online {
		t.Fatal("Connected means online")
	}
	if want := time.Date(2026, 9, 14, 18, 18, 36, 0, time.UTC); !dc.LastSeen.Equal(want) {
		t.Fatalf("last seen %s, want %s", dc.LastSeen, want)
	}
	if want := time.Date(2026, 7, 20, 6, 28, 35, 0, time.UTC); !dc.Inventoried.Equal(want) {
		t.Fatalf("the newest inventory row decides how fresh this is: %s", dc.Inventoried)
	}

	rds := Join(
		Endpoint{ID: "ep-rds", Name: "SRV-RDS.beispiel.test", Status: "Connected"},
		[]Software{
			{Name: "Microsoft Windows Desktop Runtime 10 (x64)", Version: "10.0.10.50000",
				UpdateStatus: "Important Update Available", Missing: []string{"10.0.12.50000"}},
		}, vulns)
	if len(rds.CVEs) != 1 || rds.CVEs[0].CVE != "CVE-2026-1" {
		t.Fatalf("the terminal server has the runtime, not FortiClient: %+v", rds.CVEs)
	}
	if !rds.CVEs[0].Patchable {
		t.Fatal("an application with an update waiting is patchable")
	}
	if len(rds.Pending) != 1 || rds.Pending[0] != "Microsoft Windows Desktop Runtime 10 (x64)" {
		t.Fatalf("the waiting update should be named: %+v", rds.Pending)
	}
}

func TestJoinIsExact(t *testing.T) {
	v := Vulnerability{CVE: "CVE-1", Affected: []Affected{{Product: "FortiClient", Versions: []string{"7.4.2.1737"}}}}
	for _, c := range []struct {
		name string
		sw   Software
		want int
	}{
		{"same spelling", Software{Name: "FortiClient", Version: "7.4.2.1737"}, 1},
		{"case and space do not matter", Software{Name: " fortICLIENT ", Version: " 7.4.2.1737 "}, 1},
		{"another version is another thing", Software{Name: "FortiClient", Version: "7.4.3.0"}, 0},
		{"another product is another thing", Software{Name: "FortiClient VPN", Version: "7.4.2.1737"}, 0},
		{"a row without a version cannot be matched", Software{Name: "FortiClient", Version: ""}, 0},
	} {
		m := Join(Endpoint{ID: "ep", Status: "Connected"}, []Software{c.sw}, []Vulnerability{v})
		if len(m.CVEs) != c.want {
			t.Errorf("%s: %d matches, want %d", c.name, len(m.CVEs), c.want)
		}
	}
}

// One CVE listed under two versions of the same product must not be counted twice.
func TestJoinCountsAHoleOnce(t *testing.T) {
	v := Vulnerability{CVE: "CVE-1", Affected: []Affected{
		{Product: "App", Versions: []string{"1.0", "1.1"}},
		{Product: "App", Versions: []string{"1.0"}},
	}}
	m := Join(Endpoint{Status: "Connected"}, []Software{{Name: "App", Version: "1.0"}}, []Vulnerability{v})
	if len(m.CVEs) != 1 {
		t.Fatalf("one hole, one entry: %+v", m.CVEs)
	}
}

func TestOverdue(t *testing.T) {
	if !(Vulnerability{Status: "Overdue"}).Overdue() || !(Vulnerability{Status: "overdue"}).Overdue() {
		t.Fatal("overdue is overdue, whatever the case")
	}
	if (Vulnerability{Status: "Pending"}).Overdue() {
		t.Fatal("pending is not overdue")
	}
}
