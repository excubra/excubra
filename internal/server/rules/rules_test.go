package rules

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

func facts(t *testing.T, js string) map[string]any {
	t.Helper()
	var f map[string]any
	if err := json.Unmarshal([]byte(js), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func rulesOf(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Rule)
		if f.Key != "" {
			b.WriteString("[" + f.Key + "]")
		}
		b.WriteString(" ")
	}
	return strings.TrimSpace(b.String())
}

func TestFortiGateRules(t *testing.T) {
	soon := now.Add(10 * 24 * time.Hour).Unix()
	later := now.Add(200 * 24 * time.Hour).Unix()
	cases := []struct {
		name    string
		facts   string
		metrics map[string]float64
		pinned  bool
		want    string
	}{
		{"quiet device", `{"interfaces":[{"name":"internal","role":"lan","admin":"ping https ssh","ip":"192.168.1.1"}],"ipsec":[{"name":"a","up":true}],"licenses":{"forticare":{"status":"registered"},"ips":{"status":"licensed","expires":` + itoa(later) + `}},"ha_mode":"standalone","admin_timeout_min":5}`,
			map[string]float64{"mem_pct": 40}, true, ""},
		{"admin on wan by role and public ip, plain http on lan", `{"interfaces":[{"name":"port1","role":"wan","admin":"ping https","ip":"203.0.113.5"},{"name":"internal","role":"lan","admin":"http https","ip":"10.0.0.1"},{"name":"x","role":"undefined","admin":"ssh","ip":"203.0.113.5"}]}`,
			nil, true, "fgt.admin_on_wan[port1] fgt.admin_on_wan[x] fgt.admin_plaintext[internal]"},
		{"interfaces without address or with mask notation", `{"interfaces":[{"name":"dmz","role":"dmz","admin":"ping https","ip":""},{"name":"port2","role":"undefined","admin":"https","ip":"203.0.113.9 255.255.255.0"}]}`, nil, true, "fgt.admin_on_wan[port2]"},
		{"wan by name without admin is fine", `{"interfaces":[{"name":"wan1","role":"wan","admin":"ping","ip":"203.0.113.5"}]}`, nil, true, ""},
		{"tunnel down, licence expired and expiring, forticare", `{"ipsec":[{"name":"to-hq","up":false,"gateway":"198.51.100.1"},{"name":"ok","up":true}],"licenses":{"web_filter":{"status":"expired"},"antivirus":{"status":"licensed","expires":` + itoa(soon) + `},"forticare":{"status":"pending"}}}`,
			nil, true, "fgt.license_expired[web_filter] fgt.forticare fgt.ipsec_down[to-hq] fgt.license_expiring[antivirus]"},
		{"ha degraded and hot", `{"ha_mode":"a-p"}`, map[string]float64{"ha_peers": 1, "mem_pct": 93, "cpu_pct": 95}, true, "fgt.ha_degraded fgt.cpu_high fgt.memory_high"},
		{"unpinned and lax timeout are low", `{"admin_timeout_min":60}`, nil, false, "connector.unpinned fgt.admin_timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rulesOf(Evaluate(Input{Kind: "fortigate", Facts: facts(t, tc.facts), Metrics: tc.metrics, Pinned: tc.pinned, Now: now}))
			if got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestFindingsCarryWhatAPersonNeeds(t *testing.T) {
	fs := Evaluate(Input{Kind: "fortigate", Pinned: true, Now: now, Facts: facts(t, `{"interfaces":[{"name":"wan1","role":"wan","admin":"ping https ssh","ip":"203.0.113.5"}]}`)})
	if len(fs) != 1 || fs[0].Severity != High || !strings.Contains(fs[0].Detail, "https, ssh") || fs[0].Evidence["ip"] != "203.0.113.5" {
		t.Fatalf("%+v", fs)
	}
}

func TestUnknownKindOnlyGetsGenericRules(t *testing.T) {
	if got := rulesOf(Evaluate(Input{Kind: "starface", Pinned: false, Now: now})); got != "connector.unpinned" {
		t.Fatalf("%q", got)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
