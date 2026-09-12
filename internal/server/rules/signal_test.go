package rules

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateSignal(t *testing.T) {
	now := time.Date(2026, 9, 12, 14, 0, 0, 0, time.UTC)
	cases := []struct {
		sg    Signal
		rule  string
		key   string
		title string
		ok    bool
	}{
		{Signal{Kind: "canary", IP: "192.168.1.50", Port: 445, Count: 3}, "signal.canary", "445", "Köder-Port 445 (SMB)", true},
		{Signal{Kind: "canary", IP: "192.168.1.50", Port: 8443, Count: 1}, "signal.canary", "8443", "Köder-Port 8443 angesprochen", true},
		{Signal{Kind: "port_scan", IP: "192.168.1.50", Count: 12, Detail: "22, 80, 443"}, "signal.port_scan", "", "Portscan", true},
		{Signal{Kind: "arp_scan", IP: "192.168.1.50", Count: 254}, "signal.arp_scan", "", "abgesucht", true},
		{Signal{Kind: "arp_spoof", IP: "192.168.1.1", MAC: "de:ad:be:ef:00:01", Count: 1, Detail: "gateway 00:09:0f:aa:bb:cc → de:ad:be:ef:00:01"}, "signal.arp_spoof", "192.168.1.1", "Gateway", true},
		{Signal{Kind: "arp_spoof", IP: "192.168.1.70", Count: 3, Detail: "flapping 00:00:00:00:01:01 → 00:00:00:00:01:02"}, "signal.arp_spoof", "192.168.1.70", "wechselt", true},
		{Signal{Kind: "something_new", IP: "192.168.1.50"}, "", "", "", false},
	}
	for _, c := range cases {
		c.sg.First, c.sg.Last = now, now
		f, ok := EvaluateSignal(c.sg)
		if ok != c.ok {
			t.Fatalf("%s: ok=%v", c.sg.Kind, ok)
		}
		if !ok {
			continue
		}
		if f.Rule != c.rule || f.Key != c.key || f.Severity != High || !strings.Contains(f.Title, c.title) || f.Evidence["count"] != c.sg.Count {
			t.Fatalf("%s: %+v", c.sg.Kind, f)
		}
	}
	f, _ := EvaluateSignal(Signal{Kind: "canary", Port: 3389, Count: 1, First: now, Last: now})
	if !strings.Contains(f.Detail, "1 Versuch.") {
		t.Fatalf("singular: %s", f.Detail)
	}
}
