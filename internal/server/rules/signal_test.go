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
		{Signal{Kind: "fgt_admin_fail", IP: "203.0.113.9", Count: 2, Detail: "admin, root"}, "signal.fgt_admin_fail", "203.0.113.9", "Admin-Login", true},
		{Signal{Kind: "fgt_vpn_fail", IP: "198.51.100.7", Count: 40, Detail: "j.doe"}, "signal.fgt_vpn_fail", "198.51.100.7", "durchprobiert", true},
		{Signal{Kind: "fgt_ips", IP: "198.51.100.7", Count: 3, Detail: "Apache.Log4j.Error.Log.Remote.Code.Execution|critical|dropped"}, "signal.fgt_ips", "Apache.Log4j.Error.Log.Remote.Code.Execution", "geblockt", true},
		{Signal{Kind: "dns_block", IP: "192.168.1.50", Count: 3, Detail: "evil.test|www.evil.test|blocked"}, "signal.dns_block", "evil.test", "Schad-Domain", true},
		{Signal{Kind: "dns_dga", IP: "192.168.1.50", Count: 40, Detail: "xkqzj.nx, qwrtz.nx"}, "signal.dns_dga", "", "zufällige", true},
		{Signal{Kind: "dns_tunnel", IP: "192.168.1.50", Count: 30, Detail: "tunnel.test"}, "signal.dns_tunnel", "tunnel.test", "Tunnel", true},
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
	// a few VPN typos from the LAN and a low IPS signature that was blocked are not urgent; a signature let through is
	if f, _ := EvaluateSignal(Signal{Kind: "fgt_vpn_fail", IP: "192.168.1.5", Count: 2, First: now, Last: now}); f.Severity != Medium || !strings.Contains(f.Detail, "aus dem LAN") {
		t.Fatalf("vpn typo: %+v", f)
	}
	if f, _ := EvaluateSignal(Signal{Kind: "fgt_admin_fail", IP: "192.168.1.5", Count: 1, First: now, Last: now}); f.Severity != Medium {
		t.Fatalf("one admin typo from the LAN: %+v", f)
	}
	if f, _ := EvaluateSignal(Signal{Kind: "fgt_ips", IP: "198.51.100.7", Count: 1, Detail: "Some.Scanner|low|dropped", First: now, Last: now}); f.Severity != Low {
		t.Fatalf("low blocked ips: %+v", f)
	}
	if f, _ := EvaluateSignal(Signal{Kind: "fgt_ips", IP: "198.51.100.7", Count: 1, Detail: "Some.Scanner|medium|detected", First: now, Last: now}); f.Severity != High || !strings.Contains(f.Title, "nicht geblockt") {
		t.Fatalf("let through: %+v", f)
	}
	f, _ := EvaluateSignal(Signal{Kind: "canary", Port: 3389, Count: 1, First: now, Last: now})
	if !strings.Contains(f.Detail, "1 Versuch.") {
		t.Fatalf("singular: %s", f.Detail)
	}
}
