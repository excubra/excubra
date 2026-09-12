package rules

import (
	"testing"
	"time"
)

func TestExternalRulesTreatEveryOpenDoorAsAFinding(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	in := ScanInput{Now: now, Services: []Service{
		{Port: 3389, Proto: "tcp", Name: "rdp"},
		{Port: 445, Proto: "tcp", Name: "smb"},
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.2p1"},
		{Port: 443, Proto: "tcp", Name: "https", Title: "FortiGate", TLS: &TLS{Subject: "CN=FGT60F", Issuer: "CN=FGT60F", SelfSigned: true, NotAfter: now.Add(300 * 24 * time.Hour), Version: "1.2"}},
		{Port: 8443, Proto: "tcp", Name: "https", Title: "Willkommen", TLS: &TLS{Subject: "CN=www.example.test", Issuer: "CN=R3", NotAfter: now.Add(60 * 24 * time.Hour), Version: "1.3"}},
		{Port: 993, Proto: "tcp", Name: "imaps", TLS: &TLS{Subject: "CN=mail", Issuer: "CN=R3", NotAfter: now.Add(60 * 24 * time.Hour), Version: "1.2"}},
		{Port: 5060, Proto: "tcp", Name: "sip"},
		{Port: 1723, Proto: "tcp", Name: "pptp"},
		{Port: 7777, Proto: "tcp"},
	}}
	got := EvaluateExternal(in)
	want := map[string]string{
		"wan.rdp/tcp/3389": High, "wan.smb/tcp/445": High, "wan.ssh/tcp/22": Medium, "wan.admin_ui/tcp/443": High, "wan.cert_selfsigned/tcp/443": Medium,
		"wan.web/tcp/8443": Medium, "wan.mail/tcp/993": Low, "wan.sip/tcp/5060": Medium, "wan.exposed/tcp/1723": High, "wan.open/tcp/7777": Low,
	}
	seen := map[string]bool{}
	for _, f := range got {
		k := f.Rule + "/" + f.Key
		sev, ok := want[k]
		if !ok {
			t.Errorf("unexpected %s (%s) %s", k, f.Severity, f.Title)
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s: %s, want %s", k, f.Severity, sev)
		}
		seen[k] = true
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("missing %s", k)
		}
	}
	if len(got) != len(want) || got[0].Severity != High {
		t.Fatalf("%d findings (want %d), first %+v", len(got), len(want), got[0])
	}
}
