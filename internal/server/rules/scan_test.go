package rules

import (
	"testing"
	"time"
)

func TestScanRulesSpeakUpAboutTheRightServices(t *testing.T) {
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	in := ScanInput{Now: now, Services: []Service{
		{Port: 22, Proto: "tcp", Name: "ssh", Product: "OpenSSH", Version: "9.2p1"},
		{Port: 23, Proto: "tcp", Name: "telnet"},
		{Port: 21, Proto: "tcp", Name: "ftp", Banner: "220 (vsFTPd 3.0.3)"},
		{Port: 80, Proto: "tcp", Name: "http", Title: "FRITZ!Box 7590"},
		{Port: 443, Proto: "tcp", Name: "https", Title: "FRITZ!Box 7590", TLS: &TLS{Subject: "CN=fritz.box", Issuer: "CN=fritz.box", SelfSigned: true, NotAfter: now.Add(400 * 24 * time.Hour), Version: "1.3"}},
		{Port: 8443, Proto: "tcp", Name: "https", TLS: &TLS{Subject: "CN=old", Issuer: "CN=old", SelfSigned: true, NotAfter: now.Add(-24 * time.Hour), Version: "1.0"}},
		{Port: 8006, Proto: "tcp", Name: "https", TLS: &TLS{Subject: "CN=pve", Issuer: "CN=Proxmox CA", NotAfter: now.Add(10 * 24 * time.Hour), Version: "1.3"}},
		{Port: 3389, Proto: "tcp", Name: "rdp"},
		{Port: 6379, Proto: "tcp", Name: "redis"},
		{Port: 3306, Proto: "tcp", Name: "mysql", Product: "MariaDB", Version: "10.11.6-MariaDB"},
		{Port: 2375, Proto: "tcp", Name: "docker"},
		{Port: 445, Proto: "tcp", Name: "smb"},
	}}
	got := EvaluateScan(in)
	want := map[string]string{ // rule/key -> severity
		"scan.telnet/tcp/23": High, "scan.ftp/tcp/21": Medium, "scan.rdp/tcp/3389": Low, "scan.db_open/tcp/6379": Medium, "scan.db_open/tcp/3306": Low, "scan.docker_api/tcp/2375": High,
		"scan.cert_expired/tcp/8443": High, "scan.tls_old/tcp/8443": Medium, "scan.cert_selfsigned/tcp/8443": Low, "scan.cert_expiring/tcp/8006": Medium,
	}
	seen := map[string]bool{}
	for _, f := range got {
		k := f.Rule + "/" + f.Key
		sev, ok := want[k]
		if !ok {
			t.Errorf("unexpected finding %s (%s): %s", k, f.Severity, f.Title)
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s: severity %s, want %s", k, f.Severity, sev)
		}
		if f.Title == "" || f.Detail == "" || f.Evidence["port"] == nil {
			t.Errorf("%s: incomplete finding %+v", k, f)
		}
		seen[k] = true
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("missing finding %s", k)
		}
	}
	// the FRITZ!Box's own self-signed certificate is not a finding, SSH and SMB are quiet
	if len(got) != len(want) {
		t.Fatalf("%d findings, want %d", len(got), len(want))
	}
	if got[0].Severity != High {
		t.Fatalf("not sorted worst first: %+v", got[0])
	}
	if len(EvaluateScan(ScanInput{Now: now})) != 0 {
		t.Fatal("findings without services")
	}
}
