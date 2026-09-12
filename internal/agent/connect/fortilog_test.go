package connect

import (
	"strconv"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

func TestFortiGateLogSignals(t *testing.T) {
	now := time.Date(2026, 9, 12, 14, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).UnixNano(), 10) }
	rows := []map[string]any{
		{"eventtime": at(-20 * time.Minute), "action": "login", "status": "failed", "user": "admin", "srcip": "203.0.113.9"}, // older than the lookback: not counted on a first read
		{"eventtime": at(-3 * time.Minute), "action": "login", "status": "failed", "user": "admin", "srcip": "203.0.113.9"},
		{"eventtime": at(-2 * time.Minute), "action": "login", "status": "failed", "user": "Admin", "srcip": "203.0.113.9"},
		{"eventtime": at(-1 * time.Minute), "action": "login", "status": "failed", "user": "admin", "srcip": "192.168.1.5"},
		{"eventtime": at(-1 * time.Minute), "action": "login", "status": "success", "user": "admin", "srcip": "192.168.1.5"},
		{"eventtime": float64(now.Add(-30 * time.Second).UnixNano()), "action": "logout", "user": "admin", "srcip": "192.168.1.5"},
	}
	state := map[string]string{}
	got := fortigateLogSignals("event/system", rows, state, now)
	if len(got) != 2 || got[0].IP != "203.0.113.9" || got[0].Count != 2 || got[0].Detail != "Admin, admin" || got[1].IP != "192.168.1.5" || got[1].Count != 1 {
		t.Fatalf("signals: %+v", got)
	}
	if got[0].Kind != wire.SignalFGTAdminFail || got[0].FirstAt != now.Add(-3*time.Minute) || got[0].LastAt != now.Add(-2*time.Minute) {
		t.Fatalf("times: %+v", got[0])
	}
	// the cursor moved to the newest row: the same page yields nothing more
	if got = fortigateLogSignals("event/system", rows, state, now.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("rows counted twice: %+v", got)
	}
	// a newer row after that counts
	rows = append(rows, map[string]any{"eventtime": at(10 * time.Second), "action": "login", "status": "failed", "user": "admin", "srcip": "203.0.113.9"})
	if got = fortigateLogSignals("event/system", rows, state, now.Add(time.Minute)); len(got) != 1 || got[0].Count != 1 {
		t.Fatalf("new row: %+v", got)
	}
	// VPN and IPS pages
	vpn := []map[string]any{
		{"eventtime": at(-time.Minute), "action": "ssl-login-fail", "user": "j.doe", "srcip": "198.51.100.7"},
		{"eventtime": at(-time.Minute), "logdesc": "SSL VPN login fail", "user": "j.doe", "srcip": "198.51.100.7"},
		{"eventtime": at(-time.Minute), "action": "tunnel-up", "user": "j.doe", "srcip": "198.51.100.8"},
	}
	if got = fortigateLogSignals("event/vpn", vpn, state, now); len(got) != 1 || got[0].Kind != wire.SignalFGTVPNFail || got[0].Count != 2 || got[0].Detail != "j.doe" {
		t.Fatalf("vpn: %+v", got)
	}
	ips := []map[string]any{
		{"eventtime": at(-time.Minute), "attack": "SSH.Connection.Brute.Force", "severity": "medium", "action": "detected", "srcip": "198.51.100.7"},
		{"eventtime": at(-time.Minute), "attack": "SSH.Connection.Brute.Force", "severity": "medium", "action": "detected", "srcip": "198.51.100.7"},
		{"eventtime": at(-time.Minute), "attack": "", "srcip": "198.51.100.7"},
	}
	if got = fortigateLogSignals("utm/ips", ips, state, now); len(got) != 1 || got[0].Kind != wire.SignalFGTIPS || got[0].Count != 2 || got[0].Detail != "SSH.Connection.Brute.Force|medium|detected" {
		t.Fatalf("ips: %+v", got)
	}
}
