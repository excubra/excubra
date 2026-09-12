package connect

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// fakeFortiGate answers the monitor endpoints the reader uses.
func fakeFortiGate(t *testing.T, sessions float64) *httptest.Server {
	t.Helper()
	env := func(results any) any {
		return map[string]any{"status": "success", "serial": "FGT60FTK1234", "version": "v7.2.8", "build": 1639, "results": results}
	}
	started := time.Now() // the log rows keep their timestamps across reads, like a real log
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body any
		path := strings.Replace(r.URL.Path, "/api/v2/log/disk/", "/api/v2/log/memory/", 1) // the fake logs to disk; the reader asks there
		switch path {
		case "/api/v2/monitor/system/status":
			body = env(map[string]any{"hostname": "fw-1", "model_name": "FortiGate", "model_number": "60F", "log_disk_status": "available"})
		case "/api/v2/monitor/system/resource/usage":
			cur := func(v float64) []map[string]any { return []map[string]any{{"current": v}} }
			body = env(map[string]any{"cpu": cur(7), "mem": cur(41), "session": cur(sessions), "disk": cur(3)})
		case "/api/v2/monitor/system/interface":
			body = env(map[string]any{"wan1": map[string]any{"name": "wan1", "link": true, "ip": "203.0.113.5", "speed": 1000}, "internal": map[string]any{"name": "internal", "link": true}, "dmz": map[string]any{"name": "dmz", "link": false}})
		case "/api/v2/monitor/vpn/ipsec":
			body = env([]map[string]any{{"name": "to-hq", "rgwy": "198.51.100.1", "proxyid": []map[string]any{{"p2name": "to-hq-p2", "status": "up", "incoming_bytes": 10, "outgoing_bytes": 20}}}, {"name": "to-branch", "proxyid": []map[string]any{{"p2name": "b", "status": "down"}}}})
		case "/api/v2/cmdb/system/interface":
			body = env([]map[string]any{{"name": "wan1", "role": "wan", "allowaccess": "ping https ssh", "status": "up", "type": "physical"}, {"name": "internal", "role": "lan", "allowaccess": "ping https ssh http fgfm", "status": "up", "type": "hard-switch"}, {"name": "dmz", "role": "dmz", "allowaccess": "ping", "status": "up", "type": "physical"}})
		case "/api/v2/cmdb/system/ha":
			body = env(map[string]any{"mode": "standalone"})
		case "/api/v2/monitor/license/status":
			body = env(map[string]any{"forticare": map[string]any{"status": "registered"}, "antivirus": map[string]any{"status": "expired", "expires": 1700000000}})
		case "/api/v2/cmdb/system/global":
			body = env(map[string]any{"admin-sport": 8443, "admin-ssh-port": 22, "admintimeout": 5, "timezone": "26"})
		case "/api/v2/log/memory/event/system":
			et := strconv.FormatInt(started.Add(-time.Minute).UnixNano(), 10)
			body = env([]map[string]any{
				{"eventtime": et, "logid": "0100032002", "action": "login", "status": "failed", "user": "admin", "srcip": "203.0.113.9", "logdesc": "Admin login failed"},
				{"eventtime": et, "logid": "0100032002", "action": "login", "status": "failed", "user": "root", "srcip": "203.0.113.9", "logdesc": "Admin login failed"},
				{"eventtime": et, "logid": "0100032001", "action": "login", "status": "success", "user": "admin", "srcip": "192.168.1.5", "logdesc": "Admin login successful"},
			})
		case "/api/v2/log/memory/event/vpn":
			body = env([]map[string]any{})
		case "/api/v2/log/memory/ips/signature": // utm/ips answers 404 on this release; the reader finds this one
			body = env([]map[string]any{{"eventtime": strconv.FormatInt(started.Add(-30*time.Second).UnixNano(), 10), "attack": "Apache.Log4j.Error.Log.Remote.Code.Execution", "severity": "critical", "action": "dropped", "srcip": "198.51.100.7"}})
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func testRunner() *Runner {
	// tests hand the plaintext through as the "sealed" blob
	return New(nil, func(s string) ([]byte, error) { return []byte(s), nil })
}

func TestFortiGateReading(t *testing.T) {
	srv := fakeFortiGate(t, 812)
	defer srv.Close()
	r := testRunner()
	var got []wire.Signal
	r.OnSignals = func(sigs []wire.Signal) { got = append(got, sigs...) }
	cfg := wire.ConnectorConfig{ID: "con_1", DeviceID: "dev_1", Kind: wire.ConnectorFortiGate, URL: srv.URL, Sealed: `{"token":"tok-1"}`, Version: "v1"}
	r.ReadOnce(context.Background(), cfg)
	rep, ok := r.Latest("con_1")
	if !ok || !rep.OK {
		t.Fatalf("reading: %+v", rep)
	}
	var facts map[string]any
	if err := json.Unmarshal(rep.Facts, &facts); err != nil {
		t.Fatal(err)
	}
	if facts["serial"] != "FGT60FTK1234" || facts["version"] != "v7.2.8" || facts["hostname"] != "fw-1" || facts["model"] != "FortiGate 60F" || facts["ha_mode"] != "standalone" {
		t.Fatalf("facts: %v", facts)
	}
	if facts["admin_https_port"] != 8443.0 {
		t.Fatalf("admin port: %v", facts["admin_https_port"])
	}
	wan1 := facts["interfaces"].([]any)[2].(map[string]any) // sorted by name: dmz, internal, wan1
	if wan1["name"] != "wan1" || wan1["role"] != "wan" || wan1["admin"] != "ping https ssh" || wan1["enabled"] != true {
		t.Fatalf("wan1 config not merged: %v", wan1)
	}
	for k, want := range map[string]float64{"cpu_pct": 7, "mem_pct": 41, "sessions": 812, "interfaces_up": 2, "interfaces_down": 1, "ipsec_up": 1, "ipsec_down": 1, "licenses_expired": 1} {
		if rep.Metrics[k] != want {
			t.Errorf("metric %s = %v, want %v", k, rep.Metrics[k], want)
		}
	}
	if rep.TLSFingerprint == "" || len(rep.TLSFingerprint) != 64 {
		t.Fatalf("no fingerprint reported: %q", rep.TLSFingerprint)
	}
	if _, has := facts["problems"]; has {
		t.Fatalf("no endpoint should have failed: %v", facts["problems"])
	}
	// the logs became signals, bound to the connector's device, and are not read twice
	if len(got) != 2 || got[0].Kind != wire.SignalFGTAdminFail || got[0].DeviceID != "dev_1" || got[0].IP != "203.0.113.9" || got[0].Count != 2 || got[0].Detail != "admin, root" ||
		got[1].Kind != wire.SignalFGTIPS || got[1].Detail != "Apache.Log4j.Error.Log.Remote.Code.Execution|critical|dropped" {
		t.Fatalf("signals: %+v", got)
	}
	got = nil
	r.ReadOnce(context.Background(), cfg)
	if len(got) != 0 {
		t.Fatalf("log rows counted twice: %+v", got)
	}

	// facts travel once, then only after a change
	reps := r.Reports()
	if len(reps) != 1 || reps[0].Facts == nil {
		t.Fatalf("first report must carry facts: %+v", reps)
	}
	r.Ack()
	if reps = r.Reports(); reps[0].Facts != nil {
		t.Fatal("unchanged facts must not travel again")
	}
	if reps[0].Metrics["sessions"] != 812 {
		t.Fatal("metrics travel every time")
	}
	r.Nack()

	// the pin protects against a swapped device
	cfg.TLSFingerprint = strings.Repeat("0", 64)
	r.ReadOnce(context.Background(), cfg)
	if rep, _ = r.Latest("con_1"); rep.OK || !strings.Contains(rep.Error, "certificate changed") {
		t.Fatalf("pin mismatch not detected: %+v", rep)
	}
	cfg.TLSFingerprint = reps[0].TLSFingerprint
	r.ReadOnce(context.Background(), cfg)
	if rep, _ = r.Latest("con_1"); !rep.OK {
		t.Fatalf("correct pin refused: %+v", rep)
	}

	// a wrong token is an auth error, not a mystery
	cfg.Sealed = `{"token":"nope"}`
	r.ReadOnce(context.Background(), cfg)
	if rep, _ = r.Latest("con_1"); rep.OK || !strings.Contains(rep.Error, "refused the credential") {
		t.Fatalf("auth failure: %+v", rep)
	}
}

func TestStarfaceClassicLogin(t *testing.T) {
	const user, pass, nonce = "rest", "geheim", "abc123"
	pw := sha512.Sum512([]byte(pass))
	inner := sha512.Sum512([]byte(user + nonce + hex.EncodeToString(pw[:])))
	wantSecret := user + ":" + hex.EncodeToString(inner[:])
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/rest/login" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{"nonce": nonce, "loginType": "Internal"})
		case r.URL.Path == "/rest/login" && r.Method == http.MethodPost:
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["secret"] != wantSecret || r.Header.Get("X-Version") != "2" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"authToken": "tok-xyz"})
		case r.Header.Get("authToken") != "tok-xyz":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/rest/server/version":
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "8.1.2.11", "build": "…"})
		case r.URL.Path == "/rest/server/state":
			_ = json.NewEncoder(w).Encode(map[string]any{"state": "RUNNING"})
		case r.URL.Path == "/rest/server/licenses":
			_ = json.NewEncoder(w).Encode(map[string]any{"users": 25})
		case r.URL.Path == "/rest/users":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1}, {"id": 2}, {"id": 3}})
		case r.URL.Path == "/rest/phonenumbers":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"id": 1}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	r := testRunner()
	cfg := wire.ConnectorConfig{ID: "con_2", DeviceID: "dev_2", Kind: wire.ConnectorStarface, URL: srv.URL, Sealed: `{"user":"rest","password":"geheim"}`}
	r.ReadOnce(context.Background(), cfg)
	rep, _ := r.Latest("con_2")
	if !rep.OK {
		t.Fatalf("starface: %+v", rep)
	}
	var facts map[string]any
	_ = json.Unmarshal(rep.Facts, &facts)
	if facts["login"] != "classic" || facts["version"].(map[string]any)["version"] != "8.1.2.11" || rep.Metrics["users"] != 3 || rep.Metrics["phonenumbers"] != 1 {
		t.Fatalf("facts %v metrics %v", facts, rep.Metrics)
	}
	cfg.Sealed = `{"user":"rest","password":"falsch"}`
	r.ReadOnce(context.Background(), cfg)
	if rep, _ = r.Latest("con_2"); rep.OK || !strings.Contains(rep.Error, "refused") {
		t.Fatalf("wrong password: %+v", rep)
	}
}

func TestRunnerApplyStartsStopsAndForgets(t *testing.T) {
	srv := fakeFortiGate(t, 1)
	defer srv.Close()
	r := testRunner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	cfg := wire.ConnectorConfig{ID: "con_1", DeviceID: "dev_1", Kind: wire.ConnectorFortiGate, URL: srv.URL, Sealed: `{"token":"tok-1"}`, Version: "v1", IntervalS: 60}
	r.Apply([]wire.ConnectorConfig{cfg, {ID: "con_x", Kind: "toaster", Sealed: "{}", Version: "v1"}})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if rep, ok := r.Latest("con_1"); ok && rep.OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("loop never read the device")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for {
		if rep, ok := r.Latest("con_x"); ok && strings.Contains(rep.Error, "unknown connector kind") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unknown kind not reported")
		}
		time.Sleep(50 * time.Millisecond)
	}
	r.Apply(nil)
	if _, ok := r.Latest("con_1"); ok {
		t.Fatal("removed connector still has a reading")
	}
	if len(r.Reports()) != 0 {
		t.Fatal("nothing should be reported after removal")
	}
}
