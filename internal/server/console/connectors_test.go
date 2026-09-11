package console_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/seal"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// A connector is created with a credential sealed to the box, travels to the box in
// its config, and the box's readings show up on the device and on the overview.
func TestConnectorLifecycle(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	box := seedDownHost(t, f)
	ctx := context.Background()
	now := time.Now()
	dev, _, _, err := f.st.UpsertSighting(ctx, "ten_x", "site_x", wire.Sighting{MAC: "00:09:0f:aa:bb:cc", IP: "10.0.0.1", Vendor: "Fortinet", Hostname: "fw", LastSeen: now}, now)
	must(t, err)

	// no seal key yet: the console refuses, and says why
	boxKey, err := seal.GenerateKey()
	must(t, err)
	blob, err := seal.Seal(seal.Public(boxKey), []byte(`{"token":"tok-1"}`))
	must(t, err)
	status, body := f.postJSON("/api/devices/"+dev.ID+"/connectors", url.Values{"kind": {"fortigate"}, "url": {"https://10.0.0.1"}, "sealed": {blob}}, f.csrf)
	if status != 400 || !strings.Contains(body, "Siegelschlüssel") {
		t.Fatalf("create without seal key: %d %s", status, body)
	}

	// the box reports its key with a heartbeat
	hb := wire.Heartbeat{SentAt: now, Agent: wire.AgentInfo{Version: "0.1.0", OS: "linux", Arch: "amd64", SealKey: seal.Public(boxKey)}}
	_, err = f.eng.Heartbeat(ctx, box, hb)
	must(t, err)
	status, _, body = f.getJSON("/api/devices/" + dev.ID + "/connectors")
	var dc struct {
		SealKey     string
		Fingerprint string
		Connectors  []struct {
			ID, Kind, Class, LastError, TlsFingerprint, SeenFingerprint string
			Facts                                                       map[string]any
		}
	}
	must(t, json.Unmarshal([]byte(body), &dc))
	if status != 200 || dc.SealKey != seal.Public(boxKey) || dc.Fingerprint != seal.Fingerprint(seal.Public(boxKey)) || len(dc.Connectors) != 0 {
		t.Fatalf("device connectors: %d %s", status, body)
	}

	// bad inputs are refused with a reason
	for _, tc := range []struct{ kind, u, sealed, want string }{
		{"toaster", "https://10.0.0.1", blob, "Unbekannte"},
		{"fortigate", "https://10.0.0.1/api/v2", blob, "ohne Pfad"},
		{"fortigate", "https://10.0.0.1", "short", "versiegeln"},
	} {
		if status, body := f.postJSON("/api/devices/"+dev.ID+"/connectors", url.Values{"kind": {tc.kind}, "url": {tc.u}, "sealed": {tc.sealed}}, f.csrf); status != 400 || !strings.Contains(body, tc.want) {
			t.Fatalf("%+v: %d %s", tc, status, body)
		}
	}

	status, body = f.postJSON("/api/devices/"+dev.ID+"/connectors", url.Values{"kind": {"fortigate"}, "url": {"10.0.0.1"}, "sealed": {blob}, "interval_s": {"120"}}, f.csrf)
	if status != 200 || !strings.Contains(body, "verbunden") {
		t.Fatalf("create: %d %s", status, body)
	}

	// the box gets it with its config, ciphertext included, and can open it
	cfg, err := f.eng.Config(ctx, box)
	must(t, err)
	if len(cfg.Connectors) != 1 || cfg.Connectors[0].Kind != "fortigate" || cfg.Connectors[0].URL != "https://10.0.0.1" || cfg.Connectors[0].IntervalS != 120 || cfg.Connectors[0].DeviceID != dev.ID {
		t.Fatalf("config connectors: %+v", cfg.Connectors)
	}
	if msg, err := seal.Open(boxKey, cfg.Connectors[0].Sealed); err != nil || string(msg) != `{"token":"tok-1"}` {
		t.Fatalf("box cannot open the credential: %q %v", msg, err)
	}
	conID := cfg.Connectors[0].ID

	// the first reading lands on the device page
	hb.Connectors = []wire.ConnectorReport{{ID: conID, DeviceID: dev.ID, Kind: "fortigate", OK: true, CollectedAt: now, Facts: json.RawMessage(`{"serial":"FGT60F123","version":"v7.2.8","ipsec":[{"name":"to-hq","up":true}]}`), Metrics: map[string]float64{"cpu_pct": 7, "ipsec_up": 1}, TLSFingerprint: strings.Repeat("ab", 32)}}
	_, err = f.eng.Heartbeat(ctx, box, hb)
	must(t, err)
	_, _, body = f.getJSON("/api/devices/" + dev.ID + "/connectors")
	must(t, json.Unmarshal([]byte(body), &dc))
	if len(dc.Connectors) != 1 || dc.Connectors[0].Class != "ok" || dc.Connectors[0].Facts["serial"] != "FGT60F123" || dc.Connectors[0].SeenFingerprint != strings.Repeat("ab", 32) || dc.Connectors[0].TlsFingerprint != "" {
		t.Fatalf("after reading: %+v", dc.Connectors)
	}
	samples, err := f.st.ConnectorSamples(ctx, "ten_x", conID, "cpu_pct", now.Add(-time.Hour), now.Add(time.Hour))
	must(t, err)
	if len(samples) != 1 || samples[0].Value != 7 {
		t.Fatalf("samples: %+v", samples)
	}
	status, _, body = f.getJSON("/api/connectors/" + conID + "/samples?key=cpu_pct")
	if status != 200 || !strings.Contains(body, `"value":7`) {
		t.Fatalf("samples api: %d %s", status, body)
	}

	// pin the certificate the box saw; the config version changes so the box re-reads
	v1 := cfg.Connectors[0].Version
	if status, _ := f.postJSON("/api/connectors/"+conID+"/pin", nil, f.csrf); status != 200 {
		t.Fatalf("pin: %d", status)
	}
	cfg, _ = f.eng.Config(ctx, box)
	if cfg.Connectors[0].TLSFingerprint != strings.Repeat("ab", 32) || cfg.Connectors[0].Version == v1 {
		t.Fatalf("pin not in config: %+v", cfg.Connectors[0])
	}

	// a failed reading is a problem on the overview, without facts being lost
	hb.Connectors = []wire.ConnectorReport{{ID: conID, DeviceID: dev.ID, Kind: "fortigate", OK: false, Error: "device refused the credential", CollectedAt: now}}
	_, err = f.eng.Heartbeat(ctx, box, hb)
	must(t, err)
	_, _, body = f.getJSON("/api/devices/" + dev.ID + "/connectors")
	must(t, json.Unmarshal([]byte(body), &dc))
	if dc.Connectors[0].Class != "failed" || dc.Connectors[0].Facts["serial"] != "FGT60F123" {
		t.Fatalf("after failure: %+v", dc.Connectors[0])
	}
	_, _, body = f.getJSON("/api/overview")
	if !strings.Contains(body, `"kind":"connector_failed"`) || !strings.Contains(body, "refused the credential") {
		t.Fatalf("overview lacks the failed connector: %s", body)
	}

	// the box bootstrapped its own token: the admin credential is replaced, audited
	hb.Connectors = []wire.ConnectorReport{{ID: conID, DeviceID: dev.ID, Kind: "fortigate", OK: true, CollectedAt: now, TokenSealed: strings.Repeat("T", 100)}}
	_, err = f.eng.Heartbeat(ctx, box, hb)
	must(t, err)
	if c, _ := f.st.Connector(ctx, conID); c.Sealed != strings.Repeat("T", 100) || c.SealedBy != "box:box_x" {
		t.Fatalf("bootstrap credential not stored: %+v", c)
	}
	if entries, _ := f.st.AuditEntries(ctx, 50, 0); !strings.Contains(fmtAudit(entries), "connector.bootstrap") {
		t.Fatal("bootstrap not audited")
	}

	// a report for a connector the box does not own changes nothing
	hb.Connectors = []wire.ConnectorReport{{ID: "con_other", DeviceID: dev.ID, Kind: "fortigate", OK: true, CollectedAt: now}}
	_, err = f.eng.Heartbeat(ctx, box, hb)
	must(t, err)

	// pause: gone from the config; delete: gone entirely
	if status, _ := f.postJSON("/api/connectors/"+conID+"/toggle", nil, f.csrf); status != 200 {
		t.Fatal("toggle")
	}
	if cfg, _ = f.eng.Config(ctx, box); len(cfg.Connectors) != 0 {
		t.Fatal("paused connector still in config")
	}
	if status, _ := f.postJSON("/api/connectors/"+conID+"/delete", nil, f.csrf); status != 200 {
		t.Fatal("delete")
	}
	_, _, body = f.getJSON("/api/devices/" + dev.ID + "/connectors")
	must(t, json.Unmarshal([]byte(body), &dc))
	if len(dc.Connectors) != 0 {
		t.Fatal("deleted connector still listed")
	}
}

func fmtAudit(entries []store.AuditEntry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Action + " ")
	}
	return b.String()
}
