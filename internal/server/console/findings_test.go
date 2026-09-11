package console_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/seal"
	"github.com/excubra/excubra/internal/wire"
)

// A reading with management on the WAN interface opens a finding; the next reading
// without it resolves the finding; a finding can be acknowledged like a problem.
func TestFindingsFollowTheReadings(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	box := seedDownHost(t, f)
	ctx := context.Background()
	now := time.Now()
	dev, _, _, err := f.st.UpsertSighting(ctx, "ten_x", "site_x", wire.Sighting{MAC: "00:09:0f:aa:bb:cc", IP: "10.0.0.1", Vendor: "Fortinet", Hostname: "fw", LastSeen: now}, now)
	must(t, err)
	boxKey, _ := seal.GenerateKey()
	blob, _ := seal.Seal(seal.Public(boxKey), []byte(`{"token":"tok-1"}`))
	hb := wire.Heartbeat{SentAt: now, Agent: wire.AgentInfo{Version: "0.1.0", OS: "linux", Arch: "amd64", SealKey: seal.Public(boxKey)}}
	_, err = f.eng.Heartbeat(ctx, box, hb)
	must(t, err)
	if status, body := f.postJSON("/api/devices/"+dev.ID+"/connectors", url.Values{"kind": {"fortigate"}, "url": {"https://10.0.0.1"}, "sealed": {blob}}, f.csrf); status != 200 {
		t.Fatalf("create: %d %s", status, body)
	}
	cfg, _ := f.eng.Config(ctx, box)
	conID := cfg.Connectors[0].ID

	read := func(facts string) {
		t.Helper()
		hb.Connectors = []wire.ConnectorReport{{ID: conID, DeviceID: dev.ID, Kind: "fortigate", OK: true, CollectedAt: now, Facts: json.RawMessage(facts), Metrics: map[string]float64{"mem_pct": 50}, TLSFingerprint: strings.Repeat("ab", 32)}}
		_, err := f.eng.Heartbeat(ctx, box, hb)
		must(t, err)
	}
	type fnd struct {
		ID, Rule, Key, Severity, Device string
		ResolvedAt                      *string
		Ack                             *struct{ Actor string }
	}
	list := func(path string) (open, resolved []fnd) {
		t.Helper()
		status, _, body := f.getJSON(path)
		if status != 200 {
			t.Fatalf("%s: %d %s", path, status, body)
		}
		var d struct{ Open, Resolved []fnd }
		must(t, json.Unmarshal([]byte(body), &d))
		return d.Open, d.Resolved
	}

	// management on wan1 and a tunnel down, certificate not pinned
	read(`{"interfaces":[{"name":"wan1","role":"wan","admin":"ping https","ip":"203.0.113.5"}],"ipsec":[{"name":"to-hq","up":false}]}`)
	open, _ := list("/api/findings")
	rulesOf := func(fs []fnd) string {
		var s []string
		for _, x := range fs {
			s = append(s, x.Rule)
		}
		return strings.Join(s, " ")
	}
	if got := rulesOf(open); got != "fgt.admin_on_wan fgt.ipsec_down connector.unpinned" {
		t.Fatalf("open findings: %q", got)
	}
	if open[0].Severity != "high" || open[0].Device != "fw" || open[0].Key != "wan1" {
		t.Fatalf("first finding: %+v", open[0])
	}
	_, _, body := f.getJSON("/api/me")
	if !strings.Contains(body, `"Findings":3`) {
		t.Fatalf("nav should count 3 findings: %s", body)
	}

	// acknowledge the wan finding with the outage start the app got
	_, _, body = f.getJSON("/api/findings")
	var full struct {
		Open []struct {
			ID        string
			FirstSeen string
		}
	}
	must(t, json.Unmarshal([]byte(body), &full))
	if status, body := f.postJSON("/api/ack", url.Values{"kind": {"finding"}, "id": {full.Open[0].ID}, "since": {full.Open[0].FirstSeen}, "note": {"bewusst"}}, f.csrf); status != 200 {
		t.Fatalf("ack finding: %d %s", status, body)
	}
	open, _ = list("/api/findings")
	if open[0].Ack == nil || open[0].Ack.Actor != userName {
		t.Fatalf("finding not acknowledged: %+v", open[0])
	}

	// the tunnel comes back and the certificate gets pinned: two findings resolve, one stays
	if status, body := f.postJSON("/api/connectors/"+conID+"/pin", nil, f.csrf); status != 200 {
		t.Fatalf("pin: %d %s", status, body)
	}
	read(`{"interfaces":[{"name":"wan1","role":"wan","admin":"ping https","ip":"203.0.113.5"}],"ipsec":[{"name":"to-hq","up":true}]}`)
	open, resolved := list("/api/devices/" + dev.ID + "/findings")
	if rulesOf(open) != "fgt.admin_on_wan" || rulesOf(resolved) != "connector.unpinned fgt.ipsec_down" && rulesOf(resolved) != "fgt.ipsec_down connector.unpinned" {
		t.Fatalf("after second reading: open %q resolved %q", rulesOf(open), rulesOf(resolved))
	}
	if open[0].Ack == nil {
		t.Fatal("the acknowledgement must survive a reading that still shows the finding")
	}

	// the finding goes away and comes back: it is a new one, not acknowledged
	read(`{"interfaces":[{"name":"wan1","role":"wan","admin":"ping","ip":"203.0.113.5"}]}`)
	if open, _ = list("/api/findings"); len(open) != 0 {
		t.Fatalf("still open: %+v", open)
	}
	read(`{"interfaces":[{"name":"wan1","role":"wan","admin":"ping https","ip":"203.0.113.5"}]}`)
	if open, _ = list("/api/findings"); len(open) != 1 || open[0].Ack != nil {
		t.Fatalf("reopened finding must not carry the old acknowledgement: %+v", open)
	}

	// deleting the connector closes what it found
	if status, _ := f.postJSON("/api/connectors/"+conID+"/delete", nil, f.csrf); status != 200 {
		t.Fatal("delete")
	}
	if open, _ = list("/api/findings"); len(open) != 0 {
		t.Fatalf("findings survive their connector: %+v", open)
	}
}
