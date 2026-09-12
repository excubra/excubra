package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/ai"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// A session talks to the server over a pipe: initialize, list the tools, read a
// site's situation, store an assessment, see it as a brief and as findings.
func TestSessionOverStdio(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Muster GmbH", CreatedAt: now}))
	must(t, st.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "Werk", CreatedAt: now}))
	must(t, st.CreateBox(ctx, store.Box{ID: "box_a", SiteID: "site_a", Name: "muster-box", HWID: "hw", CertSerial: "1", CertNotAfter: now.Add(time.Hour), EnrolledAt: now, LastSeen: now}))
	dev, _, _, err := st.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{MAC: "00:11:22:33:44:55", IP: "192.168.1.10", Hostname: "srv01", LastSeen: now}, now)
	must(t, err)
	_, _, err = st.UpsertServices(ctx, dev.ID, []store.Service{{DeviceID: dev.ID, Port: 3389, Proto: "tcp", Name: "rdp"}}, now)
	must(t, err)

	aiSvc := ai.New(st, nil, time.UTC)
	aiSvc.Now = func() time.Time { return now }
	srv := &Server{Store: st, AI: aiSvc, Now: func() time.Time { return now }, Actor: "jeremia"}
	in, inW := io.Pipe()
	outR, out := io.Pipe()
	go func() { _ = srv.Serve(ctx, in, out); _ = out.Close() }()
	reader := bufio.NewReader(outR)
	send := func(msg string) map[string]any {
		t.Helper()
		_, _ = inW.Write([]byte(msg + "\n"))
		if !strings.Contains(msg, `"id"`) {
			return nil
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var res map[string]any
		must(t, json.Unmarshal([]byte(line), &res))
		return res
	}
	text := func(res map[string]any) string {
		t.Helper()
		result, _ := res["result"].(map[string]any)
		content, _ := result["content"].([]any)
		if len(content) == 0 {
			t.Fatalf("no content: %v", res)
		}
		return content[0].(map[string]any)["text"].(string)
	}

	res := send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`)
	if r, _ := res["result"].(map[string]any); r["protocolVersion"] != Protocol {
		t.Fatalf("initialize: %v", res)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	res = send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if r, _ := res["result"].(map[string]any); len(r["tools"].([]any)) != 8 {
		t.Fatalf("tools: %v", res)
	}
	if !strings.Contains(text(send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ex0_overview","arguments":{}}}`)), "Muster GmbH") {
		t.Fatal("overview misses the tenant")
	}
	if !strings.Contains(text(send(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"ex0_devices","arguments":{"site_id":"site_a"}}}`)), "3389") {
		t.Fatal("devices miss the service")
	}
	sit := text(send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ex0_situation","arguments":{"site_id":"site_a"}}}`))
	if !strings.Contains(sit, dev.ID) || !strings.Contains(sit, "muster-box") {
		t.Fatalf("situation: %s", sit[:200])
	}
	saved := text(send(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"ex0_save_assessment","arguments":{"site_id":"site_a","model":"claude-fable-5-1","result":{"risk":"mittel","summary":"RDP im LAN.","priorities":[{"title":"RDP nur über VPN","why":"…","action":"…","device_id":"` + dev.ID + `","severity":"medium"}],"findings":[{"device_id":"` + dev.ID + `","slug":"rdp_ohne_vpn","severity":"medium","title":"RDP ohne VPN","detail":"…"}]}}}}`))
	if !strings.Contains(saved, "gespeichert") {
		t.Fatalf("save: %s", saved)
	}
	if !strings.Contains(text(send(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"ex0_briefs","arguments":{"site_id":"site_a"}}}`)), "claude-fable-5-1") {
		t.Fatal("brief not listed")
	}
	if !strings.Contains(text(send(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"ex0_findings","arguments":{"site_id":"site_a","severity":"medium"}}}`)), "ki.rdp_ohne_vpn") {
		t.Fatal("ki finding not listed")
	}
	res = send(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"ex0_nope","arguments":{}}}`)
	if r, _ := res["result"].(map[string]any); r["isError"] != true {
		t.Fatalf("unknown tool: %v", res)
	}
	res = send(`{"jsonrpc":"2.0","id":10,"method":"whatever"}`)
	if res["error"] == nil {
		t.Fatalf("unknown method: %v", res)
	}
	_ = inW.Close()
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
