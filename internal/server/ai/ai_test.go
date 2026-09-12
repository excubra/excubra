package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

func TestParseAndSanitize(t *testing.T) {
	text := "Hier die Einschätzung:\n```json\n{\"risk\":\"HIGH\",\"summary\":\"Zwei Türen offen.\",\"priorities\":[{\"title\":\"RDP schließen\",\"why\":\"offen\",\"action\":\"Weiterleitung entfernen\",\"device_id\":\"dev_a\",\"severity\":\"hoch\"}],\"findings\":[{\"device_id\":\"dev_a\",\"slug\":\"Alter Server + RDP!\",\"severity\":\"high\",\"title\":\"Alter Server mit RDP\",\"detail\":\"…\"},{\"device_id\":\"dev_x\",\"slug\":\"nope\",\"severity\":\"low\",\"title\":\"unbekanntes Gerät\",\"detail\":\"…\"}]}\n```\nViel Erfolg."
	r, err := parseResult(text)
	if err != nil {
		t.Fatal(err)
	}
	r = sanitize(r, map[string]bool{"dev_a": true})
	if r.Risk != "hoch" || len(r.Priorities) != 1 || r.Priorities[0].Severity != "high" || r.Priorities[0].DeviceID != "dev_a" {
		t.Fatalf("priorities: %+v", r)
	}
	if len(r.Findings) != 1 || r.Findings[0].Slug != "alter_server_rdp" || r.Findings[0].DeviceID != "dev_a" {
		t.Fatalf("findings: %+v", r.Findings)
	}
	if _, err := parseResult("keine Antwort"); err == nil {
		t.Fatal("prose accepted as JSON")
	}
	if got := redact(map[string]any{"version": "7.4", "api_token": "x", "admins": []any{map[string]any{"name": "a", "password": "p"}}}); got["api_token"] != nil || got["admins"].([]any)[0].(map[string]any)["password"] != nil || got["version"] != "7.4" {
		t.Fatalf("redact: %+v", got)
	}
}

// A fake Anthropic endpoint answers with findings for a known and an unknown
// device; the known one becomes a finding of source "ki", the brief is stored,
// the switch per tenant and the provider settings are respected.
func TestAssessWritesBriefAndFindings(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	must(t, st.CreateTenant(ctx, store.Tenant{ID: "ten_a", Name: "Muster GmbH", CreatedAt: now}))
	must(t, st.CreateSite(ctx, store.Site{ID: "site_a", TenantID: "ten_a", Name: "Werk", CreatedAt: now}))
	must(t, st.CreateBox(ctx, store.Box{ID: "box_a", SiteID: "site_a", Name: "muster-box", HWID: "hw", CertSerial: "1", CertNotAfter: now.Add(time.Hour), EnrolledAt: now, LastSeen: now, AgentVersion: "0.4.0"}))
	dev, _, _, err := st.UpsertSighting(ctx, "ten_a", "site_a", wire.Sighting{MAC: "00:11:22:33:44:55", IP: "192.168.1.10", Hostname: "srv01", LastSeen: now}, now)
	must(t, err)
	_, _, err = st.UpsertServices(ctx, dev.ID, []store.Service{{DeviceID: dev.ID, Port: 3389, Proto: "tcp", Name: "rdp"}}, now)
	must(t, err)
	_, err = st.SyncDeviceFindings(ctx, dev.ID, "scan", []store.Finding{{ID: "fnd_1", TenantID: "ten_a", SiteID: "site_a", DeviceID: dev.ID, Rule: "scan.rdp", Key: "tcp/3389", Severity: "low", Title: "RDP erreichbar"}}, now)
	must(t, err)

	var gotSystem, gotUser string
	var gotHeaders http.Header
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		body, _ := io.ReadAll(r.Body)
		var req struct {
			System   string `json:"system"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(body, &req)
		gotSystem, gotUser = req.System, req.Messages[0].Content
		answer := `{"risk":"mittel","summary":"Ein Server mit RDP im LAN, sonst ruhig.","priorities":[{"title":"RDP nur über VPN","why":"RDP ist das häufigste Einfallstor","action":"NLA erzwingen, Zugriff auf VPN beschränken","device_id":"` + dev.ID + `","severity":"medium"}],"findings":[{"device_id":"` + dev.ID + `","slug":"rdp_ohne_nla","severity":"medium","title":"RDP ohne Netzwerkauthentifizierung möglich","detail":"Prüfen, ob NLA an ist."},{"device_id":"dev_unknown","slug":"x","severity":"high","title":"erfunden","detail":"…"}]}`
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":` + strconvQuote(answer) + `}],"usage":{"input_tokens":1200,"output_tokens":300}}`))
	}))
	defer fake.Close()

	s := New(st, nil, time.UTC)
	s.Now = func() time.Time { return now }
	if _, err := s.Assess(ctx, "site_a", "test"); err == nil {
		t.Fatal("assessed without a provider")
	}
	must(t, s.SaveSettings(ctx, "anthropic", fake.URL, "claude-test", "sk-test"))
	if _, err := s.Assess(ctx, "site_a", "test"); !errors.Is(err, ErrScopeOff) {
		t.Fatalf("scope off not respected: %v", err)
	}
	must(t, st.SetTenantAI(ctx, "ten_a", store.AIScopeFacts))
	brief, err := s.Assess(ctx, "site_a", "test")
	must(t, err)
	if gotHeaders.Get("x-api-key") != "sk-test" || gotHeaders.Get("anthropic-version") == "" || !strings.Contains(gotSystem, "JSON") {
		t.Fatalf("request: headers=%v system=%q", gotHeaders, gotSystem[:40])
	}
	var pk Packet
	must(t, json.Unmarshal([]byte(gotUser), &pk))
	if pk.Tenant != "Muster GmbH" || len(pk.Devices) != 1 || pk.Devices[0].ID != dev.ID || len(pk.Devices[0].Services) != 1 || len(pk.Findings) != 1 || pk.Box == nil || pk.Box.Name != "muster-box" {
		t.Fatalf("packet: %+v", pk)
	}
	if brief.Risk != "mittel" || brief.Provider != "anthropic" || brief.Model != "claude-test" || brief.PromptBytes == 0 || !strings.Contains(brief.Summary, "RDP") {
		t.Fatalf("brief: %+v", brief)
	}
	briefs, _ := st.AIBriefs(ctx, "site_a", 5)
	if len(briefs) != 1 || briefs[0].ID != brief.ID {
		t.Fatalf("stored briefs: %+v", briefs)
	}
	open, _ := st.OpenFindings(ctx, "ten_a")
	var ki []store.Finding
	for _, f := range open {
		if f.ConnectorID == "ki" {
			ki = append(ki, f)
		}
	}
	if len(ki) != 1 || ki[0].Rule != "ki.rdp_ohne_nla" || ki[0].DeviceID != dev.ID || ki[0].Severity != "medium" {
		t.Fatalf("ki findings: %+v", ki)
	}
	// the settings never expose the key; a second assessment keeps one brief per run
	if set := s.Settings(ctx); !set.HasKey || set.Provider != "anthropic" || set.Model != "claude-test" {
		t.Fatalf("settings: %+v", set)
	}
	if reply, err := s.Test(ctx); err != nil || reply == "" {
		t.Fatalf("test: %q %v", reply, err)
	}
}

// The OpenAI-shaped backend (Ollama and friends) is read the same way.
func TestOpenAIProvider(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"OK"}}],"usage":{"prompt_tokens":5,"completion_tokens":1}}`))
	}))
	defer fake.Close()
	p := &OpenAI{URL: fake.URL, Key: "k", Mdl: "gpt-oss:120b"}
	res, err := p.Complete(context.Background(), Request{System: "s", User: "u", MaxTokens: 5})
	if err != nil || res.Text != "OK" || res.InputTokens != 5 {
		t.Fatalf("%+v %v", res, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
