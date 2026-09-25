package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/server/api"
	"github.com/excubra/excubra/internal/server/store"
)

// A source reports itself (ADR-0023): its events land in the logs, the rules make
// findings of them, a finding that opens is one security.alert. Its token posts
// and does nothing else; an operator token does not post.
func TestASourceReportsItself(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	site, err := f.st.Site(ctx, "site_a")
	must(t, err)
	src, err := f.st.CreateSource(ctx, site, "VIIDOC", "10.100.10.3", store.SourceTokenName("VIIDOC"), api.HashToken("src-secret"), f.now)
	must(t, err)

	post := func(token string, body any) (int, map[string]any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/v1/source/events", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		must(t, err)
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	alerts := func() int {
		n := 0
		for _, ev := range f.pub.events {
			if ev.Type == event.SecurityAlert && ev.Source == event.SourceApp {
				n++
			}
		}
		return n
	}
	open := func(rule string) *store.Finding {
		t.Helper()
		list, err := f.st.OpenFindings(ctx, "ten_a")
		must(t, err)
		for i := range list {
			if list[i].Rule == rule && list[i].DeviceID == src.Device.ID {
				return &list[i]
			}
		}
		return nil
	}
	ev := func(id, kind, actor, ip string) map[string]any {
		return map[string]any{"event_id": id, "occurred_at": f.now, "kind": kind, "actor": actor, "ip": ip}
	}

	batch := map[string]any{
		"events": []any{ev("a1", "auth.login", "anna@viico.test", "198.51.100.7"), ev("a2", "auth.emergency", "chef@viico.test", "198.51.100.8")},
		"status": map[string]any{"version": "abc123", "cert_not_after": f.now.Add(5 * 24 * time.Hour)},
	}
	if code, out := post("src-secret", batch); code != http.StatusOK || out["stored"] != float64(2) {
		t.Fatalf("first post: %d %v", code, out)
	}
	// two findings open, two alerts: the emergency sign-in and the certificate
	if open("app.emergency") == nil || open("app.cert_expiring") == nil || alerts() != 2 {
		t.Fatalf("after the first post: emergency %v, certificate %v, alerts %d", open("app.emergency"), open("app.cert_expiring"), alerts())
	}
	logs, err := f.st.Logs(ctx, "ten_a", src.Device.ID, f.now.Add(-time.Hour), f.now.Add(time.Hour), "", 0)
	must(t, err)
	if len(logs) != 2 || logs[0].Source != "app.viidoc" {
		t.Fatalf("logs: %+v", logs)
	}
	// a retry stores nothing and alerts nobody twice
	if code, out := post("src-secret", batch); code != http.StatusOK || out["stored"] != float64(0) || alerts() != 2 {
		t.Fatalf("retry: %d %v, alerts %d", code, out, alerts())
	}
	// the same kind again counts on the open finding
	post("src-secret", map[string]any{"events": []any{ev("a3", "auth.emergency", "chef@viico.test", "198.51.100.8")}})
	var count struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(open("app.emergency").Evidence, &count)
	if count.Count != 2 || alerts() != 2 {
		t.Fatalf("second emergency: count %d, alerts %d", count.Count, alerts())
	}
	// ten refusals from one address within the window
	var refused []any
	for i := range 10 {
		refused = append(refused, ev("r"+strconv.Itoa(i), "auth.refused", "", "203.0.113.9"))
	}
	post("src-secret", map[string]any{"events": refused})
	if open("app.refused") == nil || alerts() != 3 {
		t.Fatalf("refusals: %v, alerts %d", open("app.refused"), alerts())
	}

	// the source token reads nothing; an operator token posts nothing
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/v1/tenants", nil)
	req.Header.Set("Authorization", "Bearer src-secret")
	res, err := http.DefaultClient.Do(req)
	must(t, err)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("source token reading: %d", res.StatusCode)
	}
	if code, _ := post("crm-secret", batch); code != http.StatusForbidden {
		t.Errorf("operator token posting: %d", code)
	}
	var tooMany []any
	for i := range 501 {
		tooMany = append(tooMany, ev("m"+strconv.Itoa(i), "auth.login", "", ""))
	}
	if code, _ := post("src-secret", map[string]any{"events": tooMany}); code != http.StatusRequestEntityTooLarge {
		t.Errorf("501 events: %d", code)
	}

	// silence: eleven minutes without a word is a finding with one alert, the next post ends it
	before := alerts()
	f.now = f.now.Add(11 * time.Minute)
	must(t, f.eng.Tick(ctx))
	if open("app.silent") == nil || alerts() != before+1 {
		t.Fatalf("silence: %v, alerts %d → %d", open("app.silent"), before, alerts())
	}
	must(t, f.eng.Tick(ctx))
	if alerts() != before+1 {
		t.Fatalf("a still silent source alerted again")
	}
	if code, _ := post("src-secret", map[string]any{"events": []any{}}); code != http.StatusOK {
		t.Fatalf("heartbeat: %d", code)
	}
	if open("app.silent") != nil {
		t.Fatal("the source talks again and is still silent")
	}

	// revoked, the token posts nothing any more
	must(t, f.st.RevokeAPIToken(ctx, src.Token.ID, f.now))
	if code, _ := post("src-secret", map[string]any{"events": []any{}}); code != http.StatusUnauthorized {
		t.Errorf("revoked source posting: %d", code)
	}
	// and it is no longer watched: no silence, and its certificate finding
	// resolves after a quiet day
	before = alerts()
	f.now = f.now.Add(25 * time.Hour)
	must(t, f.eng.Tick(ctx))
	if open("app.silent") != nil || open("app.cert_expiring") != nil || alerts() != before {
		t.Fatalf("revoked source: silent %v, certificate %v, alerts %d → %d", open("app.silent"), open("app.cert_expiring"), before, alerts())
	}
}
