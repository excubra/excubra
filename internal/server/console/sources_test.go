package console_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/api"
	"github.com/excubra/excubra/internal/server/core"
)

// A source is set up in the console like a token, and what it reports shows on
// its device (ADR-0023).
func TestSourcesInTheConsole(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	ctx := context.Background()
	if status, body := f.postJSON("/api/tenants", url.Values{"slug": {"viico"}, "name": {"VIICO"}}, f.csrf); status != 200 {
		t.Fatalf("tenant: %d %s", status, body)
	}
	if status, body := f.postJSON("/api/tenants/ten_viico/sites", url.Values{"slug": {"buero"}, "name": {"Büro"}}, f.csrf); status != 200 {
		t.Fatalf("site: %d %s", status, body)
	}

	// the tokens page offers the sites a source can belong to
	if status, _, body := f.getJSON("/api/tokens"); status != 200 || !strings.Contains(body, `"id":"site_buero"`) {
		t.Fatalf("tokens without the sites: %d %s", status, body)
	}

	// a name is not an address
	status, body := f.postJSON("/api/sources", url.Values{"site": {"site_buero"}, "name": {"VIIDOC"}, "address": {"viidoc.example"}}, f.csrf)
	if status != http.StatusBadRequest || !strings.Contains(body, "IP-Adresse") {
		t.Fatalf("a host name as the address: %d %s", status, body)
	}
	status, body = f.postJSON("/api/sources", url.Values{"site": {"site_buero"}, "name": {"VIIDOC"}, "address": {"10.100.10.3"}}, f.csrf)
	var created struct {
		OK     bool   `json:"ok"`
		Token  string `json:"token"`
		Device string `json:"device"`
	}
	if status != 200 || json.Unmarshal([]byte(body), &created) != nil || !created.OK || !strings.HasPrefix(created.Token, "ex0_") || created.Device == "" {
		t.Fatalf("create source: %d %s", status, body)
	}
	// the same address on the same site twice is refused
	if status, body := f.postJSON("/api/sources", url.Values{"site": {"site_buero"}, "name": {"VIIDOC"}, "address": {"10.100.10.3"}}, f.csrf); status != http.StatusBadRequest {
		t.Fatalf("second source at the same address: %d %s", status, body)
	}
	if _, _, body := f.getJSON("/api/tokens"); !strings.Contains(body, `"deviceId":"`+created.Device+`"`) {
		t.Fatalf("the source's token is not bound to its device: %s", body)
	}

	tok, err := f.st.APITokenByHash(ctx, api.HashToken(created.Token))
	must(t, err)
	now := time.Now()
	n, err := f.eng.SourceReport(ctx, tok, core.SourcePost{Events: []core.SourceEvent{
		{EventID: "a1", OccurredAt: now.Add(-2 * time.Minute), Kind: "auth.emergency", Actor: "chef@viico.test", IP: "203.0.113.9"},
		{EventID: "a2", OccurredAt: now.Add(-time.Minute), Kind: "ticket.create", Actor: "anna@viico.test", Target: "T-1"},
	}})
	if err != nil || n != 2 {
		t.Fatalf("report: %d %v", n, err)
	}

	type logs struct {
		Entries []struct {
			EventID string `json:"eventId"`
			Kind    string `json:"kind"`
			Actor   string `json:"actor"`
		} `json:"entries"`
		Source bool `json:"source"`
		Days   int  `json:"days"`
	}
	read := func(query string) logs {
		t.Helper()
		status, _, body := f.getJSON("/api/devices/" + created.Device + "/logs" + query)
		var l logs
		if status != 200 || json.Unmarshal([]byte(body), &l) != nil {
			t.Fatalf("logs%s: %d %s", query, status, body)
		}
		return l
	}
	all := read("")
	if !all.Source || all.Days != 7 || len(all.Entries) != 2 || all.Entries[0].EventID != "a2" || all.Entries[1].Actor != "chef@viico.test" {
		t.Fatalf("logs, newest first: %+v", all)
	}
	auth := read("?kind=auth&days=1")
	if auth.Days != 1 || len(auth.Entries) != 1 || auth.Entries[0].Kind != "auth.emergency" {
		t.Fatalf("the auth family: %+v", auth)
	}

	// the emergency sign-in is a finding on the source's device
	if status, _, body := f.getJSON("/api/devices/" + created.Device + "/findings"); status != 200 || !strings.Contains(body, "app.emergency") {
		t.Fatalf("findings: %d %s", status, body)
	}
}
