package console_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// getJSON asks like the single-page app does: Accept JSON, session cookie from the jar.
func (f *fixture) getJSON(path string) (int, string, string) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+path, nil)
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Content-Type"), string(b)
}

// postJSON posts a form the way the app does: CSRF in the header, JSON answer wanted.
func (f *fixture) postJSON(path string, form url.Values, csrf string) (int, string) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAPIRequiresSession(t *testing.T) {
	f := newFixture(t)
	status, ct, body := f.getJSON("/api/me")
	if status != http.StatusUnauthorized || !strings.Contains(ct, "application/json") {
		t.Fatalf("unauthenticated /api/me: %d %s %s", status, ct, body)
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil || e.Error == "" {
		t.Fatalf("expected a JSON error, got %s", body)
	}
	// The app shell itself is behind the session too.
	if status, _ := f.get("/app/"); status != http.StatusSeeOther && status != http.StatusFound {
		t.Fatalf("unauthenticated /app/: %d", status)
	}
}

func TestAPIMeOverviewSearch(t *testing.T) {
	f := newFixture(t)
	f.login(t)

	status, ct, body := f.getJSON("/api/me")
	if status != 200 || !strings.Contains(ct, "application/json") {
		t.Fatalf("me: %d %s %s", status, ct, body)
	}
	var me struct {
		User string `json:"user"`
		CSRF string `json:"csrf"`
		Nav  struct{ Tenants, Boxes int }
	}
	if err := json.Unmarshal([]byte(body), &me); err != nil {
		t.Fatal(err)
	}
	if me.User != userName || me.CSRF != f.csrf {
		t.Fatalf("me = %+v, want user %q and the session's csrf", me, userName)
	}

	status, _, body = f.getJSON("/api/overview")
	if status != 200 {
		t.Fatalf("overview: %d %s", status, body)
	}
	var ov map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &ov); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"Cards", "Chart", "attention", "SitesTotal"} {
		if _, ok := ov[k]; !ok {
			t.Errorf("overview lacks %q", k)
		}
	}

	status, _, body = f.getJSON("/api/search?q=x")
	if status != 200 || strings.TrimSpace(body) != "[]" {
		t.Fatalf("search below the minimum length should answer an empty list: %d %s", status, body)
	}
}

func TestAPICreateTenantAndList(t *testing.T) {
	f := newFixture(t)
	f.login(t)

	// Without the CSRF header the write is refused, with a JSON error the app can show.
	status, body := f.postJSON("/api/tenants", url.Values{"slug": {"acme"}, "name": {"ACME"}}, "")
	if status != http.StatusForbidden || !strings.Contains(body, `"error"`) {
		t.Fatalf("csrf-less create: %d %s", status, body)
	}

	status, body = f.postJSON("/api/tenants", url.Values{"slug": {"acme"}, "name": {"ACME GmbH"}}, f.csrf)
	if status != 200 {
		t.Fatalf("create: %d %s", status, body)
	}
	var r struct {
		OK      bool   `json:"ok"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(body), &r); err != nil || !r.OK || !strings.Contains(r.Message, "ten_acme") {
		t.Fatalf("create answer: %s (%v)", body, err)
	}

	// Validation failures are JSON too, not a redirect with a flash.
	status, body = f.postJSON("/api/tenants", url.Values{"slug": {"Bad Slug"}, "name": {""}}, f.csrf)
	if status != http.StatusBadRequest || !strings.Contains(body, `"ok":false`) {
		t.Fatalf("invalid create: %d %s", status, body)
	}

	status, _, body = f.getJSON("/api/tenants")
	if status != 200 {
		t.Fatalf("list: %d %s", status, body)
	}
	var rows []struct {
		ID    string
		Name  string
		Sites int `json:"sites"`
	}
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "ten_acme" || rows[0].Name != "ACME GmbH" {
		t.Fatalf("tenants = %+v", rows)
	}
}

func TestAppShell(t *testing.T) {
	f := newFixture(t)
	f.login(t)
	for _, p := range []string{"/app/", "/app/tenants", "/app/sites/site_x"} {
		resp, err := f.client.Get(f.srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("%s: content type %q", p, resp.Header.Get("Content-Type"))
		}
		// Built: the app shell. Checkout without Node: the placeholder, clearly marked.
		switch resp.StatusCode {
		case 200:
			if !strings.Contains(string(b), `id="root"`) {
				t.Fatalf("%s: not the app shell:\n%s", p, b)
			}
		case http.StatusServiceUnavailable:
			if !strings.Contains(string(b), "Konsole nicht gebaut") {
				t.Fatalf("%s: not the placeholder:\n%s", p, b)
			}
		default:
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: shell must not be cached, got %q", p, resp.Header.Get("Cache-Control"))
		}
	}
	// Nothing outside webdist is reachable through the app path.
	if status, _ := f.get("/app/../ca.crt"); status == 200 {
		t.Fatal("path traversal out of /app/ must not serve files")
	}
}
