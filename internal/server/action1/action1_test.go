package action1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fake is an Action1 that behaves like the real one: a token first, a bearer on
// every call after that, and lists that are sometimes wrapped and sometimes not.
type fake struct {
	tokens   int
	calls    int
	unauthed bool
	wrap     bool
}

func (f *fake) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/3.0/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("client_id") != "id" || r.FormValue("client_secret") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.tokens++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	})
	list := func(bare string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.calls++
			if r.Header.Get("Authorization") != "Bearer tok" || f.unauthed {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if f.wrap {
				_, _ = w.Write([]byte(`{"items":` + bare + `}`))
				return
			}
			_, _ = w.Write([]byte(bare))
		}
	}
	mux.Handle("GET /api/3.0/organizations", list(`[{"id":"org-1","name":"Beispiel GmbH"}]`))
	mux.Handle("GET /api/3.0/endpoints/managed/org-1", list(`[{"id":"ep-1","name":"SRV-1.example.local","status":"Connected","last_seen":"2026-09-14_18-18-36"}]`))
	mux.Handle("GET /api/3.0/updates/org-1", list(`[{"id":"upd-1","name":"Windows Desktop Runtime","status":"Published"}]`))
	mux.Handle("GET /api/3.0/vulnerabilities/org-1", list(`[
		{"cve_id":"CVE-2026-70465","cvss_score":"8.1","endpoints_count":"1","remediation_status":"Overdue",
		 "remediation_deadline":"2026-08-27_12-19-47","cisa_kev":"No","software":[{"product_name":"FortiClient"}]},
		{"cve_id":"CVE-2026-1","cvss_score":"nonsense","endpoints_count":"","remediation_status":"Pending",
		 "remediation_deadline":"kaputt","cisa_kev":"Yes","software":[{"product_name":""}]}]`))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newClient(t *testing.T, base string) *Client {
	t.Helper()
	c := New(base+"/api/3.0/", "id", "secret") // a trailing slash must not double up
	c.Now = time.Now
	return c
}

func TestReadsAnOrganization(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		f := &fake{wrap: wrapped}
		srv := f.server(t)
		c := newClient(t, srv.URL)
		ctx := context.Background()

		orgs, err := c.Orgs(ctx)
		if err != nil || len(orgs) != 1 || orgs[0].ID != "org-1" || orgs[0].Name != "Beispiel GmbH" {
			t.Fatalf("wrapped=%v orgs: %+v %v", wrapped, orgs, err)
		}
		eps, err := c.Endpoints(ctx, "org-1")
		if err != nil || len(eps) != 1 || eps[0].Name != "SRV-1.example.local" {
			t.Fatalf("endpoints: %+v %v", eps, err)
		}
		ups, err := c.MissingUpdates(ctx, "org-1")
		if err != nil || len(ups) != 1 || ups[0].Name != "Windows Desktop Runtime" {
			t.Fatalf("updates: %+v %v", ups, err)
		}
		vs, err := c.Vulnerabilities(ctx, "org-1")
		if err != nil || len(vs) != 2 {
			t.Fatalf("vulnerabilities: %+v %v", vs, err)
		}
		v := vs[0]
		if v.CVE != "CVE-2026-70465" || v.CVSS != 8.1 || v.Endpoints != 1 || v.Status != "Overdue" || v.KEV {
			t.Fatalf("first: %+v", v)
		}
		if want := time.Date(2026, 8, 27, 12, 19, 47, 0, time.UTC); !v.Deadline.Equal(want) {
			t.Fatalf("deadline %s, want %s", v.Deadline, want)
		}
		if len(v.Products) != 1 || v.Products[0] != "FortiClient" {
			t.Fatalf("products: %+v", v.Products)
		}
		// unreadable numbers and dates become zero values, never a guess
		if bad := vs[1]; bad.CVSS != 0 || bad.Endpoints != 0 || !bad.Deadline.IsZero() || !bad.KEV || len(bad.Products) != 0 {
			t.Fatalf("second: %+v", bad)
		}
		// four calls, one token
		if f.tokens != 1 {
			t.Fatalf("the token should be reused, fetched %d times", f.tokens)
		}
	}
}

func TestWithoutCredentialsNothingIsFetched(t *testing.T) {
	c := New("", "", "")
	if c.Configured() {
		t.Fatal("no credentials is not configured")
	}
	if c.Base() != DefaultBaseURL {
		t.Fatalf("the EU instance is the default, got %q", c.Base())
	}
	if _, err := c.Orgs(context.Background()); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestRefusedCredentialsSaySo(t *testing.T) {
	f := &fake{}
	srv := f.server(t)
	c := New(srv.URL+"/api/3.0", "id", "falsch")
	if _, err := c.Orgs(context.Background()); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("a refused credential should name the token step: %v", err)
	}

	// a token that the server later rejects is forgotten, so the next call gets a
	// fresh one instead of retrying with something dead
	f2 := &fake{}
	srv2 := f2.server(t)
	c2 := newClient(t, srv2.URL)
	if _, err := c2.Orgs(context.Background()); err != nil {
		t.Fatal(err)
	}
	f2.unauthed = true
	if _, err := c2.Orgs(context.Background()); err == nil {
		t.Fatal("a refused call should be an error")
	}
	f2.unauthed = false
	if _, err := c2.Orgs(context.Background()); err != nil {
		t.Fatalf("after forgetting the token it should recover: %v", err)
	}
	if f2.tokens != 2 {
		t.Fatalf("the dead token should have been replaced once, tokens=%d", f2.tokens)
	}
}

// Action1 cuts a tenant off above thirty requests a minute, and that would take
// the account's other callers down with us.
func TestHoldsItselfBelowTheRateLimit(t *testing.T) {
	c := New("https://example.test/api/3.0", "id", "secret")
	now := time.Now()
	c.Now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < burst; i++ {
		if err := c.wait(ctx); err != nil {
			t.Fatalf("the burst should pass through: %v", err)
		}
	}
	dead, cancel := context.WithCancel(ctx)
	cancel()
	if err := c.wait(dead); !errors.Is(err, context.Canceled) {
		t.Fatalf("a waiting call should honour the context: %v", err)
	}
}

// A changed credential must not keep using the old token: removing a key in the
// console would otherwise keep reading for another hour.
func TestConfigureDropsTheCachedToken(t *testing.T) {
	c := New("https://example.test/api/3.0", "id", "secret")
	c.mu.Lock()
	c.token, c.expires = "old", time.Now().Add(time.Hour)
	c.mu.Unlock()

	c.Configure("https://example.test/api/3.0", "id", "secret") // same: keep it
	c.mu.Lock()
	same := c.token
	c.mu.Unlock()
	if same != "old" {
		t.Fatal("unchanged credentials should not throw away a valid token")
	}

	c.Configure("https://example.test/api/3.0", "id", "other")
	c.mu.Lock()
	tok := c.token
	c.mu.Unlock()
	if tok != "" {
		t.Fatalf("a new secret must drop the old token, got %q", tok)
	}
	if !c.Configured() {
		t.Fatal("it is still configured, only with a different secret")
	}
	c.Configure("", "", "")
	if c.Configured() || c.Base() != DefaultBaseURL {
		t.Fatal("cleared credentials mean not configured, and the base falls back to the default")
	}
}
