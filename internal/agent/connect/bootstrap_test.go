package connect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/excubra/excubra/internal/wire"
)

// fakeFortiGateAdmin adds the web login and the CMDB endpoints the bootstrap uses to
// the monitor endpoints of fakeFortiGate; the token it generates is "tok-1", so the
// reading that follows the bootstrap succeeds against the same handler.
func fakeFortiGateAdmin(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	inner := fakeFortiGate(t, 5)
	t.Cleanup(inner.Close)
	var calls []string
	created := map[string]bool{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.URL.Path == "/logincheck":
			_ = r.ParseForm()
			if r.PostForm.Get("username") != "admin" || r.PostForm.Get("secretkey") != "pw" {
				_, _ = w.Write([]byte("0"))
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "APSCOOKIE_1", Value: "sess", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "ccsrftoken_443_1", Value: `"csrf123"`, Path: "/"})
			_, _ = w.Write([]byte("1"))
		case r.URL.Path == "/logout":
			w.WriteHeader(200)
		case (strings.HasPrefix(r.URL.Path, "/api/v2/cmdb/") && r.Header.Get("Authorization") == "") || strings.HasPrefix(r.URL.Path, "/api/v2/monitor/system/api-user/"):
			c, err := r.Cookie("APSCOOKIE_1")
			if err != nil || c.Value != "sess" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if r.Method == http.MethodPost && r.Header.Get("X-CSRFTOKEN") != "csrf123" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/cmdb/system/accprofile/"):
				if !created["profile"] {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write([]byte(`{"status":"success"}`))
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v2/cmdb/system/api-user/"):
				if !created["user"] {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write([]byte(`{"status":"success"}`))
			case r.Method == http.MethodPost && r.URL.Path == "/api/v2/cmdb/system/accprofile":
				var p map[string]any
				_ = json.NewDecoder(r.Body).Decode(&p)
				if p["name"] != fgtProfile || p["sysgrp"] != "read" {
					w.WriteHeader(400)
					return
				}
				created["profile"] = true
				_, _ = w.Write([]byte(`{"status":"success"}`))
			case r.Method == http.MethodPost && r.URL.Path == "/api/v2/cmdb/system/api-user":
				var u map[string]any
				_ = json.NewDecoder(r.Body).Decode(&u)
				if u["name"] != fgtAPIUser || u["accprofile"] != fgtProfile {
					w.WriteHeader(400)
					return
				}
				if th, ok := u["trusthost"].([]any); !ok || len(th) != 1 {
					w.WriteHeader(400)
					return
				}
				created["user"] = true
				_, _ = w.Write([]byte(`{"status":"success"}`))
			case r.Method == http.MethodPost && r.URL.Path == "/api/v2/monitor/system/api-user/generate-key":
				if !created["user"] {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write([]byte(`{"status":"success","results":{"access_token":"tok-1"}}`))
			default:
				w.WriteHeader(404)
			}
		default:
			// monitor endpoints: the same answers as the plain fake
			req, _ := http.NewRequest(r.Method, inner.URL+r.URL.RequestURI(), nil)
			req.Header = r.Header.Clone()
			resp, err := inner.Client().Do(req)
			if err != nil {
				w.WriteHeader(502)
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			_ = json.NewEncoder(w).Encode(decodeAny(resp))
		}
	}))
	return srv, &calls
}

func decodeAny(resp *http.Response) any {
	var v any
	_ = json.NewDecoder(resp.Body).Decode(&v)
	return v
}

func TestFortiGateBootstrapMakesItsOwnToken(t *testing.T) {
	srv, calls := fakeFortiGateAdmin(t)
	defer srv.Close()
	r := testRunner()
	sealedTo := ""
	r.Seal = func(plain []byte) (string, error) {
		sealedTo = string(plain)
		return "SEALED(" + string(plain) + ")", nil
	}
	cfg := wire.ConnectorConfig{ID: "con_b", DeviceID: "dev_b", Kind: wire.ConnectorFortiGate, URL: srv.URL, Sealed: `{"admin_user":"admin","admin_password":"pw"}`, Version: "v1"}
	r.ReadOnce(context.Background(), cfg)
	rep, _ := r.Latest("con_b")
	if !rep.OK {
		t.Fatalf("bootstrap reading: %+v", rep)
	}
	if rep.TokenSealed != `SEALED({"token":"tok-1"})` || sealedTo != `{"token":"tok-1"}` {
		t.Fatalf("token not sealed for the server: %q", rep.TokenSealed)
	}
	joined := strings.Join(*calls, "\n")
	for _, want := range []string{"POST /logincheck", "POST /api/v2/cmdb/system/accprofile", "POST /api/v2/cmdb/system/api-user", "POST /api/v2/monitor/system/api-user/generate-key", "GET /logout", "GET /api/v2/monitor/system/status"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in\n%s", want, joined)
		}
	}
	// the sealed token travels once
	reps := r.Reports()
	if reps[0].TokenSealed == "" {
		t.Fatal("first report must carry the sealed token")
	}
	r.Ack()
	if reps = r.Reports(); reps[0].TokenSealed != "" {
		t.Fatal("acknowledged token must not travel again")
	}
	// the next reading uses the token, not the admin login, even before the server switched the document
	n := len(*calls)
	r.ReadOnce(context.Background(), cfg)
	if rep, _ = r.Latest("con_b"); !rep.OK || rep.TokenSealed != "" {
		t.Fatalf("second reading: %+v", rep)
	}
	if strings.Contains(strings.Join((*calls)[n:], "\n"), "/logincheck") {
		t.Fatal("second reading logged in as admin again")
	}
	// a wrong admin password is an auth error the operator understands
	cfg.Sealed = `{"admin_user":"admin","admin_password":"nope"}`
	cfg.Version = "v2"
	r.Apply([]wire.ConnectorConfig{cfg}) // forgets the override
	r.ReadOnce(context.Background(), cfg)
	if rep, _ = r.Latest("con_b"); rep.OK || !strings.Contains(rep.Error, "wrong user or password") {
		t.Fatalf("wrong admin login: %+v", rep)
	}
}
