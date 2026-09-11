//go:build preview

package console_test

// Design preview for the single-page console: seeds pilot-like data, logs in, and keeps a
// local server running for a while. It prints the URL and the raw session cookie so a
// browser can be pointed at the app without typing a password.
//
//	EX0_PREVIEW_SERVE=20m go test -tags preview -run TestPreviewServe -timeout 1h ./internal/server/console/ -v
//
// The httptest server listens on a random port. EX0_PREVIEW_ADDR additionally exposes
// it on a fixed address (127.0.0.1:18080 is what web/vite.config.ts proxies to).

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestPreviewServe(t *testing.T) {
	dur := os.Getenv("EX0_PREVIEW_SERVE")
	if dur == "" {
		t.Skip("EX0_PREVIEW_SERVE not set")
	}
	d, err := time.ParseDuration(dur)
	if err != nil {
		t.Fatal(err)
	}
	f := seedPreview(t)
	u, _ := url.Parse(f.srv.URL)
	var raw string
	for _, c := range f.client.Jar.Cookies(u) {
		if c.Name == "excubra_session" {
			raw = c.Value
		}
	}
	if addr := os.Getenv("EX0_PREVIEW_ADDR"); addr != "" {
		proxy := httputil.NewSingleHostReverseProxy(u)
		go func() { _ = http.ListenAndServe(addr, proxy) }()
		t.Logf("PREVIEW_ADDR=http://%s/app/", addr)
	}
	t.Logf("PREVIEW_URL=%s/app/", f.srv.URL)
	t.Logf("PREVIEW_COOKIE=excubra_session=%s", raw)
	time.Sleep(d)
}
