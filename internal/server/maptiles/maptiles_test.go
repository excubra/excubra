package maptiles

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestURLAndValid(t *testing.T) {
	for _, c := range []struct {
		tmpl, want string
		ok         bool
	}{
		{"https://example.test/{z}/{x}/{y}.png", "https://example.test/3/4/5.png", true},
		{"https://example.test/{z}/{x}/{y}{r}.png", "https://example.test/3/4/5.png", true}, // {r} is the retina suffix, dropped
		{"http://192.0.2.10:8080/t/{z}/{x}/{y}", "http://192.0.2.10:8080/t/3/4/5", true},
		{"https://example.test/{z}/{x}.png", "", false}, // no {y}
		{"file:///etc/{z}/{x}/{y}", "", false},          // not http(s): never a file reader
		{"javascript:alert({z}{x}{y})", "", false},      // not a URL we fetch
		{"/local/{z}/{x}/{y}.png", "", false},           // no host
		{"", "", false},
		{"off", "", false},
	} {
		got, err := Settings{Template: c.tmpl}.URL(3, 4, 5)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("URL(%q) = %q, %v; want %q", c.tmpl, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("URL(%q) should have been refused, got %q", c.tmpl, got)
		}
	}
	for _, c := range []struct {
		z, x, y int
		want    bool
	}{
		{0, 0, 0, true}, {3, 7, 7, true}, {19, 0, 0, true},
		{3, 8, 0, false}, // 2^3 = 8 tiles, so 8 is one past the edge
		{-1, 0, 0, false},
		{20, 0, 0, false}, // past MaxZoom
		{3, 0, -1, false},
	} {
		if got := Valid(c.z, c.x, c.y); got != c.want {
			t.Errorf("Valid(%d,%d,%d) = %v, want %v", c.z, c.x, c.y, got, c.want)
		}
	}
}

func TestTileFetchesOnceAndIdentifiesItself(t *testing.T) {
	var hits int
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		ua = r.Header.Get("User-Agent")
		switch {
		case strings.Contains(r.URL.Path, "/9/"):
			w.WriteHeader(http.StatusForbidden)
		case strings.Contains(r.URL.Path, "/8/"):
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>nope</html>"))
		default:
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("\x89PNG\r\n\x1a\n fake tile"))
		}
	}))
	defer srv.Close()

	s := New(t.TempDir())
	// The cache ages files by their modification time, which the operating system
	// writes from the real clock. A fixed date here would make this test pass in
	// the morning and fail in the afternoon, so the fake clock starts from now.
	now := time.Now()
	s.Now = func() time.Time { return now }
	set := Settings{Template: srv.URL + "/{z}/{x}/{y}.png"}
	ctx := context.Background()

	b, ct, err := s.Tile(ctx, set, 3, 4, 5)
	if err != nil || ct != "image/png" || !strings.HasPrefix(string(b), "\x89PNG") {
		t.Fatalf("first fetch: %v %q %q", err, ct, b)
	}
	if !strings.Contains(ua, "excubra") {
		t.Fatalf("the proxy must identify itself, got %q", ua)
	}
	// the second look is free
	if _, _, err := s.Tile(ctx, set, 3, 4, 5); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("a cached tile should not be fetched again, hits=%d", hits)
	}
	// a different template is a different cache tree
	if _, _, err := s.Tile(ctx, Settings{Template: srv.URL + "/other/{z}/{x}/{y}.png"}, 3, 4, 5); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("changing the source must not serve the old one's pictures, hits=%d", hits)
	}

	if _, _, err := s.Tile(ctx, set, 9, 4, 5); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a refused tile should say so: %v", err)
	}
	if _, _, err := s.Tile(ctx, set, 8, 4, 5); err == nil || !strings.Contains(err.Error(), "not an image") {
		t.Fatalf("a tile server sending HTML should be refused: %v", err)
	}
	if _, _, err := s.Tile(ctx, Settings{}, 3, 4, 5); !errors.Is(err, ErrDisabled) {
		t.Fatalf("without a template nothing is fetched: %v", err)
	}
	if _, _, err := s.Tile(ctx, set, 3, 99, 5); err == nil {
		t.Fatal("a tile that cannot exist should be refused before any request")
	}

	// old tiles are swept up
	later := now.Add(CacheFor + time.Hour)
	s.Now = func() time.Time { return later }
	n, err := s.Prune()
	if err != nil || n == 0 {
		t.Fatalf("prune: %d %v", n, err)
	}
}

// However fast an operator drags the map, the provider sees a trickle.
func TestRateLimit(t *testing.T) {
	s := New(t.TempDir())
	now := time.Now()
	s.Now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < Burst; i++ {
		if err := s.wait(ctx); err != nil {
			t.Fatalf("the burst should pass straight through: %v", err)
		}
	}
	// the bucket is empty and the clock does not move, so the next one waits —
	// and a cancelled request must end that wait instead of hanging
	dead, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.wait(dead); !errors.Is(err, context.Canceled) {
		t.Fatalf("a waiting fetch should honour the context: %v", err)
	}
}
