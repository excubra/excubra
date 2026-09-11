package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/agent/update"
	"github.com/excubra/excubra/internal/server/store"
)

type world struct {
	st     *store.Store
	upd    *update.Updater
	srv    *httptest.Server
	dir    string
	binary string
	trials int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	w := &world{st: st, dir: dir, binary: filepath.Join(dir, "bin", "excubra")}
	if err := os.MkdirAll(filepath.Dir(w.binary), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.binary, []byte("OLD BINARY"), 0o700); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	blob := bytes.Repeat([]byte("NEW SERVER "), 200000) // > 1 MiB
	w.srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write(blob) }))
	t.Cleanup(w.srv.Close)
	w.upd = &update.Updater{
		Dir: filepath.Join(dir, "data", "update"), Binary: w.binary, Client: w.srv.Client(), Now: time.Now, Log: slog.Default(),
		Verify: func(_ []byte, sigB64 string) error {
			if sigB64 != "good" {
				return errors.New("bad signature")
			}
			return nil
		},
		Trial: func(context.Context, string) error { w.trials++; return nil },
	}
	if err := os.MkdirAll(w.upd.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return w
}

func sha256Of(b []byte) string {
	// the updater compares the hex sha256; computed the same way it does
	h := sha256sum(b)
	return h
}

func TestServerFollowsItsChannel(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	blob := bytes.Repeat([]byte("NEW SERVER "), 200000)
	c := New(w.st, w.upd, filepath.Join(w.dir, "data"), "linux", "amd64", true, nil)

	// nothing configured: nothing happens
	if err := c.Check(ctx); err != nil {
		t.Fatalf("empty channel: %v", err)
	}
	if s := c.Status(ctx); s.Channel != "stable" || s.Available != "" || !s.Enabled {
		t.Fatalf("status %+v", s)
	}

	// a release for another platform only: reported, not installed
	must(t, w.st.PutRelease(ctx, store.Release{Version: "9.9.9", OS: "linux", Arch: "arm64", URL: w.srv.URL + "/arm", SHA256: sha256Of(blob), Signature: "good", CreatedAt: time.Now()}))
	must(t, w.st.SetChannelVersion(ctx, "stable", "9.9.9"))
	if err := c.Check(ctx); err == nil || !strings.Contains(err.Error(), "no build for linux/amd64") {
		t.Fatalf("missing platform build: %v", err)
	}
	if s := c.Status(ctx); s.Target != "9.9.9" || s.Available != "" || s.LastError == "" {
		t.Fatalf("status %+v", s)
	}

	// the right build: installed, pending, audited, restart requested
	must(t, w.st.PutRelease(ctx, store.Release{Version: "9.9.9", OS: "linux", Arch: "amd64", URL: w.srv.URL + "/amd", SHA256: sha256Of(blob), Signature: "good", CreatedAt: time.Now()}))
	if s := c.Status(ctx); s.Available != "9.9.9" {
		t.Fatalf("available should be 9.9.9: %+v", s)
	}
	err := c.Check(ctx)
	if !errors.Is(err, update.ErrRestart) {
		t.Fatalf("expected restart, got %v", err)
	}
	if got, _ := os.ReadFile(w.binary); !bytes.Equal(got, blob) {
		t.Fatal("binary not swapped")
	}
	if _, ok := w.upd.Pending(); !ok {
		t.Fatal("no pending marker")
	}
	if w.trials != 1 {
		t.Fatalf("trial runs: %d", w.trials)
	}
	entries, _ := w.st.AuditEntries(ctx, 5, 0)
	if len(entries) == 0 || entries[0].Action != "server.update" {
		t.Fatalf("audit: %+v", entries)
	}

	// channel off: even a newer release stays where it is
	must(t, c.SetChannel(ctx, "off"))
	if err := c.Check(ctx); err != nil {
		t.Fatalf("off: %v", err)
	}
	if err := c.SetChannel(ctx, "nightly"); err == nil {
		t.Fatal("bad channel accepted")
	}

	// a bad signature never reaches the binary
	must(t, w.st.SetChannelVersion(ctx, "canary", "9.9.10"))
	must(t, w.st.PutRelease(ctx, store.Release{Version: "9.9.10", OS: "linux", Arch: "amd64", URL: w.srv.URL + "/bad", SHA256: sha256Of(blob), Signature: "forged", CreatedAt: time.Now()}))
	must(t, c.SetChannel(ctx, "canary"))
	if err := c.Check(ctx); err == nil || !strings.Contains(err.Error(), "bad signature") {
		t.Fatalf("forged release: %v", err)
	}
}

func TestDisabledControllerDoesNothing(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	blob := bytes.Repeat([]byte("NEW SERVER "), 200000)
	must(t, w.st.PutRelease(ctx, store.Release{Version: "9.9.9", OS: "linux", Arch: "amd64", URL: w.srv.URL + "/amd", SHA256: sha256Of(blob), Signature: "good", CreatedAt: time.Now()}))
	must(t, w.st.SetChannelVersion(ctx, "stable", "9.9.9"))
	c := New(w.st, w.upd, filepath.Join(w.dir, "data"), "linux", "amd64", false, nil)
	if err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(w.binary); string(got) != "OLD BINARY" {
		t.Fatal("disabled controller touched the binary")
	}
}

func TestTriggerFileAsksForACheck(t *testing.T) {
	w := newWorld(t)
	dataDir := filepath.Join(w.dir, "data")
	must(t, RequestNow(dataDir))
	if _, err := os.Stat(filepath.Join(dataDir, "update", TriggerFile)); err != nil {
		t.Fatal("trigger file not written")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
