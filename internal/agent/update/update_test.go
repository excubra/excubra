package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

type fixture struct {
	u      *Updater
	srv    *httptest.Server
	blob   []byte
	binary string
	trials int
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{binary: filepath.Join(dir, "bin", "excubra"), now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)}
	if err := os.MkdirAll(filepath.Dir(f.binary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.binary, []byte("OLD BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.blob = bytes.Repeat([]byte("NEW BINARY "), 200000) // > 1 MiB
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/excubra" {
			_, _ = w.Write(f.blob)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.srv.Close)
	f.u = &Updater{
		Dir:    filepath.Join(dir, "update"),
		Binary: f.binary,
		Client: f.srv.Client(),
		Log:    slog.Default(),
		Now:    func() time.Time { return f.now },
		Verify: func(_ []byte, sigB64 string) error {
			if sigB64 != "good" {
				return errors.New("bad signature")
			}
			return nil
		},
		Trial: func(_ context.Context, candidate string) error {
			f.trials++
			if _, err := os.Stat(candidate); err != nil {
				return err
			}
			return nil
		},
	}
	if err := os.MkdirAll(f.u.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) info(v string) wire.UpdateInfo {
	sum := sha256.Sum256(f.blob)
	return wire.UpdateInfo{Version: v, URL: f.srv.URL + "/excubra", SHA256: hex.EncodeToString(sum[:]), Signature: "good"}
}

func withVersion(t *testing.T, v string) {
	t.Helper()
	old := version.Version
	version.Version = v
	t.Cleanup(func() { version.Version = old })
}

func TestApplyHappyPath(t *testing.T) {
	withVersion(t, "0.1.0")
	f := newFixture(t)
	err := f.u.Apply(context.Background(), f.info("0.2.0"))
	if !errors.Is(err, ErrRestart) {
		t.Fatalf("apply: %v", err)
	}
	got, _ := os.ReadFile(f.binary)
	if !bytes.Equal(got, f.blob) {
		t.Fatal("binary not replaced")
	}
	prev, _ := os.ReadFile(f.binary + prevSuffix)
	if string(prev) != "OLD BINARY" {
		t.Fatal("previous binary not kept")
	}
	if st, _ := os.Stat(f.binary); st.Mode().Perm()&0o111 == 0 {
		t.Fatal("new binary not executable")
	}
	p, ok := f.u.Pending()
	if !ok || p.From != "0.1.0" || p.To != "0.2.0" || f.trials != 1 {
		t.Fatalf("pending: %+v ok=%v trials=%d", p, ok, f.trials)
	}
	if _, err := os.Stat(f.binary + newSuffix); !os.IsNotExist(err) {
		t.Fatal("candidate file left behind")
	}
	// the new build confirms: marker gone, previous kept
	f.u.Confirm()
	if _, ok := f.u.Pending(); ok {
		t.Fatal("pending not cleared")
	}
	if _, err := os.Stat(f.binary + prevSuffix); err != nil {
		t.Fatal("previous binary removed on confirm")
	}
}

func TestApplyRefusals(t *testing.T) {
	withVersion(t, "0.2.0")
	f := newFixture(t)
	if err := f.u.Apply(context.Background(), f.info("0.2.0")); err != nil {
		t.Fatalf("same version: %v", err)
	}
	if err := f.u.Apply(context.Background(), f.info("0.1.9")); err == nil {
		t.Fatal("downgrade accepted")
	}
	bad := f.info("0.3.0")
	bad.SHA256 = "00"
	if err := f.u.Apply(context.Background(), bad); err == nil {
		t.Fatal("sha mismatch accepted")
	}
	bad = f.info("0.3.0")
	bad.Signature = "forged"
	if err := f.u.Apply(context.Background(), bad); err == nil {
		t.Fatal("bad signature accepted")
	}
	bad = f.info("0.3.0")
	bad.URL = "http://plain.example/excubra"
	if err := f.u.Apply(context.Background(), bad); err == nil {
		t.Fatal("plain http accepted")
	}
	bad = f.info("0.3.0")
	bad.URL = f.srv.URL + "/missing"
	if err := f.u.Apply(context.Background(), bad); err == nil {
		t.Fatal("404 accepted")
	}
	got, _ := os.ReadFile(f.binary)
	if string(got) != "OLD BINARY" || f.trials != 0 {
		t.Fatalf("binary touched by a refused update (trials=%d)", f.trials)
	}
	if _, ok := f.u.Pending(); ok {
		t.Fatal("pending written for a refused update")
	}
}

func TestTrialFailureLeavesBinaryAlone(t *testing.T) {
	withVersion(t, "0.1.0")
	f := newFixture(t)
	f.u.Trial = func(context.Context, string) error { return errors.New("selftest: cannot load certificate") }
	err := f.u.Apply(context.Background(), f.info("0.2.0"))
	if err == nil || errors.Is(err, ErrRestart) {
		t.Fatalf("trial failure: %v", err)
	}
	got, _ := os.ReadFile(f.binary)
	if string(got) != "OLD BINARY" {
		t.Fatal("binary replaced despite failed trial")
	}
	if _, err := os.Stat(f.binary + newSuffix); !os.IsNotExist(err) {
		t.Fatal("candidate not removed")
	}
}

func TestRollbackWhenNotConfirmed(t *testing.T) {
	withVersion(t, "0.1.0")
	f := newFixture(t)
	if err := f.u.Apply(context.Background(), f.info("0.2.0")); !errors.Is(err, ErrRestart) {
		t.Fatal(err)
	}
	// too early: nothing happens
	f.now = f.now.Add(ConfirmWithin - time.Second)
	if err := f.u.RollbackIfStale(); err != nil {
		t.Fatalf("early rollback: %v", err)
	}
	// the window passed without a confirmation
	f.now = f.now.Add(2 * time.Second)
	if err := f.u.RollbackIfStale(); !errors.Is(err, ErrRestart) {
		t.Fatalf("stale rollback: %v", err)
	}
	got, _ := os.ReadFile(f.binary)
	if string(got) != "OLD BINARY" {
		t.Fatal("old binary not restored")
	}
	if _, ok := f.u.Pending(); ok {
		t.Fatal("pending marker survived the rollback")
	}
	rb, ok := f.u.RolledBack()
	if !ok || rb.To != "0.2.0" {
		t.Fatalf("rolled-back record: %+v %v", rb, ok)
	}
	if _, ok := f.u.RolledBack(); ok {
		t.Fatal("rolled-back record reported twice")
	}
}

func TestNewer(t *testing.T) {
	v := func(s string) version.Semver { x, _ := version.Parse(s); return x }
	if !newer(v("0.2.0"), v("0.1.9")) || !newer(v("1.0.0"), v("0.9.9")) || !newer(v("0.1.1"), v("0.1.0")) {
		t.Fatal("newer false negative")
	}
	if newer(v("0.1.0"), v("0.1.0")) || newer(v("0.1.0"), v("0.2.0")) {
		t.Fatal("newer false positive")
	}
}
