// Package update is the signed self-update of ADR-0006: download, verify the
// SHA-256 and the release signature, trial-run the new binary, swap atomically,
// restart, and roll back on its own if the new build does not confirm health.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/sig"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// Limits and timings.
const (
	MaxBinarySize  = 64 << 20
	DownloadTime   = 5 * time.Minute
	TrialTime      = 60 * time.Second
	ConfirmWithin  = 5 * time.Minute // a restarted build must heartbeat within this window
	pendingFile    = "pending"
	rolledBackFile = "rolled-back"
	newSuffix      = ".new"
	prevSuffix     = ".prev"
)

// ErrRestart tells the caller the binary was swapped: exit with code 75 so systemd
// starts the new one.
var ErrRestart = errors.New("update: binary replaced, restart required")

// Pending records an update whose health is not confirmed yet.
type Pending struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

// Updater performs updates for the running binary.
type Updater struct {
	Dir    string // <statedir>/update
	Binary string // the running binary; resolved from os.Executable when empty
	Client *http.Client
	Log    *slog.Logger
	Now    func() time.Time
	// Verify checks blob and base64 signature; defaults to the embedded release key.
	Verify func(blob []byte, signatureB64 string) error
	// Trial runs the candidate binary once; defaults to `<candidate> agent selftest`.
	Trial func(ctx context.Context, candidate string) error
	// StateDir is passed to the default trial run.
	StateDir string
}

// New returns an updater with the production defaults.
func New(stateDir string, log *slog.Logger) (*Updater, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("update: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if log == nil {
		log = slog.Default()
	}
	u := &Updater{
		Dir:      filepath.Join(stateDir, "update"),
		Binary:   exe,
		Client:   &http.Client{Timeout: DownloadTime},
		Log:      log,
		Now:      time.Now,
		Verify:   sig.Verify,
		StateDir: stateDir,
	}
	u.Trial = u.defaultTrial
	if err := os.MkdirAll(u.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("update: %w", err)
	}
	return u, nil
}

func (u *Updater) defaultTrial(ctx context.Context, candidate string) error {
	ctx, cancel := context.WithTimeout(ctx, TrialTime)
	defer cancel()
	cmd := exec.CommandContext(ctx, candidate, "agent", "selftest", "--state-dir", u.StateDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("selftest failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply installs info if it is newer than the running version. It returns
// ErrRestart after a successful swap, nil when there is nothing to do, and any
// other error when the update was refused or failed (the running binary is
// untouched in that case).
func (u *Updater) Apply(ctx context.Context, info wire.UpdateInfo) error {
	cur := version.Current()
	target, err := version.Parse(info.Version)
	if err != nil {
		return fmt.Errorf("update: bad version %q in metadata", info.Version)
	}
	if !newer(target, cur) {
		if target == cur {
			return nil
		}
		return fmt.Errorf("update: refusing downgrade from %s to %s", cur, target)
	}
	if !strings.HasPrefix(info.URL, "https://") {
		return errors.New("update: download url must be https")
	}
	if u.Verify == nil {
		return sig.ErrNoKey
	}
	u.Log.Info("update: downloading", "version", info.Version, "url", info.URL)
	blob, err := u.download(ctx, info.URL)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(blob)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(info.SHA256)) {
		return errors.New("update: sha256 mismatch")
	}
	if err := u.Verify(blob, info.Signature); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	candidate := u.Binary + newSuffix
	if err := writeExecutable(candidate, blob); err != nil {
		return err
	}
	if err := u.Trial(ctx, candidate); err != nil {
		_ = os.Remove(candidate)
		return fmt.Errorf("update: candidate %s rejected: %w", info.Version, err)
	}
	if err := u.swap(candidate); err != nil {
		_ = os.Remove(candidate)
		return err
	}
	p := Pending{From: version.Version, To: info.Version, At: u.Now()}
	if err := writeJSON(filepath.Join(u.Dir, pendingFile), p); err != nil {
		return err
	}
	u.Log.Info("update: installed, restarting", "from", p.From, "to", p.To)
	return ErrRestart
}

func (u *Updater) download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, DownloadTime)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("update: %w", err)
	}
	req.Header.Set("User-Agent", "excubra-agent/"+version.Version)
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: download: HTTP %d", resp.StatusCode)
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, MaxBinarySize+1))
	if err != nil {
		return nil, fmt.Errorf("update: download: %w", err)
	}
	if len(blob) > MaxBinarySize {
		return nil, errors.New("update: download exceeds the size limit")
	}
	if len(blob) < 1<<20 {
		return nil, errors.New("update: download is too small to be the agent")
	}
	return blob, nil
}

// swap moves the running binary aside and the candidate into place, fsyncing the
// directory so a power cut cannot leave the path empty.
func (u *Updater) swap(candidate string) error {
	prev := u.Binary + prevSuffix
	_ = os.Remove(prev)
	if err := os.Rename(u.Binary, prev); err != nil {
		return fmt.Errorf("update: moving current binary aside: %w", err)
	}
	if err := os.Rename(candidate, u.Binary); err != nil {
		// put the old one back; the rename that just worked works again
		_ = os.Rename(prev, u.Binary)
		return fmt.Errorf("update: installing candidate: %w", err)
	}
	syncDir(filepath.Dir(u.Binary))
	return nil
}

// Pending returns the unconfirmed update, if any.
func (u *Updater) Pending() (Pending, bool) {
	var p Pending
	b, err := os.ReadFile(filepath.Join(u.Dir, pendingFile))
	if err != nil || json.Unmarshal(b, &p) != nil {
		return Pending{}, false
	}
	return p, true
}

// Confirm marks the running build healthy: the pending marker goes, the previous
// binary stays for a manual rollback.
func (u *Updater) Confirm() {
	if p, ok := u.Pending(); ok {
		u.Log.Info("update: confirmed healthy", "version", p.To)
	}
	_ = os.Remove(filepath.Join(u.Dir, pendingFile))
}

// RollbackIfStale restores the previous binary when an update was never confirmed
// within ConfirmWithin. It returns ErrRestart when it rolled back.
func (u *Updater) RollbackIfStale() error {
	p, ok := u.Pending()
	if !ok || u.Now().Sub(p.At) < ConfirmWithin {
		return nil
	}
	return u.Rollback(p)
}

// Rollback puts the previous binary back and records what happened.
func (u *Updater) Rollback(p Pending) error {
	prev := u.Binary + prevSuffix
	if _, err := os.Stat(prev); err != nil {
		_ = os.Remove(filepath.Join(u.Dir, pendingFile))
		return fmt.Errorf("update: cannot roll back, no previous binary: %w", err)
	}
	if err := os.Rename(prev, u.Binary); err != nil {
		return fmt.Errorf("update: rollback: %w", err)
	}
	syncDir(filepath.Dir(u.Binary))
	_ = os.Remove(filepath.Join(u.Dir, pendingFile))
	_ = writeJSON(filepath.Join(u.Dir, rolledBackFile), p)
	u.Log.Warn("update: rolled back", "failed_version", p.To, "restored", p.From)
	return ErrRestart
}

// RolledBack reports (once) that a previous run rolled an update back, so the
// heartbeat can tell the server.
func (u *Updater) RolledBack() (Pending, bool) {
	var p Pending
	path := filepath.Join(u.Dir, rolledBackFile)
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &p) != nil {
		return Pending{}, false
	}
	_ = os.Remove(path)
	return p, true
}

func newer(a, b version.Semver) bool {
	if a.Major != b.Major {
		return a.Major > b.Major
	}
	if a.Minor != b.Minor {
		return a.Minor > b.Minor
	}
	return a.Patch > b.Patch
}

func writeExecutable(path string, blob []byte) error {
	tmp := path + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		return fmt.Errorf("update: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("update: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".tmp", b, 0o600); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	return nil
}

func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
