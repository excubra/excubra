// Package store is the persistence layer (ADR-0005): one SQLite file for master
// data and current state, one file per tenant and UTC day for events, deliveries
// and check rollups. Retention is deleting day files; backup is copying them.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (ADR-0008)
)

//go:embed migrations/main/*.sql migrations/day/*.sql
var migrations embed.FS

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("store: not found")

// Store owns main.db and the day files under dir.
type Store struct {
	dir  string
	main *sql.DB

	mu   sync.Mutex
	days map[string]*sql.DB // "<tenant>/<day>"
}

// Open opens (or creates) the store under dir and applies migrations.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	ctx := context.Background() // Open has no caller context; migrations are bounded and local
	db, err := openDB(ctx, filepath.Join(dir, "main.db"))
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, db, "migrations/main"); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{dir: dir, main: db, days: map[string]*sql.DB{}}, nil
}

// Dir returns the data directory.
func (s *Store) Dir() string { return s.dir }

// Close closes every open database.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	for k, db := range s.days {
		if err := db.Close(); err != nil && first == nil {
			first = err
		}
		delete(s.days, k)
	}
	if err := s.main.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

// openDB opens one SQLite file with the settings from ADR-0005. One connection:
// SQLite serialises writers anyway and this removes SQLITE_BUSY from the picture.
func openDB(ctx context.Context, path string) (*sql.DB, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	return db, nil
}

var migrationName = regexp.MustCompile(`^(\d{4})_.*\.sql$`)

// migrate applies the numbered SQL files of a directory in order, tracked in
// schema_version. Each file runs in one transaction.
func migrate(ctx context.Context, db *sql.DB, dir string) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	entries, err := fs.ReadDir(migrations, dir)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if migrationName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var v int
		if _, err := fmt.Sscanf(name, "%04d_", &v); err != nil {
			return fmt.Errorf("store: migration name %q: %w", name, err)
		}
		var applied int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_version WHERE version = ?`, v).Scan(&applied); err != nil {
			return fmt.Errorf("store: %w", err)
		}
		if applied > 0 {
			continue
		}
		body, err := migrations.ReadFile(dir + "/" + name)
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`, v, ts(time.Now())); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: %w", err)
		}
	}
	return nil
}

// DayOf returns the UTC day key of t: "2026-09-05".
func DayOf(t time.Time) string { return t.UTC().Format("2006-01-02") }

// day returns the database for a tenant and day, creating it on first use.
func (s *Store) day(tenantID string, day string) (*sql.DB, error) {
	if !validID(tenantID) || !validDay(day) {
		return nil, fmt.Errorf("store: bad tenant %q or day %q", tenantID, day)
	}
	key := tenantID + "/" + day
	s.mu.Lock()
	defer s.mu.Unlock()
	if db, ok := s.days[key]; ok {
		return db, nil
	}
	dir := filepath.Join(s.dir, "tenants", tenantID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	ctx := context.Background()
	db, err := openDB(ctx, filepath.Join(dir, day+".db"))
	if err != nil {
		return nil, err
	}
	if err := migrate(ctx, db, "migrations/day"); err != nil {
		_ = db.Close()
		return nil, err
	}
	s.days[key] = db
	return db, nil
}

// dayIfExists returns the database for a day only if its file exists (reads never
// create files).
func (s *Store) dayIfExists(tenantID, day string) (*sql.DB, error) {
	if !validID(tenantID) || !validDay(day) {
		return nil, fmt.Errorf("store: bad tenant %q or day %q", tenantID, day)
	}
	s.mu.Lock()
	db, ok := s.days[tenantID+"/"+day]
	s.mu.Unlock()
	if ok {
		return db, nil
	}
	if _, err := os.Stat(filepath.Join(s.dir, "tenants", tenantID, day+".db")); err != nil {
		return nil, nil //nolint:nilnil // "no such day" is not an error
	}
	return s.day(tenantID, day)
}

// Days lists the existing day keys of a tenant, oldest first.
func (s *Store) Days(tenantID string) ([]string, error) {
	if !validID(tenantID) {
		return nil, fmt.Errorf("store: bad tenant %q", tenantID)
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "tenants", tenantID))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	var days []string
	for _, e := range entries {
		if name, ok := strings.CutSuffix(e.Name(), ".db"); ok && validDay(name) {
			days = append(days, name)
		}
	}
	sort.Strings(days)
	return days, nil
}

// Prune deletes day files older than keep for every tenant and returns their
// paths. This is the whole retention mechanism.
func (s *Store) Prune(keep time.Duration, now time.Time) ([]string, error) {
	cutoff := DayOf(now.Add(-keep))
	tenants, err := os.ReadDir(filepath.Join(s.dir, "tenants"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	var removed []string
	for _, t := range tenants {
		if !t.IsDir() {
			continue
		}
		days, err := s.Days(t.Name())
		if err != nil {
			return removed, err
		}
		for _, d := range days {
			if d >= cutoff {
				continue
			}
			key := t.Name() + "/" + d
			s.mu.Lock()
			if db, ok := s.days[key]; ok {
				_ = db.Close()
				delete(s.days, key)
			}
			s.mu.Unlock()
			base := filepath.Join(s.dir, "tenants", t.Name(), d+".db") // t.Name() passed validID in Days, d passed validDay
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if err := os.Remove(base + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) { //nolint:gosec // see above
					return removed, fmt.Errorf("store: %w", err)
				}
			}
			removed = append(removed, base)
		}
	}
	return removed, nil
}

// Backup writes a consistent snapshot of main.db into dir (VACUUM INTO) and copies
// every day file older than today plus the PKI directory. Today's day files are
// still being written and are left to the next run.
func (s *Store) Backup(ctx context.Context, dir string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	target := filepath.Join(dir, "main.db")
	_ = os.Remove(target)
	if _, err := s.main.ExecContext(ctx, `VACUUM INTO ?`, target); err != nil {
		return fmt.Errorf("store: backup main.db: %w", err)
	}
	today := DayOf(now)
	tenants, err := os.ReadDir(filepath.Join(s.dir, "tenants"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: %w", err)
	}
	for _, t := range tenants {
		days, err := s.Days(t.Name())
		if err != nil {
			return err
		}
		for _, d := range days {
			if d >= today {
				continue
			}
			db, err := s.day(t.Name(), d)
			if err != nil {
				return err
			}
			dst := filepath.Join(dir, "tenants", t.Name())
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return fmt.Errorf("store: %w", err)
			}
			out := filepath.Join(dst, d+".db")
			if _, err := os.Stat(out); err == nil {
				continue // already backed up; past days never change
			}
			if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, out); err != nil {
				return fmt.Errorf("store: backup %s/%s: %w", t.Name(), d, err)
			}
		}
	}
	return copyDir(filepath.Join(s.dir, "ca"), filepath.Join(dir, "ca"))
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		info, _ := e.Info()
		mode := os.FileMode(0o600)
		if info != nil {
			mode = info.Mode().Perm()
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, mode); err != nil { //nolint:gosec // dst is the operator's backup dir, names come from ReadDir
			return fmt.Errorf("store: %w", err)
		}
	}
	return nil
}

// ---- helpers ------------------------------------------------------------------

var (
	idRe  = regexp.MustCompile(`^[a-z]+_[a-z0-9-]{1,40}$`)
	dayRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

func validID(id string) bool { return idRe.MatchString(id) }
func validDay(d string) bool { return dayRe.MatchString(d) }

// ts formats a time for storage; zero times become "".
func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// tsp formats an optional time; nil becomes NULL.
func tsp(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return ts(*t)
}

// parseTS parses a stored time; "" becomes the zero time.
func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// parseTSP parses an optional stored time.
func parseTSP(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := parseTS(s.String)
	return &t
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// wrap turns sql.ErrNoRows into ErrNotFound and prefixes everything else.
func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("store: %s: %w", op, err)
}
