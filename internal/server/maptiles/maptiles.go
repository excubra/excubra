// Package maptiles serves the site map's background through this server instead
// of letting the browser fetch it from a foreign host.
//
// Why a proxy and not a link. A tile URL in the page means the console's content
// policy has to name that host as an image source, and every operator's browser
// then tells that host which part of which country is being looked at. Fetching
// the tiles here costs one hop and buys three things: the policy stays at
// `img-src 'self'`, the tile provider learns nothing about our customers, and the
// request can carry the identifying User-Agent that tile services ask for and a
// page in a browser is not allowed to set.
//
// Nothing is fetched unless an operator has set a tile template. Without one the
// map draws country outlines from the binary and talks to nobody.
package maptiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Setting keys.
const (
	SettingTiles       = "map.tiles"       // XYZ template, "" or "off" = no background
	SettingAttribution = "map.attribution" // what the map must say about where it came from
)

// Limits. A tile is small and a map view asks for a few dozen at once; the cache
// makes the second look free and the bucket keeps us from ever hammering a
// provider, however fast an operator drags the map.
const (
	MaxTileBytes = 1 << 20
	FetchTimeout = 15 * time.Second
	CacheFor     = 30 * 24 * time.Hour
	RatePerSec   = 8
	Burst        = 32
	MaxZoom      = 19
	userAgent    = "excubra (EX0 console; https://github.com/excubra/excubra)"
)

// ErrDisabled means no tile template is configured: the map draws outlines only.
var ErrDisabled = errors.New("maptiles: no tile source configured")

// Settings is what the service needs to know, read fresh per request by the caller.
type Settings struct {
	Template    string
	Attribution string
}

// Service fetches, caches and serves tiles.
type Service struct {
	Dir  string // <datadir>/tiles
	HTTP *http.Client
	Now  func() time.Time

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// New returns a service caching under dir.
func New(dir string) *Service {
	return &Service{Dir: dir, HTTP: &http.Client{Timeout: FetchTimeout}, Now: time.Now, tokens: Burst}
}

// Enabled reports whether a template is configured.
func (s Settings) Enabled() bool {
	t := strings.TrimSpace(s.Template)
	return t != "" && t != "off"
}

// URL builds the upstream address for one tile. It refuses anything that is not
// a plain http(s) template with the three placeholders, so a setting can never
// turn this into a general-purpose fetcher for whatever an operator types.
func (s Settings) URL(z, x, y int) (string, error) {
	if !s.Enabled() {
		return "", ErrDisabled
	}
	tmpl := strings.TrimSpace(s.Template)
	if !strings.Contains(tmpl, "{z}") || !strings.Contains(tmpl, "{x}") || !strings.Contains(tmpl, "{y}") {
		return "", errors.New("maptiles: the template needs {z}, {x} and {y}")
	}
	u, err := url.Parse(strings.NewReplacer("{z}", "0", "{x}", "0", "{y}", "0", "{r}", "").Replace(tmpl))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("maptiles: the template must be an http or https address")
	}
	return strings.NewReplacer(
		"{z}", strconv.Itoa(z), "{x}", strconv.Itoa(x), "{y}", strconv.Itoa(y), "{r}", "",
	).Replace(tmpl), nil
}

// Valid reports whether z/x/y name a tile that can exist.
func Valid(z, x, y int) bool {
	if z < 0 || z > MaxZoom {
		return false
	}
	n := 1 << z
	return x >= 0 && x < n && y >= 0 && y < n
}

// Tile returns one tile and its content type, from the cache when possible.
func (s *Service) Tile(ctx context.Context, set Settings, z, x, y int) ([]byte, string, error) {
	if !set.Enabled() {
		return nil, "", ErrDisabled
	}
	if !Valid(z, x, y) {
		return nil, "", fmt.Errorf("maptiles: %d/%d/%d is not a tile", z, x, y)
	}
	upstream, err := set.URL(z, x, y)
	if err != nil {
		return nil, "", err
	}
	path := s.cachePath(set.Template, z, x, y)
	if b, ct, ok := s.fromCache(path); ok {
		return b, ct, nil
	}
	if err := s.wait(ctx); err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream, nil)
	if err != nil {
		return nil, "", err
	}
	// The identification tile services ask for, which a browser cannot send.
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "image/*")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("maptiles: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("maptiles: the tile server answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTileBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("maptiles: %w", err)
	}
	if len(body) > MaxTileBytes {
		return nil, "", errors.New("maptiles: the tile server sent more than a tile")
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "image/") {
		return nil, "", fmt.Errorf("maptiles: the tile server sent %q, which is not an image", ct)
	}
	s.store(path, ct, body)
	return body, ct, nil
}

// cachePath keeps one tree per template, so changing the source does not serve
// the old provider's pictures.
func (s *Service) cachePath(template string, z, x, y int) string {
	sum := sha256.Sum256([]byte(template))
	return filepath.Join(s.Dir, hex.EncodeToString(sum[:6]), strconv.Itoa(z), strconv.Itoa(x), strconv.Itoa(y))
}

func (s *Service) fromCache(path string) ([]byte, string, bool) {
	fi, err := os.Stat(path)
	if err != nil || s.Now().Sub(fi.ModTime()) > CacheFor {
		return nil, "", false
	}
	b, err := os.ReadFile(path) //nolint:gosec // a path this package built from ints and a hash
	if err != nil || len(b) < 2 {
		return nil, "", false
	}
	ct, err := os.ReadFile(path + ".type") //nolint:gosec // same
	if err != nil {
		ct = []byte("image/png")
	}
	return b, string(ct), true
}

func (s *Service) store(path, ct string, body []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	// Write beside and rename, so a crash never leaves half a tile in the cache.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return
	}
	_ = os.WriteFile(path+".type", []byte(ct), 0o600)
}

// wait spends one token, refilling at RatePerSec: however fast an operator drags
// the map, the provider sees a steady trickle.
func (s *Service) wait(ctx context.Context) error {
	s.mu.Lock()
	now := s.Now()
	if !s.last.IsZero() {
		s.tokens = min(float64(Burst), s.tokens+now.Sub(s.last).Seconds()*RatePerSec)
	}
	s.last = now
	if s.tokens >= 1 {
		s.tokens--
		s.mu.Unlock()
		return nil
	}
	gap := time.Duration((1 - s.tokens) / RatePerSec * float64(time.Second))
	s.tokens = 0
	s.mu.Unlock()
	t := time.NewTimer(gap)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Prune deletes cached tiles older than CacheFor. The server's daily retention
// run calls it; a cache nobody empties is a disk that fills up.
//
// The walk and the deletes go through os.Root, so a symlink that appears between
// the two cannot lead a delete out of the cache directory.
func (s *Service) Prune() (int, error) {
	root, err := os.OpenRoot(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	cutoff := s.Now().Add(-CacheFor)
	var n int
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a tile we cannot stat is one we skip
		}
		fi, err := d.Info()
		if err != nil || fi.ModTime().After(cutoff) {
			return nil //nolint:nilerr // same
		}
		if root.Remove(path) == nil {
			n++
		}
		return nil
	})
	return n, err
}
