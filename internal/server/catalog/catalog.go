// Package catalog keeps the server's release table in step with what the project
// publishes (ADR-0006). It reads the release list of a GitHub-style API, fetches the
// manifest.json each release ships, and stores version, download URLs, checksums
// and signatures. It never downloads a binary and never signs anything: the box
// verifies every download against the public key compiled into it. Which version a
// channel points at stays an operator's decision in the console.
package catalog

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
)

// Manifest is what tools/manifest writes and a release ships as manifest.json.
type Manifest struct {
	Version         string         `json:"version"`
	MinAgentVersion string         `json:"min_agent_version,omitempty"`
	Files           []ManifestFile `json:"files"`
}

// ManifestFile is one built binary.
type ManifestFile struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

// Status is what the console shows about the catalog.
type Status struct {
	URL       string    `json:"url"`
	LastCheck time.Time `json:"lastCheck"`
	LastError string    `json:"lastError"`
	LastAdded []string  `json:"lastAdded"`
}

// Client syncs one catalog URL into one store.
type Client struct {
	URL   string
	HTTP  *http.Client
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time

	mu sync.Mutex
	st Status
}

// New returns a client for a GitHub-style releases URL.
func New(url string, st *store.Store, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{URL: url, HTTP: &http.Client{Timeout: 30 * time.Second}, Store: st, Log: log, Now: time.Now, st: Status{URL: url, LastAdded: []string{}}}
}

// Status returns what the last sync did.
func (c *Client) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.st
	s.LastAdded = append([]string{}, c.st.LastAdded...)
	return s
}

// Run syncs shortly after start and then every interval, until ctx ends.
func (c *Client) Run(ctx context.Context, every time.Duration) {
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if added, err := c.Sync(ctx); err != nil {
			c.Log.Warn("release catalog", "url", c.URL, "err", err)
		} else if len(added) > 0 {
			c.Log.Info("release catalog", "added", added)
		}
		t.Reset(every)
	}
}

// release is the slice of a GitHub release the catalog needs.
type release struct {
	TagName string `json:"tag_name"`
	Draft   bool   `json:"draft"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// Sync fetches the release list and stores every release not yet known. It returns
// the versions it added.
func (c *Client) Sync(ctx context.Context) (added []string, err error) {
	now := c.Now()
	defer func() {
		c.mu.Lock()
		c.st.LastCheck = now
		c.st.LastError = ""
		if err != nil {
			c.st.LastError = err.Error()
		}
		if len(added) > 0 {
			c.st.LastAdded = added
		}
		c.mu.Unlock()
	}()
	var rels []release
	if err := c.getJSON(ctx, c.URL, 4<<20, &rels); err != nil {
		return nil, err
	}
	known, err := c.Store.Releases(ctx)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, r := range known {
		have[r.Version] = true
	}
	for _, r := range rels {
		v := strings.TrimPrefix(r.TagName, "v")
		if r.Draft || v == "" || have[v] {
			continue
		}
		if _, err := version.Parse(v); err != nil {
			continue // not one of ours
		}
		var manifestURL string
		for _, a := range r.Assets {
			if a.Name == "manifest.json" {
				manifestURL = a.URL
			}
		}
		if manifestURL == "" {
			continue // released without the pipeline, nothing a box could verify
		}
		var m Manifest
		if err := c.getJSON(ctx, manifestURL, 1<<20, &m); err != nil {
			return added, fmt.Errorf("%s: manifest: %w", r.TagName, err)
		}
		if err := validate(v, m); err != nil {
			c.Log.Warn("release catalog: manifest refused", "version", v, "err", err)
			continue
		}
		for _, f := range m.Files {
			rel := store.Release{Version: v, OS: f.OS, Arch: f.Arch, URL: f.URL, SHA256: strings.ToLower(f.SHA256), Signature: f.Signature, MinAgentVersion: m.MinAgentVersion, CreatedAt: now}
			if err := c.Store.PutRelease(ctx, rel); err != nil {
				return added, err
			}
		}
		_ = c.Store.Audit(ctx, now, "catalog", "release.catalog", v, manifestURL)
		added = append(added, v)
	}
	return added, nil
}

// validate refuses a manifest a box could not use.
func validate(v string, m Manifest) error {
	if strings.TrimPrefix(m.Version, "v") != v {
		return fmt.Errorf("manifest says %q, release is %q", m.Version, v)
	}
	if len(m.Files) == 0 {
		return errors.New("no files")
	}
	for _, f := range m.Files {
		if f.OS != "linux" || (f.Arch != "amd64" && f.Arch != "arm64") {
			return fmt.Errorf("unexpected platform %s/%s", f.OS, f.Arch)
		}
		if !strings.HasPrefix(f.URL, "https://") {
			return fmt.Errorf("%s: url is not https", f.Name)
		}
		if h, err := hex.DecodeString(f.SHA256); err != nil || len(h) != 32 {
			return fmt.Errorf("%s: bad sha256", f.Name)
		}
		if s, err := base64.StdEncoding.DecodeString(f.Signature); err != nil || len(s) < 64 {
			return fmt.Errorf("%s: bad signature", f.Name)
		}
	}
	return nil
}

func (c *Client) getJSON(ctx context.Context, url string, limit int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json, application/json")
	req.Header.Set("User-Agent", "excubra-server/"+version.Version)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(out); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	return nil
}
