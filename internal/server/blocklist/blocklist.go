// Package blocklist assembles the domains the DNS sensor watches for (ADR-0020):
// malware distribution and command-and-control domains from abuse.ch (URLhaus
// and ThreatFox), plus what the operator adds by hand. Refreshed daily, kept in
// the store, served to the boxes as one domain per line with a version they can
// ask for.
package blocklist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/server/store"
)

// Sources and settings.
const (
	DefaultURLhaus   = "https://urlhaus.abuse.ch/downloads/hostfile/"
	DefaultThreatFox = "https://threatfox.abuse.ch/export/csv/domains/recent/"
	// SettingExtra holds the operator's own domains, one per line.
	SettingExtra = "dns.block_extra"
	Fresh        = 24 * time.Hour
	maxBody      = 16 << 20
	maxDomains   = 200000
)

// Service keeps the list and serves it.
type Service struct {
	URLhaus   string
	ThreatFox string
	HTTP      *http.Client
	Store     *store.Store
	Log       *slog.Logger
	Now       func() time.Time

	mu        sync.Mutex
	domains   map[string]string // domain → source
	body      []byte
	version   string
	fetchedAt time.Time
	sources   map[string]int // how many each source contributed
}

// New returns a service with the list restored from the store.
func New(st *store.Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{URLhaus: DefaultURLhaus, ThreatFox: DefaultThreatFox, HTTP: &http.Client{Timeout: 60 * time.Second}, Store: st, Log: log, Now: time.Now, domains: map[string]string{}, sources: map[string]int{}}
	if st != nil {
		if rows, at, err := st.Blocklist(context.Background()); err == nil && len(rows) > 0 {
			for _, r := range rows {
				s.domains[r.Domain] = r.Source
			}
			s.fetchedAt = at
			s.rebuild()
		}
	}
	return s
}

// Version identifies the list the boxes should have ("" until there is one).
func (s *Service) Version() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// Body returns the list, one domain per line, with its version.
func (s *Service) Body() ([]byte, string) {
	if s == nil {
		return nil, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.body, s.version
}

// Status describes the list for the console.
type Status struct {
	Version   string         `json:"version"`
	Domains   int            `json:"domains"`
	FetchedAt time.Time      `json:"fetchedAt"`
	Sources   map[string]int `json:"sources"`
}

// Status reports size, age and the share of every source.
func (s *Service) Status() Status {
	if s == nil {
		return Status{Sources: map[string]int{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	src := make(map[string]int, len(s.sources))
	for k, v := range s.sources {
		src[k] = v
	}
	return Status{Version: s.version, Domains: len(s.domains), FetchedAt: s.fetchedAt, Sources: src}
}

// Contains reports whether a domain or one of its parents is listed.
func (s *Service) Contains(domain string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	labels := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	for i := 0; i+1 < len(labels); i++ {
		d := strings.Join(labels[i:], ".")
		if src, ok := s.domains[d]; ok {
			return src, true
		}
	}
	return "", false
}

// Refresh fetches the sources when the list is a day old (or on demand) and
// folds the operator's own domains in; it returns whether the list changed.
func (s *Service) Refresh(ctx context.Context, force bool) (bool, error) {
	s.mu.Lock()
	stale := s.Now().Sub(s.fetchedAt) > Fresh
	s.mu.Unlock()
	if !stale && !force {
		return s.applyExtra(ctx), nil
	}
	fetched := map[string]string{}
	var errs []string
	if s.URLhaus != "" {
		if body, err := s.get(ctx, s.URLhaus); err != nil {
			errs = append(errs, "urlhaus: "+err.Error())
		} else {
			for _, d := range parseHosts(body) {
				fetched[d] = "urlhaus"
			}
		}
	}
	if s.ThreatFox != "" {
		if body, err := s.get(ctx, s.ThreatFox); err != nil {
			errs = append(errs, "threatfox: "+err.Error())
		} else {
			for _, d := range parseThreatFox(body) {
				if _, ok := fetched[d]; !ok {
					fetched[d] = "threatfox"
				}
			}
		}
	}
	if len(fetched) == 0 {
		return false, fmt.Errorf("no source answered: %s", strings.Join(errs, "; "))
	}
	if len(errs) > 0 {
		s.Log.Warn("blocklist: a source failed", "err", strings.Join(errs, "; "))
	}
	for _, d := range s.extra(ctx) {
		fetched[d] = "extra"
	}
	now := s.Now()
	s.mu.Lock()
	old := s.version
	s.domains, s.fetchedAt = fetched, now
	s.rebuild()
	changed := s.version != old
	rows := make([]store.BlockedDomain, 0, len(fetched))
	for d, src := range fetched {
		rows = append(rows, store.BlockedDomain{Domain: d, Source: src})
	}
	s.mu.Unlock()
	if s.Store != nil {
		if err := s.Store.SetBlocklist(ctx, rows, now); err != nil {
			s.Log.Error("blocklist: store", "err", err)
		}
	}
	s.Log.Info("blocklist: refreshed", "domains", len(fetched), "version", s.Version())
	return changed, nil
}

// applyExtra folds a changed extra list into the current one without a fetch.
func (s *Service) applyExtra(ctx context.Context) bool {
	extra := s.extra(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]bool{}
	for _, d := range extra {
		want[d] = true
	}
	changed := false
	for d, src := range s.domains {
		if src == "extra" && !want[d] {
			delete(s.domains, d)
			changed = true
		}
	}
	for d := range want {
		if _, ok := s.domains[d]; !ok {
			s.domains[d] = "extra"
			changed = true
		}
	}
	if changed {
		s.rebuild()
	}
	return changed
}

func (s *Service) extra(ctx context.Context) []string {
	if s.Store == nil {
		return nil
	}
	v, err := s.Store.Setting(ctx, SettingExtra)
	if err != nil {
		return nil
	}
	return parseHosts([]byte(v))
}

// rebuild derives body and version from the domains (caller holds the lock).
func (s *Service) rebuild() {
	list := make([]string, 0, len(s.domains))
	s.sources = map[string]int{}
	for d, src := range s.domains {
		list = append(list, d)
		s.sources[src]++
	}
	sort.Strings(list)
	if len(list) > maxDomains {
		list = list[:maxDomains]
	}
	var b bytes.Buffer
	for _, d := range list {
		b.WriteString(d)
		b.WriteByte('\n')
	}
	s.body = b.Bytes()
	if len(list) == 0 {
		s.version = ""
		return
	}
	sum := sha256.Sum256(s.body)
	s.version = hex.EncodeToString(sum[:8])
}

func (s *Service) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "excubra (EX0 DNS sensor blocklist)")
	res, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, maxBody))
}

// parseHosts reads domains from a hosts file or a plain list: one per line,
// comments and addresses ignored.
func parseHosts(b []byte) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if d, ok := cleanDomain(f[len(f)-1]); ok && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// parseThreatFox reads the domains of ThreatFox's CSV export: entries of type
// domain, and the hosts of entries of type url.
func parseThreatFox(b []byte) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rd := csv.NewReader(strings.NewReader(line))
		rd.TrimLeadingSpace, rd.LazyQuotes = true, true // the export separates with ", "
		rec, err := rd.Read()
		if err != nil || len(rec) < 4 {
			continue
		}
		value, kind := strings.TrimSpace(rec[2]), strings.TrimSpace(rec[3])
		var d string
		switch kind {
		case "domain":
			d = value
		case "url":
			if u, err := url.Parse(value); err == nil {
				d = u.Hostname()
			}
		default:
			continue
		}
		if d, ok := cleanDomain(d); ok && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// cleanDomain lower-cases and validates a domain: no addresses, no single labels,
// no localhost, only hostname characters.
func cleanDomain(d string) (string, bool) {
	d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
	if i := strings.IndexByte(d, ':'); i >= 0 {
		d = d[:i]
	}
	if d == "" || d == "localhost" || d == "localhost.localdomain" || !strings.Contains(d, ".") || len(d) > 253 {
		return "", false
	}
	digitsOnly := true
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z', r == '-', r == '_':
			digitsOnly = false
		case r >= '0' && r <= '9', r == '.':
		default:
			return "", false
		}
	}
	if digitsOnly { // an address, not a name
		return "", false
	}
	return d, true
}

// Run refreshes every interval.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	if _, err := s.Refresh(ctx, false); err != nil {
		s.Log.Warn("blocklist", "err", err)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := s.Refresh(ctx, false); err != nil {
			s.Log.Warn("blocklist", "err", err)
		}
	}
}
