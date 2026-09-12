// Package feed keeps end-of-life and latest-release data for the products the
// scan and the connectors identify (ADR-0018). Source: endoflife.date, one small
// JSON document per product, cached in the store so the version rules work from
// the cache and a feed outage costs nothing but freshness. Nothing about a
// customer leaves the server: the request names a product, never a device.
package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/server/rules"
	"github.com/excubra/excubra/internal/server/store"
)

// DefaultURL is where the products live: <url>/<slug>.json.
const DefaultURL = "https://endoflife.date/api"

// How long a cached product is fresh, and how soon before its end a cycle warns.
const (
	Fresh       = 24 * time.Hour
	EOLSoonDays = 90
)

// Cycle is one release line of a product as the feed lists it.
type Cycle struct {
	Cycle       string `json:"cycle"`
	Latest      string `json:"latest"`
	EOL         any    `json:"eol"` // false, or a date "2026-01-31"
	ReleaseDate string `json:"releaseDate"`
}

// Product is a cached product.
type Product struct {
	Slug      string
	FetchedAt time.Time
	Cycles    []Cycle
}

// slugs maps what a banner or a connector calls a product to the feed's name.
var slugs = map[string]string{
	"nginx": "nginx", "apache": "apache-http-server", "apache httpd": "apache-http-server", "mariadb": "mariadb", "mysql": "mysql",
	"postgresql": "postgresql", "postgres": "postgresql", "fortios": "fortios", "fortigate": "fortios", "proxmox ve": "proxmox-ve", "proxmox": "proxmox-ve",
	"postfix": "postfix", "dovecot": "dovecot", "exim": "exim", "haproxy": "haproxy", "tomcat": "tomcat", "apache tomcat": "tomcat", "redis": "redis",
	"mongodb": "mongodb", "elasticsearch": "elasticsearch", "routeros": "routeros", "mikrotik": "routeros", "opnsense": "opnsense", "truenas": "truenas", //nolint:misspell // RouterOS is the product's name
	"nextcloud": "nextcloud", "gitlab": "gitlab", "zabbix": "zabbix", "grafana": "grafana", "php": "php", "openssl": "openssl", "docker": "docker-engine",
	"windows server": "windows-server", "debian": "debian", "ubuntu": "ubuntu",
}

// Slug names the feed product for a product string, or "" when the feed has none.
func Slug(product string) string {
	return slugs[strings.ToLower(strings.TrimSpace(product))]
}

// Verdict is what the feed says about one version.
type Verdict struct {
	State   string // eol | eol_soon | outdated | current | unknown
	Cycle   string
	Latest  string
	EOLDate string
}

// Assess compares a version with the product's cycles: the cycle is the longest
// cycle name the version starts with; its end date and latest release decide.
func Assess(p *Product, version string, now time.Time) Verdict {
	v := Verdict{State: "unknown"}
	version = strings.TrimLeft(strings.TrimSpace(version), "vV")
	if p == nil || version == "" {
		return v
	}
	var best *Cycle
	for i := range p.Cycles {
		c := p.Cycles[i].Cycle
		if version == c || strings.HasPrefix(version, c+".") || strings.HasPrefix(version, c+"p") {
			if best == nil || len(c) > len(best.Cycle) {
				best = &p.Cycles[i]
			}
		}
	}
	if best == nil {
		return v
	}
	v.Cycle, v.Latest, v.State = best.Cycle, best.Latest, "current"
	if d, ok := best.EOL.(string); ok && d != "" {
		v.EOLDate = d
		if t, err := time.Parse("2006-01-02", d); err == nil {
			switch {
			case !t.After(now):
				v.State = "eol"
				return v
			case t.Sub(now) < EOLSoonDays*24*time.Hour:
				v.State = "eol_soon"
			}
		}
	}
	if v.State == "current" && best.Latest != "" && compareVersions(version, best.Latest) < 0 {
		v.State = "outdated"
	}
	return v
}

// compareVersions compares dotted versions numerically, segment by segment;
// letters and suffixes are ignored ("9.2p1" is 9.2).
func compareVersions(a, b string) int {
	as, bs := segments(a), segments(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func segments(v string) []int {
	var out []int
	cur := ""
	flush := func() {
		if cur != "" {
			n, _ := strconv.Atoi(cur)
			out = append(out, n)
			cur = ""
		}
	}
	for _, r := range v {
		if r >= '0' && r <= '9' {
			cur += string(r)
		} else {
			flush()
			if r != '.' {
				break // a suffix like "p1", "-log", "-MariaDB": stop
			}
		}
	}
	flush()
	return out
}

// Service fetches and caches products and re-evaluates when something changed.
type Service struct {
	URL   string
	HTTP  *http.Client
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	// OnRefresh runs after products changed; the engine re-assesses versions then.
	OnRefresh func(ctx context.Context)

	mu    sync.Mutex
	cache map[string]*Product
	want  map[string]bool
}

// New returns a service with the cache loaded from the store.
func New(st *store.Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{URL: DefaultURL, HTTP: &http.Client{Timeout: 15 * time.Second}, Store: st, Log: log, Now: time.Now, cache: map[string]*Product{}, want: map[string]bool{}}
	if st != nil {
		if feeds, err := st.Feeds(context.Background()); err == nil {
			for _, f := range feeds {
				if p, err := parse(f.Slug, f.Body, f.FetchedAt); err == nil {
					s.cache[f.Slug] = p
				}
			}
		}
	}
	return s
}

func parse(slug string, body []byte, at time.Time) (*Product, error) {
	var cycles []Cycle
	if err := json.Unmarshal(body, &cycles); err != nil {
		return nil, err
	}
	return &Product{Slug: slug, FetchedAt: at, Cycles: cycles}, nil
}

// Lookup returns the cached product, or nil. A product nobody fetched yet is
// remembered as wanted; the loop fetches it.
func (s *Service) Lookup(slug string) *Product {
	if s == nil || slug == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.cache[slug]
	if p == nil || s.Now().Sub(p.FetchedAt) > Fresh {
		s.want[slug] = true
	}
	return p
}

// Put stores a product straight into the cache (tests, imports).
func (s *Service) Put(p *Product) {
	s.mu.Lock()
	s.cache[p.Slug] = p
	delete(s.want, p.Slug)
	s.mu.Unlock()
}

// Refresh fetches every wanted product; it returns how many changed.
func (s *Service) Refresh(ctx context.Context) int {
	s.mu.Lock()
	var slugs []string
	for k := range s.want {
		slugs = append(slugs, k)
	}
	s.mu.Unlock()
	sort.Strings(slugs)
	changed := 0
	for _, slug := range slugs {
		p, err := s.fetch(ctx, slug)
		if err != nil {
			s.Log.Warn("feed", "product", slug, "err", err)
			continue
		}
		s.Put(p)
		if s.Store != nil {
			body, _ := json.Marshal(p.Cycles)
			_ = s.Store.SetFeed(ctx, slug, body, p.FetchedAt)
		}
		changed++
	}
	return changed
}

func (s *Service) fetch(ctx context.Context, slug string) (*Product, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL+"/"+slug+".json", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "excubra (EX0 version rules)")
	res, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 512<<10))
	if err != nil {
		return nil, err
	}
	return parse(slug, body, s.Now())
}

// Run refreshes wanted products every interval and calls OnRefresh when something
// changed.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.Refresh(ctx) > 0 && s.OnRefresh != nil {
			s.OnRefresh(ctx)
		}
	}
}

// Findings judges the versions of a device's services: a release line past its
// end is urgent, one about to end warns, a newer release in the line is a note.
func (s *Service) Findings(services []rules.Service, now time.Time) []rules.Finding {
	var out []rules.Finding
	for _, svc := range services {
		slug := Slug(svc.Product)
		if slug == "" || svc.Version == "" {
			continue
		}
		v := Assess(s.Lookup(slug), svc.Version, now)
		key := fmt.Sprintf("%s/%d", firstNonEmpty(svc.Proto, "tcp"), svc.Port)
		ev := map[string]any{"port": svc.Port, "product": svc.Product, "version": svc.Version, "cycle": v.Cycle, "latest": v.Latest, "eol": v.EOLDate}
		name := svc.Product + " " + svc.Version
		switch v.State {
		case "eol":
			out = append(out, rules.Finding{Rule: "version.eol", Key: key, Severity: rules.High, Title: name + " hat kein Support mehr",
				Detail: fmt.Sprintf("Die Release-Linie %s von %s wird seit %s nicht mehr gepflegt: keine Sicherheitsupdates, bekannte Lücken bleiben offen. Auf eine gepflegte Version wechseln (aktuell %s).", v.Cycle, svc.Product, v.EOLDate, orDash(latestOf(s, slug))), Evidence: ev})
		case "eol_soon":
			out = append(out, rules.Finding{Rule: "version.eol_soon", Key: key, Severity: rules.Medium, Title: name + " verliert bald den Support",
				Detail: fmt.Sprintf("Die Release-Linie %s von %s endet am %s. Das Update auf eine gepflegte Linie einplanen (aktuell %s).", v.Cycle, svc.Product, v.EOLDate, orDash(latestOf(s, slug))), Evidence: ev})
		case "outdated":
			out = append(out, rules.Finding{Rule: "version.outdated", Key: key, Severity: rules.Low, Title: name + ": Update verfügbar",
				Detail: fmt.Sprintf("In der Release-Linie %s ist %s aktuell. Beim nächsten Wartungsfenster nachziehen.", v.Cycle, v.Latest), Evidence: ev})
		}
	}
	return out
}

// latestOf is the newest supported release line's latest version.
func latestOf(s *Service, slug string) string {
	p := s.Lookup(slug)
	if p == nil {
		return ""
	}
	for _, c := range p.Cycles {
		if b, ok := c.EOL.(bool); ok && !b {
			return c.Latest
		}
		if d, ok := c.EOL.(string); ok {
			if t, err := time.Parse("2006-01-02", d); err == nil && t.After(s.Now()) {
				return c.Latest
			}
		}
	}
	return ""
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "–"
	}
	return s
}
