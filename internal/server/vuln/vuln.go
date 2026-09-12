// Package vuln matches the product versions the scan and the connectors identify
// against the public vulnerability databases (ADR-0018 §8): NVD for the upstream
// view, OSV for distribution packages (it knows which fixes Debian and Ubuntu
// backported, so a patched 9.2p1 is not blamed for upstream's CVEs), CISA's KEV
// list for "exploited in the wild". Results are cached in the store and fetched
// only for products a customer actually runs; a query names a product and a
// version, never a customer.
package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/server/rules"
	"github.com/excubra/excubra/internal/server/store"
)

// Defaults and bounds.
const (
	DefaultNVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultOSV = "https://api.osv.dev/v1/query"
	DefaultKEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// SettingNVDKey is the settings key of an NVD API key: without one NVD allows
	// five requests per half minute, with one fifty.
	SettingNVDKey = "vuln.nvd_key"
	Fresh         = 24 * time.Hour
	retryAfter    = 15 * time.Minute
	maxCVEs       = 40 // kept per product version
	maxBody       = 8 << 20
	kevKey        = "kev"
)

// CVE is one known vulnerability of a product version.
type CVE struct {
	ID        string  `json:"id"`
	Score     float64 `json:"score,omitempty"`     // CVSS base score; 0 when nobody scored it
	Exploited bool    `json:"exploited,omitempty"` // on CISA's KEV list
	Summary   string  `json:"summary,omitempty"`
	Fixed     string  `json:"fixed,omitempty"`     // the distribution version that fixes it (OSV)
	Published string  `json:"published,omitempty"` // YYYY-MM-DD
	// Untriaged: the distribution lists it but has not judged it yet ("not yet
	// assigned" in Debian's tracker) and has no fix; nothing to install, only to
	// watch — such findings never rise above medium unless the CVE is exploited.
	Untriaged bool `json:"untriaged,omitempty"`
}

// resultVersion changes whenever the judgement of a result changes (what is
// dropped, what is marked untriaged): cached results of another version are
// fetched again instead of trusted.
const resultVersion = 2

// Result is what the databases say about one product version.
type Result struct {
	Key       string    `json:"key"`
	Product   string    `json:"product"`
	Version   string    `json:"version"`
	FetchedAt time.Time `json:"fetched_at"`
	CVEs      []CVE     `json:"cves"`
	Judged    int       `json:"judged,omitempty"` // resultVersion of the code that built it
}

// Query is one product version to look up. CPEs ask NVD (the upstream view);
// Ecosystem, Package and PkgVersion ask OSV about the distribution's package —
// then only what OSV still lists as unfixed survives.
type Query struct {
	Product    string
	Version    string
	CPEs       []string
	Ecosystem  string
	Package    string
	PkgVersion string
}

// Key identifies the query in the cache.
func (q Query) Key() string {
	if q.Ecosystem != "" {
		return "osv|" + q.Ecosystem + "|" + q.Package + "|" + q.PkgVersion
	}
	return "cpe|" + strings.Join(q.CPEs, ",")
}

// products maps what the scan calls a product to its NVD CPE prefix (vendor:product).
var products = map[string][]string{
	"openssh":    {"a:openbsd:openssh"},
	"dropbear":   {"a:dropbear_ssh_project:dropbear_ssh"},
	"nginx":      {"a:f5:nginx", "a:nginx:nginx"},
	"apache":     {"a:apache:http_server"},
	"lighttpd":   {"a:lighttpd:lighttpd"},
	"exim":       {"a:exim:exim"},
	"postfix":    {"a:postfix:postfix"},
	"dovecot":    {"a:dovecot:dovecot"},
	"proftpd":    {"a:proftpd:proftpd"},
	"vsftpd":     {"a:vsftpd_project:vsftpd"},
	"pure-ftpd":  {"a:pureftpd:pure-ftpd"},
	"mysql":      {"a:oracle:mysql"},
	"mariadb":    {"a:mariadb:mariadb"},
	"postgresql": {"a:postgresql:postgresql"},
	"squid":      {"a:squid-cache:squid"},
	"tomcat":     {"a:apache:tomcat"},
	"jetty":      {"a:eclipse:jetty"},
	"fortios":    {"o:fortinet:fortios"},
	"fortigate":  {"o:fortinet:fortios"},
	"routeros":   {"o:mikrotik:routeros"}, //nolint:misspell // MikroTik's product name
}

var (
	// "9.2p1" → version 9.2, update p1 — how NVD spells OpenSSH.
	opensshVer = regexp.MustCompile(`^(\d+\.\d+)(p\d+)?$`)
	// the distribution's package revision at the end of an OpenSSH banner
	debianRev = regexp.MustCompile(`(?:Debian|Raspbian)-(\S+?deb(\d+)u\d+)\b`)
	ubuntuRev = regexp.MustCompile(`Ubuntu-(\d\S*ubuntu\S*)`)
	versionOK = regexp.MustCompile(`^[\w.-]+$`)
)

// ubuntuRelease maps the OpenSSH version a release ships to that release; the
// banner names the revision but not the release.
var ubuntuRelease = map[string]string{"7.6p1": "18.04:LTS", "8.2p1": "20.04:LTS", "8.9p1": "22.04:LTS", "9.6p1": "24.04:LTS", "9.7p1": "24.10", "9.9p1": "25.04", "10.0p2": "25.10"}

// Identify turns a service into a query, or reports that nothing can be looked up
// (no version, or a product the databases do not name that way).
func Identify(sv rules.Service) (Query, bool) {
	name := strings.ToLower(strings.TrimSpace(sv.Product))
	ver := strings.TrimPrefix(strings.TrimSpace(sv.Version), "v") // FortiOS says v7.4.12
	prefixes, ok := products[name]
	if !ok || ver == "" || !versionOK.MatchString(ver) {
		return Query{}, false
	}
	q := Query{Product: sv.Product, Version: ver}
	cpeVer, upd := ver, "*"
	if name == "openssh" {
		if m := opensshVer.FindStringSubmatch(ver); m != nil {
			cpeVer = m[1]
			if m[2] != "" {
				upd = m[2]
			}
		}
		// a distribution's OpenSSH: ask OSV about the package, with the backports it carries
		if m := debianRev.FindStringSubmatch(sv.Banner); m != nil {
			q.Ecosystem, q.Package, q.PkgVersion = "Debian:"+m[2], "openssh", "1:"+ver+"-"+m[1]
		} else if m := ubuntuRev.FindStringSubmatch(sv.Banner); m != nil {
			if rel, ok := ubuntuRelease[ver]; ok {
				q.Ecosystem, q.Package, q.PkgVersion = "Ubuntu:"+rel, "openssh", "1:"+ver+"-"+m[1]
			}
		}
	}
	for _, p := range prefixes {
		q.CPEs = append(q.CPEs, fmt.Sprintf("cpe:2.3:%s:%s:%s:*:*:*:*:*:*", p, cpeVer, upd))
	}
	return q, true
}

// Service looks queries up, caches the answers and re-evaluates when they change.
type Service struct {
	NVD   string
	OSV   string
	KEV   string
	HTTP  *http.Client
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	// OnRefresh runs after results changed; the engine re-assesses devices then.
	OnRefresh func(ctx context.Context)

	mu      sync.Mutex
	cache   map[string]*Result
	want    map[string]Query
	failed  map[string]time.Time // last failure per key, for the retry pause
	kev     map[string]bool
	kevAt   time.Time
	lastNVD time.Time
	gapNVD  func(keyed bool) time.Duration // the pause between NVD requests; tests shorten it
}

// New returns a service with the cache loaded from the store.
func New(st *store.Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{NVD: DefaultNVD, OSV: DefaultOSV, KEV: DefaultKEV, HTTP: &http.Client{Timeout: 60 * time.Second}, Store: st, Log: log, Now: time.Now,
		cache: map[string]*Result{}, want: map[string]Query{}, failed: map[string]time.Time{}, kev: map[string]bool{}, gapNVD: nvdGap}
	if st != nil {
		if rows, err := st.Vulns(context.Background()); err == nil {
			for _, r := range rows {
				if r.Key == kevKey {
					var ids []string
					if json.Unmarshal(r.Body, &ids) == nil {
						s.kev = set(ids)
						s.kevAt = r.FetchedAt
					}
					continue
				}
				var res Result
				if json.Unmarshal(r.Body, &res) == nil && res.Judged == resultVersion {
					res.Key, res.FetchedAt = r.Key, r.FetchedAt
					s.cache[r.Key] = &res
				}
			}
		}
	}
	return s
}

func set(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

// lookup returns the cached result or nil; an unknown or stale query is
// remembered as wanted and the loop fetches it.
func (s *Service) lookup(q Query) *Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := q.Key()
	r := s.cache[key]
	if r == nil || s.Now().Sub(r.FetchedAt) > Fresh {
		s.want[key] = q
	}
	return r
}

// Put stores a result straight into the cache (tests, imports).
func (s *Service) Put(r *Result) {
	s.mu.Lock()
	s.cache[r.Key] = r
	delete(s.want, r.Key)
	s.mu.Unlock()
}

// Refresh fetches the KEV list when it is a day old and every wanted query; it
// returns how many results changed.
func (s *Service) Refresh(ctx context.Context) int {
	now := s.Now()
	changed := 0
	s.mu.Lock()
	kevStale := now.Sub(s.kevAt) > Fresh
	var keys []string
	for k, last := range s.failed {
		if now.Sub(last) > retryAfter {
			delete(s.failed, k)
		}
	}
	for k := range s.want {
		if _, paused := s.failed[k]; !paused {
			keys = append(keys, k)
		}
	}
	s.mu.Unlock()
	if kevStale && s.KEV != "" {
		if ids, err := s.fetchKEV(ctx); err != nil {
			s.Log.Warn("vuln: kev list", "err", err)
		} else {
			s.mu.Lock()
			s.kev, s.kevAt = set(ids), now
			s.mu.Unlock()
			if s.Store != nil {
				body, _ := json.Marshal(ids)
				_ = s.Store.SetVuln(ctx, kevKey, body, now)
			}
			changed++
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if ctx.Err() != nil {
			return changed
		}
		s.mu.Lock()
		q := s.want[key]
		s.mu.Unlock()
		r, err := s.fetch(ctx, q)
		if err != nil {
			s.Log.Warn("vuln: lookup", "product", q.Product, "version", q.Version, "err", err)
			s.mu.Lock()
			s.failed[key] = s.Now()
			s.mu.Unlock()
			continue
		}
		s.Put(r)
		if s.Store != nil {
			body, _ := json.Marshal(r)
			_ = s.Store.SetVuln(ctx, key, body, r.FetchedAt)
		}
		changed++
	}
	return changed
}

// Run refreshes every interval and calls OnRefresh when something changed.
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

// fetch asks the databases about one query and merges what they say.
func (s *Service) fetch(ctx context.Context, q Query) (*Result, error) {
	upstream := map[string]CVE{}
	for _, cpe := range q.CPEs {
		found, err := s.fetchNVD(ctx, cpe)
		if err != nil {
			return nil, fmt.Errorf("nvd %s: %w", cpe, err)
		}
		for _, c := range found {
			if cur, ok := upstream[c.ID]; !ok || c.Score > cur.Score {
				upstream[c.ID] = c
			}
		}
	}
	var cves []CVE
	if q.Ecosystem != "" {
		// the distribution's view decides: only what it still lists as unfixed counts
		unfixed, err := s.fetchOSV(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("osv: %w", err)
		}
		for id, o := range unfixed {
			c, ok := upstream[id]
			if !ok {
				c = CVE{ID: id, Score: o.Score, Summary: o.Summary}
			}
			c.Fixed, c.Untriaged = o.Fixed, o.Untriaged
			if c.Summary == "" {
				c.Summary = o.Summary
			}
			cves = append(cves, c)
		}
	} else {
		for _, c := range upstream {
			cves = append(cves, c)
		}
	}
	s.mu.Lock()
	for i := range cves {
		if s.kev[cves[i].ID] {
			cves[i].Exploited = true
		}
	}
	s.mu.Unlock()
	sort.Slice(cves, func(i, j int) bool {
		if cves[i].Exploited != cves[j].Exploited {
			return cves[i].Exploited
		}
		if cves[i].Score != cves[j].Score {
			return cves[i].Score > cves[j].Score
		}
		return cves[i].ID > cves[j].ID
	})
	if len(cves) > maxCVEs {
		cves = cves[:maxCVEs]
	}
	if cves == nil {
		cves = []CVE{}
	}
	return &Result{Key: q.Key(), Product: q.Product, Version: q.Version, FetchedAt: s.Now(), CVEs: cves, Judged: resultVersion}, nil
}

// ---- NVD ------------------------------------------------------------------------------

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			VulnStatus   string `json:"vulnStatus"`
			ExploitAdded string `json:"cisaExploitAdd"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics map[string][]struct {
				Type     string `json:"type"`
				CVSSData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdKey reads the API key from the settings, if there is one.
func (s *Service) nvdKey(ctx context.Context) string {
	if s.Store == nil {
		return ""
	}
	v, _ := s.Store.Setting(ctx, SettingNVDKey)
	return strings.TrimSpace(v)
}

// nvdGap is the pause that keeps under NVD's public rate: five requests per
// thirty seconds without a key, fifty with one.
func nvdGap(keyed bool) time.Duration {
	if keyed {
		return 700 * time.Millisecond
	}
	return 6500 * time.Millisecond
}

func (s *Service) throttleNVD(ctx context.Context, keyed bool) error {
	gap := s.gapNVD(keyed)
	s.mu.Lock()
	wait := gap - time.Since(s.lastNVD)
	s.mu.Unlock()
	if wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	s.mu.Lock()
	s.lastNVD = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *Service) fetchNVD(ctx context.Context, cpe string) ([]CVE, error) {
	key := s.nvdKey(ctx)
	if err := s.throttleNVD(ctx, key != ""); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.NVD+"?noRejected&resultsPerPage=2000&cpeName="+cpe, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "excubra (EX0 vulnerability matching)")
	if key != "" {
		req.Header.Set("apiKey", key)
	}
	res, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var body nvdResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(&body); err != nil {
		return nil, err
	}
	out := make([]CVE, 0, len(body.Vulnerabilities))
	for _, v := range body.Vulnerabilities {
		c := v.CVE
		if strings.EqualFold(c.VulnStatus, "Rejected") {
			continue
		}
		cve := CVE{ID: c.ID, Exploited: c.ExploitAdded != ""}
		if len(c.Published) >= 10 {
			cve.Published = c.Published[:10]
		}
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				cve.Summary = firstSentence(d.Value)
				break
			}
		}
		for _, name := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if ms := c.Metrics[name]; len(ms) > 0 {
				cve.Score = ms[0].CVSSData.BaseScore
				for _, m := range ms {
					if m.Type == "Primary" {
						cve.Score = m.CVSSData.BaseScore
						break
					}
				}
				break
			}
		}
		out = append(out, cve)
	}
	return out, nil
}

// ---- OSV ------------------------------------------------------------------------------

type osvVuln struct {
	Score     float64
	Summary   string
	Fixed     string
	Untriaged bool
	Skip      bool // the distribution says it does not matter ("unimportant")
}

type osvResponse struct {
	Vulns []struct {
		ID       string   `json:"id"`
		Summary  string   `json:"summary"`
		Details  string   `json:"details"`
		Aliases  []string `json:"aliases"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			EcosystemSpecific map[string]any `json:"ecosystem_specific"`
			Ranges            []struct {
				Type   string `json:"type"`
				Events []struct {
					Introduced string `json:"introduced"`
					Fixed      string `json:"fixed"`
				} `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	} `json:"vulns"`
}

// fetchOSV returns the CVEs the distribution still lists for the package version,
// keyed by CVE id, with the version that fixes each where one exists.
func (s *Service) fetchOSV(ctx context.Context, q Query) (map[string]osvVuln, error) {
	payload, _ := json.Marshal(map[string]any{"version": q.PkgVersion, "package": map[string]string{"name": q.Package, "ecosystem": q.Ecosystem}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.OSV, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "excubra (EX0 vulnerability matching)")
	res, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var body osvResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(&body); err != nil {
		return nil, err
	}
	out := map[string]osvVuln{}
	for _, v := range body.Vulns {
		var ids []string
		for _, id := range append([]string{v.ID}, v.Aliases...) {
			if i := strings.Index(id, "CVE-"); i >= 0 {
				ids = append(ids, id[i:])
			}
		}
		if len(ids) == 0 {
			continue
		}
		o := osvVuln{Summary: firstSentence(firstNonEmpty(v.Summary, v.Details))}
		for _, sev := range v.Severity {
			if strings.HasPrefix(sev.Type, "CVSS_V3") || strings.HasPrefix(sev.Type, "CVSS_V4") {
				if sc, ok := ScoreFromVector(sev.Score); ok && sc > o.Score {
					o.Score = sc
				}
			}
		}
		for _, a := range v.Affected {
			if a.Package.Ecosystem != q.Ecosystem || a.Package.Name != q.Package {
				continue
			}
			// Debian's tracker grades what it lists: "unimportant" is a non-issue in
			// Debian's build, "not yet assigned" is not judged yet
			if u, _ := a.EcosystemSpecific["urgency"].(string); u != "" {
				switch strings.ToLower(u) {
				case "unimportant":
					o.Skip = true
				case "not yet assigned", "end-of-life":
					o.Untriaged = true
				}
			}
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						o.Fixed = e.Fixed
					}
				}
			}
		}
		if o.Skip {
			continue
		}
		if o.Fixed != "" {
			o.Untriaged = false // a fix exists: that is a judgement
		}
		for _, id := range ids {
			if cur, ok := out[id]; !ok || (cur.Fixed == "" && o.Fixed != "") {
				out[id] = o
			}
		}
	}
	return out, nil
}

// ---- KEV ------------------------------------------------------------------------------

func (s *Service) fetchKEV(ctx context.Context) ([]string, error) {
	ids, err := s.fetchKEVCISA(ctx)
	if err == nil {
		return ids, nil
	}
	s.Log.Info("vuln: kev list from NVD instead of CISA", "cisa_err", err)
	ids, err2 := s.fetchKEVNVD(ctx)
	if err2 != nil {
		return nil, fmt.Errorf("cisa: %w; nvd: %w", err, err2)
	}
	return ids, nil
}

func (s *Service) fetchKEVCISA(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.KEV, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "excubra (EX0 vulnerability matching)")
	res, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var body struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(&body); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(body.Vulnerabilities))
	for _, v := range body.Vulnerabilities {
		if v.CVEID != "" {
			ids = append(ids, v.CVEID)
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	sort.Strings(ids)
	return ids, nil
}

// fetchKEVNVD pages through NVD's copy of the KEV list (every CVE with a CISA
// exploit date), five hundred at a time.
func (s *Service) fetchKEVNVD(ctx context.Context) ([]string, error) {
	key := s.nvdKey(ctx)
	var ids []string
	for start := 0; start < 20000; {
		if err := s.throttleNVD(ctx, key != ""); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s?hasKev&noRejected&resultsPerPage=500&startIndex=%d", s.NVD, start), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "excubra (EX0 vulnerability matching)")
		if key != "" {
			req.Header.Set("apiKey", key)
		}
		res, err := s.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		var body struct {
			TotalResults    int `json:"totalResults"`
			Vulnerabilities []struct {
				CVE struct {
					ID string `json:"id"`
				} `json:"cve"`
			} `json:"vulnerabilities"`
		}
		if res.StatusCode != http.StatusOK {
			_ = res.Body.Close()
			return nil, fmt.Errorf("HTTP %d", res.StatusCode)
		}
		err = json.NewDecoder(io.LimitReader(res.Body, 4*maxBody)).Decode(&body)
		_ = res.Body.Close()
		if err != nil {
			return nil, err
		}
		for _, v := range body.Vulnerabilities {
			ids = append(ids, v.CVE.ID)
		}
		start += 500
		if len(body.Vulnerabilities) == 0 || start >= body.TotalResults {
			break
		}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	sort.Strings(ids)
	return ids, nil
}

// Exploited reports whether a CVE is on the KEV list (for the rules of other sources).
func (s *Service) Exploited(cveID string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kev[cveID]
}

// ---- findings ---------------------------------------------------------------------------

// Findings judges a device's services against the cache: one finding per service
// that runs a version with known vulnerabilities, urgent when one is exploited in
// the wild or scored high.
func (s *Service) Findings(services []rules.Service, now time.Time) []rules.Finding {
	if s == nil {
		return nil
	}
	var out []rules.Finding
	for _, sv := range services {
		q, ok := Identify(sv)
		if !ok {
			continue
		}
		r := s.lookup(q)
		if r == nil || len(r.CVEs) == 0 {
			continue
		}
		f := finding(sv, q, r)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rules.Rank(out[i].Severity) != rules.Rank(out[j].Severity) {
			return rules.Rank(out[i].Severity) < rules.Rank(out[j].Severity)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func finding(sv rules.Service, q Query, r *Result) rules.Finding {
	key := "connector"
	if sv.Port > 0 {
		key = fmt.Sprintf("%s/%d", firstNonEmpty(sv.Proto, "tcp"), sv.Port)
	}
	var exploited []string
	maxScore, scored, untriaged := 0.0, false, 0
	for _, c := range r.CVEs {
		if c.Exploited {
			exploited = append(exploited, c.ID)
		}
		if c.Untriaged {
			untriaged++
		}
		if c.Score > 0 {
			scored = true
			if c.Score > maxScore {
				maxScore = c.Score
			}
		}
	}
	sev := rules.Low
	switch {
	case len(exploited) > 0 || maxScore >= 7:
		sev = rules.High
	case maxScore >= 4 || !scored:
		sev = rules.Medium
	}
	allUntriaged := untriaged == len(r.CVEs)
	if allUntriaged && len(exploited) == 0 && sev == rules.High {
		sev = rules.Medium // reported, not judged, nothing to install: watch, do not panic
	}
	label := q.Product + " " + q.Version
	title := fmt.Sprintf("%s: %s", label, count(len(r.CVEs), "bekannte Schwachstelle", "bekannte Schwachstellen"))
	if allUntriaged {
		title = fmt.Sprintf("%s: %s, Fix der Distribution steht aus", label, count(len(r.CVEs), "gemeldete Schwachstelle", "gemeldete Schwachstellen"))
	}
	switch {
	case len(exploited) == 1:
		title += ", eine wird aktiv ausgenutzt"
	case len(exploited) > 1:
		title += fmt.Sprintf(", %d werden aktiv ausgenutzt", len(exploited))
	case maxScore > 0 && !allUntriaged:
		title += fmt.Sprintf(", höchste CVSS %.1f", maxScore)
	}
	var b strings.Builder
	source := "NVD"
	if q.Ecosystem != "" {
		source = "OSV für " + strings.SplitN(q.Ecosystem, ":", 2)[0] + " (zurückportierte Fixes berücksichtigt) und NVD"
	}
	fmt.Fprintf(&b, "Für %s %s (Quelle: %s, Stand %s). ", label, plainCount(len(r.CVEs)), source, r.FetchedAt.Format("02.01.2006"))
	if untriaged > 0 {
		fmt.Fprintf(&b, "%s hat die Distribution noch nicht eingestuft und noch nicht behoben: nichts zu installieren, aber im Blick behalten und den Dienst nicht aus dem Internet erreichbar lassen. ", count(untriaged, "davon", "davon"))
	}
	if len(exploited) > 0 {
		fmt.Fprintf(&b, "Auf der Liste der aktiv ausgenutzten Schwachstellen (CISA KEV): %s. ", strings.Join(exploited, ", "))
	}
	top := r.CVEs
	if len(top) > 3 {
		top = top[:3]
	}
	parts := make([]string, 0, len(top))
	for _, c := range top {
		p := c.ID
		if c.Score > 0 {
			p += fmt.Sprintf(" (CVSS %.1f)", c.Score)
		}
		if c.Summary != "" {
			p += ": " + c.Summary
		}
		parts = append(parts, p)
	}
	fmt.Fprintf(&b, "Die wichtigsten: %s. ", strings.Join(parts, " — "))
	fixed := ""
	for _, c := range r.CVEs {
		if c.Fixed != "" && (fixed == "" || c.Fixed > fixed) {
			fixed = c.Fixed
		}
	}
	switch {
	case fixed != "":
		fmt.Fprintf(&b, "Behoben ab Paketversion %s: ein Update der Distribution genügt.", fixed)
	case q.Ecosystem != "":
		b.WriteString("Die Distribution hat dafür noch keinen Fix: Version prüfen, Dienst einschränken oder ersetzen.")
	default:
		b.WriteString("Auf eine aktuelle Version bringen. Läuft der Dienst aus einer Distribution, kann der Fix schon zurückportiert sein; dann ist die Paketversion maßgeblich, nicht die Versionsnummer im Banner.")
	}
	ev := map[string]any{"product": q.Product, "version": q.Version, "count": len(r.CVEs), "max_score": maxScore, "untriaged": untriaged, "fetched": r.FetchedAt.UTC().Format(time.RFC3339), "cves": r.CVEs}
	if len(exploited) > 0 {
		ev["exploited"] = exploited
	}
	if q.Ecosystem != "" {
		ev["package"] = q.Ecosystem + " " + q.Package + " " + q.PkgVersion
	}
	return rules.Finding{Rule: "vuln.known", Key: key, Severity: sev, Title: title, Detail: b.String(), Evidence: ev}
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func plainCount(n int) string {
	if n == 1 {
		return "ist eine Schwachstelle bekannt"
	}
	return fmt.Sprintf("sind %d Schwachstellen bekannt", n)
}

// firstSentence clips a description to its first sentence, at most 220 characters.
func firstSentence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i > 40 {
		s = s[:i+1]
	}
	if len(s) > 220 {
		s = s[:217] + "…"
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}
