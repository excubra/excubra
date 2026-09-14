// Package action1 reads endpoint patch state from Action1, the cloud endpoint
// manager VIICO already runs on its customers' Windows machines.
//
// Why this is worth a reader at all. EX0 sees a network: banners, TLS
// certificates, versions a service announces. A Windows application announces
// nothing, which is exactly why ADR-0018 §8 leaves Windows out of the CPE
// matching — its version string does not move when it is patched. Action1 has an
// agent on the machine and knows. The two together say something neither says
// alone: a network-exploitable hole, overdue for weeks, on a machine whose ports
// we can also see from outside.
//
// It only reads. Action1 can deploy patches and run scripts; EX0 does not act on
// customer systems (salt E15, E16), and reading stays reading.
package action1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Settings keys. The credentials are sealed at rest like every other secret
// (store.SecretSetting matches on the suffixes).
const (
	SettingBaseURL      = "action1.base_url"
	SettingClientID     = "action1.client_id"
	SettingClientSecret = "action1.client_secret"
)

// DefaultBaseURL is the EU instance. Action1 is regional and the wrong region
// answers with an empty account rather than an error, so this is a setting.
const DefaultBaseURL = "https://app.eu.action1.com/api/3.0"

// Limits. Action1 allows fewer than thirty requests a minute per tenant, so the
// client holds itself to twenty and never finds out what happens at thirty.
const (
	requestsPerMinute = 20
	burst             = 5
	httpTimeout       = 30 * time.Second
	tokenEarly        = 2 * time.Minute // refresh this long before expiry
	maxBody           = 8 << 20
)

// ErrNotConfigured means no credentials are set; nothing is fetched and that is
// a state, not a failure.
var ErrNotConfigured = errors.New("action1: no credentials configured")

// Org is one Action1 organization, which is how they model a customer.
type Org struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Endpoint is one managed machine.
type Endpoint struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	LastSeen string `json:"last_seen"`
}

// Vulnerability is one CVE Action1 found on this organization's machines,
// flattened to what a finding needs.
type Vulnerability struct {
	CVE       string    `json:"cve_id"`
	CVSS      float64   `json:"-"`
	CVSSRaw   string    `json:"cvss_score"`
	Endpoints int       `json:"-"`
	Status    string    `json:"remediation_status"` // Overdue, Pending, …
	Deadline  time.Time `json:"-"`
	KEV       bool      `json:"-"`
	Products  []string  `json:"-"`
	// Affected is the software and versions this CVE sits in. It is what makes
	// the hole attributable to a machine: the organization-wide list says a hole
	// exists somewhere, and only the per-machine inventory says where.
	Affected []Affected `json:"-"`
}

// Affected is one product and the versions of it this CVE applies to.
type Affected struct {
	Product  string
	Versions []string
}

// MissingUpdate is one patch Action1 offers but has not installed.
type MissingUpdate struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Client talks to one Action1 tenant. The credentials are behind the mutex
// because an operator can change them in the console while a sync is running.
type Client struct {
	HTTP *http.Client
	Now  func() time.Time

	mu      sync.Mutex
	baseURL string
	id      string
	secret  string
	token   string
	expires time.Time
	tokens  float64
	last    time.Time
}

// New returns a client. An empty id or secret yields a client whose every call
// answers ErrNotConfigured, so callers need no second nil check.
func New(baseURL, id, secret string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultBaseURL
	}
	c := &Client{HTTP: &http.Client{Timeout: httpTimeout}, Now: time.Now, tokens: burst}
	c.Configure(baseURL, id, secret)
	return c
}

// Configure replaces the credentials, as when somebody enters them in the
// console. A change drops the cached token: it belongs to the old credential
// and would otherwise keep a removed key alive for its remaining hour.
func (c *Client) Configure(baseURL, id, secret string) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = DefaultBaseURL
	}
	id, secret = strings.TrimSpace(id), strings.TrimSpace(secret)
	c.mu.Lock()
	defer c.mu.Unlock()
	if base == c.baseURL && id == c.id && secret == c.secret {
		return
	}
	c.baseURL, c.id, c.secret = base, id, secret
	c.token, c.expires = "", time.Time{}
}

// creds reads the credentials as one consistent set.
func (c *Client) creds() (base, id, secret string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.baseURL, c.id, c.secret
}

// Base is the instance this client talks to.
func (c *Client) Base() string { base, _, _ := c.creds(); return base }

// Configured reports whether there is anything to talk to.
func (c *Client) Configured() bool { _, id, secret := c.creds(); return id != "" && secret != "" }

// Orgs lists the organizations the credential can see, so an operator picks from
// a list instead of typing a UUID.
func (c *Client) Orgs(ctx context.Context) ([]Org, error) {
	var out []Org
	if err := c.get(ctx, "/organizations", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Endpoints lists the managed machines of one organization.
func (c *Client) Endpoints(ctx context.Context, orgID string) ([]Endpoint, error) {
	var out []Endpoint
	if err := c.get(ctx, "/endpoints/managed/"+url.PathEscape(orgID), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// MissingUpdates lists the patches that are offered and not installed.
func (c *Client) MissingUpdates(ctx context.Context, orgID string) ([]MissingUpdate, error) {
	var out []MissingUpdate
	if err := c.get(ctx, "/updates/"+url.PathEscape(orgID), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Vulnerabilities lists the CVEs Action1 found, with the products they sit in.
func (c *Client) Vulnerabilities(ctx context.Context, orgID string) ([]Vulnerability, error) {
	var raw []struct {
		CVE       string `json:"cve_id"`
		CVSS      string `json:"cvss_score"`
		Endpoints string `json:"endpoints_count"`
		Status    string `json:"remediation_status"`
		Deadline  string `json:"remediation_deadline"`
		KEV       string `json:"cisa_kev"`
		Software  []struct {
			Product  string `json:"product_name"`
			Versions []struct {
				Version string `json:"version"`
			} `json:"versions"`
		} `json:"software"`
	}
	if err := c.get(ctx, "/vulnerabilities/"+url.PathEscape(orgID), &raw); err != nil {
		return nil, err
	}
	out := make([]Vulnerability, 0, len(raw))
	for _, r := range raw {
		v := Vulnerability{CVE: r.CVE, CVSSRaw: r.CVSS, Status: r.Status, KEV: strings.EqualFold(r.KEV, "yes")}
		v.CVSS, _ = strconv.ParseFloat(r.CVSS, 64)
		v.Endpoints, _ = strconv.Atoi(r.Endpoints)
		v.Deadline = parseTime(r.Deadline)
		for _, sw := range r.Software {
			if sw.Product == "" {
				continue
			}
			v.Products = append(v.Products, sw.Product)
			a := Affected{Product: sw.Product}
			for _, ver := range sw.Versions {
				if ver.Version != "" {
					a.Versions = append(a.Versions, ver.Version)
				}
			}
			v.Affected = append(v.Affected, a)
		}
		out = append(out, v)
	}
	return out, nil
}

// parseTime reads Action1's "2026-08-27_12-19-47", which is not a format any
// library knows. An unreadable time is the zero time, never a guess.
func parseTime(s string) time.Time {
	t, err := time.Parse("2006-01-02_15-04-05", strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// ---- transport -------------------------------------------------------------------

// get reads a list, accepting both a bare array and an {"items": …} envelope.
func (c *Client) get(ctx context.Context, path string, into any) error {
	return c.fetch(ctx, path, into, true)
}

// getRaw reads a document as it stands, envelope and all: the report endpoints
// carry paging beside the rows, and unwrapping would throw it away.
func (c *Client) getRaw(ctx context.Context, path string, into any) error {
	return c.fetch(ctx, path, into, false)
}

func (c *Client) fetch(ctx context.Context, path string, into any, unwrap bool) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	tok, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	if err := c.wait(ctx); err != nil {
		return err
	}
	base, _, _ := c.creds()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("action1 %s: %w", path, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		c.forget()
		return fmt.Errorf("action1 %s: credentials refused", path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("action1 %s: answered %s", path, resp.Status)
	}
	// Action1 wraps lists in {"items": [...]}; older paths answer a bare array.
	// Read once and accept both rather than guess per endpoint.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("action1 %s: %w", path, err)
	}
	if unwrap {
		var env struct {
			Items json.RawMessage `json:"items"`
		}
		if json.Unmarshal(body, &env) == nil && len(env.Items) > 0 {
			body = env.Items
		}
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("action1 %s: unreadable answer: %w", path, err)
	}
	return nil
}

// bearer returns a valid token, fetching one when the old is gone or nearly so.
func (c *Client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && c.Now().Before(c.expires.Add(-tokenEarly)) {
		tok := c.token
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	if err := c.wait(ctx); err != nil {
		return "", err
	}
	base, id, secret := c.creds()
	form := url.Values{"client_id": {id}, "client_secret": {secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("action1 token: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("action1 token: answered %s", resp.Status)
	}
	var tr struct {
		Token   string `json:"access_token"`
		Expires int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return "", fmt.Errorf("action1 token: unreadable answer: %w", err)
	}
	if tr.Token == "" {
		return "", errors.New("action1 token: the answer carried no token")
	}
	if tr.Expires <= 0 {
		tr.Expires = 3600
	}
	c.mu.Lock()
	c.token, c.expires = tr.Token, c.Now().Add(time.Duration(tr.Expires)*time.Second)
	c.mu.Unlock()
	return tr.Token, nil
}

func (c *Client) forget() {
	c.mu.Lock()
	c.token, c.expires = "", time.Time{}
	c.mu.Unlock()
}

// wait spends one token, refilling at requestsPerMinute. Action1 cuts a tenant
// off above thirty a minute, and a reader that trips that limit takes the whole
// account's other callers down with it.
func (c *Client) wait(ctx context.Context) error {
	const perSecond = requestsPerMinute / 60.0
	c.mu.Lock()
	now := c.Now()
	if !c.last.IsZero() {
		c.tokens = min(float64(burst), c.tokens+now.Sub(c.last).Seconds()*perSecond)
	}
	c.last = now
	if c.tokens >= 1 {
		c.tokens--
		c.mu.Unlock()
		return nil
	}
	gap := time.Duration((1 - c.tokens) / perSecond * float64(time.Second))
	c.tokens = 0
	c.mu.Unlock()
	t := time.NewTimer(gap)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ---- per-machine software, which is what makes a finding attributable ---------------

// Software is one application on one machine, as the agent inventoried it.
type Software struct {
	Name         string
	Version      string
	Vendor       string
	UpdateStatus string   // Current | None | Important Update Available | …
	Missing      []string // versions the manager has ready for this application
	LastRefresh  time.Time
}

// Pending reports whether the manager has an update ready for this application.
func (s Software) Pending() bool { return len(s.Missing) > 0 }

// softwarePage is the report envelope these endpoints answer with.
type softwarePage struct {
	Items []struct {
		Fields struct {
			Name         string `json:"Name"`
			Version      string `json:"Version"`
			Vendor       string `json:"Vendor"`
			UpdateStatus string `json:"Update Status"`
			Missing      []struct {
				Version string `json:"version"`
			} `json:"_Missing_Updates"`
		} `json:"fields"`
		LastRefresh string `json:"last_refresh"`
	} `json:"items"`
	HasMore    bool `json:"has_more"`
	NextOffset *int `json:"next_offset"`
}

// maxSoftwarePages stops a runaway inventory from becoming an endless loop.
const maxSoftwarePages = 20

// EndpointSoftware lists what is installed on one machine. This is the call that
// makes patch state attributable: the organization-wide vulnerability list says
// which holes exist somewhere, and only this says on which machine.
func (c *Client) EndpointSoftware(ctx context.Context, orgID, endpointID string) ([]Software, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	var out []Software
	offset := 0
	for page := 0; page < maxSoftwarePages; page++ {
		var p softwarePage
		path := fmt.Sprintf("/installed-software/%s/data/%s?limit=500&offset=%d",
			url.PathEscape(orgID), url.PathEscape(endpointID), offset)
		if err := c.getRaw(ctx, path, &p); err != nil {
			return nil, err
		}
		for _, it := range p.Items {
			s := Software{
				Name: strings.TrimSpace(it.Fields.Name), Version: strings.TrimSpace(it.Fields.Version),
				Vendor: strings.TrimSpace(it.Fields.Vendor), UpdateStatus: it.Fields.UpdateStatus,
				LastRefresh: parseTime(it.LastRefresh),
			}
			for _, m := range it.Fields.Missing {
				if m.Version != "" {
					s.Missing = append(s.Missing, m.Version)
				}
			}
			if s.Name != "" {
				out = append(out, s)
			}
		}
		if !p.HasMore || p.NextOffset == nil || *p.NextOffset <= offset {
			break
		}
		offset = *p.NextOffset
	}
	return out, nil
}
