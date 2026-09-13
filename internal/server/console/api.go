package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
)

// The JSON API behind the single-page console (web/). It reuses the page builders and
// the mutation handlers: a POST that comes from the app (Accept: application/json)
// gets {ok, message} instead of a redirect with a flash.

func wantsJSON(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/api/") || strings.Contains(r.Header.Get("Accept"), "application/json")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type apiErr struct {
	Error string `json:"error"`
}

// ---- me ------------------------------------------------------------------------------------

type meData struct {
	User    string    `json:"user"`
	CSRF    string    `json:"csrf"`
	Version string    `json:"version"`
	Now     string    `json:"now"`
	Secure  bool      `json:"secure"`
	Map     mapConfig `json:"map"` // where map tiles come from, so the map page needs no extra fetch
	// What this operator pinned, for the top of the sidebar. Travels with /api/me
	// because the sidebar is on every page.
	Pins []store.Pin `json:"pins"`
	Nav  navCounts
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	d := meData{CSRF: sess.CSRF, Version: version.Version, Now: s.Now().In(s.Loc).Format(time.RFC3339), Secure: s.Secure, Map: s.mapConfig(r), Pins: s.pinsFor(r), Nav: s.navCounts(r.Context())}
	if u := userFrom(r); u != nil {
		d.User = u.Name
	}
	writeJSON(w, http.StatusOK, d)
}

// ---- overview -----------------------------------------------------------------------------

// attention is one thing that needs a person now.
type attention struct {
	Kind     string    `json:"kind"` // host_down | box_silent | box_unassigned | host_unknown
	Since    time.Time `json:"since"`
	Tenant   string    `json:"tenant"`
	TenantID string    `json:"tenantId"`
	Site     string    `json:"site"`
	SiteID   string    `json:"siteId"`
	Name     string    `json:"name"`
	Address  string    `json:"address"`
	ID       string    `json:"id"`
	Href     string    `json:"href"`
	Detail   string    `json:"detail"`
	Ack      *ackView  `json:"ack,omitempty"` // set when an operator has seen this outage
}

type overviewData struct {
	statusData
	Attention []attention `json:"attention"`
}

func (s *Server) buildAttention(ctx context.Context, d statusData, now time.Time) []attention {
	var out []attention
	acks, err := s.Store.Acks(ctx)
	if err != nil {
		s.Log.Error("acks", "err", err)
	}
	for _, c := range d.Cards {
		if c.HasBox && !c.Online {
			a := attention{Kind: "box_silent", Since: c.Box.State.SilentSince, Tenant: c.Tenant.Name, TenantID: c.Tenant.ID, Site: c.Site.Name, SiteID: c.Site.ID,
				Name: firstNonEmpty(c.Box.Name, c.Box.ID), ID: c.Box.ID, Href: "/sites/" + c.Site.ID + "?tab=technik", Detail: "Box meldet sich nicht"}
			if a.Since.IsZero() {
				a.Since = c.Box.State.LastHeartbeat
			}
			out = append(out, a)
		}
		for _, h := range c.Hosts {
			if h.StateClass == "down" {
				out = append(out, attention{Kind: "host_down", Since: h.State.Since, Tenant: c.Tenant.Name, TenantID: c.Tenant.ID, Site: c.Site.Name, SiteID: c.Site.ID,
					Name: h.Name, Address: h.Address, ID: h.ID, Href: "/hosts/" + h.ID, Detail: h.Checks})
			}
		}
	}
	for _, b := range d.Unassigned {
		out = append(out, attention{Kind: "box_unassigned", Since: b.EnrolledAt, Name: b.ID, ID: b.ID, Href: "/boxes/" + b.ID, Detail: "keinem Standort zugeordnet"})
	}
	out = append(out, s.failedConnectors(ctx)...)
	for i := range out {
		out[i].Ack = ackFor(acks, out[i].Kind, out[i].ID, out[i].Since)
	}
	sort.SliceStable(out, func(i, j int) bool { // unacknowledged first, then oldest problem first
		if (out[i].Ack == nil) != (out[j].Ack == nil) {
			return out[i].Ack == nil
		}
		return out[i].Since.Before(out[j].Since)
	})
	_ = now
	return out
}

func (s *Server) apiOverview(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildStatus(r.Context(), r.URL.Query().Get("range"))
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, overviewData{statusData: d, Attention: s.buildAttention(r.Context(), d, s.Now())})
}

// siteRowAPI is one row of the flat site list: the card plus what is open on it.
// With many customers this list, not the customer tree, is the way in.
type siteRowAPI struct {
	siteCard
	Findings int `json:"findings"` // open, not acknowledged
}

// apiSites is every site of every customer in one flat, searchable list.
func (s *Server) apiSites(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, err := s.buildStatus(ctx, "")
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	acks, _ := s.Store.Acks(ctx)
	open := map[string]int{}
	if fs, err := s.Store.OpenFindings(ctx, ""); err == nil {
		for _, f := range fs {
			if _, acked := acks["finding/"+f.ID]; !acked && f.SiteID != "" {
				open[f.SiteID]++
			}
		}
	}
	rows := make([]siteRowAPI, 0, len(d.Cards))
	for _, c := range d.Cards {
		c.Hosts = nil // the list does not show hosts; keep the payload small
		rows = append(rows, siteRowAPI{siteCard: c, Findings: open[c.Site.ID]})
	}
	writeJSON(w, http.StatusOK, rows)
}

// ---- tenants -----------------------------------------------------------------------------

type tenantRowAPI struct {
	store.Tenant
	Sites       int `json:"sites"`
	Boxes       int `json:"boxes"`
	BoxesOnline int `json:"boxesOnline"`
	Hosts       int `json:"hosts"`
	Down        int `json:"down"`
	Devices     int `json:"devices"`
	Attention   int `json:"attention"`
}

func (s *Server) apiTenants(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildStatus(r.Context(), "")
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	byTenant := map[string]*tenantRowAPI{}
	var order []string
	for _, tb := range d.Tenants {
		byTenant[tb.Tenant.ID] = &tenantRowAPI{Tenant: tb.Tenant}
		order = append(order, tb.Tenant.ID)
	}
	for _, c := range d.Cards {
		t := byTenant[c.Tenant.ID]
		if t == nil {
			continue
		}
		t.Sites++
		t.Hosts += c.Monitored
		t.Down += c.Down
		t.Devices += c.Devices
		if c.HasBox {
			t.Boxes++
			if c.Online {
				t.BoxesOnline++
			} else {
				t.Attention++
			}
		}
		t.Attention += c.Down
	}
	rows := make([]tenantRowAPI, 0, len(order))
	for _, id := range order {
		rows = append(rows, *byTenant[id])
	}
	writeJSON(w, http.StatusOK, rows)
}

type tenantDetail struct {
	Tenant store.Tenant  `json:"tenant"`
	Sites  []siteCard    `json:"sites"`
	Events []recentEvent `json:"events"`
}

func (s *Server) apiTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := s.Store.Tenant(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	d, err := s.buildStatus(ctx, "")
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	out := tenantDetail{Tenant: t}
	for _, c := range d.Cards {
		if c.Tenant.ID == t.ID {
			out.Sites = append(out.Sites, c)
		}
	}
	for _, e := range d.Recent {
		if e.TenantID == t.ID {
			out.Events = append(out.Events, e)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- site --------------------------------------------------------------------------------

func (s *Server) apiSite(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildSite(r.Context(), r.PathValue("id"), r.URL.Query().Get("tab"), r.URL.Query().Get("range"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func statusFor(err error) int {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

// ---- device -----------------------------------------------------------------------------

type deviceDetail struct {
	Device   deviceCard    `json:"device"`
	Tenant   store.Tenant  `json:"tenant"`
	Site     store.Site    `json:"site"`
	Host     *hostCard     `json:"host"`
	Events   []recentEvent `json:"events"`
	Services []serviceView `json:"services"` // what the scan saw listening (ADR-0018)
	LogsNote string        `json:"logsNote"`
}

func (s *Server) apiDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.Store.Device(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	sd, err := s.buildSite(ctx, dev.SiteID, "", "")
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	out := deviceDetail{Tenant: sd.Tenant, Site: sd.Site, Services: s.deviceServices(ctx, dev.ID), LogsNote: "Logs je Gerät kommen mit Phase 2 (Syslog-Empfang auf der Box, Agent-Logs). Der Platz hier ist dafür reserviert."}
	for _, c := range sd.Devices {
		if c.ID == dev.ID {
			out.Device = c
			break
		}
	}
	if out.Device.Monitored {
		for i := range sd.Hosts {
			if sd.Hosts[i].ID == out.Device.HostID {
				out.Host = &sd.Hosts[i]
				break
			}
		}
	}
	for _, e := range sd.Events {
		if e.DeviceID == dev.ID || (out.Host != nil && e.HostID == out.Host.ID) {
			out.Events = append(out.Events, e)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- events ------------------------------------------------------------------------------

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	rng := q.Get("range")
	tm, sm, err := s.lookups(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	now := s.Now()
	since := now.Add(-24 * time.Hour)
	switch rng {
	case "7d":
		since = now.Add(-7 * 24 * time.Hour)
	case "30d":
		since = now.Add(-30 * 24 * time.Hour)
	default:
		rng = "24h"
	}
	limit := 500
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 5000 {
		limit = n
	}
	var out []recentEvent
	for _, t := range tm {
		if tid := q.Get("tenant"); tid != "" && t.ID != tid {
			continue
		}
		evs, err := s.Store.Events(ctx, t.ID, since, now.Add(time.Minute), q.Get("host"), limit)
		if err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		for _, ev := range evs {
			if ty := q.Get("type"); ty != "" && string(ev.Type) != ty {
				continue
			}
			if sid := q.Get("site"); sid != "" && ev.SiteID != sid {
				continue
			}
			re := recentEvent{Event: ev, TenantName: t.Name, Class: eventClass(ev), Title: eventTitle(ev), Info: eventInfo(ev)}
			if site, ok := sm[ev.SiteID]; ok {
				re.SiteName = site.Name
			}
			out = append(out, re)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].OccurredAt.After(out[j].OccurredAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{"range": rng, "events": out})
}

// ---- boxes -------------------------------------------------------------------------------

func (s *Server) apiBoxes(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildBoxes(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) apiBox(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildBox(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// ---- host --------------------------------------------------------------------------------

func (s *Server) apiHost(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildHost(r.Context(), r.PathValue("id"), r.URL.Query().Get("tab"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// ---- admin lists --------------------------------------------------------------------------

type keyRowAPI struct {
	ID        string     `json:"id"`
	Note      string     `json:"note"`
	SiteID    string     `json:"siteId"`
	SiteName  string     `json:"siteName"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt"`
	UsedBy    string     `json:"usedBy"`
	RevokedAt *time.Time `json:"revokedAt"`
}

func (s *Server) apiKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keys, err := s.Store.EnrollmentKeys(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	sites, tenants := s.siteIndex(ctx)
	rows := make([]keyRowAPI, 0, len(keys))
	for _, k := range keys {
		row := keyRowAPI{ID: k.ID, Note: k.Note, SiteID: k.SiteID, CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt, UsedAt: k.UsedAt, UsedBy: k.UsedByBox, RevokedAt: k.RevokedAt}
		if site, ok := sites[k.SiteID]; ok {
			row.SiteName = tenants[site.TenantID].Name + " · " + site.Name
		}
		rows = append(rows, row)
	}
	var opts []siteOption
	for _, site := range sites {
		opts = append(opts, siteOption{ID: site.ID, Name: tenants[site.TenantID].Name + " · " + site.Name})
	}
	sort.Slice(opts, func(i, j int) bool { return opts[i].Name < opts[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"keys": rows, "sites": opts})
}

type siteOption struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
}

// siteIndex maps sites and tenants by id.
func (s *Server) siteIndex(ctx context.Context) (map[string]store.Site, map[string]store.Tenant) {
	sites := map[string]store.Site{}
	tenants := map[string]store.Tenant{}
	if ts, err := s.Store.Tenants(ctx); err == nil {
		for _, t := range ts {
			tenants[t.ID] = t
		}
	}
	if ss, err := s.Store.Sites(ctx, ""); err == nil {
		for _, site := range ss {
			sites[site.ID] = site
		}
	}
	return sites, tenants
}

// apiKeysCreate makes enrollment keys — for a site, so the box assigns itself on
// enrollment (ADR-0017) — and hands back the one-liners that turn a machine or a
// Proxmox container into that box.
func (s *Server) apiKeysCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := r.PostForm
	count, _ := strconv.Atoi(f.Get("count"))
	if count < 1 || count > 20 {
		count = 1
	}
	days, _ := strconv.Atoi(f.Get("expires_days"))
	if days < 1 || days > 365 {
		days = 30
	}
	note := strings.TrimSpace(f.Get("note"))
	siteID := strings.TrimSpace(f.Get("site_id"))
	hostname := ""
	if siteID != "" {
		site, err := s.Store.Site(ctx, siteID)
		if err != nil {
			s.flashErr(w, r, "Standort nicht gefunden.", "/keys")
			return
		}
		tenant, _ := s.Store.Tenant(ctx, site.TenantID)
		hostname = boxHostname(tenant.Name, site.Name)
		if note == "" {
			note = tenant.Name + " · " + site.Name
		}
	}
	now := s.Now()
	var secrets []string
	var commands []installerCommand
	for i := 0; i < count; i++ {
		k, err := pki.NewEnrollmentKey(s.Ingest, s.IngestPt, s.CA.Fingerprint())
		if err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		rec := store.EnrollmentKey{ID: id.New("key"), SecretHash: k.SecretHash(), Note: note, SiteID: siteID, CreatedAt: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour)}
		if err := s.Store.CreateEnrollmentKey(ctx, rec); err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		_ = s.Store.Audit(ctx, now, actor(r), "key.new", rec.ID, note+" site="+siteID)
		secrets = append(secrets, k.String())
		if count == 1 {
			commands = installerCommands(k.String(), hostname)
		}
	}
	msg := "Key erzeugt. Einmalig sichtbar."
	if siteID != "" {
		msg = "Key für den Standort erzeugt. Die Box ordnet sich damit selbst zu."
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg, "secrets": secrets, "commands": commands})
}

type installerCommand struct {
	Title string `json:"title"`
	Cmd   string `json:"cmd"`
}

// installerBase is where the installers of this server's release live; a
// development build points at main.
func installerBase() (base, ver string) {
	ref := "main"
	if v := version.Version; regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(v) {
		ref, ver = "v"+v, v
	}
	return "https://raw.githubusercontent.com/excubra/excubra/" + ref + "/image", ver
}

// reinstallCommand brings an enrolled box's installation up to the current
// release (units, helper, firewall rules) without touching its identity: the
// installer without a key, run once on the box.
func reinstallCommand() string {
	base, ver := installerBase()
	cmd := "curl -fsSL " + base + "/ex0-box.sh | bash -s --"
	if ver != "" {
		cmd += " --version " + ver
	}
	return cmd
}

// installerCommands are the two ways a box comes to life with this key: on a
// machine (mini PC, Pi, VM) and as a container on a Proxmox host.
func installerCommands(key, hostname string) []installerCommand {
	base, ver := installerBase()
	args := "--enroll-key '" + key + "'"
	if hostname != "" {
		args += " --hostname " + hostname
	}
	if ver != "" {
		args += " --version " + ver
	}
	return []installerCommand{
		{Title: "Auf einem Proxmox-Host (legt den Container an und richtet ihn ein)", Cmd: "curl -fsSL " + base + "/ex0-box-pct.sh | bash -s -- " + args},
		{Title: "Auf der Box selbst (Mini-PC, Raspberry Pi, VM mit frischem Debian, als root)", Cmd: "curl -fsSL " + base + "/ex0-box.sh | bash -s -- " + args},
	}
}

// boxHostname makes a hostname out of tenant and site: letters, digits, dashes.
func boxHostname(tenant, site string) string {
	slug := func(v string) string {
		v = strings.ToLower(strings.TrimSpace(v))
		r := strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss")
		v = r.Replace(v)
		var b strings.Builder
		dash := false
		for _, c := range v {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
				b.WriteRune(c)
				dash = false
			default:
				if !dash && b.Len() > 0 {
					b.WriteByte('-')
					dash = true
				}
			}
		}
		return strings.Trim(b.String(), "-")
	}
	name := strings.Trim(slug(tenant)+"-"+slug(site), "-")
	if len(name) > 40 {
		name = strings.Trim(name[:40], "-")
	}
	if name == "" {
		return "ex0-box"
	}
	return "ex0-" + name
}

type tokenRowAPI struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Tenants   []string   `json:"tenants"`
	CreatedAt time.Time  `json:"createdAt"`
	LastUsed  *time.Time `json:"lastUsed"`
	RevokedAt *time.Time `json:"revokedAt"`
}

func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request) {
	d, err := s.tokensData(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	rows := make([]tokenRowAPI, 0, len(d.Tokens))
	for _, t := range d.Tokens {
		rows = append(rows, tokenRowAPI{ID: t.ID, Name: t.Name, Tenants: t.Tenants, CreatedAt: t.CreatedAt, LastUsed: t.LastUsedAt, RevokedAt: t.RevokedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": rows, "tenants": d.Tenants})
}

type webhookRowAPI struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

func (s *Server) apiWebhooks(w http.ResponseWriter, r *http.Request) {
	d, err := s.webhooksData(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	rows := make([]webhookRowAPI, 0, len(d.Targets))
	for _, t := range d.Targets {
		rows = append(rows, webhookRowAPI{ID: t.ID, Name: t.Name, URL: t.URL, Enabled: t.Enabled, CreatedAt: t.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": rows, "failed": d.Failed, "tenants": d.Tenants})
}

type userRowAPI struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	TOTP         bool       `json:"totp"`
	Disabled     bool       `json:"disabled"`
	Locked       bool       `json:"locked"`
	LockedUntil  *time.Time `json:"lockedUntil"`
	FailedLogins int        `json:"failedLogins"`
	CreatedAt    time.Time  `json:"createdAt"`
}

func (s *Server) apiUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.Users(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	now := s.Now()
	rows := make([]userRowAPI, 0, len(users))
	for _, u := range users {
		rows = append(rows, userRowAPI{ID: u.ID, Name: u.Name, TOTP: u.TOTPSecret != "", Disabled: u.Disabled, Locked: u.LockedUntil != nil && u.LockedUntil.After(now), LockedUntil: u.LockedUntil, FailedLogins: u.FailedLogins, CreatedAt: u.CreatedAt})
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) apiAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n <= 2000 {
		limit = n
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	rows, err := s.Store.AuditEntries(r.Context(), limit, before)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) apiMaintenance(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildMaintenance(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// ---- search ------------------------------------------------------------------------------

type searchHit struct {
	Kind   string `json:"kind"` // tenant | site | device | host | box
	ID     string `json:"id"`
	Title  string `json:"title"`
	Sub    string `json:"sub"`
	Href   string `json:"href"`
	Tenant string `json:"tenant"`
}

// apiSearch answers the command palette: customers, sites, devices and boxes by name,
// address or MAC. Devices are searched per tenant in the store; fine up to a few
// thousand devices per tenant, the index on (tenant, last_seen) keeps it cheap.
func (s *Server) apiSearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if len(q) < 2 {
		writeJSON(w, http.StatusOK, []searchHit{})
		return
	}
	tm, sm, err := s.lookups(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	var hits []searchHit
	for _, t := range tm {
		if strings.Contains(strings.ToLower(t.Name), q) || strings.Contains(t.ID, q) {
			hits = append(hits, searchHit{Kind: "tenant", ID: t.ID, Title: t.Name, Sub: t.ID, Href: "/tenants/" + t.ID, Tenant: t.Name})
		}
	}
	for _, st := range sm {
		if strings.Contains(strings.ToLower(st.Name), q) || strings.Contains(st.ID, q) {
			hits = append(hits, searchHit{Kind: "site", ID: st.ID, Title: st.Name, Sub: tm[st.TenantID].Name, Href: "/sites/" + st.ID, Tenant: tm[st.TenantID].Name})
		}
	}
	boxes, err := s.Store.Boxes(ctx, "")
	if err == nil {
		for _, b := range boxes {
			if b.RevokedAt == nil && (strings.Contains(strings.ToLower(b.Name), q) || strings.Contains(b.ID, q) || strings.Contains(b.NetbirdIP, q)) {
				hits = append(hits, searchHit{Kind: "box", ID: b.ID, Title: firstNonEmpty(b.Name, b.ID), Sub: b.ID, Href: "/boxes/" + b.ID})
			}
		}
	}
	for _, t := range tm {
		if len(hits) > 40 {
			break
		}
		devs, err := s.Store.Devices(ctx, t.ID, "", time.Time{})
		if err != nil {
			continue
		}
		for _, dev := range devs {
			hay := strings.ToLower(dev.Hostname + " " + dev.IP + " " + dev.MAC + " " + dev.Vendor)
			if strings.Contains(hay, q) {
				hits = append(hits, searchHit{Kind: "device", ID: dev.ID, Title: deviceName(dev), Sub: firstNonEmpty(dev.IP, dev.MAC) + " · " + vendorShort(dev.Vendor), Href: "/devices/" + dev.ID, Tenant: t.Name})
				if len(hits) > 40 {
					break
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, hits)
}

// ---- helpers shared with the pages ----------------------------------------------------

// classOfState maps a box state to the api's status vocabulary.
func classOfState(b state.Box) string {
	if b.Status == state.Silent {
		return "silent"
	}
	if b.LastHeartbeat.IsZero() {
		return "never"
	}
	return "online"
}

var _ = classOfState
var _ context.Context
var _ event.Type

// failedConnectors lists connectors whose last reading failed, as problems.
func (s *Server) failedConnectors(ctx context.Context) []attention {
	cons, err := s.Store.Connectors(ctx, "")
	if err != nil {
		s.Log.Error("connectors", "err", err)
		return nil
	}
	var out []attention
	var tm map[string]store.Tenant
	var sm map[string]store.Site
	for _, c := range cons {
		if c.Disabled || c.LastOK == nil || *c.LastOK {
			continue
		}
		if tm == nil {
			if tm, sm, err = s.lookups(ctx); err != nil {
				return out
			}
		}
		a := attention{Kind: "connector_failed", ID: c.ID, Name: ConnectorLabel(c.Kind), Address: c.URL, Href: "/devices/" + c.DeviceID + "?tab=konnektor", Detail: c.LastError, TenantID: c.TenantID, SiteID: c.SiteID}
		if c.LastAt != nil {
			a.Since = *c.LastAt
		}
		if t, ok := tm[c.TenantID]; ok {
			a.Tenant = t.Name
		}
		if st, ok := sm[c.SiteID]; ok {
			a.Site = st.Name
		}
		if dev, err := s.Store.Device(ctx, c.DeviceID); err == nil {
			a.Name = ConnectorLabel(c.Kind) + " · " + firstNonEmpty(dev.Hostname, dev.IP)
		}
		out = append(out, a)
	}
	return out
}
