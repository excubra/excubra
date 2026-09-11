package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/event"
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
	User    string `json:"user"`
	CSRF    string `json:"csrf"`
	Version string `json:"version"`
	Now     string `json:"now"`
	Secure  bool   `json:"secure"`
	Nav     navCounts
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	d := meData{CSRF: sess.CSRF, Version: version.Version, Now: s.Now().In(s.Loc).Format(time.RFC3339), Secure: s.Secure, Nav: s.navCounts(r.Context())}
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
}

type overviewData struct {
	statusData
	Attention []attention `json:"attention"`
}

func (s *Server) buildAttention(d statusData, now time.Time) []attention {
	var out []attention
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
	sort.SliceStable(out, func(i, j int) bool { // oldest problem first
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
	writeJSON(w, http.StatusOK, overviewData{statusData: d, Attention: s.buildAttention(d, s.Now())})
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
	out := deviceDetail{Tenant: sd.Tenant, Site: sd.Site, LogsNote: "Logs je Gerät kommen mit Phase 2 (Syslog-Empfang auf der Box, Agent-Logs). Der Platz hier ist dafür reserviert."}
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
			re := recentEvent{Event: ev, TenantName: t.Name, Class: eventClass(ev.Type), Title: eventTitle(ev), Info: eventInfo(ev)}
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
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt"`
	UsedBy    string     `json:"usedBy"`
	RevokedAt *time.Time `json:"revokedAt"`
}

func (s *Server) apiKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Store.EnrollmentKeys(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	rows := make([]keyRowAPI, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, keyRowAPI{ID: k.ID, Note: k.Note, CreatedAt: k.CreatedAt, ExpiresAt: k.ExpiresAt, UsedAt: k.UsedAt, UsedBy: k.UsedByBox, RevokedAt: k.RevokedAt})
	}
	writeJSON(w, http.StatusOK, rows)
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
