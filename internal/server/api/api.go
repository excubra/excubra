// Package api is the status API of contract v1 (salt: "Schnittstelle EX0 → CRM"),
// served on the overlay listener and, where one is set, on the listener in our own
// network (ADR-0022). Bearer tokens are scoped to tenants; the CRM writes nothing
// but maintenance windows and test pings. A source token (ADR-0023) posts its
// application's events and does nothing else.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
)

// Server holds the API handlers.
type Server struct {
	Engine *core.Engine
	Store  *store.Store
	Log    *slog.Logger
	Now    func() time.Time
}

// New wires the API.
func New(eng *core.Engine, st *store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{Engine: eng, Store: st, Log: log, Now: time.Now}
}

// Handler returns the route table under /v1/.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /v1/tenants", s.auth(s.tenants))
	mux.Handle("GET /v1/tenants/{tenant_id}/sites", s.auth(s.sites))
	mux.Handle("GET /v1/tenants/{tenant_id}/hosts", s.auth(s.hosts))
	mux.Handle("GET /v1/tenants/{tenant_id}/devices", s.auth(s.devices))
	mux.Handle("GET /v1/tenants/{tenant_id}/events", s.auth(s.events))
	mux.Handle("GET /v1/hosts/{host_id}", s.auth(s.host))
	mux.Handle("PUT /v1/hosts/{host_id}/maintenance", s.auth(s.hostMaintenance))
	mux.Handle("DELETE /v1/hosts/{host_id}/maintenance", s.auth(s.hostMaintenanceEnd))
	mux.Handle("PUT /v1/sites/{site_id}/maintenance", s.auth(s.siteMaintenance))
	mux.Handle("DELETE /v1/sites/{site_id}/maintenance", s.auth(s.siteMaintenanceEnd))
	mux.Handle("POST /v1/webhooks/{target_id}/test", s.auth(s.webhookTest))
	mux.Handle("POST /v1/source/events", s.sourceAuth(s.sourceEvents))
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusNotFound, "not_found", "no such route")
	})
	return mux
}

type ctxKey int

const tokenKey ctxKey = 1

func tokenFrom(r *http.Request) store.APIToken {
	t, _ := r.Context().Value(tokenKey).(store.APIToken)
	return t
}

// HashToken is how tokens are stored: hex SHA-256 of the presented value.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return s.bearer(false, next)
}

// sourceAuth admits source tokens and nothing else (ADR-0023).
func (s *Server) sourceAuth(next http.HandlerFunc) http.Handler {
	return s.bearer(true, next)
}

// bearer checks the token and its kind: an operator token reads and sets windows,
// a source token posts its events. Neither is the other.
func (s *Server) bearer(source bool, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		if raw == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, http.StatusUnauthorized, "unauthorized", "bearer token required")
			return
		}
		tok, err := s.Store.APITokenByHash(r.Context(), HashToken(raw))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "unknown or revoked token")
			return
		}
		if (tok.DeviceID != "") != source {
			if source {
				writeErr(w, http.StatusForbidden, "forbidden", "only a source token posts events")
			} else {
				writeErr(w, http.StatusForbidden, "forbidden", "a source token posts its events and nothing else")
			}
			return
		}
		_ = s.Store.TouchAPIToken(r.Context(), tok.ID, s.Now())
		next(w, r.WithContext(context.WithValue(r.Context(), tokenKey, tok)))
	})
}

func allowed(tok store.APIToken, tenantID string) bool {
	return slices.Contains(tok.Tenants, "*") || slices.Contains(tok.Tenants, tenantID)
}

// requireTenant checks the token scope for a tenant and answers 404 otherwise
// (never reveal whether a tenant exists).
func (s *Server) requireTenant(w http.ResponseWriter, r *http.Request, tenantID string) bool {
	if !allowed(tokenFrom(r), tenantID) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown tenant")
		return false
	}
	return true
}

// ---- reads ---------------------------------------------------------------------------

func (s *Server) tenants(w http.ResponseWriter, r *http.Request) {
	tok := tokenFrom(r)
	all, err := s.Store.Tenants(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []map[string]any{}
	for _, t := range all {
		if allowed(tok, t.ID) {
			out = append(out, map[string]any{"tenant_id": t.ID, "name": t.Name})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": out})
}

type boxOut struct {
	BoxID         string     `json:"box_id"`
	Name          string     `json:"name"`
	State         string     `json:"state"`
	LastHeartbeat *time.Time `json:"last_heartbeat"`
	AgentVersion  string     `json:"agent_version"`
	NetbirdStatus string     `json:"netbird_status"`
	NetbirdIP     string     `json:"netbird_ip,omitempty"`
}

func (s *Server) sites(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !s.requireTenant(w, r, tenantID) {
		return
	}
	sites, err := s.Store.Sites(r.Context(), tenantID)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []map[string]any{}
	for _, site := range sites {
		boxes, err := s.Store.Boxes(r.Context(), site.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		bo := []boxOut{}
		for _, b := range boxes {
			if b.RevokedAt != nil {
				continue
			}
			bo = append(bo, s.boxOut(b))
		}
		entry := map[string]any{"site_id": site.ID, "name": site.Name, "boxes": bo}
		if len(bo) > 0 {
			entry["box"] = bo[0]
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sites": out})
}

func (s *Server) boxOut(b store.Box) boxOut {
	o := boxOut{BoxID: b.ID, Name: b.Name, State: string(state.Online), AgentVersion: b.AgentVersion, NetbirdStatus: b.NetbirdStatus, NetbirdIP: b.NetbirdIP}
	if bs, ok := s.Engine.BoxState(b.ID); ok {
		o.State = string(bs.Status)
		if !bs.LastHeartbeat.IsZero() {
			t := bs.LastHeartbeat
			o.LastHeartbeat = &t
		}
	}
	return o
}

type checkOut struct {
	Type      string `json:"type"`
	OK        bool   `json:"ok"`
	LatencyMS *int64 `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

type hostOut struct {
	HostID       string     `json:"host_id"`
	SiteID       string     `json:"site_id"`
	BoxID        string     `json:"box_id"`
	Name         string     `json:"name"`
	IP           string     `json:"ip"`
	MAC          string     `json:"mac,omitempty"`
	Vendor       string     `json:"vendor,omitempty"`
	State        string     `json:"state"`
	Since        *time.Time `json:"since"`
	LastCheck    *time.Time `json:"last_check"`
	Checks       []checkOut `json:"checks"`
	ParentHostID string     `json:"parent_host_id,omitempty"`
	IsUplink     bool       `json:"is_uplink"`
	SuppressedBy string     `json:"suppressed_by,omitempty"`
}

func (s *Server) hostOut(v core.HostView) hostOut {
	o := hostOut{HostID: v.ID, SiteID: v.SiteID, BoxID: v.BoxID, Name: v.Name, IP: v.Address, MAC: v.MAC, Vendor: v.Vendor,
		ParentHostID: v.ParentID, IsUplink: v.IsUplink, SuppressedBy: v.Suppressed, Checks: []checkOut{}}
	o.State = string(v.State.Observed)
	if o.State == "" {
		o.State = string(state.Unknown)
	}
	if v.Suppressed == "maintenance" {
		o.State = "maintenance"
	}
	if !v.State.Since.IsZero() {
		t := v.State.Since
		o.Since = &t
	}
	if !v.State.LastBoxTime.IsZero() {
		t := v.State.LastBoxTime
		o.LastCheck = &t
	}
	for _, c := range v.State.LastChecks {
		o.Checks = append(o.Checks, checkOut{Type: c.Type, OK: c.OK, LatencyMS: c.LatencyMS, Error: c.Error})
	}
	return o
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !s.requireTenant(w, r, tenantID) {
		return
	}
	views, err := s.Engine.HostViews(r.Context(), tenantID)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []hostOut{}
	for _, v := range views {
		out = append(out, s.hostOut(v))
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}

func (s *Server) host(w http.ResponseWriter, r *http.Request) {
	v, err := s.Engine.HostView(r.Context(), r.PathValue("host_id"))
	if err != nil || !allowed(tokenFrom(r), v.TenantID) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown host")
		return
	}
	now := s.Now()
	from := now.Add(-24 * time.Hour)
	rollups, err := s.Store.Rollups(r.Context(), v.TenantID, v.ID, from, now)
	if err != nil {
		s.fail(w, err)
		return
	}
	var rounds, failed int
	for _, ru := range rollups {
		rounds += ru.Rounds
		failed += ru.Failed
	}
	availability := 100.0
	if rounds > 0 {
		availability = 100 * float64(rounds-failed) / float64(rounds)
	}
	evs, err := s.Store.Events(r.Context(), v.TenantID, from, now.Add(time.Minute), v.ID, 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	type outage struct {
		From     time.Time  `json:"from"`
		To       *time.Time `json:"to"`
		Duration int64      `json:"duration_s"`
	}
	outages := []outage{}
	var open *outage
	if v.State.Observed == state.Down && !v.State.DownSince.IsZero() && v.State.DownSince.Before(from) {
		open = &outage{From: v.State.DownSince}
	}
	for _, e := range evs {
		switch e.Type {
		case event.HostDown:
			start := e.OccurredAt
			if e.Since != nil {
				start = *e.Since
			}
			open = &outage{From: start}
		case event.HostUp:
			if open != nil {
				end := e.OccurredAt
				if e.Since != nil {
					end = *e.Since
				}
				open.To = &end
				open.Duration = int64(end.Sub(open.From) / time.Second)
				outages = append(outages, *open)
				open = nil
			}
		}
	}
	if open != nil {
		open.Duration = int64(now.Sub(open.From) / time.Second)
		outages = append(outages, *open)
	}
	out := map[string]any{
		"host": s.hostOut(v),
		"last_24h": map[string]any{
			"availability_percent": availability,
			"rounds":               rounds,
			"failed_rounds":        failed,
			"outages":              outages,
		},
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !s.requireTenant(w, r, tenantID) {
		return
	}
	since, ok := parseSince(w, r)
	if !ok {
		return
	}
	devs, err := s.Store.Devices(r.Context(), tenantID, "", since)
	if err != nil {
		s.fail(w, err)
		return
	}
	hosts, err := s.Store.Hosts(r.Context(), tenantID, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	monitored := map[string]bool{}
	for _, h := range hosts {
		if h.DeviceID != "" {
			monitored["id:"+h.DeviceID] = true
		}
		if h.MAC != "" {
			monitored["mac:"+strings.ToLower(h.MAC)] = true
		}
		monitored["ip:"+h.SiteID+"/"+h.Address] = true
	}
	out := []map[string]any{}
	for _, d := range devs {
		out = append(out, map[string]any{
			"device_id": d.ID, "site_id": d.SiteID, "ip": d.IP, "mac": d.MAC, "vendor": d.Vendor, "hostname": d.Hostname,
			"first_seen": d.FirstSeen, "last_seen": d.LastSeen, "gone": d.GoneAt != nil, "ignored": d.Ignored,
			"monitored": monitored["id:"+d.ID] || monitored["mac:"+d.MAC] || monitored["ip:"+d.SiteID+"/"+d.IP],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !s.requireTenant(w, r, tenantID) {
		return
	}
	since, ok := parseSince(w, r)
	if !ok {
		return
	}
	if since.IsZero() {
		since = s.Now().Add(-24 * time.Hour)
	}
	evs, err := s.Store.Events(r.Context(), tenantID, since, s.Now().Add(time.Minute), "", 500)
	if err != nil {
		s.fail(w, err)
		return
	}
	if evs == nil {
		evs = []event.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs})
}

// ---- writes: maintenance and test ping ---------------------------------------------------

type maintenanceReq struct {
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

func (s *Server) hostMaintenance(w http.ResponseWriter, r *http.Request) {
	v, err := s.Engine.HostView(r.Context(), r.PathValue("host_id"))
	if err != nil || !allowed(tokenFrom(r), v.TenantID) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown host")
		return
	}
	var req maintenanceReq
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Engine.StartMaintenance(r.Context(), store.Maintenance{TenantID: v.TenantID, SiteID: v.SiteID, Scope: "host", TargetID: v.ID, Until: req.Until, Reason: req.Reason}, "api:"+tokenFrom(r).Name); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) hostMaintenanceEnd(w http.ResponseWriter, r *http.Request) {
	v, err := s.Engine.HostView(r.Context(), r.PathValue("host_id"))
	if err != nil || !allowed(tokenFrom(r), v.TenantID) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown host")
		return
	}
	s.endWindows(w, r, v.ID)
}

func (s *Server) siteMaintenance(w http.ResponseWriter, r *http.Request) {
	site, err := s.Store.Site(r.Context(), r.PathValue("site_id"))
	if err != nil || !allowed(tokenFrom(r), site.TenantID) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown site")
		return
	}
	var req maintenanceReq
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Engine.StartMaintenance(r.Context(), store.Maintenance{TenantID: site.TenantID, SiteID: site.ID, Scope: "site", TargetID: site.ID, Until: req.Until, Reason: req.Reason}, "api:"+tokenFrom(r).Name); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteMaintenanceEnd(w http.ResponseWriter, r *http.Request) {
	site, err := s.Store.Site(r.Context(), r.PathValue("site_id"))
	if err != nil || !allowed(tokenFrom(r), site.TenantID) {
		writeErr(w, http.StatusNotFound, "not_found", "unknown site")
		return
	}
	s.endWindows(w, r, site.ID)
}

func (s *Server) endWindows(w http.ResponseWriter, r *http.Request, targetID string) {
	for _, m := range s.Engine.MaintenanceFor(targetID) {
		if err := s.Engine.EndMaintenance(r.Context(), m.ID, "api:"+tokenFrom(r).Name); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.fail(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) webhookTest(w http.ResponseWriter, r *http.Request) {
	tok := tokenFrom(r)
	target, err := s.Store.WebhookTarget(r.Context(), r.PathValue("target_id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "unknown target")
		return
	}
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
	}
	tenantID := req.TenantID
	if tenantID == "" && target.TenantScope != "*" {
		tenantID = target.TenantScope
	}
	if tenantID == "" {
		all, err := s.Store.Tenants(r.Context())
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, t := range all {
			if allowed(tok, t.ID) {
				tenantID = t.ID
				break
			}
		}
	}
	if tenantID == "" || !allowed(tok, tenantID) {
		writeErr(w, http.StatusConflict, "no_tenant", "no tenant in scope for the test event")
		return
	}
	ev, err := s.Engine.TestPing(r.Context(), tenantID, target.ID, "api:"+tok.Name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"event_id": ev.ID})
}

// ---- helpers -------------------------------------------------------------------------------

func parseSince(w http.ResponseWriter, r *http.Request) (time.Time, bool) {
	raw := r.URL.Query().Get("since")
	if raw == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "since must be RFC 3339")
		return time.Time{}, false
	}
	return t, true
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

// ---- sources (ADR-0023) ------------------------------------------------------------------

// sourceEvents takes a post of the source the token belongs to.
func (s *Server) sourceEvents(w http.ResponseWriter, r *http.Request) {
	var post core.SourcePost
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&post); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body is not a source post")
		return
	}
	if len(post.Events) > core.MaxSourceEvents {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_many", "at most 500 events per post")
		return
	}
	n, err := s.Engine.SourceReport(r.Context(), tokenFrom(r), post)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": len(post.Events), "stored": n})
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log.Error("api", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal", "request failed")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}
