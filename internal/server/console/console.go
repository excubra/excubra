// Package console is the operator UI (salt: "Konsole — Phase 1", ADR-0011):
// server-rendered html/template pages with a vendored htmx for the few live
// updates, reachable only on the overlay listener. It is a tool, not a product.
package console

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// The single-page console (web/), built with Vite into webdist/ before `go build`.
//
//go:embed webdist
var webdistFS embed.FS

// Server holds the console handlers.
type Server struct {
	Engine   *core.Engine
	Store    *store.Store
	CA       *pki.CA
	Log      *slog.Logger
	Now      func() time.Time
	Loc      *time.Location
	Secure   bool   // set the Secure flag on cookies (overlay TLS on)
	Ingest   string // host of the ingest, for enrollment keys
	IngestPt int

	pages    map[string]*template.Template
	partials *template.Template

	flashMu sync.Mutex
	flashes map[string]string       // session hash → message
	pending map[string]pendingLogin // login cookie hash → passed step one
}

// New wires the console. ingestHost/ingestPort go into enrollment keys.
func New(eng *core.Engine, st *store.Store, ca *pki.CA, log *slog.Logger, loc *time.Location, ingestHost string, ingestPort int) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	if loc == nil {
		loc = time.UTC
	}
	s := &Server{Engine: eng, Store: st, CA: ca, Log: log, Now: time.Now, Loc: loc, Ingest: ingestHost, IngestPt: ingestPort, flashes: map[string]string{}}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"ts": func(t time.Time) string {
			if t.IsZero() {
				return "–"
			}
			return t.In(s.Loc).Format("02.01.2006 15:04:05")
		},
		"tsp": func(t *time.Time) string {
			if t == nil || t.IsZero() {
				return "–"
			}
			return t.In(s.Loc).Format("02.01.2006 15:04:05")
		},
		"ago": func(t time.Time) string { return ago(t, s.Now()) },
		"agop": func(t *time.Time) string {
			if t == nil {
				return "–"
			}
			return ago(*t, s.Now())
		},
		"dur":     func(d time.Duration) string { return humanDur(d) },
		"join":    strings.Join,
		"version": func() string { return version.Version },
		"lower":   strings.ToLower,
		"inputTime": func(t time.Time) string { // for <input type=datetime-local>
			if t.IsZero() {
				return ""
			}
			return t.In(s.Loc).Format("2006-01-02T15:04")
		},
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"gb":  func(b uint64) string { return fmt.Sprintf("%.1f", float64(b)/1e9) },
		"pct": func(f float64) string { return fmt.Sprintf("%.1f", f) },
		"short": func(s string) string {
			if i := strings.Index(s, "_"); i >= 0 && len(s) > i+9 {
				return s[:i+9] + "…"
			}
			return s
		},
		"has":    func(s, sub string) bool { return strings.Contains(s, sub) },
		"mod":    func(a, b int) int { return a % b },
		"mulDur": func(secs int64) time.Duration { return time.Duration(secs) * time.Second },
		"initial": func(s string) string {
			if s == "" {
				return "?"
			}
			return strings.ToUpper(s[:1])
		},
		"unix": func(t time.Time) int64 {
			if t.IsZero() {
				return 0
			}
			return t.Unix()
		},
		"deref": func(t *time.Time) time.Time {
			if t == nil {
				return time.Time{}
			}
			return *t
		},
		"tsShort": func(t time.Time) string {
			if t.IsZero() {
				return "–"
			}
			return t.In(s.Loc).Format("02.01. 15:04")
		},
		"cleanName": cleanHostname,
		"chart":     areaSVG,
		"tsTime": func(t time.Time) string {
			if t.IsZero() {
				return "–"
			}
			return t.In(s.Loc).Format("15:04:05")
		},
	}
}

func (s *Server) parseTemplates() error {
	names := []string{"login", "status", "host", "boxes", "box", "tenants", "site", "events", "users", "maintenance", "webhooks", "keys", "tokens", "audit", "error"}
	s.pages = map[string]*template.Template{}
	for _, n := range names {
		t, err := template.New("layout.html").Funcs(s.funcs()).ParseFS(templatesFS, "templates/layout.html", "templates/_status_table.html", "templates/"+n+".html")
		if err != nil {
			return fmt.Errorf("console: template %s: %w", n, err)
		}
		s.pages[n] = t
	}
	p, err := template.New("partials").Funcs(s.funcs()).ParseFS(templatesFS, "templates/_status_table.html")
	if err != nil {
		return fmt.Errorf("console: partials: %w", err)
	}
	s.partials = p
	return nil
}

// Handler returns the console routes. Everything but /login and /static needs a session.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /login/code", s.loginCodePage)
	mux.HandleFunc("POST /login/code", s.loginCodeSubmit)
	mux.HandleFunc("GET /ca.crt", s.caCert)
	mux.Handle("POST /logout", s.auth(s.logout))

	mux.Handle("GET /{$}", s.auth(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/app/", http.StatusFound) }))
	mux.Handle("GET /app/{path...}", s.auth(s.spa)) // also matches /app/ itself
	mux.Handle("GET /api/me", s.auth(s.apiMe))
	mux.Handle("GET /api/overview", s.auth(s.apiOverview))
	mux.Handle("GET /api/search", s.auth(s.apiSearch))
	mux.Handle("GET /api/tenants", s.auth(s.apiTenants))
	mux.Handle("GET /api/tenants/{id}", s.auth(s.apiTenant))
	mux.Handle("POST /api/tenants", s.auth(s.tenantCreate))
	mux.Handle("POST /api/tenants/{id}/sites", s.auth(s.siteCreate))
	mux.Handle("GET /api/sites/{id}", s.auth(s.apiSite))
	mux.Handle("GET /api/devices/{id}", s.auth(s.apiDevice))
	mux.Handle("POST /api/devices/{id}/watch", s.auth(s.deviceWatch))
	mux.Handle("POST /api/devices/{id}/monitor", s.auth(s.deviceMonitor))
	mux.Handle("POST /api/devices/{id}/ignore", s.auth(s.deviceIgnore))
	mux.Handle("GET /api/hosts/{id}", s.auth(s.apiHost))
	mux.Handle("POST /api/hosts/{id}", s.auth(s.hostUpdate))
	mux.Handle("POST /api/hosts/{id}/unwatch", s.auth(s.hostUnwatch))
	mux.Handle("POST /api/hosts/{id}/uplink", s.auth(s.hostUplink))
	mux.Handle("POST /api/hosts/{id}/delete", s.auth(s.hostDelete))
	mux.Handle("POST /api/hosts/{id}/maintenance", s.auth(s.hostMaintenance))
	mux.Handle("GET /api/events", s.auth(s.apiEvents))
	mux.Handle("GET /api/boxes", s.auth(s.apiBoxes))
	mux.Handle("GET /api/boxes/{id}", s.auth(s.apiBox))
	mux.Handle("POST /api/boxes/{id}/assign", s.auth(s.boxAssign))
	mux.Handle("POST /api/boxes/{id}/settings", s.auth(s.boxSettings))
	mux.Handle("POST /api/boxes/{id}/netbird", s.auth(s.boxNetbird))
	mux.Handle("POST /api/boxes/{id}/revoke", s.auth(s.boxRevoke))
	mux.Handle("POST /api/boxes/{id}/delete", s.auth(s.boxDelete))
	mux.Handle("GET /api/maintenance", s.auth(s.apiMaintenance))
	mux.Handle("POST /api/maintenance", s.auth(s.maintenanceCreate))
	mux.Handle("POST /api/maintenance/{id}/end", s.auth(s.maintenanceEnd))
	mux.Handle("GET /api/webhooks", s.auth(s.apiWebhooks))
	mux.Handle("POST /api/webhooks", s.auth(s.webhookCreate))
	mux.Handle("POST /api/webhooks/{id}", s.auth(s.webhookUpdate))
	mux.Handle("POST /api/webhooks/{id}/delete", s.auth(s.webhookDelete))
	mux.Handle("POST /api/webhooks/{id}/test", s.auth(s.webhookTest))
	mux.Handle("GET /api/keys", s.auth(s.apiKeys))
	mux.Handle("POST /api/keys", s.auth(s.keysCreate))
	mux.Handle("POST /api/keys/{id}/revoke", s.auth(s.keyRevoke))
	mux.Handle("GET /api/tokens", s.auth(s.apiTokens))
	mux.Handle("POST /api/tokens", s.auth(s.tokenCreate))
	mux.Handle("POST /api/tokens/{id}/revoke", s.auth(s.tokenRevoke))
	mux.Handle("GET /api/users", s.auth(s.apiUsers))
	mux.Handle("GET /api/audit", s.auth(s.apiAudit))
	mux.Handle("POST /api/logout", s.auth(s.logout))
	mux.Handle("GET /status", s.auth(s.statusPage))
	mux.Handle("GET /status/table", s.auth(s.statusTable))
	mux.Handle("GET /hosts/{id}", s.auth(s.hostPage))
	mux.Handle("POST /hosts/{id}", s.auth(s.hostUpdate))
	mux.Handle("POST /hosts/{id}/delete", s.auth(s.hostDelete))
	mux.Handle("POST /hosts/{id}/maintenance", s.auth(s.hostMaintenance))
	mux.Handle("GET /boxes", s.auth(s.boxesPage))
	mux.Handle("GET /boxes/{id}", s.auth(s.boxPage))
	mux.Handle("POST /boxes/{id}/assign", s.auth(s.boxAssign))
	mux.Handle("POST /boxes/{id}/settings", s.auth(s.boxSettings))
	mux.Handle("POST /boxes/{id}/netbird", s.auth(s.boxNetbird))
	mux.Handle("POST /boxes/{id}/revoke", s.auth(s.boxRevoke))
	mux.Handle("POST /boxes/{id}/delete", s.auth(s.boxDelete))
	mux.Handle("GET /tenants", s.auth(s.tenantsPage))
	mux.Handle("POST /tenants", s.auth(s.tenantCreate))
	mux.Handle("POST /tenants/{id}/sites", s.auth(s.siteCreate))
	mux.Handle("GET /sites/{id}", s.auth(s.sitePage))
	mux.Handle("GET /sites/{id}/inventory", s.auth(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/sites/"+r.PathValue("id")+"?tab=netz", http.StatusFound)
	}))
	mux.Handle("GET /events", s.auth(s.eventsPage))
	mux.Handle("GET /users", s.auth(s.usersPage))
	mux.Handle("POST /devices/{id}/watch", s.auth(s.deviceWatch))
	mux.Handle("POST /hosts/{id}/unwatch", s.auth(s.hostUnwatch))
	mux.Handle("POST /hosts/{id}/uplink", s.auth(s.hostUplink))
	mux.Handle("GET /devices/{id}", s.auth(s.deviceRedirect))
	mux.Handle("POST /devices/{id}/monitor", s.auth(s.deviceMonitor))
	mux.Handle("POST /devices/{id}/ignore", s.auth(s.deviceIgnore))
	mux.Handle("GET /maintenance", s.auth(s.maintenancePage))
	mux.Handle("POST /maintenance", s.auth(s.maintenanceCreate))
	mux.Handle("POST /maintenance/{id}/end", s.auth(s.maintenanceEnd))
	mux.Handle("GET /webhooks", s.auth(s.webhooksPage))
	mux.Handle("POST /webhooks", s.auth(s.webhookCreate))
	mux.Handle("POST /webhooks/{id}", s.auth(s.webhookUpdate))
	mux.Handle("POST /webhooks/{id}/delete", s.auth(s.webhookDelete))
	mux.Handle("POST /webhooks/{id}/test", s.auth(s.webhookTest))
	mux.Handle("GET /keys", s.auth(s.keysPage))
	mux.Handle("POST /keys", s.auth(s.keysCreate))
	mux.Handle("POST /keys/{id}/revoke", s.auth(s.keyRevoke))
	mux.Handle("GET /tokens", s.auth(s.tokensPage))
	mux.Handle("POST /tokens", s.auth(s.tokenCreate))
	mux.Handle("POST /tokens/{id}/revoke", s.auth(s.tokenRevoke))
	mux.Handle("GET /audit", s.auth(s.auditPage))
	return s.headers(mux)
}

// headers adds the security headers of ADR-0011 to every response.
func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		csp := "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
		if strings.HasPrefix(r.URL.Path, "/app") {
			csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
		}
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ---- rendering ---------------------------------------------------------------------

// page is the data every template sees.
type page struct {
	Title   string
	User    string
	CSRF    string
	Flash   string
	Path    string
	Data    any
	Version string
	Nav     navCounts
	Crumbs  []crumb
	Search  bool
	Clock   string
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title string, data any) {
	s.renderOpts(w, r, name, title, data, pageOpts{})
}

func (s *Server) renderOpts(w http.ResponseWriter, r *http.Request, name, title string, data any, o pageOpts) {
	sess := sessionFrom(r)
	p := page{Title: title, CSRF: sess.CSRF, Path: r.URL.Path, Data: data, Version: version.Version, Crumbs: o.Crumbs, Search: o.Search, Clock: s.Now().In(s.Loc).Format("15:04:05")}
	if u := userFrom(r); u != nil {
		p.User = u.Name
		p.Nav = s.navCounts(r.Context())
	}
	if sess.TokenHash != "" {
		p.Flash = s.takeFlash(sess.TokenHash)
	}
	t, ok := s.pages[name]
	if !ok {
		http.Error(w, "no such page", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", p); err != nil {
		s.Log.Error("console: render", "page", name, "err", err)
		http.Error(w, "Seite konnte nicht gerendert werden — Details im Server-Log.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

func (s *Server) renderPartial(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.partials.ExecuteTemplate(&buf, name, data); err != nil {
		s.Log.Error("console: render partial", "name", name, "err", err)
		http.Error(w, "Fehler", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// fail shows an error page for unexpected errors and a plain message for known ones.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error, status int) {
	if status >= 500 {
		s.Log.Error("console", "path", r.URL.Path, "err", err)
	}
	msg := err.Error()
	if status >= 500 {
		msg = "Interner Fehler — Details im Server-Log."
	}
	if errors.Is(err, store.ErrNotFound) {
		msg = "Nicht gefunden."
	}
	if wantsJSON(r) {
		writeJSON(w, status, apiErr{Error: msg})
		return
	}
	w.WriteHeader(status)
	s.render(w, r, "error", "Fehler", map[string]any{"Message": msg, "Status": status})
}

// flash stores a one-time message for the session and redirects.
func (s *Server) flash(w http.ResponseWriter, r *http.Request, msg, to string) {
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg, "to": to})
		return
	}
	if sess := sessionFrom(r); sess.TokenHash != "" {
		s.flashMu.Lock()
		s.flashes[sess.TokenHash] = msg
		s.flashMu.Unlock()
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// flashErr is flash for a request that failed validation: the templates get the same
// message and redirect, the app gets ok:false and a 400 so it shows an error toast.
func (s *Server) flashErr(w http.ResponseWriter, r *http.Request, msg, to string) {
	if wantsJSON(r) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": msg, "to": to})
		return
	}
	s.flash(w, r, msg, to)
}

func (s *Server) takeFlash(hash string) string {
	s.flashMu.Lock()
	defer s.flashMu.Unlock()
	m := s.flashes[hash]
	delete(s.flashes, hash)
	return m
}

// actor names the logged-in user for audit entries.
func actor(r *http.Request) string {
	if u := userFrom(r); u != nil {
		return "console:" + u.Name
	}
	return "console"
}

func formTime(v string, loc *time.Location) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, errors.New("Zeitpunkt fehlt")
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.ParseInLocation(layout, v, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("Zeitpunkt %q nicht lesbar", v)
}

func ago(t, now time.Time) string {
	if t.IsZero() {
		return "–"
	}
	d := now.Sub(t)
	if d < 0 {
		return "in " + humanDur(-d)
	}
	return "vor " + humanDur(d)
}

func humanDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h %d min", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%d Tage", int(d.Hours()/24))
	}
}

// spa serves the built single-page console: real files as they are (hashed assets may be
// cached for a year), everything else gets index.html so the app can route client-side.
func (s *Server) spa(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(webdistFS, "webdist")
	if err != nil {
		http.Error(w, "console app not built", http.StatusNotFound)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/app/")
	if p != "" && p != "index.html" && fs.ValidPath(p) {
		if f, err := sub.Open(p); err == nil {
			_ = f.Close()
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			http.ServeFileFS(w, r, sub, p) //nolint:gosec // p passed fs.ValidPath and sub is the embedded, read-only webdist
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		// A checkout without Node still builds: the committed placeholder says what is missing.
		b, _ := fs.ReadFile(sub, "unbuilt.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write(b)
		return
	}
	http.ServeFileFS(w, r, sub, "index.html")
}
