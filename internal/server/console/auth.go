package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/auth"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/store"
)

// Session policy (ADR-0011).
const (
	cookieName      = "excubra_session"
	loginCookieName = "excubra_login" // step one passed, step two pending
	sessionIdle     = 12 * time.Hour
	sessionAbsolute = 7 * 24 * time.Hour
	pendingFor      = 5 * time.Minute
	lockAfter       = 5
	lockFor         = 15 * time.Minute
	loginFailedMsg  = "Anmeldung fehlgeschlagen."
	codeFailedMsg   = "Der Code passt nicht. Die App zeigt alle 30 Sekunden einen neuen."
)

type ctxKey int

const (
	sessionKey ctxKey = iota
	userKey
)

// pendingLogin is a login that passed the password and waits for the second factor.
// It lives in memory only: a restart simply sends the person back to step one.
type pendingLogin struct {
	UserID  string
	Expires time.Time
}

func sessionFrom(r *http.Request) store.Session {
	s, _ := r.Context().Value(sessionKey).(store.Session)
	return s
}

func userFrom(r *http.Request) *store.User {
	u, _ := r.Context().Value(userKey).(*store.User)
	return u
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// auth requires a live session and, for state-changing methods, the CSRF token.
func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value == "" {
			s.toLogin(w, r)
			return
		}
		ctx := r.Context()
		now := s.Now()
		hash := hashToken(c.Value)
		sess, err := s.Store.Session(ctx, hash)
		if err != nil || now.Sub(sess.LastSeen) > sessionIdle || now.Sub(sess.CreatedAt) > sessionAbsolute {
			if err == nil {
				_ = s.Store.DeleteSession(ctx, hash)
			}
			s.clearCookie(w)
			s.toLogin(w, r)
			return
		}
		u, err := s.Store.User(ctx, sess.UserID)
		if err != nil || u.Disabled {
			_ = s.Store.DeleteSession(ctx, hash)
			s.clearCookie(w)
			s.toLogin(w, r)
			return
		}
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			// Parse the form here for every write: the handlers read r.PostForm directly,
			// whether the token arrived as a form field (templates) or a header (the app).
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.PostForm.Get("csrf")
			}
			if tok == "" || tok != sess.CSRF {
				const msg = "CSRF-Token fehlt oder passt nicht — Seite neu laden."
				if wantsJSON(r) {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": msg})
					return
				}
				http.Error(w, msg, http.StatusForbidden)
				return
			}
		}
		_ = s.Store.TouchSession(ctx, hash, now)
		ctx = context.WithValue(ctx, sessionKey, sess)
		ctx = context.WithValue(ctx, userKey, &u)
		next(w, r.WithContext(ctx))
	})
}

func (s *Server) toLogin(w http.ResponseWriter, r *http.Request) {
	if wantsJSON(r) {
		// The app sends the browser to /login itself when it sees a 401.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "nicht angemeldet"})
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) setCookie(w http.ResponseWriter, value string, maxAge int) {
	//nolint:gosec // Secure follows EXCUBRA_OVERLAY_TLS (ADR-0011); plain HTTP exists only inside the encrypted overlay
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: value, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

func (s *Server) clearCookie(w http.ResponseWriter) { s.setCookie(w, "", -1) }

func (s *Server) setLoginCookie(w http.ResponseWriter, value string, maxAge int) {
	//nolint:gosec // same policy as the session cookie
	http.SetCookie(w, &http.Cookie{Name: loginCookieName, Value: value, Path: "/login", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

// ---- pending logins (between password and code) -----------------------------------------

var pendingMu sync.Mutex

func (s *Server) putPending(hash, userID string, now time.Time) {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	if s.pending == nil {
		s.pending = map[string]pendingLogin{}
	}
	for k, p := range s.pending { // keep the map small
		if now.After(p.Expires) {
			delete(s.pending, k)
		}
	}
	s.pending[hash] = pendingLogin{UserID: userID, Expires: now.Add(pendingFor)}
}

func (s *Server) takePending(r *http.Request, now time.Time, consume bool) (pendingLogin, bool) {
	c, err := r.Cookie(loginCookieName)
	if err != nil || c.Value == "" {
		return pendingLogin{}, false
	}
	pendingMu.Lock()
	defer pendingMu.Unlock()
	p, ok := s.pending[hashToken(c.Value)]
	if !ok || now.After(p.Expires) {
		delete(s.pending, hashToken(c.Value))
		return pendingLogin{}, false
	}
	if consume {
		delete(s.pending, hashToken(c.Value))
	}
	return p, true
}

func (s *Server) dropPending(r *http.Request) {
	if c, err := r.Cookie(loginCookieName); err == nil && c.Value != "" {
		pendingMu.Lock()
		delete(s.pending, hashToken(c.Value))
		pendingMu.Unlock()
	}
}

// ---- pages ----------------------------------------------------------------------------------

type loginData struct {
	Step  string // credentials | code
	Error string
	User  string
	TLS   bool
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, d loginData) {
	d.TLS = s.Secure
	t := s.pages["login"]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", page{Title: "Anmelden", Path: r.URL.Path, Data: d}); err != nil {
		s.Log.Error("console: render login", "err", err)
	}
}

// loginPage is step one; opening it starts over.
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.dropPending(r)
	s.setLoginCookie(w, "", -1)
	s.renderLogin(w, r, loginData{Step: "credentials"})
}

// loginSubmit checks the password with one generic error for every failure mode and
// locks the account after repeated failures; a correct password leads to the code step.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, loginData{Step: "credentials", Error: loginFailedMsg})
		return
	}
	ctx := r.Context()
	now := s.Now()
	name := strings.TrimSpace(r.PostForm.Get("user"))
	password := r.PostForm.Get("password")
	u, err := s.Store.UserByName(ctx, name)
	if err != nil || u.Disabled {
		// still burn the time a real check would take
		_ = auth.VerifyPassword("pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
		s.renderLogin(w, r, loginData{Step: "credentials", Error: loginFailedMsg})
		return
	}
	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		s.renderLogin(w, r, loginData{Step: "credentials", Error: loginFailedMsg})
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, password) {
		s.noteFailure(ctx, u, now, r)
		s.renderLogin(w, r, loginData{Step: "credentials", Error: loginFailedMsg})
		return
	}
	raw := id.Secret(32)
	s.putPending(hashToken(raw), u.ID, now)
	s.setLoginCookie(w, raw, int(pendingFor/time.Second))
	http.Redirect(w, r, "/login/code", http.StatusSeeOther)
}

// loginCodePage is step two: the code from the authenticator app.
func (s *Server) loginCodePage(w http.ResponseWriter, r *http.Request) {
	p, ok := s.takePending(r, s.Now(), false)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	u, err := s.Store.User(r.Context(), p.UserID)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.renderLogin(w, r, loginData{Step: "code", User: u.Name})
}

func (s *Server) loginCodeSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.Now()
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	p, ok := s.takePending(r, now, false)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	u, err := s.Store.User(ctx, p.UserID)
	if err != nil || u.Disabled || (u.LockedUntil != nil && u.LockedUntil.After(now)) {
		s.dropPending(r)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	code := strings.TrimSpace(strings.ReplaceAll(r.PostForm.Get("totp"), " ", ""))
	counter, totpOK := auth.VerifyTOTP(u.TOTPSecret, code, now, u.TOTPLastCounter)
	if !totpOK {
		locked := s.noteFailure(ctx, u, now, r)
		if locked {
			s.dropPending(r)
			s.setLoginCookie(w, "", -1)
			s.renderLogin(w, r, loginData{Step: "credentials", Error: loginFailedMsg})
			return
		}
		s.renderLogin(w, r, loginData{Step: "code", User: u.Name, Error: codeFailedMsg})
		return
	}
	if err := s.Store.UpdateUserLoginState(ctx, u.ID, 0, nil, counter); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	s.takePending(r, now, true)
	s.setLoginCookie(w, "", -1)
	raw := id.Secret(32)
	sess := store.Session{TokenHash: hashToken(raw), UserID: u.ID, CSRF: id.Secret(24), CreatedAt: now, LastSeen: now, IP: clientIP(r)}
	if err := s.Store.CreateSession(ctx, sess); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, now, "console:"+u.Name, "login", u.ID, clientIP(r))
	s.setCookie(w, raw, int(sessionAbsolute/time.Second))
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

// noteFailure counts a failed password or code and locks after lockAfter of them.
func (s *Server) noteFailure(ctx context.Context, u store.User, now time.Time, r *http.Request) (locked bool) {
	failed := u.FailedLogins + 1
	var until *time.Time
	if failed >= lockAfter {
		t := now.Add(lockFor)
		until = &t
		failed = 0
		locked = true
	}
	_ = s.Store.UpdateUserLoginState(ctx, u.ID, failed, until, u.TOTPLastCounter)
	_ = s.Store.Audit(ctx, now, "console", "login.failed", u.ID, clientIP(r))
	return locked
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.Store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	s.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// caCert hands out the internal CA certificate so a browser can trust the overlay TLS.
func (s *Server) caCert(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="ex0-ca.crt"`)
	_, _ = w.Write(s.CA.CertPEM())
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
