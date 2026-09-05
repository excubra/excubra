package console

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/auth"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/store"
)

// Session policy (ADR-0011).
const (
	cookieName      = "excubra_session"
	sessionIdle     = 12 * time.Hour
	sessionAbsolute = 7 * 24 * time.Hour
	lockAfter       = 5
	lockFor         = 15 * time.Minute
	loginFailedMsg  = "Anmeldung fehlgeschlagen."
)

type ctxKey int

const (
	sessionKey ctxKey = iota
	userKey
)

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
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				if err := r.ParseForm(); err != nil {
					http.Error(w, "bad form", http.StatusBadRequest)
					return
				}
				tok = r.PostForm.Get("csrf")
			}
			if tok == "" || tok != sess.CSRF {
				http.Error(w, "CSRF-Token fehlt oder passt nicht — Seite neu laden.", http.StatusForbidden)
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

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.renderLogin(w, r, "")
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, msg string) {
	t := s.pages["login"]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", page{Title: "Anmelden", Path: r.URL.Path, Data: map[string]any{"Error": msg}}); err != nil {
		s.Log.Error("console: render login", "err", err)
	}
}

// loginSubmit checks password and TOTP with one generic error for every failure
// mode and locks the account after repeated failures.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, loginFailedMsg)
		return
	}
	ctx := r.Context()
	now := s.Now()
	name := strings.TrimSpace(r.PostForm.Get("user"))
	password := r.PostForm.Get("password")
	code := strings.TrimSpace(r.PostForm.Get("totp"))
	u, err := s.Store.UserByName(ctx, name)
	if err != nil || u.Disabled {
		// still burn the time a real check would take
		_ = auth.VerifyPassword("pbkdf2-sha256$600000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", password)
		s.renderLogin(w, r, loginFailedMsg)
		return
	}
	if u.LockedUntil != nil && u.LockedUntil.After(now) {
		s.renderLogin(w, r, loginFailedMsg)
		return
	}
	pwOK := auth.VerifyPassword(u.PasswordHash, password)
	counter, totpOK := auth.VerifyTOTP(u.TOTPSecret, code, now, u.TOTPLastCounter)
	if !pwOK || !totpOK {
		failed := u.FailedLogins + 1
		var locked *time.Time
		if failed >= lockAfter {
			t := now.Add(lockFor)
			locked = &t
			failed = 0
		}
		_ = s.Store.UpdateUserLoginState(ctx, u.ID, failed, locked, u.TOTPLastCounter)
		_ = s.Store.Audit(ctx, now, "console", "login.failed", u.ID, clientIP(r))
		s.renderLogin(w, r, loginFailedMsg)
		return
	}
	if err := s.Store.UpdateUserLoginState(ctx, u.ID, 0, nil, counter); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
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

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.Store.DeleteSession(r.Context(), hashToken(c.Value))
	}
	s.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
