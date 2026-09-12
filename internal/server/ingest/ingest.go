// Package ingest is the only public surface of an EX0 server (ADR-0002): the mTLS
// listener with enrollment, heartbeat, config pull, NetBird hand-over and update
// metadata. Every route except /v1/enroll requires a verified, unrevoked box
// certificate; identity comes from the certificate, never from the payload.
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// Body limits.
const (
	maxEnrollBody    = 64 << 10
	maxHeartbeatBody = 1 << 20
	maxHosts         = 1000
)

// Server holds the handlers of the ingest listener.
type Server struct {
	Engine *core.Engine
	Store  *store.Store
	CA     *pki.CA
	Log    *slog.Logger
	Now    func() time.Time
	// Version is what agents are compared against (ADR-0002); defaults to this build.
	Version version.Semver

	enrollLimit *limiter
	boxLimit    *limiter
}

// New wires the ingest handlers.
func New(eng *core.Engine, st *store.Store, ca *pki.CA, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{Engine: eng, Store: st, CA: ca, Log: log, Now: time.Now, Version: version.Current()}
	s.enrollLimit = newLimiter(5, 5, func() time.Time { return s.Now() })
	s.boxLimit = newLimiter(10, 30, func() time.Time { return s.Now() })
	return s
}

// Handler returns the complete route table. Unknown paths answer 404 with an
// empty body; there is no index and nothing that could reach the overlay.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.enroll)
	mux.Handle("POST /v1/renew", s.box(s.renew))
	mux.Handle("POST /v1/heartbeat", s.box(s.heartbeat))
	mux.Handle("GET /v1/config", s.box(s.config))
	mux.Handle("POST /v1/netbird/claim", s.box(s.netbirdClaim))
	mux.Handle("GET /v1/update", s.box(s.update))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	return mux
}

type ctxKey int

const boxKey ctxKey = 1

func boxFrom(r *http.Request) store.Box {
	b, _ := r.Context().Value(boxKey).(store.Box)
	return b
}

// box is the middleware for every route but enrollment.
func (s *Server) box(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "client certificate required")
			return
		}
		cert := r.TLS.PeerCertificates[0]
		boxID, err := pki.BoxIDFromCert(cert)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "certificate is not a box certificate")
			return
		}
		serial := cert.SerialNumber.Text(16)
		if s.Engine.IsRevoked(serial) {
			writeErr(w, http.StatusForbidden, wire.ErrRevoked, "certificate revoked")
			return
		}
		b, err := s.Store.Box(r.Context(), boxID)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, wire.ErrUnauthorized, "unknown box")
			return
		}
		if b.RevokedAt != nil {
			writeErr(w, http.StatusForbidden, wire.ErrRevoked, "box revoked")
			return
		}
		if !s.boxLimit.allow(boxID) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "slow down")
			return
		}
		if v := r.Header.Get(wire.HeaderAgentVersion); v != "" {
			av, err := version.Parse(v)
			if err != nil {
				writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, "bad agent version header")
				return
			}
			if !version.Compatible(av, s.Version) {
				info, _ := s.updateInfo(r.Context(), b, b.OS, b.Arch, v)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUpgradeRequired)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": wire.ErrUpgradeRequired, "message": "agent version outside the compatibility window", "update": info,
				})
				return
			}
		}
		next(w, r.WithContext(context.WithValue(r.Context(), boxKey, b)))
	})
}

// enroll turns a one-time key and a CSR into a box identity (ADR-0010).
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.enrollLimit.allow(ip) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, wire.ErrRateLimited, "slow down")
		return
	}
	var req wire.EnrollRequest
	if err := decode(r, maxEnrollBody, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, err.Error())
		return
	}
	key, err := pki.ParseEnrollmentKey(req.Key)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, "malformed enrollment key")
		return
	}
	csrPEM := []byte(req.CSR)
	if _, err := pki.ParseCSRPEM(csrPEM); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, err.Error())
		return
	}
	now := s.Now()
	boxID := id.New("box")
	certPEM, cert, err := s.CA.IssueBox(csrPEM, boxID, pki.BoxCertValidity)
	if err != nil {
		s.Log.Error("enroll: issuing certificate", "err", err)
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "certificate issue failed")
		return
	}
	ek, err := s.Store.UseEnrollmentKey(r.Context(), key.SecretHash(), boxID, now)
	if err != nil {
		if errors.Is(err, store.ErrKeyInvalid) {
			s.Log.Warn("enroll: invalid key", "ip", ip, "key_prefix", prefix(key.Secret, 6))
			writeErr(w, http.StatusUnauthorized, wire.ErrKeyInvalid, "enrollment key unknown, used, expired or revoked")
			return
		}
		s.Log.Error("enroll: key", "err", err)
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "enrollment failed")
		return
	}
	b := store.Box{ID: boxID, HWID: prefix(req.HWID, 64), AgentVersion: req.AgentVersion, OS: prefix(req.OS, 16), Arch: prefix(req.Arch, 16),
		CertSerial: cert.SerialNumber.Text(16), CertNotAfter: cert.NotAfter, EnrolledAt: now}
	if err := s.Store.CreateBox(r.Context(), b); err != nil {
		s.Log.Error("enroll: creating box", "err", err)
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "enrollment failed")
		return
	}
	s.Engine.RegisterBox(b)
	if ek.SiteID != "" {
		// a key made for a site: the box lands there by itself (ADR-0017); the tenant
		// comes from the key record on the server, never from the box
		if err := s.Engine.AssignBox(r.Context(), boxID, ek.SiteID, "key "+ek.ID); err != nil {
			s.Log.Warn("enroll: pre-assignment failed", "box", boxID, "site", ek.SiteID, "err", err)
		}
	}
	_ = s.Store.Audit(r.Context(), now, "ingest", "box.enroll", boxID, "key "+ek.ID+" hw "+b.HWID+" from "+ip)
	s.Log.Info("box enrolled", "box", boxID, "key", ek.ID, "ip", ip)
	writeJSON(w, http.StatusOK, wire.EnrollResponse{BoxID: boxID, Certificate: string(certPEM), CA: string(s.CA.CertPEM()), NotAfter: cert.NotAfter})
}

// renew issues a fresh certificate for a box that presents its current one.
func (s *Server) renew(w http.ResponseWriter, r *http.Request) {
	b := boxFrom(r)
	var req wire.RenewRequest
	if err := decode(r, maxEnrollBody, &req); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, err.Error())
		return
	}
	certPEM, cert, err := s.CA.IssueBox([]byte(req.CSR), b.ID, pki.BoxCertValidity)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, err.Error())
		return
	}
	if err := s.Store.UpdateBoxCert(r.Context(), b.ID, cert.SerialNumber.Text(16), cert.NotAfter); err != nil {
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "renewal failed")
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), "ingest", "box.renew", b.ID, "serial "+cert.SerialNumber.Text(16))
	writeJSON(w, http.StatusOK, wire.RenewResponse{Certificate: string(certPEM), NotAfter: cert.NotAfter})
}

// heartbeat is the once-a-minute report.
func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	b := boxFrom(r)
	var hb wire.Heartbeat
	if err := decode(r, maxHeartbeatBody, &hb); err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, err.Error())
		return
	}
	if len(hb.Hosts) > maxHosts {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, "too many hosts")
		return
	}
	for i := range hb.Hosts {
		if len(hb.Hosts[i].Rounds) > wire.MaxRoundsPerHost {
			hb.Hosts[i].Rounds = hb.Hosts[i].Rounds[len(hb.Hosts[i].Rounds)-wire.MaxRoundsPerHost:]
		}
	}
	// where the heartbeat comes from is the site's public address (ADR-0018, outside view)
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && ip != b.PublicIP && b.Role != store.RoleOutpost {
		if err := s.Store.SetBoxPublicIP(r.Context(), b.ID, ip); err == nil {
			b.PublicIP = ip
		}
	}
	resp, err := s.Engine.Heartbeat(r.Context(), b, hb)
	if err != nil {
		s.Log.Error("heartbeat", "box", b.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "heartbeat not processed")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// config serves the pulled configuration with ETag support.
func (s *Server) config(w http.ResponseWriter, r *http.Request) {
	b := boxFrom(r)
	cfg, err := s.Engine.Config(r.Context(), b)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "config unavailable")
		return
	}
	etag := `"` + cfg.Version + `"`
	w.Header().Set("ETag", etag)
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// netbirdClaim hands the NetBird setup key over exactly once.
func (s *Server) netbirdClaim(w http.ResponseWriter, r *http.Request) {
	b := boxFrom(r)
	if b.SiteID == "" {
		writeErr(w, http.StatusConflict, wire.ErrNotAssigned, "box is not assigned")
		return
	}
	profile := r.URL.Query().Get("profile")
	if profile == "" {
		profile = wire.NetbirdProfileCustomer
	}
	if profile != wire.NetbirdProfileCustomer && profile != wire.NetbirdProfileOperator {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, "profile must be customer or operator")
		return
	}
	k, err := s.Store.ClaimNetbirdKeyProfile(r.Context(), b.ID, profile, s.Now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, wire.ErrNothingPending, "no NetBird key pending")
			return
		}
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "claim failed")
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), "ingest", "netbird.claim", b.ID, profile+" "+k.ManagementURL)
	writeJSON(w, http.StatusOK, wire.NetbirdClaimResponse{Profile: profile, ManagementURL: k.ManagementURL, SetupKey: k.SetupKey})
}

// update serves release metadata for the box's channel, or 204.
func (s *Server) update(w http.ResponseWriter, r *http.Request) {
	b := boxFrom(r)
	osName, arch := r.URL.Query().Get("os"), r.URL.Query().Get("arch")
	if osName != "linux" || (arch != "amd64" && arch != "arm64") {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest, "os must be linux, arch amd64 or arm64")
		return
	}
	info, err := s.updateInfo(r.Context(), b, osName, arch, r.Header.Get(wire.HeaderAgentVersion))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal, "update lookup failed")
		return
	}
	if info == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) updateInfo(ctx context.Context, b store.Box, osName, arch, agentVersion string) (*wire.UpdateInfo, error) {
	channel := b.Channel
	if channel == "" {
		channel = wire.ChannelStable
	}
	v, err := s.Store.ChannelVersion(ctx, channel)
	if err != nil {
		return nil, err
	}
	if v == "" || v == strings.TrimPrefix(agentVersion, "v") {
		return nil, nil //nolint:nilnil // nothing to update to
	}
	rel, err := s.Store.Release(ctx, v, osName, arch)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil //nolint:nilnil
	}
	if err != nil {
		return nil, err
	}
	return &wire.UpdateInfo{Version: rel.Version, URL: rel.URL, SHA256: rel.SHA256, Signature: rel.Signature, MinAgentVersion: rel.MinAgentVersion}, nil
}

// ---- helpers -------------------------------------------------------------------------

func decode(r *http.Request, limit int64, v any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return errors.New("content type must be application/json")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, limit+1))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, wire.Error{Error: code, Message: msg})
}

func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
