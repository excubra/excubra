package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// Request limits on the agent side. The server has its own (ADR-0002).
const (
	requestTimeout  = 30 * time.Second
	maxResponseBody = 4 << 20
)

// Client talks to the ingest. Every request is opened by the agent; the CA is
// pinned by the fingerprint from the enrollment key, system roots are never used.
type Client struct {
	server string // host:port
	http   *http.Client
}

// ServerError is a structured error response from the ingest.
type ServerError struct {
	Status  int
	Code    string
	Message string
}

func (e *ServerError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("ingest: %s (%s, HTTP %d)", e.Message, e.Code, e.Status)
	}
	return fmt.Sprintf("ingest: HTTP %d", e.Status)
}

// Retryable reports whether trying again later can succeed. An invalid enrollment
// key or a revoked certificate cannot.
func (e *ServerError) Retryable() bool {
	switch e.Code {
	case wire.ErrKeyInvalid, wire.ErrRevoked, wire.ErrUnauthorized:
		return false
	}
	return e.Status >= 500 || e.Status == http.StatusTooManyRequests
}

// NewClient builds a pinned client. cert may be nil before enrollment.
func NewClient(server, caFingerprint string, state *State) (*Client, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("agent: server address %q is not host:port: %w", server, err)
	}
	var cert *tls.Certificate
	if state != nil {
		cert = state.Certificate()
	}
	tr := &http.Transport{
		TLSClientConfig:       pki.AgentTLSConfig(caFingerprint, host, cert),
		MaxIdleConns:          2,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		ForceAttemptHTTP2:     true,
	}
	return &Client{server: server, http: &http.Client{Transport: tr, Timeout: requestTimeout}}, nil
}

// Enroll exchanges a one-time key and a CSR for a box identity (ADR-0010).
func (c *Client) Enroll(ctx context.Context, req wire.EnrollRequest) (wire.EnrollResponse, error) {
	var resp wire.EnrollResponse
	err := c.do(ctx, http.MethodPost, "/v1/enroll", req, &resp, nil)
	return resp, err
}

// Renew asks for a fresh certificate, authenticated with the current one.
func (c *Client) Renew(ctx context.Context, csrPEM string) (wire.RenewResponse, error) {
	var resp wire.RenewResponse
	err := c.do(ctx, http.MethodPost, "/v1/renew", wire.RenewRequest{CSR: csrPEM}, &resp, nil)
	return resp, err
}

// Heartbeat reports box state, check rounds and sightings.
func (c *Client) Heartbeat(ctx context.Context, hb wire.Heartbeat) (wire.HeartbeatResponse, error) {
	var resp wire.HeartbeatResponse
	err := c.do(ctx, http.MethodPost, "/v1/heartbeat", hb, &resp, nil)
	return resp, err
}

// Config pulls the configuration. etag may be empty; on 304 it returns notModified.
func (c *Client) Config(ctx context.Context, etag string) (cfg wire.Config, notModified bool, err error) {
	h := http.Header{}
	if etag != "" {
		h.Set("If-None-Match", `"`+etag+`"`)
	}
	err = c.do(ctx, http.MethodGet, "/v1/config", nil, &cfg, h)
	var se *ServerError
	if errors.As(err, &se) && se.Status == http.StatusNotModified {
		return wire.Config{}, true, nil
	}
	return cfg, false, err
}

// ClaimNetbird fetches the NetBird setup key exactly once. A missing key is not an
// error the caller needs to retry: it means the operator has not set one.
func (c *Client) ClaimNetbird(ctx context.Context, profile string) (wire.NetbirdClaimResponse, bool, error) {
	var resp wire.NetbirdClaimResponse
	err := c.do(ctx, http.MethodPost, "/v1/netbird/claim?profile="+profile, nil, &resp, nil)
	var se *ServerError
	if errors.As(err, &se) && (se.Code == wire.ErrNothingPending || se.Code == wire.ErrNotAssigned) {
		return wire.NetbirdClaimResponse{}, false, nil
	}
	if err != nil {
		return wire.NetbirdClaimResponse{}, false, err
	}
	return resp, true, nil
}

// UpdateInfo asks for release metadata for this platform; false means "nothing new".
func (c *Client) UpdateInfo(ctx context.Context, osName, arch string) (wire.UpdateInfo, bool, error) {
	var info wire.UpdateInfo
	path := "/v1/update?os=" + osName + "&arch=" + arch
	err := c.do(ctx, http.MethodGet, path, nil, &info, nil)
	var se *ServerError
	if errors.As(err, &se) && se.Status == http.StatusNoContent {
		return wire.UpdateInfo{}, false, nil
	}
	if err != nil {
		return wire.UpdateInfo{}, false, err
	}
	return info, info.Version != "", nil
}

// do performs one request. 2xx decodes into out; anything else becomes a
// *ServerError carrying the stable code from the body when there is one.
func (c *Client) do(ctx context.Context, method, path string, body, out any, header http.Header) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("agent: encoding request: %w", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+c.server+path, rd)
	if err != nil {
		return fmt.Errorf("agent: building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(wire.HeaderAgentVersion, version.Version)
	req.Header.Set("User-Agent", "excubra-agent/"+version.Version)
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified || resp.StatusCode == http.StatusNoContent {
		return &ServerError{Status: resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return fmt.Errorf("agent: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		se := &ServerError{Status: resp.StatusCode}
		var werr wire.Error
		if json.Unmarshal(raw, &werr) == nil {
			se.Code, se.Message = werr.Error, werr.Message
		}
		return se
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("agent: decoding response: %w", err)
		}
	}
	// carry the ETag out for config pulls
	if cfg, ok := out.(*wire.Config); ok && cfg.Version == "" {
		if et := resp.Header.Get("ETag"); len(et) > 2 {
			cfg.Version = et[1 : len(et)-1]
		}
	}
	return nil
}
