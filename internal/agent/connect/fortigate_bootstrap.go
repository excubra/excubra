package connect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// FortiGate bootstrap: the operator gives an admin login once, the box creates a
// read-only API user for itself (profile, user, trusted host = the box), generates
// the token and never uses the admin login again. The server gets the token sealed
// to the box's own key and drops the admin credential (ADR-0015).
//
// Names on the device are fixed so the step is idempotent: a second run finds the
// user and only generates a new key.
const (
	fgtProfile = "excubra-ro"
	fgtAPIUser = "excubra"
)

// fortigateBootstrap returns the new API token.
func fortigateBootstrap(ctx context.Context, t Target, adminUser, adminPass string) (string, error) {
	base := strings.TrimRight(t.URL, "/")
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Transport: t.Client.Transport, Timeout: t.Client.Timeout, Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// 1. web login: form post, the answer's first character says how it went
	form := url.Values{"username": {adminUser}, "secretkey": {adminPass}, "ajax": {"1"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/logincheck", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("admin login: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	code := strings.TrimSpace(string(body))
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode != 200:
		return "", fmt.Errorf("admin login: HTTP %d", resp.StatusCode)
	case strings.HasPrefix(code, "1"):
	case strings.HasPrefix(code, "0"):
		return "", errors.New("admin login refused: wrong user or password")
	case strings.HasPrefix(code, "2"):
		return "", errors.New("admin login refused: the device demands a password change first")
	default:
		return "", fmt.Errorf("admin login: unexpected answer %q", firstLine(code))
	}
	u, _ := url.Parse(base)
	csrf := ""
	for _, c := range jar.Cookies(u) {
		if strings.HasPrefix(c.Name, "ccsrftoken") {
			csrf = strings.Trim(c.Value, `"`)
		}
	}
	if csrf == "" {
		return "", errors.New("admin login gave no CSRF token")
	}
	defer func() { // best effort logout, the session would expire anyway
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/logout", nil); err == nil {
			if resp, err := client.Do(req); err == nil {
				_ = resp.Body.Close()
			}
		}
	}()
	post := func(path string, payload any) (int, map[string]any, error) {
		b, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(b))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-CSRFTOKEN", csrf)
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
		return resp.StatusCode, out, nil
	}
	exists := func(path string) bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}

	// 2. a read-only profile
	if !exists("/api/v2/cmdb/system/accprofile/" + fgtProfile) {
		status, out, err := post("/api/v2/cmdb/system/accprofile", map[string]any{
			"name": fgtProfile, "scope": "vdom", "comments": "EX0 read-only (created by the box)",
			"secfabgrp": "read", "ftviewgrp": "read", "authgrp": "read", "sysgrp": "read", "netgrp": "read",
			"loggrp": "read", "fwgrp": "read", "vpngrp": "read", "utmgrp": "read", "wifi": "read",
		})
		if err != nil {
			return "", fmt.Errorf("create profile: %w", err)
		}
		if status != 200 {
			return "", fmt.Errorf("create profile %s: HTTP %d %s", fgtProfile, status, apiError(out))
		}
	}

	// 3. the API user, trusted only from the box's own address
	boxIP := localIPFor(ctx, u.Host)
	if !exists("/api/v2/cmdb/system/api-user/" + fgtAPIUser) {
		user := map[string]any{"name": fgtAPIUser, "accprofile": fgtProfile, "comments": "EX0 box, read-only", "vdom": []map[string]string{{"name": "root"}}}
		if boxIP != "" {
			user["trusthost"] = []map[string]any{{"id": 1, "type": "ipv4-trusthost", "ipv4-trusthost": boxIP + " 255.255.255.255"}}
		}
		status, out, err := post("/api/v2/cmdb/system/api-user", user)
		if err != nil {
			return "", fmt.Errorf("create api user: %w", err)
		}
		if status != 200 {
			return "", fmt.Errorf("create api user %s: HTTP %d %s", fgtAPIUser, status, apiError(out))
		}
	}

	// 4. a fresh token; an older one becomes invalid, which is what we want
	status, out, err := post("/api/v2/monitor/system/api-user/generate-key", map[string]any{"api-user": fgtAPIUser})
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	if status != 200 {
		return "", fmt.Errorf("generate key: HTTP %d %s", status, apiError(out))
	}
	results, _ := out["results"].(map[string]any)
	token, _ := results["access_token"].(string)
	if token == "" {
		return "", errors.New("generate key answered without access_token")
	}
	return token, nil
}

// localIPFor is the address the box uses towards host:port (no packet is sent).
func localIPFor(ctx context.Context, hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "443"
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok && a.IP.To4() != nil {
		return a.IP.String()
	}
	return ""
}

func apiError(out map[string]any) string {
	if out == nil {
		return ""
	}
	for _, k := range []string{"error", "cli_error", "http_status"} {
		if v, ok := out[k]; ok {
			return fmt.Sprintf("(%s: %v)", k, v)
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return s
}
