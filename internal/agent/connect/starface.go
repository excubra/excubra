package connect

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// starface reads a STARFACE PBX through its REST interface (/rest). The sealed
// credential is {"user": "…", "password": "…"}. STARFACE 10 speaks OAuth 2.0
// (resource owner password flow, client rest-client-headless); older releases use
// the classic nonce login. The reader tries the classic login first and falls back
// to OAuth, and reports which one worked.
//
// Version, state and licence answers are stored as the PBX returns them: their
// exact shape differs between releases and is documented only in the Swagger file
// each PBX ships, so the console shows them as key/value.
type starface struct{}

func (starface) Read(ctx context.Context, t Target) (Reading, error) {
	var cred struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(t.Secret, &cred); err != nil || cred.User == "" || cred.Password == "" {
		return Reading{}, errors.New("credential needs user and password")
	}
	base := strings.TrimRight(t.URL, "/")
	hdr, mode, err := starfaceLogin(ctx, t.Client, base, cred.User, cred.Password)
	if err != nil {
		return Reading{}, err
	}
	facts := map[string]any{"login": mode}
	metrics := map[string]float64{}
	var problems []string
	get := func(path string, out any) error { return getJSON(ctx, t.Client, base+path, hdr, out) }

	var version json.RawMessage
	if err := get("/rest/server/version", &version); err != nil {
		return Reading{}, fmt.Errorf("server version: %w", err)
	}
	facts["version"] = compact(version)

	var state json.RawMessage
	if err := get("/rest/server/state", &state); err == nil {
		facts["state"] = compact(state)
	} else {
		problems = append(problems, "state: "+err.Error())
	}
	var lic json.RawMessage
	if err := get("/rest/server/licenses", &lic); err == nil {
		facts["licenses"] = compact(lic)
	} else {
		problems = append(problems, "licenses: "+err.Error())
	}
	var users []json.RawMessage
	if err := get("/rest/users", &users); err == nil {
		metrics["users"] = float64(len(users))
	} else {
		problems = append(problems, "users: "+err.Error())
	}
	var numbers []json.RawMessage
	if err := get("/rest/phonenumbers", &numbers); err == nil {
		metrics["phonenumbers"] = float64(len(numbers))
	} else {
		problems = append(problems, "phonenumbers: "+err.Error())
	}
	if len(problems) > 0 {
		facts["problems"] = problems
	}
	return Reading{Facts: facts, Metrics: metrics}, nil
}

// compact keeps small JSON as-is for the console and shortens anything large.
func compact(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	if len(raw) > 4096 {
		return map[string]any{"_truncated": true, "_size": len(raw)}
	}
	return v
}

// starfaceLogin returns the headers to use and the login mode that worked.
func starfaceLogin(ctx context.Context, client *http.Client, base, user, password string) (map[string]string, string, error) {
	tok, classicErr := starfaceClassic(ctx, client, base, user, password)
	if classicErr == nil {
		return map[string]string{"authToken": tok, "X-Version": "2"}, "classic", nil
	}
	if errors.Is(classicErr, ErrAuth) {
		return nil, "", classicErr
	}
	tok, oauthErr := starfaceOAuth(ctx, client, base, user, password)
	if oauthErr == nil {
		return map[string]string{"Authorization": "Bearer " + tok, "X-Version": "2"}, "oauth2", nil
	}
	return nil, "", fmt.Errorf("login failed (classic: %w; oauth2: %w)", classicErr, oauthErr)
}

// starfaceClassic is the nonce login: secret = user:SHA512(user + nonce + SHA512(password)).
func starfaceClassic(ctx context.Context, client *http.Client, base, user, password string) (string, error) {
	var challenge struct {
		Nonce     string `json:"nonce"`
		LoginType string `json:"loginType"`
	}
	if err := getJSON(ctx, client, base+"/rest/login", map[string]string{"X-Version": "2"}, &challenge); err != nil {
		return "", err
	}
	if challenge.Nonce == "" {
		return "", errors.New("no nonce in login challenge")
	}
	pw := sha512.Sum512([]byte(password))
	inner := sha512.Sum512([]byte(user + challenge.Nonce + hex.EncodeToString(pw[:])))
	secret := user + ":" + hex.EncodeToString(inner[:])
	loginType := challenge.LoginType
	if loginType == "" {
		loginType = "Internal"
	}
	body, _ := json.Marshal(map[string]string{"loginType": loginType, "nonce": challenge.Nonce, "secret": secret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Version", "2")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", ErrAuth
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d from /rest/login", resp.StatusCode)
	}
	var out struct {
		AuthToken string `json:"authToken"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.AuthToken == "" {
		return "", errors.New("login answered without authToken")
	}
	return out.AuthToken, nil
}

// starfaceOAuth is the STARFACE 10 resource-owner password flow.
func starfaceOAuth(ctx context.Context, client *http.Client, base, user, password string) (string, error) {
	form := url.Values{"grant_type": {"password"}, "client_id": {"rest-client-headless"}, "username": {user}, "password": {password}, "scope": {"pbx-login"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/auth/realms/pbx/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
		return "", ErrAuth
	}
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d from the token endpoint", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.AccessToken == "" {
		return "", errors.New("token endpoint answered without access_token")
	}
	return out.AccessToken, nil
}
