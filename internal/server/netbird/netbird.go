// Package netbird is the slice of the NetBird management API EX0 needs to bring a
// customer LAN into VIICO's own overlay (salt: Vollausbau, Stufe B): groups, a
// one-off setup key for the box, the peer it becomes, a network with the LAN as a
// resource and the box as its router, and the policy that lets technicians in.
// It talks to our stack, never to a customer's; the token is a server setting.
package netbird

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to one management API.
type Client struct {
	BaseURL string // https://viico.vpn.example.test
	Token   string // personal access token of a dedicated admin user
	HTTP    *http.Client
}

// New returns a client with sane timeouts.
func New(baseURL, token string) *Client {
	return &Client{BaseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), Token: strings.TrimSpace(token), HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// Configured reports whether URL and token are set.
func (c *Client) Configured() bool { return c != nil && c.BaseURL != "" && c.Token != "" }

// ErrAuth says the token was refused.
var ErrAuth = errors.New("netbird: token refused")

// Group is a NetBird group.
type Group struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	PeersCount     int    `json:"peers_count"`
	ResourcesCount int    `json:"resources_count"`
}

// Peer is what the list endpoint says about a peer.
type Peer struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	IP        string    `json:"ip"`
	Connected bool      `json:"connected"`
	LastSeen  time.Time `json:"last_seen"`
	Groups    []Group   `json:"groups"`
	Version   string    `json:"version"`
}

// SetupKey is a created key; Key is shown exactly once by the API.
type SetupKey struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Expires   time.Time `json:"expires"`
	Valid     bool      `json:"valid"`
	Revoked   bool      `json:"revoked"`
	UsedTimes int       `json:"used_times"`
}

// Network, Resource and Router are the pieces of a routed LAN.
type Network struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Resource struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
	Groups  []any  `json:"groups"` // ids on write, objects on read
}

type Router struct {
	ID         string `json:"id"`
	Peer       string `json:"peer"`
	Masquerade bool   `json:"masquerade"`
	Metric     int    `json:"metric"`
	Enabled    bool   `json:"enabled"`
}

// Policy is the access rule; only what EX0 writes and reads back.
type Policy struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Enabled bool         `json:"enabled"`
	Rules   []PolicyRule `json:"rules"`
}

type PolicyRule struct {
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Action        string `json:"action"`
	Bidirectional bool   `json:"bidirectional"`
	Protocol      string `json:"protocol"`
	Sources       []any  `json:"sources"`      // ids on write, objects on read
	Destinations  []any  `json:"destinations"` // ids on write, objects on read
}

// Groups lists all groups.
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	var out []Group
	return out, c.do(ctx, http.MethodGet, "/api/groups", nil, &out)
}

// EnsureGroup returns the group with that name, creating it when missing.
func (c *Client) EnsureGroup(ctx context.Context, name string) (Group, error) {
	gs, err := c.Groups(ctx)
	if err != nil {
		return Group{}, err
	}
	for _, g := range gs {
		if g.Name == name {
			return g, nil
		}
	}
	var g Group
	err = c.do(ctx, http.MethodPost, "/api/groups", map[string]any{"name": name, "peers": []string{}}, &g)
	return g, err
}

// CreateSetupKey creates a one-off key that lands the peer in the given groups.
func (c *Client) CreateSetupKey(ctx context.Context, name string, autoGroups []string, ttl time.Duration) (SetupKey, error) {
	var k SetupKey
	body := map[string]any{"name": name, "type": "one-off", "expires_in": int(ttl.Seconds()), "auto_groups": autoGroups, "ephemeral": false, "usage_limit": 1}
	return k, c.do(ctx, http.MethodPost, "/api/setup-keys", body, &k)
}

// Peers lists all peers.
func (c *Client) Peers(ctx context.Context) ([]Peer, error) {
	var out []Peer
	return out, c.do(ctx, http.MethodGet, "/api/peers", nil, &out)
}

// Networks lists all networks.
func (c *Client) Networks(ctx context.Context) ([]Network, error) {
	var out []Network
	return out, c.do(ctx, http.MethodGet, "/api/networks", nil, &out)
}

// CreateNetwork creates a network.
func (c *Client) CreateNetwork(ctx context.Context, name, description string) (Network, error) {
	var n Network
	return n, c.do(ctx, http.MethodPost, "/api/networks", map[string]any{"name": name, "description": description}, &n)
}

// DeleteNetwork removes a network with its resources and routers.
func (c *Client) DeleteNetwork(ctx context.Context, networkID string) error {
	return c.do(ctx, http.MethodDelete, "/api/networks/"+networkID, nil, nil)
}

// CreateResource adds a LAN (CIDR) to a network.
func (c *Client) CreateResource(ctx context.Context, networkID, name, cidr string, groups []string, enabled bool) (Resource, error) {
	var r Resource
	body := map[string]any{"name": name, "address": cidr, "enabled": enabled, "groups": groups}
	return r, c.do(ctx, http.MethodPost, "/api/networks/"+networkID+"/resources", body, &r)
}

// Resources lists the resources of a network.
func (c *Client) Resources(ctx context.Context, networkID string) ([]Resource, error) {
	var out []Resource
	return out, c.do(ctx, http.MethodGet, "/api/networks/"+networkID+"/resources", nil, &out)
}

// SetResourceEnabled switches a resource on or off without touching the rest.
func (c *Client) SetResourceEnabled(ctx context.Context, networkID, resourceID, name, cidr string, groups []string, enabled bool) error {
	body := map[string]any{"name": name, "address": cidr, "enabled": enabled, "groups": groups}
	return c.do(ctx, http.MethodPut, "/api/networks/"+networkID+"/resources/"+resourceID, body, nil)
}

// CreateRouter makes a peer the router of a network.
func (c *Client) CreateRouter(ctx context.Context, networkID, peerID string, masquerade bool, metric int) (Router, error) {
	var r Router
	body := map[string]any{"peer": peerID, "masquerade": masquerade, "metric": metric, "enabled": true}
	return r, c.do(ctx, http.MethodPost, "/api/networks/"+networkID+"/routers", body, &r)
}

// Policies lists all policies.
func (c *Client) Policies(ctx context.Context) ([]Policy, error) {
	var out []Policy
	return out, c.do(ctx, http.MethodGet, "/api/policies", nil, &out)
}

// EnsurePolicy returns the policy with that name or creates "sources → destinations, all protocols".
func (c *Client) EnsurePolicy(ctx context.Context, name string, sources, destinations []string) (Policy, error) {
	ps, err := c.Policies(ctx)
	if err != nil {
		return Policy{}, err
	}
	for _, p := range ps {
		if p.Name == name {
			return p, nil
		}
	}
	src := make([]any, 0, len(sources))
	for _, s := range sources {
		src = append(src, s)
	}
	dst := make([]any, 0, len(destinations))
	for _, d := range destinations {
		dst = append(dst, d)
	}
	var p Policy
	body := map[string]any{"name": name, "description": "managed by EX0", "enabled": true, "rules": []map[string]any{{
		"name": name, "enabled": true, "action": "accept", "bidirectional": false, "protocol": "all", "sources": src, "destinations": dst,
	}}}
	return p, c.do(ctx, http.MethodPost, "/api/policies", body, &p)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	if !c.Configured() {
		return errors.New("netbird: not configured")
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+c.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("netbird: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrAuth
	case resp.StatusCode >= 300:
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("netbird: %s %s: HTTP %d: %s", method, path, resp.StatusCode, msg)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("netbird: %s %s: %w", method, path, err)
		}
	}
	return nil
}
