// Package watch holds the words for "what is monitored at a site": the proposal
// the console makes ("beobachten, was zählt"), a pick somebody makes, and what
// came of it. The rule itself lives in the console package, next to the device
// classification it needs; the types live here so that the MCP server can ask
// for a proposal and act on it without knowing the console.
package watch

import "github.com/excubra/excubra/internal/wire"

// Device is one device the way a proposal names it.
type Device struct {
	DeviceID string   `json:"device_id"`
	Name     string   `json:"name"`
	IP       string   `json:"ip"`
	Kind     string   `json:"kind"`              // what it is, in words: Firewall, Server, Telefonie …
	Uplink   bool     `json:"uplink,omitempty"`  // the way out of the site: its outage is one outage, not forty
	HostID   string   `json:"host_id,omitempty"` // set when the device is watched
	Checks   []string `json:"checks,omitempty"`  // icmp, tcp:443, http
	State    string   `json:"state,omitempty"`   // erreichbar, ausgefallen, …
}

// Proposal is what the rule would switch on at a site, what it leaves out and
// why, and what is watched already.
type Proposal struct {
	HasBox  bool           `json:"has_box"`
	Add     []Device       `json:"add"`
	Skipped map[string]int `json:"skipped"` // reason → number of devices
	Watched []Device       `json:"watched"`
}

// Pick is one device somebody wants watched, or watched differently.
type Pick struct {
	DeviceID string
	Checks   []wire.CheckConfig // empty: a ping for a new host, unchanged for a watched one
	Uplink   *bool              // nil: by kind for a new host, unchanged for a watched one
}

// Outcome is what switching on did, by device name.
type Outcome struct {
	Added   []string       `json:"added"`
	Updated []string       `json:"updated,omitempty"`
	Failed  []string       `json:"failed,omitempty"` // "name: why"
	Skipped map[string]int `json:"skipped,omitempty"`
}
