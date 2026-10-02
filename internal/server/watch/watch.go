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
	Uplink   bool     `json:"uplink,omitempty"`  // marked as something other hosts can sit behind
	Behind   string   `json:"behind,omitempty"`  // the watched device this one sits behind, by name
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
	// Behind names the device this one sits behind: while that one is down, this
	// one's outage is not reported. "" takes it out from behind anything, nil
	// leaves it as it is. The device named has to be watched itself.
	Behind *string
}

// Outcome is what switching on did, by device name.
type Outcome struct {
	Added   []string       `json:"added"`
	Updated []string       `json:"updated,omitempty"`
	Failed  []string       `json:"failed,omitempty"` // "name: why"
	Skipped map[string]int `json:"skipped,omitempty"`
}
