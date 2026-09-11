// Package wire holds the request and response types of the agent↔server protocol,
// version 1 (ADR-0002, ADR-0003). Changes are additive only. Both roles import this
// package; nothing else does.
package wire

import (
	"fmt"
	"time"
)

// HeaderAgentVersion carries the agent's semantic version on every request.
const HeaderAgentVersion = "X-Excubra-Agent-Version"

// Error is the body of every non-2xx response. Codes are stable protocol strings.
type Error struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Error codes.
const (
	ErrBadRequest      = "bad_request"
	ErrUnauthorized    = "unauthorized" // no or invalid client certificate
	ErrRevoked         = "revoked"      // certificate or box revoked
	ErrKeyInvalid      = "key_invalid"  // enrollment key unknown/used/expired
	ErrRateLimited     = "rate_limited"
	ErrUpgradeRequired = "upgrade_required" // agent outside the compatibility window
	ErrNotAssigned     = "not_assigned"     // action needs an assigned box
	ErrNothingPending  = "nothing_pending"  // netbird claim without a pending key
	ErrInternal        = "internal"
)

// ---- enrollment ------------------------------------------------------------

// EnrollRequest is POST /v1/enroll. The key carries the ingest address and the CA
// fingerprint (ADR-0010); the CSR is PEM.
type EnrollRequest struct {
	Key          string `json:"key"`
	HWID         string `json:"hw_id"`
	CSR          string `json:"csr"`
	AgentVersion string `json:"agent_version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
}

// EnrollResponse returns the box identity. Certificate and CA are PEM.
type EnrollResponse struct {
	BoxID       string    `json:"box_id"`
	Certificate string    `json:"certificate"`
	CA          string    `json:"ca"`
	NotAfter    time.Time `json:"not_after"`
}

// RenewRequest is POST /v1/renew, authenticated with the current certificate.
type RenewRequest struct {
	CSR string `json:"csr"`
}

// RenewResponse carries the renewed certificate (PEM).
type RenewResponse struct {
	Certificate string    `json:"certificate"`
	NotAfter    time.Time `json:"not_after"`
}

// ---- heartbeat --------------------------------------------------------------

// Heartbeat is POST /v1/heartbeat, once per minute per box.
type Heartbeat struct {
	SentAt        time.Time       `json:"sent_at"`
	Agent         AgentInfo       `json:"agent"`
	Box           BoxInfo         `json:"box"`
	Netbird       NetbirdInfo     `json:"netbird"`
	ConfigVersion string          `json:"config_version"`
	ConfigErrors  []string        `json:"config_errors,omitempty"`
	Notes         []string        `json:"notes,omitempty"` // what the agent wants an operator to see, e.g. a rollback
	Hosts         []HostReport    `json:"hosts,omitempty"`
	Discovery     DiscoveryReport `json:"discovery"`
	Buffer        BufferInfo      `json:"buffer"`
	TaskResults   []TaskResult    `json:"task_results,omitempty"` // finished tasks since the last successful heartbeat
}

// AgentInfo describes the running agent.
type AgentInfo struct {
	Version string `json:"version"`
	UptimeS int64  `json:"uptime_s"`
	BootID  string `json:"boot_id,omitempty"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// BoxInfo is the box's self-monitoring snapshot.
type BoxInfo struct {
	DiskTotalBytes uint64  `json:"disk_total_bytes"`
	DiskFreeBytes  uint64  `json:"disk_free_bytes"`
	Load1          float64 `json:"load1"`
	MemTotalBytes  uint64  `json:"mem_total_bytes"`
	MemFreeBytes   uint64  `json:"mem_free_bytes"`
	ClockOffsetMS  *int64  `json:"clock_offset_ms"` // box clock minus server clock, from the last response; nil if unknown
}

// NetbirdInfo reports the state of the NetBird client on the box.
type NetbirdInfo struct {
	Status        string `json:"status"`
	IP            string `json:"ip,omitempty"`
	Version       string `json:"version,omitempty"`
	ManagementURL string `json:"management_url,omitempty"`
}

// NetBird status values.
const (
	NetbirdNotConfigured = "not_configured"
	NetbirdConnected     = "connected"
	NetbirdDisconnected  = "disconnected"
	NetbirdError         = "error"
)

// HostReport carries the check rounds of one host since the last successful
// heartbeat, oldest first, at most MaxRoundsPerHost.
type HostReport struct {
	HostID string  `json:"host_id"`
	Rounds []Round `json:"rounds"`
}

// MaxRoundsPerHost bounds the rounds per host in one heartbeat (ADR-0003).
const MaxRoundsPerHost = 10

// Round is one execution of all checks of a host. OK iff every check is ok.
type Round struct {
	At     time.Time     `json:"at"` // box time
	OK     bool          `json:"ok"`
	Checks []CheckResult `json:"checks"`
}

// CheckResult is the outcome of one check. Type is the check label: "icmp",
// "tcp:443", "http".
type CheckResult struct {
	Type      string `json:"type"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	LatencyMS *int64 `json:"latency_ms"`
	Status    int    `json:"status,omitempty"` // HTTP status code when applicable
}

// DiscoveryReport lists devices seen since the last successful heartbeat.
type DiscoveryReport struct {
	Seen []Sighting `json:"seen,omitempty"`
}

// MaxSightings bounds DiscoveryReport.Seen.
const MaxSightings = 2000

// Sighting is one device as the box saw it.
type Sighting struct {
	MAC      string    `json:"mac"`
	IP       string    `json:"ip,omitempty"`
	IPv6     []string  `json:"ipv6,omitempty"`
	Vendor   string    `json:"vendor,omitempty"`
	Hostname string    `json:"hostname,omitempty"`
	LastSeen time.Time `json:"last_seen"` // box time
}

// BufferInfo is the agent's send buffer state.
type BufferInfo struct {
	Queued  int   `json:"queued"`
	Dropped int64 `json:"dropped"`
}

// HeartbeatResponse tells the agent the server time (for clock offset) and the
// current config version so it knows whether to pull.
type HeartbeatResponse struct {
	ServerTime    time.Time `json:"server_time"`
	ConfigVersion string    `json:"config_version"`
	Assigned      bool      `json:"assigned"`
}

// ---- config -----------------------------------------------------------------

// Config is GET /v1/config. Version doubles as ETag.
type Config struct {
	Version        string          `json:"version"`
	Assigned       bool            `json:"assigned"`
	Intervals      Intervals       `json:"intervals"`
	Hosts          []HostConfig    `json:"hosts"`
	Discovery      DiscoveryConfig `json:"discovery"`
	NetbirdPending bool            `json:"netbird_pending"`
	Update         UpdateConfig    `json:"update"`
	Tasks          []Task          `json:"tasks,omitempty"` // pending one-shot tasks (ADR-0014)
}

// Intervals in seconds.
type Intervals struct {
	HeartbeatS    int `json:"heartbeat_s"`
	CheckS        int `json:"check_s"`
	ConfigMaxAgeS int `json:"config_max_age_s"`
}

// DefaultIntervals are the values from the concept: heartbeat 60 s, checks 30 s,
// config at least every 15 minutes.
var DefaultIntervals = Intervals{HeartbeatS: 60, CheckS: 30, ConfigMaxAgeS: 900}

// HostConfig is one monitored host with its checks.
type HostConfig struct {
	HostID  string        `json:"host_id"`
	Address string        `json:"address"`
	Checks  []CheckConfig `json:"checks"`
}

// CheckConfig is one check. The set of types is closed: the agent refuses others.
type CheckConfig struct {
	Type         string `json:"type"`
	Port         int    `json:"port,omitempty"`          // tcp
	URL          string `json:"url,omitempty"`           // http
	ExpectStatus []int  `json:"expect_status,omitempty"` // http: inclusive [min, max]; default [200, 399]
}

// Check types — the complete list. There is no other kind of probe in the agent.
const (
	CheckICMP = "icmp"
	CheckTCP  = "tcp"
	CheckHTTP = "http"
)

// Label returns the result label for a check config: "icmp", "tcp:443", "http".
func (c CheckConfig) Label() string {
	if c.Type == CheckTCP {
		return fmt.Sprintf("tcp:%d", c.Port)
	}
	return c.Type
}

// DiscoveryConfig controls discovery (ADR-0007).
type DiscoveryConfig struct {
	Mode           string   `json:"mode"`
	Subnets        []string `json:"subnets,omitempty"`
	SweepIntervalS int      `json:"sweep_interval_s"`
	MaxPPS         int      `json:"max_pps"`
}

// Discovery modes — the complete list.
const (
	DiscoveryPassive = "passive"
	DiscoverySweep   = "sweep"
)

// UpdateConfig selects the release channel.
type UpdateConfig struct {
	Channel string `json:"channel"`
}

// Update channels.
const (
	ChannelStable = "stable"
	ChannelCanary = "canary"
)

// ---- tasks ----------------------------------------------------------------------

// Task is one request the server puts into the config for the box to run once
// (ADR-0014). The list of kinds is closed and a task has no parameters: every kind
// is something the box does on its own anyway, the server only chooses the moment.
type Task struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	IssuedAt time.Time `json:"issued_at"`
}

// Task kinds — the complete list. The agent refuses others and reports that.
const (
	TaskSweep   = "sweep"   // one discovery sweep now instead of at the next interval
	TaskRecheck = "recheck" // one check round of every host now
	TaskUpdate  = "update"  // ask for update metadata now instead of at the daily tick
	TaskRestart = "restart" // exit 75 so the service manager starts the agent again
)

// TaskKinds lists the kinds in display order.
var TaskKinds = []string{TaskSweep, TaskRecheck, TaskUpdate, TaskRestart}

// ValidTaskKind reports whether k is one of the closed list.
func ValidTaskKind(k string) bool {
	for _, x := range TaskKinds {
		if x == k {
			return true
		}
	}
	return false
}

// MaxTasks bounds Config.Tasks; the server queues at most one pending task per kind.
const MaxTasks = 4

// TaskResult reports one finished task in the next heartbeat.
type TaskResult struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	OK         bool      `json:"ok"`
	Detail     string    `json:"detail,omitempty"`
	FinishedAt time.Time `json:"finished_at"` // box time
}

// ---- update and netbird -------------------------------------------------------

// UpdateInfo is GET /v1/update — metadata only, never a binary (ADR-0006).
type UpdateInfo struct {
	Version         string `json:"version"`
	URL             string `json:"url"`
	SHA256          string `json:"sha256"`
	Signature       string `json:"signature"` // base64 DER ECDSA over sha256(blob), cosign-compatible
	MinAgentVersion string `json:"min_agent_version,omitempty"`
}

// NetbirdClaimResponse is POST /v1/netbird/claim — delivered exactly once.
type NetbirdClaimResponse struct {
	ManagementURL string `json:"management_url"`
	SetupKey      string `json:"setup_key"`
}
