// Package wire holds the request and response types of the agent↔server protocol,
// version 1 (ADR-0002, ADR-0003). Changes are additive only. Both roles import this
// package; nothing else does.
package wire

import (
	"encoding/json"
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
	SentAt          time.Time         `json:"sent_at"`
	Agent           AgentInfo         `json:"agent"`
	Box             BoxInfo           `json:"box"`
	Netbird         NetbirdInfo       `json:"netbird"`
	NetbirdOperator *NetbirdInfo      `json:"netbird_operator,omitempty"` // second client in the operator's own overlay, if the box has one
	ConfigVersion   string            `json:"config_version"`
	ConfigErrors    []string          `json:"config_errors,omitempty"`
	Notes           []string          `json:"notes,omitempty"` // what the agent wants an operator to see, e.g. a rollback
	Hosts           []HostReport      `json:"hosts,omitempty"`
	Discovery       DiscoveryReport   `json:"discovery"`
	Buffer          BufferInfo        `json:"buffer"`
	TaskResults     []TaskResult      `json:"task_results,omitempty"` // finished tasks since the last successful heartbeat
	Connectors      []ConnectorReport `json:"connectors,omitempty"`   // latest reading of every connector (ADR-0015)
	Scan            *ScanReport       `json:"scan,omitempty"`         // a chunk of the last service scan round (ADR-0018)
	Signals         []Signal          `json:"signals,omitempty"`      // live signs of an attack in the LAN since the last acknowledged heartbeat (ADR-0018 §7)
	DNS             *DNSReport        `json:"dns,omitempty"`          // the DNS sensor's state and counters (ADR-0020)
}

// DNSReport is the DNS sensor's state and its counters since the last
// acknowledged heartbeat (ADR-0020).
type DNSReport struct {
	Listening   string `json:"listening,omitempty"`    // "192.168.1.9:53", or "" when it does not
	Error       string `json:"error,omitempty"`        // why it does not listen
	ListVersion string `json:"list_version,omitempty"` // the blocklist the box uses
	ListSize    int    `json:"list_size"`
	Upstream    string `json:"upstream,omitempty"` // the resolver the box forwards to
	Queries     int    `json:"queries"`
	Blocked     int    `json:"blocked"`
	NXDomain    int    `json:"nxdomain"`
	Failed      int    `json:"failed"`            // no upstream answered
	Clients     int    `json:"clients"`           // distinct sources in the interval
	Refused     int    `json:"refused,omitempty"` // queries from outside the private ranges, dropped unanswered
}

// AgentInfo describes the running agent.
type AgentInfo struct {
	Version string `json:"version"`
	UptimeS int64  `json:"uptime_s"`
	BootID  string `json:"boot_id,omitempty"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	SealKey string `json:"seal_key,omitempty"` // base64 X25519 public key credentials are sealed to (ADR-0015)
}

// BoxInfo is the box's self-monitoring snapshot.
type BoxInfo struct {
	DiskTotalBytes uint64  `json:"disk_total_bytes"`
	DiskFreeBytes  uint64  `json:"disk_free_bytes"`
	Load1          float64 `json:"load1"`
	MemTotalBytes  uint64  `json:"mem_total_bytes"`
	MemFreeBytes   uint64  `json:"mem_free_bytes"`
	ClockOffsetMS  *int64  `json:"clock_offset_ms"` // box clock minus server clock, from the last response; nil if unknown
	// LAN lists the private IPv4 networks the box sits in, the interface with the
	// default route first; the server takes the first as the site's LAN (ADR-0017).
	LAN []string `json:"lan,omitempty"`
	// Canary lists the decoy ports the box currently listens on (ADR-0018 §7).
	Canary []int `json:"canary,omitempty"`
	// LANIP is the box's own address in the LAN: what a router points at for the
	// DNS sensor (ADR-0020).
	LANIP string `json:"lan_ip,omitempty"`
	// Caps lists the capabilities the agent process actually has (CAP_NET_RAW,
	// CAP_NET_BIND_SERVICE): an installation from before a release that needs
	// more shows up here, and the console says what to do (ADR-0006).
	Caps []string `json:"caps,omitempty"`
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

// Signal kinds — the complete list. The box reports; the server judges.
const (
	SignalCanary   = "canary"    // a decoy port of the box was touched
	SignalPortScan = "port_scan" // one source knocked on many ports of the box within a minute
	SignalARPScan  = "arp_scan"  // one source asked for many addresses within a minute
	SignalARPSpoof = "arp_spoof" // an address changed its MAC: the gateway, or flapping between two
	// From a FortiGate's logs, read through its connector (the device that sees the WAN):
	SignalFGTAdminFail = "fgt_admin_fail" // failed admin logins
	SignalFGTVPNFail   = "fgt_vpn_fail"   // failed SSL-VPN logins
	SignalFGTIPS       = "fgt_ips"        // an IPS signature matched
	// From the DNS sensor on the box (ADR-0020):
	SignalDNSBlock  = "dns_block"  // a client asked for a domain on the blocklist
	SignalDNSDGA    = "dns_dga"    // a client asks for random-looking names that do not exist
	SignalDNSTunnel = "dns_tunnel" // a client sends long or TXT queries to one domain in numbers
)

// MaxSignals bounds Heartbeat.Signals.
const MaxSignals = 200

// Signal is one thing the box saw that a healthy LAN does not show (ADR-0018 §7).
// IP and MAC name the source; for arp_spoof, IP is the address that changed and
// Detail names the MACs. Count is touches, ports, addresses or changes, depending
// on the kind.
type Signal struct {
	Kind     string    `json:"kind"`
	DeviceID string    `json:"device_id,omitempty"` // set when a connector's device reported it; IP is then the remote source
	IP       string    `json:"ip,omitempty"`
	MAC      string    `json:"mac,omitempty"`
	Port     int       `json:"port,omitempty"` // canary: the decoy port
	Count    int       `json:"count"`
	Detail   string    `json:"detail,omitempty"` // port_scan: the ports; arp_spoof: "gateway"/"flapping" and the MACs
	FirstAt  time.Time `json:"first_at"`         // box time
	LastAt   time.Time `json:"last_at"`
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
	Version                string            `json:"version"`
	Assigned               bool              `json:"assigned"`
	Intervals              Intervals         `json:"intervals"`
	Hosts                  []HostConfig      `json:"hosts"`
	Discovery              DiscoveryConfig   `json:"discovery"`
	NetbirdPending         bool              `json:"netbird_pending"`
	NetbirdOperatorPending bool              `json:"netbird_operator_pending,omitempty"` // a key for the operator overlay waits (remote access)
	Update                 UpdateConfig      `json:"update"`
	Tasks                  []Task            `json:"tasks,omitempty"`      // pending one-shot tasks (ADR-0014)
	Connectors             []ConnectorConfig `json:"connectors,omitempty"` // devices to read through their API (ADR-0015)
	Scan                   ScanConfig        `json:"scan"`                 // the service scan of the site's LAN (ADR-0018)
	Canary                 CanaryConfig      `json:"canary"`               // decoy ports and the live signals of the LAN (ADR-0018 §7)
	DNS                    DNSConfig         `json:"dns"`                  // the DNS sensor (ADR-0020)
}

// DNSConfig switches the box's DNS sensor on: a forwarding resolver on the LAN
// address that the router hands out, watching what the devices ask for. Block
// answers listed domains with NXDOMAIN instead of only reporting them. The box
// fetches the blocklist from the server when ListVersion changes.
type DNSConfig struct {
	Enabled     bool     `json:"enabled"`
	Block       bool     `json:"block"`
	Upstreams   []string `json:"upstreams,omitempty"` // resolvers to forward to; empty: the box's own
	ListVersion string   `json:"list_version,omitempty"`
}

// CanaryConfig switches the box's live detection on: decoy ports that look like the
// services an intruder goes for (SMB, RDP, telnet, MSSQL, VNC) and the watcher behind
// them that counts who knocks. Nothing on the box answers a byte of protocol.
type CanaryConfig struct {
	Enabled bool  `json:"enabled"`
	Ports   []int `json:"ports,omitempty"` // empty: the built-in list
}

// ScanConfig is the box's service scan (ADR-0018, decision E20): switched on per
// site, on a schedule, rate-limited. The box enumerates and reads banners; it never
// exploits and never tries a credential.
type ScanConfig struct {
	Enabled   bool     `json:"enabled"`
	IntervalS int      `json:"interval_s,omitempty"` // a full round this often; default a day, at least an hour
	MaxPPS    int      `json:"max_pps,omitempty"`    // connection attempts per second; default 20, at most 50
	Ports     []int    `json:"ports,omitempty"`      // empty: the built-in list
	Exclude   []string `json:"exclude,omitempty"`    // addresses or networks never touched
	// External is the outpost's list (ADR-0018, outside view): public addresses of
	// customer sites to scan from our own infrastructure. A box with this list scans
	// these instead of its LAN, with the external port list.
	External []ScanTarget `json:"external,omitempty"`
}

// ScanTarget is one public address to scan from outside, for one site.
type ScanTarget struct {
	SiteID string `json:"site_id"`
	IP     string `json:"ip"`
}

// Limits of a scan report chunk.
const (
	MaxScanHosts    = 50  // hosts per heartbeat; a round is sent in chunks
	MaxScanServices = 64  // services per host
	MaxScanBanner   = 200 // characters of banner or title kept
)

// ScanReport is one chunk of a scan round: the hosts the box scanned with every
// service it found on them. A host with no services says "nothing listens there".
// Final marks the last chunk of the round.
type ScanReport struct {
	Round     string     `json:"round"`
	StartedAt time.Time  `json:"started_at"`
	Hosts     []ScanHost `json:"hosts"`
	Final     bool       `json:"final"`
	Scanned   int        `json:"scanned"` // hosts the round attempted, on the final chunk
	Errors    int        `json:"errors,omitempty"`
}

// ScanHost is one scanned device. SiteID is set by an outpost: the host is the
// public address of that site, not a device in the box's own LAN.
type ScanHost struct {
	IP       string        `json:"ip"`
	MAC      string        `json:"mac,omitempty"`
	SiteID   string        `json:"site_id,omitempty"`
	Services []ScanService `json:"services"`
}

// ScanService is one listening service as the scan saw it.
type ScanService struct {
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`             // tcp
	Name    string   `json:"name,omitempty"`    // ssh, http, https, rdp, smb …
	Product string   `json:"product,omitempty"` // OpenSSH, nginx, Microsoft-IIS …
	Version string   `json:"version,omitempty"`
	Banner  string   `json:"banner,omitempty"` // first line the service said, or the HTTP Server header
	Title   string   `json:"title,omitempty"`  // HTML title of a web service
	TLS     *TLSInfo `json:"tls,omitempty"`
}

// TLSInfo is what the scan learned from a TLS handshake.
type TLSInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotAfter   time.Time `json:"not_after"`
	SelfSigned bool      `json:"self_signed"`
	Version    string    `json:"version"` // the highest version the server negotiated
	DNSNames   []string  `json:"dns_names,omitempty"`
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

// ---- connectors (ADR-0015) ----------------------------------------------------------

// ConnectorConfig tells the box to read one device through its API. The credential
// is sealed in the browser to this box's seal key; the server relays ciphertext.
type ConnectorConfig struct {
	ID             string `json:"id"`
	DeviceID       string `json:"device_id"`
	Kind           string `json:"kind"`
	URL            string `json:"url"` // scheme and host, no path: https://192.168.1.1
	Sealed         string `json:"sealed"`
	IntervalS      int    `json:"interval_s"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty"` // sha256 of the device certificate to pin; empty = accept and report
	Version        string `json:"version"`                   // changes with url, credential or pin; the box restarts the reader
}

// Connector kinds — the complete list. Each is a reader in internal/agent/connect.
const (
	ConnectorFortiGate = "fortigate"
	ConnectorStarface  = "starface"
)

// ConnectorKinds lists the kinds in display order.
var ConnectorKinds = []string{ConnectorFortiGate, ConnectorStarface}

// ValidConnectorKind reports whether k is one of the closed list.
func ValidConnectorKind(k string) bool {
	for _, x := range ConnectorKinds {
		if x == k {
			return true
		}
	}
	return false
}

// Bounds on connectors per box and facts per report.
const (
	MaxConnectors         = 64
	MaxConnectorFactsSize = 32 * 1024
)

// ConnectorReport is the latest reading of one connector. Facts travel only when
// they changed since the server last acknowledged them; Metrics travel every time.
type ConnectorReport struct {
	ID             string             `json:"id"`
	DeviceID       string             `json:"device_id"`
	Kind           string             `json:"kind"`
	OK             bool               `json:"ok"`
	Error          string             `json:"error,omitempty"`
	CollectedAt    time.Time          `json:"collected_at"` // box time
	Facts          json.RawMessage    `json:"facts,omitempty"`
	Metrics        map[string]float64 `json:"metrics,omitempty"`
	TLSFingerprint string             `json:"tls_fingerprint,omitempty"` // what the device presented
	// TokenSealed is set once when the box turned an admin login into an API token of
	// its own (FortiGate bootstrap): the token sealed to the box's own key, for the
	// server to store in place of the admin credential. The server never sees the token.
	TokenSealed string `json:"token_sealed,omitempty"`
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

// NetBird profiles a box may hold a key for: the customer's own stack (its VPN and
// the routing peer for its staff) and the operator's stack (remote access for us).
const (
	NetbirdProfileCustomer = "customer"
	NetbirdProfileOperator = "operator"
)

// NetbirdClaimResponse is POST /v1/netbird/claim?profile=… — delivered exactly once.
type NetbirdClaimResponse struct {
	Profile       string `json:"profile"`
	ManagementURL string `json:"management_url"`
	SetupKey      string `json:"setup_key"`
}
