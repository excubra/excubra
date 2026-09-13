package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// Tenant is a customer as EX0 knows it: an id and a name, nothing else.
type Tenant struct {
	ID        string
	Name      string
	CreatedAt time.Time
	AIScope   string // what the AI may see for this tenant: off | facts (ADR-0019)
}

// AI scopes.
const (
	AIScopeOff   = "off"
	AIScopeFacts = "facts" // inventory, services, findings, events, connector facts — no raw logs
)

// AIBrief is one assessment the AI wrote for a site.
type AIBrief struct {
	ID            string
	SiteID        string
	TenantID      string
	At            time.Time
	Provider      string
	Model         string
	Risk          string // hoch | mittel | niedrig
	Summary       string
	Body          json.RawMessage // the model's structured answer
	PromptBytes   int
	ResponseBytes int
	DurationMS    int
	RequestedBy   string
}

// Site is a location of a tenant; boxes and hosts belong to a site.
type Site struct {
	ID          string
	TenantID    string
	Name        string
	CreatedAt   time.Time
	ScanEnabled bool // the service scan runs on this site (ADR-0018)
	// CanaryEnabled switches the box's decoy ports and live signals (ADR-0018 §7);
	// on by default.
	CanaryEnabled bool
	// The DNS sensor (ADR-0020): off until the router points at the box; Block
	// answers listed domains with NXDOMAIN; Upstreams override the box's own.
	DNSEnabled   bool
	DNSBlock     bool
	DNSUpstreams []string
	// Where the site is, for the map. Address is what the operator typed; Lat and
	// Lon mean nothing unless Located is true, because 0/0 is a real place.
	Address string
	Lat     float64
	Lon     float64
	Located bool
}

// Box is an enrolled device. SiteID is empty until the console assigns it.
type Box struct {
	ID           string
	SiteID       string
	Name         string
	HWID         string
	AgentVersion string
	OS           string
	Arch         string
	CertSerial   string
	CertNotAfter time.Time
	Channel      string
	// Discovery settings pulled by the agent (ADR-0007).
	DiscoveryMode    string
	DiscoverySubnets []string
	// Last heartbeat facts, for console and API.
	NetbirdStatus  string
	NetbirdIP      string
	DiskTotalBytes uint64
	DiskFreeBytes  uint64
	UptimeS        int64
	LastSeen       time.Time
	EnrolledAt     time.Time
	RevokedAt      *time.Time
	SealKey        string // base64 X25519 public key the box reported (ADR-0015)
	// the second NetBird client, in the operator's overlay (remote access)
	NetbirdOpStatus string
	NetbirdOpIP     string
	// the box's own networks as it reports them, default-route interface first
	LAN []string
	// PublicIP is where the box's heartbeats come from: the site's public address.
	PublicIP string
	// Role is "box" (in a customer LAN) or "outpost" (in our infrastructure, scans
	// the sites' public addresses; ADR-0018)
	Role string
	// Canary lists the decoy ports the box reported as armed (ADR-0018 §7).
	Canary []int
	// DNS is the sensor's last report (ADR-0020), nil when it never sent one.
	DNS *wire.DNSReport
	// LANIP is the box's own address in the LAN, as it reports it.
	LANIP string
	// Caps are the capabilities the agent process reported (ADR-0006).
	Caps []string
}

// BlockedDomain is one entry of the DNS blocklist.
type BlockedDomain struct {
	Domain string
	Source string
}

// DNSDay is a site's DNS totals of one day.
type DNSDay struct {
	SiteID   string
	Day      string
	Queries  int
	Blocked  int
	NXDomain int
	Failed   int
}

// EnrollmentKey is a one-time key; only the hash of the secret is stored.
type EnrollmentKey struct {
	ID         string
	SecretHash string
	Note       string
	SiteID     string // made for a site: the box lands there on enrollment (ADR-0017)
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UsedAt     *time.Time
	UsedByBox  string
	RevokedAt  *time.Time
}

// NetbirdKey is the pending NetBird hand-over for a box (ADR-0010).
type NetbirdKey struct {
	BoxID         string
	Profile       string // customer (default) or operator
	ManagementURL string
	SetupKey      string
	CreatedAt     time.Time
	ClaimedAt     *time.Time
}

// RemoteAccess is one site's LAN in the operator's overlay (salt: Vollausbau B).
type RemoteAccess struct {
	SiteID     string
	TenantID   string
	BoxID      string
	CIDR       string
	Enabled    bool
	State      string // key | joining | wiring | active | off | error
	Detail     string
	PeerID     string
	PeerIP     string
	NetworkID  string
	ResourceID string
	RouterID   string
	// the resource's label in the operator stack, "Kunde · Standort"; "" until named
	ResourceName string
	RequestedBy  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Remote access states.
const (
	RemoteKey     = "key"     // setup key created, the box has not fetched it yet
	RemoteJoining = "joining" // the box has the key, its peer has not appeared yet
	RemoteWiring  = "wiring"  // network, resource and router are being created
	RemoteActive  = "active"
	RemoteOff     = "off"
	RemoteError   = "error"
)

// Device is something discovery has seen at a site.
type Device struct {
	ID        string
	TenantID  string
	SiteID    string
	MAC       string
	IP        string
	Vendor    string
	Hostname  string
	FirstSeen time.Time
	LastSeen  time.Time
	GoneAt    *time.Time
	Ignored   bool
	External  bool // stands for the site's public address, not a device in the LAN
}

// Box roles.
const (
	RoleBox     = "box"
	RoleOutpost = "outpost"
)

// ScanTarget is a site's public address an outpost scans.
type ScanTarget struct {
	SiteID   string
	TenantID string
	IP       string
}

// Service is one listening service the scan found on a device (ADR-0018).
type Service struct {
	DeviceID  string
	Port      int
	Proto     string
	Name      string
	Product   string
	Version   string
	Banner    string
	Title     string
	TLS       json.RawMessage // wire.TLSInfo, or empty
	FirstSeen time.Time
	LastSeen  time.Time
	GoneAt    *time.Time
}

// ScanRound is one round a box ran over its site.
type ScanRound struct {
	ID         string
	BoxID      string
	SiteID     string
	StartedAt  time.Time
	FinishedAt *time.Time
	Hosts      int
	Services   int
	Errors     int
	External   bool // an outpost's look at the site's public address
}

// Host is a monitored system, checked by its box.
type Host struct {
	ID        string
	TenantID  string
	SiteID    string
	BoxID     string
	DeviceID  string
	Name      string
	Address   string
	MAC       string
	Vendor    string
	ParentID  string
	IsUplink  bool
	Checks    []wire.CheckConfig
	CreatedAt time.Time
}

// Maintenance is a window; Scope is tenant, site or host.
type Maintenance struct {
	ID        string
	TenantID  string
	SiteID    string
	Scope     string
	TargetID  string
	Until     time.Time
	Reason    string
	SetBy     string
	CreatedAt time.Time
}

// WebhookTarget receives events of one tenant or of all ("*").
type WebhookTarget struct {
	ID          string
	Name        string
	URL         string
	Secret      string
	TenantScope string
	Enabled     bool
	CreatedAt   time.Time
}

// APIToken authenticates the status API; Tenants is a list of ids or ["*"].
type APIToken struct {
	ID         string
	Name       string
	TokenHash  string
	Tenants    []string
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// User is a console account.
type User struct {
	ID              string
	Name            string
	PasswordHash    string
	TOTPSecret      string
	TOTPLastCounter int64
	FailedLogins    int
	LockedUntil     *time.Time
	Disabled        bool
	CreatedAt       time.Time
}

// Session is a console login; only the hash of the cookie value is stored.
type Session struct {
	TokenHash string
	UserID    string
	CSRF      string
	CreatedAt time.Time
	LastSeen  time.Time
	IP        string
}

// AuditEntry records one write through console or API.
type AuditEntry struct {
	ID      int64
	At      time.Time
	Actor   string
	Action  string
	Target  string
	Summary string
}

// Release is update metadata for one version/os/arch (ADR-0006).
type Release struct {
	Version         string
	OS              string
	Arch            string
	URL             string
	SHA256          string
	Signature       string
	MinAgentVersion string
	CreatedAt       time.Time
}

// Delivery states.
const (
	DeliveryPending   = "pending"
	DeliveryDelivered = "delivered"
	DeliveryFailed    = "failed"
)

// Delivery is one webhook delivery attempt record; it lives in the event's day
// file, so TenantID and Day say where.
type Delivery struct {
	TenantID      string
	Day           string
	EventID       string
	TargetID      string
	State         string
	Attempts      int
	NextAttemptAt time.Time
	LastStatus    int
	LastError     string
	Body          string
	CreatedAt     time.Time
	DeliveredAt   time.Time
}

// Rollup is one hour of check results for one host and check type.
type Rollup struct {
	HostID       string
	Hour         time.Time
	CheckType    string
	Rounds       int
	Failed       int
	LatencySumMS int64
	LatencyMaxMS int64
}

// BoxTask is a one-shot request to a box (ADR-0014): queued by the console, pulled
// with the config, reported back in a heartbeat.
type BoxTask struct {
	ID        string
	BoxID     string
	Kind      string
	IssuedAt  time.Time
	IssuedBy  string
	ExpiresAt time.Time
	DoneAt    *time.Time
	OK        *bool
	Detail    string
}

// BoxNote is a line the agent wanted an operator to see (heartbeat notes).
type BoxNote struct {
	ID    int64
	BoxID string
	At    time.Time
	Text  string
}

// Ack records that an operator has seen a problem. Since is the start of that
// outage, so the same object failing again is a new, unacknowledged problem.
type Ack struct {
	Kind     string
	TargetID string
	Since    time.Time
	Actor    string
	At       time.Time
	Note     string
}

// Connector is one device the box reads through its API (ADR-0015). Sealed is
// ciphertext only this box can open; the server never sees the credential.
type Connector struct {
	ID             string
	TenantID       string
	SiteID         string
	BoxID          string
	DeviceID       string
	Kind           string
	URL            string
	Sealed         string
	SealedBy       string
	SealedAt       time.Time
	IntervalS      int
	TLSFingerprint string
	CreatedAt      time.Time
	Disabled       bool
	// last reading, written from heartbeats
	LastOK          *bool
	LastError       string
	LastAt          *time.Time
	SeenFingerprint string
	Facts           json.RawMessage
	FactsAt         *time.Time
	Metrics         map[string]float64
}

// Version identifies what the box must know to read: a change restarts the reader.
func (c Connector) Version() string {
	h := sha256.Sum256([]byte(c.URL + "\x00" + c.Sealed + "\x00" + c.TLSFingerprint + "\x00" + strconv.Itoa(c.IntervalS)))
	return "cv_" + hex.EncodeToString(h[:6])
}

// Sample is one number a connector reported at one time.
type Sample struct {
	At    time.Time
	Key   string
	Value float64
}

// Finding is one thing the rules found on a device (salt: Vollausbau 3.8).
type Finding struct {
	ID          string
	TenantID    string
	SiteID      string
	DeviceID    string
	ConnectorID string
	Rule        string
	Key         string
	Severity    string
	Title       string
	Detail      string
	Evidence    json.RawMessage
	FirstSeen   time.Time
	LastSeen    time.Time
	ResolvedAt  *time.Time
}
