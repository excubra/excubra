package ai

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// Packet is the situation of one site as the model sees it. Scope "facts": what
// the box and the connectors report — never credentials (those are sealed and
// never on the server in the clear), never raw logs (there are none yet).
type Packet struct {
	Now          string       `json:"now"`
	Tenant       string       `json:"tenant"`
	Site         string       `json:"site"`
	Box          *PBox        `json:"box,omitempty"`
	RemoteAccess string       `json:"remote_access,omitempty"`
	Scan         PScan        `json:"scan"`
	Devices      []PDevice    `json:"devices"`
	Outside      *PDevice     `json:"outside,omitempty"`
	Findings     []PFinding   `json:"findings"`
	Events       []PEvent     `json:"events_24h"`
	Connectors   []PConnector `json:"connectors,omitempty"`
}

type PBox struct {
	Name     string `json:"name"`
	Version  string `json:"agent_version"`
	LastSeen string `json:"last_seen"`
	Netbird  string `json:"customer_vpn"`
	Operator string `json:"operator_vpn"`
	LAN      string `json:"lan,omitempty"`
}

type PScan struct {
	Enabled     bool   `json:"enabled"`
	LastInside  string `json:"last_inside,omitempty"`
	LastOutside string `json:"last_outside,omitempty"`
}

type PDevice struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	IP        string     `json:"ip,omitempty"`
	MAC       string     `json:"mac,omitempty"`
	Vendor    string     `json:"vendor,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	FirstSeen string     `json:"first_seen"`
	LastSeen  string     `json:"last_seen"`
	Gone      string     `json:"gone_since,omitempty"`
	Ignored   bool       `json:"ignored,omitempty"`
	Services  []PService `json:"services,omitempty"`
}

type PService struct {
	Port    int    `json:"port"`
	Name    string `json:"name,omitempty"`
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
	Banner  string `json:"banner,omitempty"`
	TLS     string `json:"tls,omitempty"` // "TLS 1.2, self-signed, expires 2027-01-01"
	Since   string `json:"since"`
}

type PFinding struct {
	DeviceID string `json:"device_id"`
	Source   string `json:"source"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Since    string `json:"since"`
	Acked    bool   `json:"acknowledged,omitempty"`
}

type PEvent struct {
	At       string `json:"at"`
	Type     string `json:"type"`
	DeviceID string `json:"device_id,omitempty"`
	HostID   string `json:"host_id,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type PConnector struct {
	DeviceID string         `json:"device_id"`
	Kind     string         `json:"kind"`
	OK       *bool          `json:"ok,omitempty"`
	Error    string         `json:"error,omitempty"`
	Facts    map[string]any `json:"facts,omitempty"`
}

// Caps keep a packet within what a model reads well.
const (
	maxDevices    = 200
	maxServices   = 800
	maxFindings   = 200
	maxEvents     = 100
	maxFactsBytes = 8 << 10
)

// packet builds the situation of a site and the set of device ids the model may
// name in its findings.
func (s *Service) packet(ctx context.Context, tenant store.Tenant, site store.Site) (Packet, map[string]bool) {
	now := s.Now()
	pk := Packet{Now: now.In(s.Loc).Format(time.RFC3339), Tenant: tenant.Name, Site: site.Name, Devices: []PDevice{}, Findings: []PFinding{}, Events: []PEvent{}}
	devices := map[string]bool{}
	boxes, _ := s.Store.Boxes(ctx, site.ID)
	for _, b := range boxes {
		if b.RevokedAt != nil {
			continue
		}
		pk.Box = &PBox{Name: firstNonEmpty(b.Name, b.ID), Version: b.AgentVersion, LastSeen: rel(b.LastSeen, now), Netbird: b.NetbirdStatus, Operator: b.NetbirdOpStatus, LAN: strings.Join(b.LAN, ", ")}
	}
	if ra, err := s.Store.RemoteAccess(ctx, site.ID); err == nil {
		pk.RemoteAccess = ra.State + " " + ra.CIDR
	}
	pk.Scan.Enabled = site.ScanEnabled
	if rounds, err := s.Store.ScanRounds(ctx, site.ID, 10); err == nil {
		for _, r := range rounds {
			if r.External && pk.Scan.LastOutside == "" {
				pk.Scan.LastOutside = rel(r.StartedAt, now)
			}
			if !r.External && pk.Scan.LastInside == "" {
				pk.Scan.LastInside = rel(r.StartedAt, now)
			}
		}
	}
	svcs, _ := s.Store.OpenServicesForSite(ctx, site.ID)
	byDevice := map[string][]PService{}
	n := 0
	for _, sv := range svcs {
		if n >= maxServices {
			break
		}
		n++
		byDevice[sv.DeviceID] = append(byDevice[sv.DeviceID], PService{Port: sv.Port, Name: sv.Name, Product: sv.Product, Version: sv.Version, Title: sv.Title, Banner: sv.Banner, TLS: tlsText(sv.TLS), Since: rel(sv.FirstSeen, now)})
	}
	devs, _ := s.Store.Devices(ctx, tenant.ID, site.ID, now.Add(-30*24*time.Hour))
	for i, d := range devs {
		if i >= maxDevices {
			break
		}
		pd := PDevice{ID: d.ID, Name: firstNonEmpty(cleanHost(d.Hostname), d.Vendor, d.IP, d.MAC), IP: d.IP, MAC: d.MAC, Vendor: d.Vendor, Hostname: d.Hostname, FirstSeen: rel(d.FirstSeen, now), LastSeen: rel(d.LastSeen, now), Ignored: d.Ignored, Services: byDevice[d.ID]}
		if d.GoneAt != nil {
			pd.Gone = rel(*d.GoneAt, now)
		}
		pk.Devices = append(pk.Devices, pd)
		devices[d.ID] = true
	}
	if ext, err := s.Store.ExternalDevice(ctx, site.ID); err == nil {
		pk.Outside = &PDevice{ID: ext.ID, Name: "Internet-Adresse " + ext.IP, IP: ext.IP, FirstSeen: rel(ext.FirstSeen, now), LastSeen: rel(ext.LastSeen, now), Services: byDevice[ext.ID]}
		devices[ext.ID] = true
	}
	acks, _ := s.Store.Acks(ctx)
	if open, err := s.Store.OpenFindings(ctx, tenant.ID); err == nil {
		for _, f := range open {
			if f.SiteID != site.ID || len(pk.Findings) >= maxFindings {
				continue
			}
			_, acked := acks["finding/"+f.ID]
			pk.Findings = append(pk.Findings, PFinding{DeviceID: f.DeviceID, Source: source(f.ConnectorID), Rule: f.Rule, Severity: f.Severity, Title: f.Title, Detail: f.Detail, Since: rel(f.FirstSeen, now), Acked: acked})
		}
	}
	if evs, err := s.Store.Events(ctx, tenant.ID, now.Add(-24*time.Hour), now, "", 500); err == nil {
		for _, e := range evs {
			if e.SiteID != site.ID || len(pk.Events) >= maxEvents {
				continue
			}
			pk.Events = append(pk.Events, PEvent{At: e.OccurredAt.In(s.Loc).Format("15:04"), Type: string(e.Type), DeviceID: e.DeviceID, HostID: e.HostID, Severity: string(e.Severity)})
		}
	}
	if cons, err := s.Store.Connectors(ctx, tenant.ID); err == nil {
		for _, c := range cons {
			if c.SiteID != site.ID || c.Disabled {
				continue
			}
			pc := PConnector{DeviceID: c.DeviceID, Kind: c.Kind, OK: c.LastOK, Error: clip(c.LastError, 200)}
			if len(c.Facts) > 0 && len(c.Facts) <= maxFactsBytes {
				var facts map[string]any
				if json.Unmarshal(c.Facts, &facts) == nil {
					pc.Facts = redact(facts)
				}
			}
			pk.Connectors = append(pk.Connectors, pc)
		}
	}
	return pk, devices
}

var secretKey = regexp.MustCompile(`(?i)token|secret|password|passwd|api[_-]?key|private|credential`)

// redact drops anything that looks like a credential, however deep.
func redact(v map[string]any) map[string]any {
	out := make(map[string]any, len(v))
	for k, val := range v {
		if secretKey.MatchString(k) {
			continue
		}
		switch x := val.(type) {
		case map[string]any:
			out[k] = redact(x)
		case []any:
			var list []any
			for _, item := range x {
				if m, ok := item.(map[string]any); ok {
					list = append(list, redact(m))
				} else {
					list = append(list, item)
				}
			}
			out[k] = list
		default:
			out[k] = val
		}
	}
	return out
}

func source(connectorID string) string {
	switch connectorID {
	case "scan":
		return "scan_inside"
	case "wan":
		return "scan_outside"
	case "version":
		return "version_feed"
	case "ki":
		return "ai"
	case "signal":
		return "live_detection"
	case "vuln":
		return "cve"
	}
	return "connector"
}

func tlsText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var t wire.TLSInfo
	if json.Unmarshal(raw, &t) != nil {
		return ""
	}
	parts := []string{"TLS " + t.Version}
	if t.SelfSigned {
		parts = append(parts, "self-signed")
	}
	if !t.NotAfter.IsZero() {
		parts = append(parts, "expires "+t.NotAfter.Format("2006-01-02"))
	}
	return strings.Join(parts, ", ")
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(h, ".local")
	return strings.TrimSuffix(h, ".lan")
}

// rel says when something happened, relative and short: "3h ago", "12d ago".
func rel(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < time.Hour:
		return "just now"
	case d < 48*time.Hour:
		return strings.TrimSuffix(d.Round(time.Hour).String(), "0m0s") + " ago"
	default:
		return t.Format("2006-01-02")
	}
}
