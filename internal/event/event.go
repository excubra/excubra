// Package event defines the event envelope shared by all phases (ADR-0003) and the
// webhook body of contract v1, which is the same object plus a link.
package event

import (
	"time"

	"github.com/excubra/excubra/internal/id"
)

// Type is a stable event type name; the catalogue is part of the CRM contract.
type Type string

// Phase 1 event types. Phase 2 adds SecurityAlert; nothing else changes.
const (
	BoxSilent          Type = "box.silent"
	BoxBack            Type = "box.back"
	HostDown           Type = "host.down"
	HostUp             Type = "host.up"
	DeviceNew          Type = "device.new"
	DeviceGone         Type = "device.gone"
	MaintenanceStarted Type = "maintenance.started"
	MaintenanceEnded   Type = "maintenance.ended"
	TestPing           Type = "test.ping"
	SecurityAlert      Type = "security.alert"
)

// Severity is the contract's three-level scale.
type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// DefaultSeverity returns the severity the contract assigns to a type. SecurityAlert
// carries its own severity per rule and returns Warning here.
func (t Type) DefaultSeverity() Severity {
	switch t {
	case BoxSilent:
		return Critical
	case HostDown, SecurityAlert:
		return Warning
	default:
		return Info
	}
}

// Valid reports whether t is a known type.
func (t Type) Valid() bool {
	switch t {
	case BoxSilent, BoxBack, HostDown, HostUp, DeviceNew, DeviceGone,
		MaintenanceStarted, MaintenanceEnded, TestPing, SecurityAlert:
		return true
	}
	return false
}

// Sources name the component that produced an event.
const (
	SourceState       = "server.state"
	SourceMaintenance = "server.maintenance"
	SourceDiscovery   = "server.discovery"
	SourceSignals     = "server.signals" // live detection on the box (ADR-0018 §7)
	SourceApp         = "server.app"     // what an application reported about itself (ADR-0023)
	SourceConsole     = "console"
)

// HostRef describes the host an event is about, as the contract shows it.
type HostRef struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	MAC    string `json:"mac,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

// DeviceRef describes a discovered device.
type DeviceRef struct {
	IP        string     `json:"ip"`
	MAC       string     `json:"mac"`
	Vendor    string     `json:"vendor,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// MaintenanceRef describes a maintenance window.
type MaintenanceRef struct {
	Scope  string     `json:"scope"` // tenant | site | host
	Until  *time.Time `json:"until,omitempty"`
	Reason string     `json:"reason,omitempty"`
	SetBy  string     `json:"set_by,omitempty"`
	Ended  string     `json:"ended,omitempty"` // expired | cleared
}

// Event is the envelope. Its JSON form is the webhook body of contract v1: the
// contract's field names are used verbatim and fields are only ever added.
type Event struct {
	ID         string     `json:"event_id"`
	Type       Type       `json:"type"`
	Severity   Severity   `json:"severity"`
	OccurredAt time.Time  `json:"occurred_at"`
	ReceivedAt time.Time  `json:"received_at"`
	Since      *time.Time `json:"since,omitempty"`

	TenantID string `json:"tenant_id"`
	SiteID   string `json:"site_id,omitempty"`
	BoxID    string `json:"box_id,omitempty"`
	HostID   string `json:"host_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`

	Source string `json:"source"`

	Host        *HostRef        `json:"host,omitempty"`
	Device      *DeviceRef      `json:"device,omitempty"`
	Maintenance *MaintenanceRef `json:"maintenance,omitempty"`
	Details     map[string]any  `json:"details,omitempty"`

	// Link is filled at delivery time (console URL of the object), never stored.
	Link string `json:"link,omitempty"`
}

// New returns an event with id, type, default severity and both timestamps set to at.
func New(t Type, at time.Time) Event {
	at = at.UTC()
	return Event{
		ID:         id.NewSortable("evt", at),
		Type:       t,
		Severity:   t.DefaultSeverity(),
		OccurredAt: at,
		ReceivedAt: at,
	}
}
