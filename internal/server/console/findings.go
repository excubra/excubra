package console

// Findings (salt: Vollausbau 3.8): what the rules say, on the device page and on the
// prevention page, acknowledgeable like every other problem.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/excubra/excubra/internal/server/store"
)

// findingView is a finding with the names a person needs.
type findingView struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenantId"`
	TenantName  string          `json:"tenant"`
	SiteID      string          `json:"siteId"`
	SiteName    string          `json:"site"`
	DeviceID    string          `json:"deviceId"`
	DeviceName  string          `json:"device"`
	ConnectorID string          `json:"connectorId"`
	Source      string          `json:"source"` // where it comes from: Scan innen, Außenansicht, Versionsabgleich, or the connector's kind
	Rule        string          `json:"rule"`
	Key         string          `json:"key"`
	Severity    string          `json:"severity"`
	Title       string          `json:"title"`
	Detail      string          `json:"detail"`
	Evidence    json.RawMessage `json:"evidence"`
	FirstSeen   time.Time       `json:"firstSeen"`
	LastSeen    time.Time       `json:"lastSeen"`
	ResolvedAt  *time.Time      `json:"resolvedAt"`
	Ack         *ackView        `json:"ack,omitempty"`
}

type findingsData struct {
	Open     []findingView  `json:"open"`
	Resolved []findingView  `json:"resolved,omitempty"`
	Counts   map[string]int `json:"counts"`
}

func (s *Server) viewFindings(ctx context.Context, fs []store.Finding) []findingView {
	out := make([]findingView, 0, len(fs))
	if len(fs) == 0 {
		return out
	}
	tm, sm, err := s.lookups(ctx)
	if err != nil {
		s.Log.Error("lookups", "err", err)
	}
	acks, _ := s.Store.Acks(ctx)
	names := map[string]string{}
	kinds := map[string]string{}
	for _, f := range fs {
		v := findingView{ID: f.ID, TenantID: f.TenantID, SiteID: f.SiteID, DeviceID: f.DeviceID, ConnectorID: f.ConnectorID, Rule: f.Rule, Key: f.Key, Severity: f.Severity,
			Title: f.Title, Detail: f.Detail, Evidence: f.Evidence, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen, ResolvedAt: f.ResolvedAt}
		if len(v.Evidence) == 0 {
			v.Evidence = json.RawMessage("{}")
		}
		if t, ok := tm[f.TenantID]; ok {
			v.TenantName = t.Name
		}
		if st, ok := sm[f.SiteID]; ok {
			v.SiteName = st.Name
		}
		if n, ok := names[f.DeviceID]; ok {
			v.DeviceName = n
		} else if dev, err := s.Store.Device(ctx, f.DeviceID); err == nil {
			v.DeviceName = firstNonEmpty(cleanHostname(dev.Hostname), dev.IP, dev.MAC)
			if dev.External {
				v.DeviceName = deviceName(dev)
			}
			names[f.DeviceID] = v.DeviceName
		}
		v.Source = s.findingSource(ctx, f.ConnectorID, kinds)
		if f.ResolvedAt == nil {
			v.Ack = ackFor(acks, "finding", f.ID, f.FirstSeen)
		}
		out = append(out, v)
	}
	return out
}

// apiFindings lists every open finding, worst first.
func (s *Server) apiFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fs, err := s.Store.OpenFindings(ctx, r.URL.Query().Get("tenant"))
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	counts, err := s.Store.FindingCounts(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, findingsData{Open: s.viewFindings(ctx, fs), Counts: counts})
}

// apiDeviceFindings lists a device's open findings and those resolved in the last 30 days.
func (s *Server) apiDeviceFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	fs, err := s.Store.FindingsForDevice(ctx, r.PathValue("id"), s.Now().Add(-30*24*time.Hour))
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	d := findingsData{Open: []findingView{}, Resolved: []findingView{}, Counts: map[string]int{}}
	for _, v := range s.viewFindings(ctx, fs) {
		if v.ResolvedAt == nil {
			d.Open = append(d.Open, v)
			d.Counts[v.Severity]++
		} else {
			d.Resolved = append(d.Resolved, v)
		}
	}
	writeJSON(w, http.StatusOK, d)
}

// findingSource names where a finding comes from.
func (s *Server) findingSource(ctx context.Context, connectorID string, kinds map[string]string) string {
	switch connectorID {
	case "scan":
		return "Scan innen"
	case "wan":
		return "Außenansicht"
	case "version":
		return "Versionsabgleich"
	case "signal":
		return "Live-Erkennung"
	case "":
		return ""
	}
	if k, ok := kinds[connectorID]; ok {
		return k
	}
	label := "Konnektor"
	if c, err := s.Store.Connector(ctx, connectorID); err == nil {
		label = ConnectorLabel(c.Kind)
	}
	kinds[connectorID] = label
	return label
}
