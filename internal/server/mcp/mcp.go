// Package mcp is EX0 for an assistant: a Model Context Protocol server over
// stdio, meant to be started through SSH from a machine in the operator overlay
// (`ssh root@ex0 excubra server mcp`), so nothing new listens anywhere. It reads
// what the console shows — tenants, sites, devices, services, findings, events,
// the situation packet — and stores an assessment the assistant wrote. It
// acknowledges nothing, changes nothing else: the planner role from the concept
// (salt: Vollausbau 3.8), it reads and proposes.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/server/ai"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/version"
)

// Protocol is the MCP revision this server speaks.
const Protocol = "2025-06-18"

// Server answers JSON-RPC 2.0 messages, one per line.
type Server struct {
	Store *store.Store
	AI    *ai.Service
	Log   *slog.Logger
	Now   func() time.Time
	Actor string // who the assistant acts for, in audits
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads requests from r and writes responses to w until r ends.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	enc := json.NewEncoder(w)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			_ = enc.Encode(response{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue // a notification: nothing to answer
		}
		res := s.handle(ctx, req)
		res.ID, res.JSONRPC = req.ID, "2.0"
		if err := enc.Encode(res); err != nil {
			return err
		}
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req request) response {
	switch req.Method {
	case "initialize":
		return response{Result: map[string]any{"protocolVersion": Protocol, "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo":   map[string]any{"name": "ex0", "version": version.Version},
			"instructions": "EX0 (excubra) ist das Monitoring- und Präventionssystem von VIICO für Kundennetze. Du liest Standorte, Geräte, Dienste, Findings, Ereignisse und das Lagebild; du kannst eine Einschätzung speichern (ex0_save_assessment). Du führst nichts aus und quittierst nichts: Ein Mensch entscheidet."}}
	case "ping":
		return response{Result: map[string]any{}}
	case "tools/list":
		return response{Result: map[string]any{"tools": tools()}}
	case "tools/call":
		var p struct {
			Name string         `json:"name"`
			Args map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return response{Error: &rpcError{Code: -32602, Message: "invalid params"}}
		}
		text, err := s.call(ctx, p.Name, p.Args)
		if err != nil {
			return response{Result: map[string]any{"content": []map[string]any{{"type": "text", "text": "Fehler: " + err.Error()}}, "isError": true}}
		}
		return response{Result: map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}}
	}
	return response{Error: &rpcError{Code: -32601, Message: "method not found: " + req.Method}}
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func schema(props map[string]any, required ...string) map[string]any {
	sch := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		sch["required"] = required
	}
	return sch
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func tools() []tool {
	return []tool{
		{Name: "ex0_overview", Description: "Alle Kunden und Standorte mit Box-Zustand, Geräten und offenen Findings je Schwere. Der Einstieg.", InputSchema: schema(map[string]any{})},
		{Name: "ex0_site", Description: "Ein Standort im Detail: Box, gemeldetes LAN, Fernzugriff, Scan-Stand, Zahl der Geräte und Dienste, letzte KI-Einschätzung.", InputSchema: schema(map[string]any{"site_id": str("Standort-Kennung, z. B. site_geschaeftsstelle")}, "site_id")},
		{Name: "ex0_devices", Description: "Das Inventar eines Standorts: Geräte mit Adresse, Hersteller, Name, zuletzt gesehen, und ihre offenen Dienste aus dem Scan (Port, Produkt, Version, Titel, Zertifikat).", InputSchema: schema(map[string]any{"site_id": str("Standort-Kennung")}, "site_id")},
		{Name: "ex0_findings", Description: "Offene Findings, schwerste zuerst: Regeln über Scan innen, Außenansicht, Versionsabgleich, Konnektoren und KI. Optional nach Standort oder Schwere gefiltert.", InputSchema: schema(map[string]any{"site_id": str("nur dieser Standort (optional)"), "severity": str("high | medium | low (optional)")})},
		{Name: "ex0_events", Description: "Ereignisse der letzten Stunden eines Kunden: Ausfälle, Rückkehr, neue Geräte, Box-Schweigen, Sicherheitswarnungen der Live-Erkennung (Köder-Ports, Portscans, ARP).", InputSchema: schema(map[string]any{"tenant_id": str("Kunden-Kennung"), "hours": map[string]any{"type": "integer", "description": "Zeitraum, Standard 24"}}, "tenant_id")},
		{Name: "ex0_situation", Description: "Das vollständige Lagebild eines Standorts als JSON, genau das, was das Nacht-Modell bekommt: Box, Geräte mit Diensten, Außenansicht, Findings, Ereignisse, Konnektor-Facts. Grundlage für eine Einschätzung.", InputSchema: schema(map[string]any{"site_id": str("Standort-Kennung")}, "site_id")},
		{Name: "ex0_save_assessment", Description: "Speichert deine Einschätzung eines Standorts als KI-Bericht in der Konsole (Reiter KI) und legt gerätegebundene Findings der Quelle „ki“ an. Schema: {\"risk\":\"hoch|mittel|niedrig\",\"summary\":\"2-4 Sätze\",\"priorities\":[{\"title\",\"why\",\"action\",\"device_id\",\"severity\":\"high|medium|low\"}],\"findings\":[{\"device_id\",\"slug\",\"severity\",\"title\",\"detail\"}]}. Nur Geräte-Kennungen aus dem Lagebild.", InputSchema: schema(map[string]any{"site_id": str("Standort-Kennung"), "result": map[string]any{"type": "object", "description": "die Einschätzung im Schema"}, "model": str("welches Modell du bist, z. B. claude-fable-5-1")}, "site_id", "result")},
		{Name: "ex0_briefs", Description: "Die bisherigen KI-Einschätzungen eines Standorts, neueste zuerst.", InputSchema: schema(map[string]any{"site_id": str("Standort-Kennung")}, "site_id")},
	}
}

func argString(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

func (s *Server) call(ctx context.Context, name string, args map[string]any) (string, error) {
	switch name {
	case "ex0_overview":
		return s.overview(ctx)
	case "ex0_site":
		return s.site(ctx, argString(args, "site_id"))
	case "ex0_devices":
		return s.devices(ctx, argString(args, "site_id"))
	case "ex0_findings":
		return s.findings(ctx, argString(args, "site_id"), argString(args, "severity"))
	case "ex0_events":
		hours := 24
		if h, ok := args["hours"].(float64); ok && h > 0 && h <= 24*14 {
			hours = int(h)
		}
		return s.events(ctx, argString(args, "tenant_id"), hours)
	case "ex0_situation":
		if s.AI == nil {
			return "", errors.New("no ai service")
		}
		pk, err := s.AI.Packet(ctx, argString(args, "site_id"))
		if err != nil {
			return "", err
		}
		return pretty(pk), nil
	case "ex0_save_assessment":
		if s.AI == nil {
			return "", errors.New("no ai service")
		}
		raw, err := json.Marshal(args["result"])
		if err != nil {
			return "", err
		}
		r, err := ai.ParseResult(string(raw))
		if err != nil {
			return "", fmt.Errorf("result is not in the agreed shape: %w", err)
		}
		brief, err := s.AI.Import(ctx, argString(args, "site_id"), s.Actor, "session", firstNonEmpty(argString(args, "model"), "session"), r, 0)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("gespeichert: %s, Risiko %s, %d Prioritäten, %d Findings. In der Konsole unter Standort → KI.", brief.ID, brief.Risk, len(r.Priorities), len(r.Findings)), nil
	case "ex0_briefs":
		briefs, err := s.Store.AIBriefs(ctx, argString(args, "site_id"), 10)
		if err != nil {
			return "", err
		}
		out := make([]map[string]any, 0, len(briefs))
		for _, b := range briefs {
			var r ai.Result
			_ = json.Unmarshal(b.Body, &r)
			out = append(out, map[string]any{"at": b.At, "provider": b.Provider, "model": b.Model, "risk": b.Risk, "summary": b.Summary, "priorities": r.Priorities, "findings": r.Findings, "requested_by": b.RequestedBy})
		}
		return pretty(out), nil
	}
	return "", errors.New("unknown tool " + name)
}

func (s *Server) overview(ctx context.Context) (string, error) {
	tenants, err := s.Store.Tenants(ctx)
	if err != nil {
		return "", err
	}
	now := s.Now()
	var out []map[string]any
	for _, t := range tenants {
		sites, _ := s.Store.Sites(ctx, t.ID)
		open, _ := s.Store.OpenFindings(ctx, t.ID)
		var siteRows []map[string]any
		for _, site := range sites {
			row := map[string]any{"site_id": site.ID, "name": site.Name, "scan": site.ScanEnabled}
			boxes, _ := s.Store.Boxes(ctx, site.ID)
			for _, b := range boxes {
				if b.RevokedAt != nil {
					continue
				}
				row["box"] = map[string]any{"id": b.ID, "name": b.Name, "version": b.AgentVersion, "last_seen": rel(b.LastSeen, now), "silent": now.Sub(b.LastSeen) > 5*time.Minute, "lan": b.LAN, "public_ip": b.PublicIP, "operator_vpn": b.NetbirdOpStatus, "customer_vpn": b.NetbirdStatus, "role": b.Role}
			}
			devs, _ := s.Store.Devices(ctx, t.ID, site.ID, now.Add(-30*24*time.Hour))
			row["devices"] = len(devs)
			sev := map[string]int{}
			for _, f := range open {
				if f.SiteID == site.ID {
					sev[f.Severity]++
				}
			}
			row["open_findings"] = sev
			siteRows = append(siteRows, row)
		}
		out = append(out, map[string]any{"tenant_id": t.ID, "name": t.Name, "ai_scope": t.AIScope, "sites": siteRows})
	}
	return pretty(out), nil
}

func (s *Server) site(ctx context.Context, siteID string) (string, error) {
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return "", err
	}
	now := s.Now()
	out := map[string]any{"site_id": site.ID, "name": site.Name, "tenant_id": site.TenantID, "scan_enabled": site.ScanEnabled}
	boxes, _ := s.Store.Boxes(ctx, siteID)
	for _, b := range boxes {
		if b.RevokedAt == nil {
			out["box"] = map[string]any{"id": b.ID, "name": b.Name, "version": b.AgentVersion, "last_seen": rel(b.LastSeen, now), "lan": b.LAN, "public_ip": b.PublicIP, "operator_vpn": b.NetbirdOpStatus, "operator_ip": b.NetbirdOpIP, "customer_vpn": b.NetbirdStatus}
		}
	}
	if ra, err := s.Store.RemoteAccess(ctx, siteID); err == nil {
		out["remote_access"] = map[string]any{"state": ra.State, "lan": ra.CIDR, "enabled": ra.Enabled, "detail": ra.Detail}
	}
	if rounds, err := s.Store.ScanRounds(ctx, siteID, 10); err == nil {
		for _, r := range rounds {
			key := "last_scan_inside"
			if r.External {
				key = "last_scan_outside"
			}
			if _, done := out[key]; !done {
				out[key] = map[string]any{"at": rel(r.StartedAt, now), "hosts": r.Hosts, "services": r.Services}
			}
		}
	}
	devs, _ := s.Store.Devices(ctx, site.TenantID, siteID, now.Add(-30*24*time.Hour))
	svcs, _ := s.Store.OpenServicesForSite(ctx, siteID)
	out["devices"], out["open_services"] = len(devs), len(svcs)
	if ext, err := s.Store.ExternalDevice(ctx, siteID); err == nil {
		var ports []int
		for _, sv := range svcs {
			if sv.DeviceID == ext.ID {
				ports = append(ports, sv.Port)
			}
		}
		out["outside"] = map[string]any{"device_id": ext.ID, "ip": ext.IP, "open_ports": ports}
	}
	if briefs, err := s.Store.AIBriefs(ctx, siteID, 1); err == nil && len(briefs) > 0 {
		out["latest_assessment"] = map[string]any{"at": briefs[0].At, "risk": briefs[0].Risk, "summary": briefs[0].Summary, "model": briefs[0].Model}
	}
	return pretty(out), nil
}

func (s *Server) devices(ctx context.Context, siteID string) (string, error) {
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return "", err
	}
	now := s.Now()
	svcs, _ := s.Store.OpenServicesForSite(ctx, siteID)
	byDev := map[string][]map[string]any{}
	for _, sv := range svcs {
		row := map[string]any{"port": sv.Port, "name": sv.Name}
		if sv.Product != "" {
			row["product"] = sv.Product
		}
		if sv.Version != "" {
			row["version"] = sv.Version
		}
		if sv.Title != "" {
			row["title"] = sv.Title
		}
		if sv.Banner != "" && sv.Title == "" {
			row["banner"] = sv.Banner
		}
		if len(sv.TLS) > 0 {
			row["tls"] = sv.TLS
		}
		row["since"] = rel(sv.FirstSeen, now)
		byDev[sv.DeviceID] = append(byDev[sv.DeviceID], row)
	}
	devs, err := s.Store.Devices(ctx, site.TenantID, siteID, time.Time{})
	if err != nil {
		return "", err
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].IP < devs[j].IP })
	out := make([]map[string]any, 0, len(devs))
	for _, d := range devs {
		row := map[string]any{"device_id": d.ID, "ip": d.IP, "mac": d.MAC, "vendor": d.Vendor, "hostname": d.Hostname, "first_seen": rel(d.FirstSeen, now), "last_seen": rel(d.LastSeen, now)}
		if d.GoneAt != nil {
			row["gone_since"] = rel(*d.GoneAt, now)
		}
		if d.Ignored {
			row["ignored"] = true
		}
		if len(byDev[d.ID]) > 0 {
			row["services"] = byDev[d.ID]
		}
		out = append(out, row)
	}
	if ext, err := s.Store.ExternalDevice(ctx, siteID); err == nil {
		out = append(out, map[string]any{"device_id": ext.ID, "ip": ext.IP, "outside": true, "services": byDev[ext.ID]})
	}
	return pretty(out), nil
}

func (s *Server) findings(ctx context.Context, siteID, severity string) (string, error) {
	tenants, err := s.Store.Tenants(ctx)
	if err != nil {
		return "", err
	}
	acks, _ := s.Store.Acks(ctx)
	now := s.Now()
	var out []map[string]any
	for _, t := range tenants {
		open, err := s.Store.OpenFindings(ctx, t.ID)
		if err != nil {
			continue
		}
		for _, f := range open {
			if (siteID != "" && f.SiteID != siteID) || (severity != "" && f.Severity != severity) {
				continue
			}
			_, acked := acks["finding/"+f.ID]
			row := map[string]any{"finding_id": f.ID, "tenant_id": f.TenantID, "site_id": f.SiteID, "device_id": f.DeviceID, "source": source(f.ConnectorID), "rule": f.Rule, "key": f.Key, "severity": f.Severity, "title": f.Title, "detail": f.Detail, "since": rel(f.FirstSeen, now), "acknowledged": acked}
			if len(f.Evidence) > 2 {
				row["evidence"] = f.Evidence
			}
			out = append(out, row)
		}
	}
	if len(out) == 0 {
		return "keine offenen Findings", nil
	}
	return pretty(out), nil
}

func (s *Server) events(ctx context.Context, tenantID string, hours int) (string, error) {
	if tenantID == "" {
		return "", errors.New("tenant_id required")
	}
	now := s.Now()
	evs, err := s.Store.Events(ctx, tenantID, now.Add(-time.Duration(hours)*time.Hour), now, "", 300)
	if err != nil {
		return "", err
	}
	out := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		row := map[string]any{"at": e.OccurredAt, "type": string(e.Type), "severity": string(e.Severity), "site_id": e.SiteID}
		if e.HostID != "" {
			row["host_id"] = e.HostID
		}
		if e.DeviceID != "" {
			row["device_id"] = e.DeviceID
		}
		if e.Host != nil {
			row["host"] = e.Host.Name
		}
		if e.Device != nil {
			row["device"] = firstNonEmpty(e.Device.Hostname, e.Device.IP)
		}
		if e.Type == event.SecurityAlert && e.Details != nil {
			row["title"], row["info"] = e.Details["title"], e.Details["info"]
		}
		out = append(out, row)
	}
	if len(out) == 0 {
		return "keine Ereignisse im Zeitraum", nil
	}
	return pretty(out), nil
}

func source(connectorID string) string {
	switch connectorID {
	case "scan":
		return "Scan innen"
	case "wan":
		return "Außenansicht"
	case "version":
		return "Versionsabgleich"
	case "ki":
		return "KI"
	case "signal":
		return "Live-Erkennung"
	case "":
		return ""
	}
	return "Konnektor"
}

func pretty(v any) string {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func rel(t, now time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "gerade eben"
	case d < time.Hour:
		return fmt.Sprintf("vor %d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("vor %d h", int(d.Hours()))
	default:
		return t.Format("2006-01-02")
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
