// Package mcp is EX0 for an assistant: a Model Context Protocol server, reached
// through SSH from a machine in the operator overlay (`ssh root@ex0 excubra
// server mcp`), so nothing new listens anywhere. It reads what the console
// shows — tenants, sites, devices, services, findings, events, the situation
// packet — and stores an assessment the assistant wrote.
//
// And it sets a customer up (ADR-0017 amendment, ADR-0024): tenant, site,
// enrollment key with the complete command, the site's LAN, the hand-over to
// the customer's VPN, what is monitored, the scan with the consent on record,
// and one answer to "how far is this site". Set-up is work on our server; it
// is audited under the session's actor and reaches no customer system.
//
// It acknowledges nothing and operates nothing: a finding, an outage, a
// device's credentials stay with a person in the console.
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

	// For minting enrollment keys (ex0_new_box): the CA's pin and the address
	// boxes dial. The pin comes from the certificate; the CA's private key is
	// not needed and not held here. Left empty, that one tool refuses and
	// everything else works.
	CAFingerprint string
	Ingest        string // host the boxes dial
	IngestPt      int

	// The running server's engine and services, for the set-up tools
	// (rollout.go). nil when the command answers from the files.
	Engine Engine
	Remote Remote
	Watch  Watcher
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
			"instructions": instructions}}
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

// instructions is what a session reads first.
const instructions = "EX0 (excubra) ist das Monitoring- und Präventionssystem von VIICO für Kundennetze. " +
	"Lesen: Standorte, Geräte, Dienste, Findings, Ereignisse, Lagebild; eine Einschätzung speichern (ex0_save_assessment). " +
	"Einrichten — ein Kunde in einer Sitzung, in dieser Reihenfolge: ex0_create_tenant, ex0_create_site, ex0_new_box (mit allen Container-Werten und den SSH-Schlüsseln der Techniker; liefert den vollständigen Befehl), " +
	"dann ex0_rollout_status, bis die Box da ist; ex0_site_lan nur, wenn der Status es verlangt (LAN außerhalb RFC 1918, überlappendes Netz); ex0_customer_vpn, wenn der Kunde ein eigenes VPN bekommt; " +
	"ex0_watch_suggestion und ex0_watch für die Überwachung; ex0_site_scan nur mit festgehaltener Einwilligung. ex0_rollout_status sagt zu jedem Schritt, was fehlt. " +
	"Das alles sind Aufträge an unseren Server, kein Zugriff auf ein Kundensystem. Der Befehl aus ex0_new_box läuft mit root auf dem Proxmox oder der Box des Kunden: Den führt aus, wer dort Zugang hat. " +
	"Quittieren, Wartung, DNS-Sensor, Konnektor-Zugangsdaten und alles Operative bleiben bei einem Menschen in der Konsole."

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

func integer(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

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
		{Name: "ex0_create_tenant", Description: "Legt einen Kunden (Mandanten) an. Einrichtung auf dem Server, kein Zugriff auf Kundensysteme. Kürzel wird zur Kennung ten_<kürzel> und taucht in Webhooks und der API auf: kurz, klein, ohne Umlaute.", InputSchema: schema(map[string]any{"slug": str("Kürzel, a-z 0-9 Bindestrich, z. B. muster"), "name": str("Anzeigename, z. B. Kanzlei Muster")}, "slug", "name")},
		{Name: "ex0_create_site", Description: "Legt einen Standort für einen Kunden an; mit Adresse wird er serverseitig nachgeschlagen und steht auf der Karte. Einrichtung, kein Zugriff auf Kundensysteme.", InputSchema: schema(map[string]any{"tenant_id": str("Kunden-Kennung, z. B. ten_muster"), "slug": str("Kürzel des Standorts, z. B. kanzlei"), "name": str("Anzeigename, z. B. Kanzlei"), "address": str("Postadresse für die Karte (optional)")}, "tenant_id", "slug", "name")},
		{Name: "ex0_new_box", Description: "Erzeugt einen Enrollment-Key für einen Standort und liefert die beiden vollständigen Befehle (Proxmox-Host / Box selbst) mit der Release-Version dieses Servers. Alles, was über den Container bekannt ist, gehört in diesen Aufruf und steht dann im Befehl: nichts wird von Hand angehängt. Die Box ordnet sich mit dem Key selbst dem Standort zu (ADR-0017). Der Key ist einmalig und gehört nur in den Befehl.", InputSchema: schema(map[string]any{
			"site_id":      str("Standort-Kennung, z. B. site_kanzlei"),
			"note":         str("Notiz zum Key, z. B. Container auf dem Kunden-Proxmox (optional)"),
			"expires_days": integer("Gültigkeit in Tagen, Standard 30, höchstens 365"),
			"ctid":         integer("Proxmox: Container-ID; ohne Angabe die nächste freie"),
			"bridge":       str("Proxmox: Bridge des Kunden-LANs, z. B. vmbr0 (Standard: vmbr0, sonst die der Default-Route)"),
			"ip":           str("Proxmox: feste Adresse der Box mit Präfixlänge, z. B. 192.168.10.60/24 — oder dhcp (Standard). Fest ist besser: die Box wird Router fürs LAN"),
			"gw":           str("Proxmox: Gateway des Netzes, bei fester Adresse Pflicht"),
			"storage":      str("Proxmox: Speicher für die Container-Disk, z. B. local-lvm oder local-zfs (Standard: der erste passende)"),
			"disk":         integer("Proxmox: Disk in GiB, Standard 8"),
			"memory":       integer("Proxmox: RAM in MiB, Standard 1024"),
			"ssh_keys":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "öffentliche SSH-Schlüssel der Techniker für root auf der Box (je einer: Typ, Schlüssel, optional Name). Ohne Schlüssel kommt niemand per SSH auf die Box"},
		}, "site_id")},
		{Name: "ex0_rollout_status", Description: "Wie weit ist dieser Standort? Jeder Schritt eines Rollouts mit Zustand (ok, open, waiting, optional), Begründung und dem nächsten Handgriff: Box, Version, Techniker-VPN, LAN, Fernzugriff, Kunden-VPN, Geräte, Überwachung, Scan. Nach jedem Schritt aufrufen statt zu raten; »done: true« ist die Abnahme.", InputSchema: schema(map[string]any{"site_id": str("Standort-Kennung")}, "site_id")},
		{Name: "ex0_site_lan", Description: "Schaltet den Fernzugriff auf das LAN eines Standorts ein: Das Netz erscheint im Techniker-Stack als eigener Eintrag, geroutet über die Box. Normalerweise passiert das von selbst; dieses Werkzeug ist für die Fälle, in denen ex0_rollout_status es verlangt — ein anderes Netz als das gemeldete, ein behobener Konflikt, oder ein LAN außerhalb RFC 1918 (z. B. 192.0.2.0/24). Letzteres nur mit confirm_public: true und nur, wenn ein Mensch für diesen Kunden bestätigt hat, dass das Netz wirklich so nummeriert ist.", InputSchema: schema(map[string]any{
			"site_id":        str("Standort-Kennung"),
			"lan":            str("das LAN in CIDR-Schreibweise; ohne Angabe das Netz, das die Box meldet"),
			"confirm_public": map[string]any{"type": "boolean", "description": "true erklärt ein Netz außerhalb RFC 1918 zum LAN dieses Standorts. Nur nach Bestätigung durch einen Menschen; steht im Audit-Log"},
		}, "site_id")},
		{Name: "ex0_customer_vpn", Description: "Übergibt der Box eines Standorts den Zugang zum eigenen NetBird-Stack des Kunden (Mitarbeiter-VPN): Management-URL und Setup-Key der Box-Gruppe. Die Box holt den Schlüssel einmalig ab und tritt bei; der Server vergisst ihn danach. Ein Einmal-Key ist richtig: Er geht durch diese Sitzung.", InputSchema: schema(map[string]any{
			"site_id":        str("Standort-Kennung"),
			"management_url": str("https://<kunde>.vpn.… — der Stack des Kunden"),
			"setup_key":      str("Setup-Key der Box-Gruppe dieses Stacks, einmalig verwendbar"),
		}, "site_id", "management_url", "setup_key")},
		{Name: "ex0_watch_suggestion", Description: "Was die Regel »beobachten, was zählt« an diesem Standort einschalten würde (Firewall, Netzwerk, Server, VMs, Telefonie, Drucker), was sie übergeht und warum, und was schon beobachtet wird — mit Geräte-Kennungen für ex0_watch.", InputSchema: schema(map[string]any{"site_id": str("Standort-Kennung")}, "site_id")},
		{Name: "ex0_watch", Description: "Schaltet die Überwachung ein. suggested: true übernimmt den Vorschlag der Regel (Ping; Firewall und Router als Uplink). devices nimmt einzelne Geräte auf oder ändert beobachtete: je Gerät device_id, optional checks (icmp, tcp:<port>, http(s)-URL — andere Prüfungen kennt die Box nicht) und uplink. Die Box prüft ab der nächsten Minute. Nicht beobachten, was kommt und geht (Laptops, Telefone ohne feste Adresse): Das macht jeden Abend Störungen.", InputSchema: schema(map[string]any{
			"site_id":   str("Standort-Kennung"),
			"suggested": map[string]any{"type": "boolean", "description": "den Vorschlag aus ex0_watch_suggestion übernehmen"},
			"devices": map[string]any{"type": "array", "description": "einzelne Geräte", "items": map[string]any{"type": "object", "properties": map[string]any{
				"device_id": str("Geräte-Kennung"),
				"checks":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "icmp | tcp:<port> | http(s)://… ; ohne Angabe Ping (neu) bzw. unverändert"},
				"uplink":    map[string]any{"type": "boolean", "description": "der Weg nach draußen: fällt er aus, wird nur er gemeldet"},
			}, "required": []string{"device_id"}}},
		}, "site_id")},
		{Name: "ex0_site_scan", Description: "Schaltet den Schwachstellen-Scan eines Standorts (innen durch die Box, außen durch den Außenposten). Einschalten braucht die Einwilligung des Kunden (E20): consent sagt in einem Satz, wer wann zugestimmt hat und wo es steht — er kommt ins Audit-Log. Ohne Einwilligung bleibt der Scan aus.", InputSchema: schema(map[string]any{
			"site_id": str("Standort-Kennung"),
			"on":      map[string]any{"type": "boolean", "description": "an oder aus"},
			"consent": str("beim Einschalten Pflicht: wer hat wann eingewilligt, wo steht es"),
		}, "site_id", "on")},
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
	case "ex0_create_tenant":
		return s.createTenant(ctx, argString(args, "slug"), argString(args, "name"))
	case "ex0_create_site":
		return s.createSite(ctx, argString(args, "tenant_id"), argString(args, "slug"), argString(args, "name"), argString(args, "address"))
	case "ex0_new_box":
		days := 0
		if d, ok := args["expires_days"].(float64); ok {
			days = int(d)
		}
		return s.newBox(ctx, argString(args, "site_id"), argString(args, "note"), days, installerArgs(args))
	case "ex0_rollout_status":
		return s.rolloutStatus(ctx, argString(args, "site_id"))
	case "ex0_site_lan":
		confirm, _ := args["confirm_public"].(bool)
		return s.siteLAN(ctx, argString(args, "site_id"), argString(args, "lan"), confirm)
	case "ex0_customer_vpn":
		key, _ := args["setup_key"].(string)
		return s.customerVPN(ctx, argString(args, "site_id"), argString(args, "management_url"), strings.TrimSpace(key))
	case "ex0_watch_suggestion":
		return s.watchSuggestion(ctx, argString(args, "site_id"))
	case "ex0_watch":
		picks, err := watchArgs(args)
		if err != nil {
			return "", err
		}
		suggested, _ := args["suggested"].(bool)
		return s.watchApply(ctx, argString(args, "site_id"), suggested, picks)
	case "ex0_site_scan":
		on, ok := args["on"].(bool)
		if !ok {
			return "", errors.New("on: true oder false")
		}
		return s.siteScan(ctx, argString(args, "site_id"), on, argString(args, "consent"))
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
	case "vuln":
		return "CVE-Abgleich"
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
