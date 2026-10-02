package mcp

// What a rollout needs after the box is born, as tools (ADR-0024): declare the
// site's LAN, hand the box the customer's VPN, switch monitoring on, switch
// the scan on with the consent on the record — and one answer to "how far is
// this site", so that a session finishes a customer in one go instead of
// handing a person a list of clicks.
//
// Every one of them is set-up on our server, audited under the session's
// actor. None reaches into a customer's network by itself: the box still pulls
// its configuration, and the server still chooses only from the closed list of
// checks. What stays with a person is acknowledging, operating, and typing a
// device's credentials.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/server/remote"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/server/watch"
	"github.com/excubra/excubra/internal/version"
	"github.com/excubra/excubra/internal/wire"
)

// Engine, Remote and Watcher are the parts of the running server the set-up
// tools drive. They are nil when the command answers from the files, without a
// server on the socket; a tool that needs one says so.
type Engine interface {
	CreateSite(ctx context.Context, s store.Site, actor string) error
	SetSiteScan(ctx context.Context, siteID string, enabled bool, actor string) error
}

// Remote is remote access through the box (ADR-0016).
type Remote interface {
	Enable(ctx context.Context, siteID, cidr, actor string) (store.RemoteAccess, error)
	Declare(ctx context.Context, siteID, cidr, actor string) (store.RemoteAccess, error)
}

// Watcher is the console's "beobachten, was zählt".
type Watcher interface {
	WatchProposal(ctx context.Context, siteID string) (watch.Proposal, error)
	WatchSuggested(ctx context.Context, siteID, actor string) (watch.Outcome, error)
	WatchDevices(ctx context.Context, siteID, actor string, picks []watch.Pick) (watch.Outcome, error)
}

var errNeedsServer = errors.New("dieses Werkzeug arbeitet im laufenden Server; der antwortet gerade nicht auf seinem Socket (Dienst läuft nicht, oder noch die alte Version). Lesen geht, Einrichten erst wieder, wenn der Server da ist")

// activeBox is the site's box that is not revoked.
func (s *Server) activeBox(ctx context.Context, siteID string) (store.Box, error) {
	boxes, err := s.Store.Boxes(ctx, siteID)
	if err != nil {
		return store.Box{}, err
	}
	for _, b := range boxes {
		if b.RevokedAt == nil {
			return b, nil
		}
	}
	return store.Box{}, errors.New("an diesem Standort ist noch keine Box angekommen — erst der Befehl aus ex0_new_box, dann dieser Schritt")
}

// siteLAN switches remote access on for a network the caller names, or the one
// the box reports. A network outside RFC 1918 takes the caller's explicit
// confirmation: it is a statement about this customer, and the route carries
// real traffic for that range.
func (s *Server) siteLAN(ctx context.Context, siteID, lan string, confirmPublic bool) (string, error) {
	if s.Remote == nil {
		return "", errNeedsServer
	}
	if _, err := s.Store.Site(ctx, siteID); err != nil {
		return "", fmt.Errorf("site %q: %w", siteID, err)
	}
	box, err := s.activeBox(ctx, siteID)
	if err != nil {
		return "", err
	}
	if lan == "" {
		switch {
		case len(box.LAN) > 0:
			lan = box.LAN[0]
		case len(box.LANOther) > 0:
			lan = box.LANOther[0]
		default:
			return "", errors.New("die Box meldet noch kein Netz (der erste Heartbeat nach dem Enrollment bringt es); sonst das LAN als lan angeben")
		}
	}
	var ra store.RemoteAccess
	if confirmPublic {
		ra, err = s.Remote.Declare(ctx, siteID, lan, s.Actor)
	} else {
		ra, err = s.Remote.Enable(ctx, siteID, lan, s.Actor)
	}
	switch {
	case errors.Is(err, remote.ErrNotDeclared):
		return "", fmt.Errorf("%s ist kein privater Adressbereich (RFC 1918). Als LAN gilt es nur, wenn ein Mensch für diesen Kunden bestätigt hat, dass das Netz so nummeriert ist — dann denselben Aufruf mit confirm_public: true. Die Route im Techniker-Stack nimmt den echten Internetverkehr für diesen Bereich mit", lan)
	case errors.Is(err, remote.ErrNotAttached):
		return "", fmt.Errorf("nur ein Netz, in dem die Box selbst steht, lässt sich zum LAN erklären: %w", err)
	case errors.Is(err, remote.ErrBadCIDR):
		return "", errors.New("lan: ein IPv4-Netz in CIDR-Schreibweise, /8 bis /30, z. B. 192.168.10.0/24")
	case errors.Is(err, remote.ErrOverlap):
		return "", fmt.Errorf("dieses Netz ist im Techniker-Stack schon vergeben: %w — zwei Standorte mit demselben LAN können nicht beide eingeschaltet sein", err)
	case errors.Is(err, remote.ErrNotConfigured):
		return "", errors.New("der Techniker-Stack ist auf diesem Server nicht eingerichtet (Konsole → Einstellungen)")
	case err != nil:
		return "", err
	}
	return pretty(map[string]any{"site_id": siteID, "lan": ra.CIDR, "state": ra.State, "detail": ra.Detail,
		"next": "ex0_rollout_status zeigt, wann der Fernzugriff aktiv ist; im NetBird-Client der Techniker erscheint das Netz als eigener Eintrag"}), nil
}

// customerVPN hands the site's box what it needs to join the customer's own
// NetBird stack: the management URL and a setup key. The box claims the key
// once, with its next config pull, and the server forgets it at that moment.
// It should be a one-off key all the same: it passes through a session.
func (s *Server) customerVPN(ctx context.Context, siteID, url, key string) (string, error) {
	if _, err := s.Store.Site(ctx, siteID); err != nil {
		return "", fmt.Errorf("site %q: %w", siteID, err)
	}
	box, err := s.activeBox(ctx, siteID)
	if err != nil {
		return "", err
	}
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if !strings.HasPrefix(url, "https://") || len(url) > 200 || strings.ContainsAny(url, " \t\"'") {
		return "", errors.New("management_url: https://<kunde>.vpn.… — die Adresse des Kunden-Stacks")
	}
	if len(key) < 16 || len(key) > 200 || strings.ContainsAny(key, " \t\r\n\"'") {
		return "", errors.New("setup_key: der Setup-Key der Box-Gruppe im Kunden-Stack, so wie der Stack ihn ausgibt")
	}
	if err := s.Store.SetNetbirdKey(ctx, store.NetbirdKey{BoxID: box.ID, ManagementURL: url, SetupKey: key, CreatedAt: s.Now()}); err != nil {
		return "", err
	}
	_ = s.Store.Audit(ctx, s.Now(), s.Actor, "netbird.set", box.ID, url)
	return pretty(map[string]any{"site_id": siteID, "box_id": box.ID, "management_url": url,
		"next": "Die Box holt den Schlüssel mit ihrem nächsten Config-Pull und tritt dem Kunden-Stack bei (ein, zwei Minuten). ex0_rollout_status zeigt customer_vpn."}), nil
}

// parseCheck reads "icmp", "tcp:443" or an http(s) URL.
func parseCheck(v string) (wire.CheckConfig, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "" || v == wire.CheckICMP || v == "ping":
		return wire.CheckConfig{Type: wire.CheckICMP}, nil
	case strings.HasPrefix(v, "tcp:"):
		port, err := strconv.Atoi(strings.TrimPrefix(v, "tcp:"))
		if err != nil || port < 1 || port > 65535 {
			return wire.CheckConfig{}, fmt.Errorf("check %q: tcp:<port>, 1 bis 65535", v)
		}
		return wire.CheckConfig{Type: wire.CheckTCP, Port: port}, nil
	case strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://"):
		if len(v) > 300 || strings.ContainsAny(v, " \t\r\n") {
			return wire.CheckConfig{}, fmt.Errorf("check %q: eine URL ohne Leerzeichen", v)
		}
		return wire.CheckConfig{Type: wire.CheckHTTP, URL: v}, nil
	}
	return wire.CheckConfig{}, fmt.Errorf("check %q: icmp, tcp:<port> oder eine http(s)-URL — andere Prüfungen kennt die Box nicht", v)
}

// watchArgs reads the devices of ex0_watch.
func watchArgs(args map[string]any) ([]watch.Pick, error) {
	list, _ := args["devices"].([]any)
	if len(list) > 200 {
		return nil, errors.New("devices: höchstens 200 in einem Aufruf")
	}
	picks := make([]watch.Pick, 0, len(list))
	for _, v := range list {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("devices: je Gerät ein Objekt {device_id, checks?, uplink?}")
		}
		p := watch.Pick{DeviceID: argString(m, "device_id")}
		if p.DeviceID == "" {
			return nil, errors.New("devices: device_id fehlt (aus ex0_devices oder ex0_watch_suggestion)")
		}
		var checks []string
		if c := argString(m, "check"); c != "" {
			checks = append(checks, c)
		}
		if cl, ok := m["checks"].([]any); ok {
			for _, c := range cl {
				if cs, ok := c.(string); ok {
					checks = append(checks, cs)
				}
			}
		}
		if len(checks) > 5 {
			return nil, errors.New("devices: höchstens fünf Prüfungen je Gerät")
		}
		for _, c := range checks {
			cc, err := parseCheck(c)
			if err != nil {
				return nil, err
			}
			p.Checks = append(p.Checks, cc)
		}
		if up, ok := m["uplink"].(bool); ok {
			p.Uplink = &up
		}
		picks = append(picks, p)
	}
	return picks, nil
}

func (s *Server) watchSuggestion(ctx context.Context, siteID string) (string, error) {
	if s.Watch == nil {
		return "", errNeedsServer
	}
	p, err := s.Watch.WatchProposal(ctx, siteID)
	if err != nil {
		return "", err
	}
	return pretty(map[string]any{"site_id": siteID, "has_box": p.HasBox, "would_add": p.Add, "skipped": p.Skipped, "watched": p.Watched,
		"next": "ex0_watch mit suggested: true übernimmt would_add (Ping, Firewall und Router als Uplink); mit devices lassen sich Geräte einzeln und mit eigener Prüfung aufnehmen oder ändern"}), nil
}

func (s *Server) watchApply(ctx context.Context, siteID string, suggested bool, picks []watch.Pick) (string, error) {
	if s.Watch == nil {
		return "", errNeedsServer
	}
	if !suggested && len(picks) == 0 {
		return "", errors.New("suggested: true für den Vorschlag der Regel, oder devices mit den Geräten, die beobachtet werden sollen")
	}
	out := map[string]any{"site_id": siteID}
	if suggested {
		o, err := s.Watch.WatchSuggested(ctx, siteID, s.Actor)
		if err != nil {
			return "", err
		}
		out["suggested"] = o
	}
	if len(picks) > 0 {
		o, err := s.Watch.WatchDevices(ctx, siteID, s.Actor, picks)
		if err != nil {
			return "", err
		}
		out["devices"] = o
	}
	out["next"] = "Die Box prüft ab ihrem nächsten Config-Pull, innerhalb einer Minute. Der Zustand steht in der Konsole unter Standort → Überwachung und in ex0_watch_suggestion unter watched."
	return pretty(out), nil
}

// siteScan switches the service scan. Switching it on takes the customer's
// consent — it is in the contract or it is not — and the tool wants to be told
// who gave it, so the audit log answers the question later.
func (s *Server) siteScan(ctx context.Context, siteID string, on bool, consent string) (string, error) {
	if s.Engine == nil {
		return "", errNeedsServer
	}
	if _, err := s.Store.Site(ctx, siteID); err != nil {
		return "", fmt.Errorf("site %q: %w", siteID, err)
	}
	consent = strings.TrimSpace(consent)
	if on && len(consent) < 12 {
		return "", errors.New("consent: der Scan braucht die Einwilligung des Kunden (E20). Wer hat wann zugestimmt, und wo steht es — ein Satz, er kommt ins Audit-Log. Ohne das bleibt der Scan aus")
	}
	if len(consent) > 300 {
		consent = consent[:300]
	}
	if on {
		_ = s.Store.Audit(ctx, s.Now(), s.Actor, "site.scan.consent", siteID, consent)
	}
	if err := s.Engine.SetSiteScan(ctx, siteID, on, s.Actor); err != nil {
		return "", err
	}
	state := "aus"
	if on {
		state = "an; die erste Runde läuft innerhalb der nächsten Stunde an, gedrosselt, und liest nur"
	}
	return pretty(map[string]any{"site_id": siteID, "scan": state}), nil
}

// step is one line of the rollout's checklist.
type step struct {
	Step   string `json:"step"`
	State  string `json:"state"` // ok | open | waiting | optional
	Detail string `json:"detail"`
	Next   string `json:"next,omitempty"`
}

// rolloutStatus answers "how far is this site" in one call: every step of a
// rollout with its state and, where something is missing, what to do about it.
func (s *Server) rolloutStatus(ctx context.Context, siteID string) (string, error) {
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return "", fmt.Errorf("site %q: %w", siteID, err)
	}
	tenant, _ := s.Store.Tenant(ctx, site.TenantID)
	now := s.Now()
	var steps []step
	add := func(name, state, detail, next string) {
		steps = append(steps, step{Step: name, State: state, Detail: detail, Next: next})
	}

	box, berr := s.activeBox(ctx, siteID)
	if berr != nil {
		waiting := 0
		if keys, err := s.Store.EnrollmentKeys(ctx); err == nil {
			for _, k := range keys {
				if k.SiteID == siteID && k.UsedAt == nil && k.RevokedAt == nil && k.ExpiresAt.After(now) {
					waiting++
				}
			}
		}
		if waiting > 0 {
			add("box", "waiting", fmt.Sprintf("noch keine Box; %d Enrollment-Key%s für diesen Standort wartet auf seinen Befehl", waiting, pluralS(waiting)), "den Befehl aus ex0_new_box auf dem Proxmox-Host oder der Box ausführen; er endet mit »EX0-RESULT: ok …«")
		} else {
			add("box", "open", "noch keine Box und kein offener Enrollment-Key", "ex0_new_box für diesen Standort")
		}
		return pretty(map[string]any{"site_id": siteID, "site": site.Name, "tenant": tenant.Name, "done": false, "steps": steps}), nil
	}

	age := now.Sub(box.LastSeen)
	switch {
	case box.LastSeen.IsZero():
		add("box", "waiting", box.ID+" ist enrollt, der erste Heartbeat steht aus", "eine Minute warten")
	case age > 5*time.Minute:
		add("box", "open", fmt.Sprintf("%s schweigt seit %s", box.ID, rel(box.LastSeen, now)), "Läuft der Container bzw. die Maschine? Kommt sie ins Internet (ausgehend 443 zum Server)?")
	default:
		add("box", "ok", fmt.Sprintf("%s meldet sich (%s), Adresse im LAN %s", box.ID, rel(box.LastSeen, now), firstNonEmpty(box.LANIP, "unbekannt")), "")
	}
	if v := version.Version; box.AgentVersion == v {
		add("version", "ok", "Agent "+box.AgentVersion+", wie der Server", "")
	} else {
		add("version", "waiting", "Agent "+firstNonEmpty(box.AgentVersion, "?")+", Server "+v, "die Box zieht das Update von selbst (einmal täglich; sofort mit Konsole → Updates → Update holen)")
	}

	switch box.NetbirdOpStatus {
	case wire.NetbirdConnected:
		add("operator_vpn", "ok", "im Techniker-Stack, Overlay-Adresse "+box.NetbirdOpIP+" — ssh root@"+box.NetbirdOpIP+" aus dem VIICO-Tunnel", "")
	case "":
		add("operator_vpn", "open", "die Box meldet keinen Operator-Peer", "Box mit dem Installer eingerichtet? (provision-box.sh bringt ihn mit)")
	default:
		add("operator_vpn", "waiting", "Operator-Peer: "+box.NetbirdOpStatus+" — die Box holt ihren Schlüssel und tritt bei", "zwei, drei Minuten nach dem Enrollment")
	}

	ra, rerr := s.Store.RemoteAccess(ctx, siteID)
	switch {
	case len(box.LAN) == 0 && len(box.LANOther) == 0:
		add("lan", "waiting", "die Box hat noch kein Netz gemeldet", "kommt mit dem nächsten Heartbeat")
	case len(box.LAN) == 0 && !declaredAny(site, box.LANOther):
		add("lan", "open", strings.Join(box.LANOther, ", ")+" — kein privater Adressbereich (RFC 1918), nicht als LAN erklärt",
			"Ist das wirklich das LAN dieses Kunden: von Jeremia bestätigen lassen, dann ex0_site_lan mit confirm_public: true")
	case len(box.LAN) > 0:
		add("lan", "ok", strings.Join(box.LAN, ", "), "")
	default:
		add("lan", "ok", strings.Join(box.LANOther, ", ")+" (für diesen Standort zum LAN erklärt)", "")
	}
	switch {
	case rerr != nil:
		add("remote_access", "waiting", "noch nicht eingeschaltet", "schaltet sich von selbst ein, sobald die Box im Techniker-Stack ist und ihr LAN meldet; sonst ex0_site_lan")
	case ra.State == store.RemoteActive:
		add("remote_access", "ok", ra.CIDR+" ist im Techniker-Stack erreichbar, Eintrag »"+firstNonEmpty(ra.ResourceName, tenant.Name+" · "+site.Name)+"«", "")
	case ra.State == store.RemoteError:
		add("remote_access", "open", ra.CIDR+": "+ra.Detail, "die Ursache beheben, dann ex0_site_lan (bei einem Netz außerhalb RFC 1918 mit confirm_public: true)")
	case ra.State == store.RemoteOff:
		add("remote_access", "open", ra.CIDR+": "+firstNonEmpty(ra.Detail, "abgeschaltet"), "ein Mensch hat es abgeschaltet; nur auf seine Bitte wieder einschalten (ex0_site_lan)")
	default:
		add("remote_access", "waiting", ra.CIDR+": "+firstNonEmpty(ra.Detail, ra.State), "wird gerade verdrahtet, zwei bis drei Minuten")
	}

	nk, kerr := s.Store.NetbirdKey(ctx, box.ID)
	switch {
	case box.NetbirdStatus == wire.NetbirdConnected:
		add("customer_vpn", "ok", "die Box ist im Kunden-Stack, Adresse "+box.NetbirdIP, "")
	case kerr == nil && nk.ClaimedAt == nil:
		add("customer_vpn", "waiting", "Übergabe an "+nk.ManagementURL+" hinterlegt, die Box hat sie noch nicht abgeholt", "eine Minute")
	case kerr == nil:
		add("customer_vpn", "waiting", "die Box hat den Schlüssel für "+nk.ManagementURL+" abgeholt, ihr Client meldet: "+firstNonEmpty(box.NetbirdStatus, "nichts"), "wenn das so bleibt: Ist der Setup-Key noch gültig und nicht verbraucht?")
	default:
		add("customer_vpn", "optional", "kein Kunden-VPN übergeben", "nur wenn die Mitarbeiter des Kunden ein VPN bekommen: Stack anlegen, dann ex0_customer_vpn")
	}

	devs, _ := s.Store.Devices(ctx, site.TenantID, siteID, now.Add(-30*24*time.Hour))
	if len(devs) > 0 {
		add("devices", "ok", fmt.Sprintf("%d Geräte im Netz gesehen", len(devs)), "")
	} else {
		add("devices", "waiting", "noch keine Geräte", "die erste Erkennung braucht einige Minuten (passiv, dazu ein ARP-Sweep alle 15 Minuten)")
	}

	hosts, _ := s.Store.Hosts(ctx, site.TenantID, box.ID)
	uplinks := 0
	for _, h := range hosts {
		if h.IsUplink {
			uplinks++
		}
	}
	switch {
	case len(hosts) == 0:
		add("watch", "open", "nichts wird beobachtet", "ex0_watch_suggestion ansehen, dann ex0_watch")
	case uplinks == 0:
		add("watch", "open", fmt.Sprintf("%d Geräte werden beobachtet, keines ist Uplink", len(hosts)), "Firewall oder Router als Uplink setzen (ex0_watch mit uplink: true), sonst macht eine gekappte Leitung vierzig Störungen statt einer")
	default:
		add("watch", "ok", fmt.Sprintf("%d Geräte werden beobachtet, %d davon Uplink", len(hosts), uplinks), "")
	}

	if site.ScanEnabled {
		add("scan", "ok", "an", "")
	} else {
		add("scan", "optional", "aus", "nur mit Einwilligung des Kunden: ex0_site_scan mit consent")
	}
	if site.CanaryEnabled {
		add("live_detection", "ok", "Köder-Ports an (Standard)", "")
	} else {
		add("live_detection", "optional", "Köder-Ports aus", "")
	}
	if site.DNSEnabled {
		add("dns_sensor", "ok", "an; der Router muss auf "+firstNonEmpty(box.LANIP, "die Box")+" zeigen", "")
	} else {
		add("dns_sensor", "optional", "aus (Standard)", "ein Mensch schaltet ihn in der Konsole ein und trägt die Box im Router als DNS ein")
	}

	done := true
	var open []string
	for _, st := range steps {
		if st.State == "open" || st.State == "waiting" {
			done = false
			open = append(open, st.Step)
		}
	}
	sort.Strings(open)
	out := map[string]any{"site_id": siteID, "site": site.Name, "tenant": tenant.Name, "done": done, "steps": steps}
	if !done {
		out["open"] = open
	}
	return pretty(out), nil
}

// declaredAny reports whether one of the networks lies in a declared network of the site.
func declaredAny(site store.Site, nets []string) bool {
	for _, n := range nets {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			continue
		}
		for _, d := range site.LocalNets {
			if dp, err := netip.ParsePrefix(d); err == nil && dp.Bits() <= p.Bits() && dp.Contains(p.Addr()) {
				return true
			}
		}
	}
	return false
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
