// Package rules is the first layer of prevention (salt: Vollausbau 3.8): deterministic
// checks over what a connector read, producing findings a person can act on. No
// network, no state, no clock beyond Input.Now — a pure function, tested by table.
package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Severities, in the order the console shows them.
const (
	High   = "high"
	Medium = "medium"
	Low    = "low"
)

// Rank orders severities for sorting: high first.
func Rank(sev string) int {
	switch sev {
	case High:
		return 0
	case Medium:
		return 1
	default:
		return 2
	}
}

// Finding is what a rule says about a device right now. Rule and Key identify it
// across readings: the same finding again means "still there", a missing one means
// "resolved".
type Finding struct {
	Rule     string // stable id, e.g. fgt.admin_on_wan
	Key      string // distinguishes several findings of one rule (interface, licence, tunnel)
	Severity string
	Title    string
	Detail   string
	Evidence map[string]any
}

// Input is what the rules see.
type Input struct {
	Kind    string
	Facts   map[string]any
	Metrics map[string]float64
	Pinned  bool // the device certificate is pinned in the connector
	Now     time.Time
}

// LicenceWarnDays is how early an expiring licence becomes a finding.
const LicenceWarnDays = 30

// Evaluate runs every rule for the kind and returns the findings, sorted.
func Evaluate(in Input) []Finding {
	var out []Finding
	if !in.Pinned {
		out = append(out, Finding{Rule: "connector.unpinned", Severity: Low, Title: "Zertifikat des Geräts nicht festgenagelt",
			Detail: "Ein getauschtes Gerät oder ein Angreifer dazwischen fiele nicht auf. Im Tab „Konnektor“ das Zertifikat festnageln."})
	}
	switch in.Kind {
	case "fortigate":
		out = append(out, fortigate(in)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if Rank(out[i].Severity) != Rank(out[j].Severity) {
			return Rank(out[i].Severity) < Rank(out[j].Severity)
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// adminProtocols are the allowaccess tokens that mean "you can administer me here".
var adminProtocols = map[string]bool{"https": true, "http": true, "ssh": true, "telnet": true}

func fortigate(in Input) []Finding {
	var out []Finding
	f := in.Facts

	// management reachable on a WAN interface, and plain-text management anywhere
	for _, i := range list(f["interfaces"]) {
		name, _ := i["name"].(string)
		admin, _ := i["admin"].(string)
		role, _ := i["role"].(string)
		ip, _ := i["ip"].(string)
		if admin == "" {
			continue
		}
		var mgmt, plain []string
		for _, tok := range strings.Fields(admin) {
			if adminProtocols[tok] {
				mgmt = append(mgmt, tok)
			}
			if tok == "http" || tok == "telnet" {
				plain = append(plain, tok)
			}
		}
		wan := role == "wan" || strings.HasPrefix(strings.ToLower(name), "wan") || isPublic(ip)
		if wan && len(mgmt) > 0 {
			out = append(out, Finding{Rule: "fgt.admin_on_wan", Key: name, Severity: High,
				Title:    fmt.Sprintf("Verwaltung auf %s von außen erreichbar", name),
				Detail:   fmt.Sprintf("%s (%s) erlaubt %s. Verwaltung gehört auf ein internes Interface oder hinter VPN; sonst mindestens Trusted Hosts für jeden Administrator.", name, orDash(ip), strings.Join(mgmt, ", ")),
				Evidence: map[string]any{"interface": name, "ip": ip, "admin": admin, "role": role}})
		}
		if len(plain) > 0 {
			out = append(out, Finding{Rule: "fgt.admin_plaintext", Key: name, Severity: Medium,
				Title:    fmt.Sprintf("Unverschlüsselte Verwaltung auf %s", name),
				Detail:   fmt.Sprintf("%s erlaubt %s. Passwörter gehen im Klartext über das Netz; nur HTTPS und SSH zulassen.", name, strings.Join(plain, ", ")),
				Evidence: map[string]any{"interface": name, "admin": admin}})
		}
	}

	// IPsec tunnels that are down
	for _, t := range list(f["ipsec"]) {
		name, _ := t["name"].(string)
		if up, _ := t["up"].(bool); !up && name != "" {
			gw, _ := t["gateway"].(string)
			out = append(out, Finding{Rule: "fgt.ipsec_down", Key: name, Severity: Medium,
				Title:    fmt.Sprintf("IPsec-Tunnel %s ist unten", name),
				Detail:   fmt.Sprintf("Keine Phase 2 des Tunnels%s ist aufgebaut. Gegenstelle prüfen, oder den Tunnel entfernen, wenn er nicht mehr gebraucht wird.", gwText(gw)),
				Evidence: map[string]any{"tunnel": name, "gateway": gw}})
		}
	}

	// licences: expired now, or expiring soon
	if lic, ok := f["licenses"].(map[string]any); ok {
		for name, v := range lic {
			e, _ := v.(map[string]any)
			status, _ := e["status"].(string)
			exp, _ := e["expires"].(float64)
			switch {
			case strings.EqualFold(status, "expired"):
				out = append(out, Finding{Rule: "fgt.license_expired", Key: name, Severity: High,
					Title:    fmt.Sprintf("Lizenz %s ist abgelaufen", name),
					Detail:   "Der Dienst läuft ohne Updates oder gar nicht mehr. Verlängerung bei Fortinet oder dem Distributor anstoßen.",
					Evidence: map[string]any{"license": name, "status": status}})
			case strings.EqualFold(status, "licensed") && exp > 0:
				expAt := time.Unix(int64(exp), 0)
				if days := int(expAt.Sub(in.Now).Hours() / 24); days >= 0 && days <= LicenceWarnDays {
					out = append(out, Finding{Rule: "fgt.license_expiring", Key: name, Severity: Medium,
						Title:    fmt.Sprintf("Lizenz %s läuft in %d Tagen ab", name, days),
						Detail:   fmt.Sprintf("Ablauf am %s. Verlängerung rechtzeitig einkaufen, sonst steht der Dienst.", expAt.Format("02.01.2006")),
						Evidence: map[string]any{"license": name, "expires": expAt.Format(time.RFC3339)}})
				}
			case name == "forticare" && status != "" && !strings.EqualFold(status, "registered"):
				out = append(out, Finding{Rule: "fgt.forticare", Severity: Medium, Title: "FortiCare nicht registriert",
					Detail:   "Ohne Registrierung keine Firmware-Updates und kein Support. Gerät im FortiCare-Portal registrieren.",
					Evidence: map[string]any{"status": status}})
			}
		}
	}

	// HA cluster missing its partner
	if mode, _ := f["ha_mode"].(string); mode != "" && mode != "standalone" {
		if peers := in.Metrics["ha_peers"]; peers < 2 {
			out = append(out, Finding{Rule: "fgt.ha_degraded", Severity: High, Title: "HA-Verbund unvollständig",
				Detail:   fmt.Sprintf("Modus %s, aber nur %d Mitglied sichtbar. Der Partner ist ausgefallen oder nicht mehr im Verbund.", mode, int(peers)),
				Evidence: map[string]any{"mode": mode, "peers": peers}})
		}
	}

	// resources
	if v := in.Metrics["mem_pct"]; v >= 90 {
		out = append(out, Finding{Rule: "fgt.memory_high", Severity: Medium, Title: fmt.Sprintf("Speicher zu %.0f %% belegt", v),
			Detail:   "Ab etwa 88 % geht die FortiGate in den Conserve Mode und lässt Verbindungen fallen. Sessions, UTM-Profile und Logs prüfen.",
			Evidence: map[string]any{"mem_pct": v}})
	}
	if v := in.Metrics["cpu_pct"]; v >= 90 {
		out = append(out, Finding{Rule: "fgt.cpu_high", Severity: Medium, Title: fmt.Sprintf("CPU zu %.0f %% ausgelastet", v),
			Detail:   "Dauerhaft hohe CPU-Last bremst den Durchsatz. Top-Sessions und IPS-Profile prüfen.",
			Evidence: map[string]any{"cpu_pct": v}})
	}

	// lax admin timeout
	if t, ok := number(f["admin_timeout_min"]); ok && t > 30 {
		out = append(out, Finding{Rule: "fgt.admin_timeout", Severity: Low, Title: fmt.Sprintf("Admin-Timeout %d Minuten", int(t)),
			Detail:   "Eine vergessene Sitzung bleibt so lange nutzbar. Zehn Minuten sind üblich.",
			Evidence: map[string]any{"admin_timeout_min": t}})
	}
	return out
}

func list(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

// isPublic reports whether ip (possibly "addr mask") is a routable public IPv4/6 address.
func isPublic(ip string) bool {
	fields := strings.Fields(ip)
	if len(fields) == 0 {
		return false
	}
	a, err := netip.ParseAddr(fields[0])
	if err != nil || !a.IsValid() || a.IsUnspecified() {
		return false
	}
	return !a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast()
}

func orDash(s string) string {
	if s == "" {
		return "ohne Adresse"
	}
	return s
}

func gwText(gw string) string {
	if gw == "" {
		return ""
	}
	return " zu " + gw
}
