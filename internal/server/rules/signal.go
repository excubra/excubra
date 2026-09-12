package rules

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Signal is what the box saw live (ADR-0018 §7), as the rules see it: one source,
// one kind, how often. The judgement is fixed per kind; the box does not judge.
type Signal struct {
	Kind   string
	Device string // the reporting device's name, for signals a connector read from its logs
	IP     string
	MAC    string
	Port   int
	Count  int
	Detail string
	First  time.Time
	Last   time.Time
}

// decoyNames names the services the decoy ports pretend to be.
var decoyNames = map[int]string{21: "FTP", 23: "Telnet", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 5985: "WinRM", 8080: "HTTP"}

// PortLabel is "445 (SMB)" for a known decoy port, "8443" otherwise.
func PortLabel(port int) string {
	if n, ok := decoyNames[port]; ok {
		return fmt.Sprintf("%d (%s)", port, n)
	}
	return strconv.Itoa(port)
}

// EvaluateSignal turns one live signal into a finding on its source device. Every
// kind is urgent: a healthy LAN produces none of them, and the one legitimate
// producer (an inventory or monitoring tool) is known to the operator and
// acknowledged once.
func EvaluateSignal(sg Signal) (Finding, bool) {
	ev := map[string]any{"kind": sg.Kind, "ip": sg.IP, "count": sg.Count, "first": sg.First.UTC().Format(time.RFC3339), "last": sg.Last.UTC().Format(time.RFC3339)}
	if sg.MAC != "" {
		ev["mac"] = sg.MAC
	}
	if sg.Detail != "" {
		ev["detail"] = sg.Detail
	}
	switch sg.Kind {
	case "canary":
		ev["port"] = sg.Port
		return Finding{Rule: "signal.canary", Key: strconv.Itoa(sg.Port), Severity: High, Title: "Köder-Port " + PortLabel(sg.Port) + " angesprochen",
			Detail: CanaryDetail(sg.Port, sg.Count), Evidence: ev}, true
	case "port_scan":
		return Finding{Rule: "signal.port_scan", Severity: High, Title: "Portscan gegen die EX0-Box",
			Detail: fmt.Sprintf("Das Gerät hat innerhalb einer Minute an %d verschiedene Ports der Box geklopft (%s). Das macht ein Scanner, kein Anwender: Erkundung des Netzes von diesem Gerät aus.", sg.Count, sg.Detail), Evidence: ev}, true
	case "arp_scan":
		return Finding{Rule: "signal.arp_scan", Severity: High, Title: "Netz wird abgesucht (ARP)",
			Detail: fmt.Sprintf("Das Gerät hat innerhalb einer Minute nach %d Adressen im LAN gefragt. So erkundet nmap, ein Wurm oder ein Angreifer das Netz. Ein Inventar- oder Monitoring-Werkzeug sieht genauso aus; dann ist es bekannt und wird einmal quittiert.", sg.Count), Evidence: ev}, true
	case "fgt_admin_fail":
		where := origin(sg.IP)
		sev := Medium
		if sg.Count >= 5 || !private(sg.IP) {
			sev = High
		}
		return Finding{Rule: "signal.fgt_admin_fail", Key: sg.IP, Severity: sev, Title: fmt.Sprintf("Admin-Login auf der FortiGate: %s", plural(sg.Count, "Fehlversuch", "Fehlversuche")),
			Detail: fmt.Sprintf("Von %s%s%s. Ist die Verwaltung auf dem WAN-Interface erreichbar, wird sie gerade durchprobiert: Admin-Zugang auf WAN abschalten, Trusted Hosts setzen, Zwei-Faktor für Admins. Aus dem LAN heraus: klären, wer da an der Firewall probiert.", sg.IP, where, users(sg.Detail)), Evidence: ev}, true
	case "fgt_vpn_fail":
		sev := Medium
		if sg.Count >= 20 {
			sev = High
		}
		title := fmt.Sprintf("SSL-VPN-Anmeldung: %s", plural(sg.Count, "Fehlversuch", "Fehlversuche"))
		if sg.Count >= 20 {
			title = fmt.Sprintf("SSL-VPN wird durchprobiert: %d Fehlversuche", sg.Count)
		}
		return Finding{Rule: "signal.fgt_vpn_fail", Key: sg.IP, Severity: sev, Title: title,
			Detail: fmt.Sprintf("Von %s%s%s. Ein Anwender vertippt sich ein paarmal; Dutzende Versuche in Minuten sind ein Wörterbuch-Angriff auf das VPN. Bei Bedarf die Quelle sperren, Konten mit schwachen Passwörtern prüfen, Zwei-Faktor für das VPN.", sg.IP, origin(sg.IP), users(sg.Detail)), Evidence: ev}, true
	case "fgt_ips":
		attack, ipsSev, action := splitIPS(sg.Detail)
		sev := Medium
		switch strings.ToLower(ipsSev) {
		case "critical", "high":
			sev = High
		case "low", "info", "information":
			sev = Low
		}
		blocked := action == "dropped" || action == "reset" || action == "blocked" || action == "reject"
		verdict := "nicht geblockt"
		if blocked {
			verdict = "geblockt"
		} else if sev != High {
			sev = High // seen but let through
		}
		ev["attack"], ev["ips_severity"], ev["action"] = attack, ipsSev, action
		return Finding{Rule: "signal.fgt_ips", Key: attack, Severity: sev, Title: fmt.Sprintf("IPS: %s von %s (%s)", attack, sg.IP, verdict),
			Detail: fmt.Sprintf("Die FortiGate hat die Signatur „%s“ %s erkannt, Quelle %s%s, Einstufung %s, Aktion: %s. Geblockt heißt: der Versuch war da; nicht geblockt heißt: er ist durch, das Ziel prüfen.", attack, plural(sg.Count, "Mal", "Mal"), sg.IP, origin(sg.IP), firstNonEmptyStr(ipsSev, "unbekannt"), firstNonEmptyStr(action, "unbekannt")), Evidence: ev}, true
	case "arp_spoof":
		macs := sg.Detail
		if i := strings.IndexByte(macs, ' '); i > 0 {
			macs = macs[i+1:]
		}
		if strings.HasPrefix(sg.Detail, "gateway") {
			return Finding{Rule: "signal.arp_spoof", Key: sg.IP, Severity: High, Title: "ARP-Spoofing: das Gateway antwortet von einer anderen MAC",
				Detail: fmt.Sprintf("Die Adresse des Gateways %s wird jetzt von diesem Gerät beansprucht (%s). Entweder wurde der Router getauscht, oder jemand lenkt den Verkehr des Netzes über sich (Man-in-the-Middle). Sofort klären.", sg.IP, macs), Evidence: ev}, true
		}
		return Finding{Rule: "signal.arp_spoof", Key: sg.IP, Severity: High, Title: "ARP-Spoofing: Adresse wechselt die MAC",
			Detail: fmt.Sprintf("Die Adresse %s springt zwischen zwei Geräten hin und her (%s, %s in zehn Minuten). Ein neuer DHCP-Lease erklärt einen Wechsel, nicht ein Hin und Her: Typisch für ARP-Spoofing gegen dieses Gerät.", sg.IP, macs, plural(sg.Count, "Wechsel", "Wechsel")), Evidence: ev}, true
	}
	return Finding{}, false
}

// CanaryDetail is the canary finding's text for a port and a number of touches;
// the engine renews it as touches add up.
func CanaryDetail(port, count int) string {
	return fmt.Sprintf("Das Gerät hat auf der EX0-Box Port %s angesprochen. Dort läuft kein echter Dienst, und kein normales Gerät sucht ihn: So sehen Scans, Würmer und ein Angreifer aus, der sich im Netz umsieht. %s.",
		PortLabel(port), plural(count, "Versuch", "Versuche"))
}

// origin says whether an address is inside or outside.
func origin(ip string) string {
	if ip == "" {
		return ""
	}
	if private(ip) {
		return " (aus dem LAN)"
	}
	return " (aus dem Internet)"
}

func private(ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && (a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast())
}

// users renders the user list a signal carries in its detail.
func users(detail string) string {
	if detail == "" {
		return ""
	}
	return ", Benutzer: " + detail
}

// splitIPS reads the "attack|severity|action" detail of an IPS signal.
func splitIPS(detail string) (attack, severity, action string) {
	parts := strings.SplitN(detail, "|", 3)
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	return parts[0], parts[1], parts[2]
}

func firstNonEmptyStr(v ...string) string {
	for _, x := range v {
		if x != "" {
			return x
		}
	}
	return ""
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
