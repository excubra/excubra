package rules

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Signal is what the box saw live (ADR-0018 §7), as the rules see it: one source,
// one kind, how often. The judgement is fixed per kind; the box does not judge.
type Signal struct {
	Kind   string
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

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
