package rules

import (
	"fmt"
	"sort"
	"strings"
)

// EvaluateExternal runs the rules over what the outpost saw on a site's public
// address (ADR-0018, outside view). Outside, every open door counts: services
// that are normal in a LAN are findings here, and the worst ones are urgent.
func EvaluateExternal(in ScanInput) []Finding {
	var out []Finding
	for _, svc := range in.Services {
		key := fmt.Sprintf("tcp/%d", svc.Port)
		if svc.Proto != "" {
			key = fmt.Sprintf("%s/%d", svc.Proto, svc.Port)
		}
		ev := evidence(svc)
		name := svc.Name
		if name == "" {
			name = fmt.Sprintf("Port %d", svc.Port)
		}
		switch svc.Port {
		case 3389:
			out = append(out, Finding{Rule: "wan.rdp", Key: key, Severity: High, Title: "Remotedesktop aus dem Internet erreichbar",
				Detail: "RDP auf der öffentlichen Adresse ist das häufigste Einfallstor für Verschlüsselungstrojaner: Passwörter werden rund um die Uhr durchprobiert. Weiterleitung schließen, Zugriff nur über VPN.", Evidence: ev})
		case 445, 139, 135:
			out = append(out, Finding{Rule: "wan.smb", Key: key, Severity: High, Title: "Windows-Dateifreigabe aus dem Internet erreichbar",
				Detail: "SMB/NetBIOS auf der öffentlichen Adresse. Dafür gibt es keinen legitimen Grund; Weiterleitung sofort schließen.", Evidence: ev})
		case 23, 21, 5900, 2375, 5985, 389, 111, 2049, 9100, 1723:
			what := map[int]string{23: "Telnet", 21: "FTP", 5900: "VNC", 2375: "Docker-API", 5985: "WinRM ohne TLS", 389: "LDAP", 111: "RPC", 2049: "NFS", 9100: "Drucker-Port", 1723: "PPTP-VPN"}[svc.Port]
			out = append(out, Finding{Rule: "wan.exposed", Key: key, Severity: High, Title: what + " aus dem Internet erreichbar",
				Detail: what + " auf der öffentlichen Adresse: Klartext, ohne Anmeldung oder mit gebrochener Verschlüsselung. Weiterleitung schließen; wenn Fernzugriff gebraucht wird, nur über VPN.", Evidence: ev})
		case 3306, 5432, 1433, 1521, 6379, 27017, 9200:
			out = append(out, Finding{Rule: "wan.database", Key: key, Severity: High, Title: "Datenbank aus dem Internet erreichbar",
				Detail: "Eine Datenbank (" + name + ") antwortet auf der öffentlichen Adresse. Datenbanken gehören nie ins Internet; Weiterleitung schließen.", Evidence: ev})
		case 22:
			out = append(out, Finding{Rule: "wan.ssh", Key: key, Severity: Medium, Title: "SSH aus dem Internet erreichbar",
				Detail: "SSH auf der öffentlichen Adresse wird ständig mit Passwortlisten angegangen. Nur mit Schlüsseln, besser nur über VPN.", Evidence: ev})
		case 5060, 5061:
			out = append(out, Finding{Rule: "wan.sip", Key: key, Severity: Medium, Title: "Telefonanlage (SIP) aus dem Internet erreichbar",
				Detail: "SIP auf der öffentlichen Adresse lädt zu Gebührenbetrug ein. Nur die Adressen des Providers zulassen oder hinter VPN.", Evidence: ev})
		case 25, 465, 587, 110, 143, 993, 995:
			out = append(out, Finding{Rule: "wan.mail", Key: key, Severity: Low, Title: "Maildienst aus dem Internet erreichbar",
				Detail: name + " auf der öffentlichen Adresse. Bei einem eigenen Mailserver gewollt; dann quittieren und den Server aktuell halten.", Evidence: ev})
		case 1194:
			out = append(out, Finding{Rule: "wan.vpn", Key: key, Severity: Low, Title: "VPN-Endpunkt aus dem Internet erreichbar",
				Detail: "OpenVPN auf der öffentlichen Adresse. Gewollt, wenn der Kunde ein eigenes VPN betreibt; quittieren und aktuell halten.", Evidence: ev})
		default:
			if isWeb(svc) {
				if adminUI(svc) {
					out = append(out, Finding{Rule: "wan.admin_ui", Key: key, Severity: High, Title: "Verwaltungsoberfläche aus dem Internet erreichbar",
						Detail: fmt.Sprintf("Auf Port %d antwortet eine Verwaltungsoberfläche (%s). Sie ist das erste Ziel automatisierter Angriffe; Fernzugriff abschalten oder nur über VPN.", svc.Port, orDash(firstNonEmpty(svc.Title, svc.Product))), Evidence: ev})
				} else {
					out = append(out, Finding{Rule: "wan.web", Key: key, Severity: Medium, Title: fmt.Sprintf("Webdienst auf Port %d aus dem Internet erreichbar", svc.Port),
						Detail: fmt.Sprintf("Ein Webdienst (%s) antwortet auf der öffentlichen Adresse. Wenn das die eigene Website ist: quittieren und aktuell halten. Sonst Weiterleitung schließen.", orDash(firstNonEmpty(svc.Title, svc.Product, svc.Banner))), Evidence: ev})
				}
			} else {
				out = append(out, Finding{Rule: "wan.open", Key: key, Severity: Low, Title: name + " aus dem Internet erreichbar",
					Detail: fmt.Sprintf("Port %d ist auf der öffentlichen Adresse offen. Prüfen, ob die Weiterleitung noch gebraucht wird.", svc.Port), Evidence: ev})
			}
		}
		if svc.TLS != nil {
			for _, f := range tlsFindings(svc, key, in.Now) {
				f.Rule = strings.Replace(f.Rule, "scan.", "wan.", 1)
				// outside, a self-signed or old-TLS service is one grade worse
				if f.Rule == "wan.cert_selfsigned" || f.Rule == "wan.tls_old" {
					f.Severity = worse(f.Severity)
				}
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
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

func isWeb(svc Service) bool {
	return svc.Name == "http" || svc.Name == "https" || svc.Title != "" || svc.TLS != nil && svc.Port != 465 && svc.Port != 993 && svc.Port != 995 && svc.Port != 636
}

// adminUI recognises the login pages of the devices small networks run.
func adminUI(svc Service) bool {
	hay := strings.ToLower(svc.Title + " " + svc.Banner + " " + svc.Product)
	for _, w := range []string{"fritz", "fortigate", "fortinet", "proxmox", "pve", "starface", "synology", "qnap", "unifi", "ubiquiti", "router", "gateway", "firewall",
		"speedport", "lancom", "sophos", "watchguard", "mikrotik", "router os", "pfsense", "opnsense", "ilo", "idrac", "webmin", "cockpit", "truenas", "freenas", "nas", "admin", "login", "anmeld"} {
		if strings.Contains(hay, w) {
			return true
		}
	}
	return svc.Port == 8006 || svc.Port == 10000
}

func worse(sev string) string {
	switch sev {
	case Low:
		return Medium
	default:
		return High
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
