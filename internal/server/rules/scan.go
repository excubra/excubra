package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ScanInput is what the scan rules see: the open services of one device as the
// box's service scan found them (ADR-0018).
type ScanInput struct {
	Services []Service
	Now      time.Time
}

// Service mirrors wire.ScanService without the dependency.
type Service struct {
	Port    int
	Proto   string
	Name    string
	Product string
	Version string
	Banner  string
	Title   string
	TLS     *TLS
}

// TLS mirrors wire.TLSInfo.
type TLS struct {
	Subject    string
	Issuer     string
	NotAfter   time.Time
	SelfSigned bool
	Version    string
}

// CertWarnDays is how early an expiring certificate becomes a finding.
const CertWarnDays = 14

// EvaluateScan runs the rules over a device's services. Inside a LAN most
// services are normal; the rules speak up about plain-text logins, services that
// are usually unauthenticated, remote-control services and certificates.
func EvaluateScan(in ScanInput) []Finding {
	var out []Finding
	for _, svc := range in.Services {
		key := fmt.Sprintf("%s/%d", orDash(svc.Proto), svc.Port)
		if svc.Proto == "" {
			key = fmt.Sprintf("tcp/%d", svc.Port)
		}
		where := fmt.Sprintf("Port %d", svc.Port)
		switch svc.Port {
		case 23:
			out = append(out, Finding{Rule: "scan.telnet", Key: key, Severity: High, Title: "Telnet erreichbar",
				Detail: "Telnet überträgt Anmeldung und Sitzung im Klartext. Abschalten und SSH verwenden; auf alten Geräten zumindest im Netz einschränken.", Evidence: evidence(svc)})
		case 21:
			out = append(out, Finding{Rule: "scan.ftp", Key: key, Severity: Medium, Title: "FTP erreichbar",
				Detail: "FTP überträgt Passwörter im Klartext. Auf SFTP oder FTPS umstellen, oder den Dienst abschalten, wenn niemand ihn braucht.", Evidence: evidence(svc)})
		case 5900:
			out = append(out, Finding{Rule: "scan.vnc", Key: key, Severity: Medium, Title: "VNC erreichbar",
				Detail: "VNC (" + where + ") ist oft nur mit einem kurzen Passwort geschützt und unverschlüsselt. Nur über VPN oder gar nicht erreichbar machen.", Evidence: evidence(svc)})
		case 2375:
			out = append(out, Finding{Rule: "scan.docker_api", Key: key, Severity: High, Title: "Docker-API ohne Verschlüsselung erreichbar",
				Detail: "Port 2375 ist die Docker-API ohne TLS: Wer sie erreicht, kann Container mit Root-Rechten starten. Abschalten oder auf 2376 mit TLS und Client-Zertifikaten.", Evidence: evidence(svc)})
		case 6379, 27017, 9200:
			name := map[int]string{6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}[svc.Port]
			out = append(out, Finding{Rule: "scan.db_open", Key: key, Severity: Medium, Title: name + " im Netz erreichbar",
				Detail: name + " läuft ab Werk ohne Anmeldung. Auf localhost binden oder Anmeldung erzwingen, und nur den Anwendungen erreichbar machen, die es brauchen.", Evidence: evidence(svc)})
		case 3306, 5432, 1433, 1521:
			name := map[int]string{3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "MS SQL", 1521: "Oracle"}[svc.Port]
			out = append(out, Finding{Rule: "scan.db_open", Key: key, Severity: Low, Title: name + " im Netz erreichbar",
				Detail: name + " ist aus dem ganzen Netz erreichbar. Wenn nur eine Anwendung auf demselben Server zugreift, auf localhost binden.", Evidence: evidence(svc)})
		case 3389:
			out = append(out, Finding{Rule: "scan.rdp", Key: key, Severity: Low, Title: "Remotedesktop erreichbar",
				Detail: "RDP ist im Netz erreichbar. Im LAN üblich für Server; nie aus dem Internet, und Netzwerk-Authentifizierung (NLA) muss an sein.", Evidence: evidence(svc)})
		case 5985:
			out = append(out, Finding{Rule: "scan.winrm_plain", Key: key, Severity: Medium, Title: "WinRM ohne TLS erreichbar",
				Detail: "Windows-Fernverwaltung auf Port 5985 läuft ohne Verschlüsselung. Auf 5986 mit Zertifikat umstellen oder im Netz einschränken.", Evidence: evidence(svc)})
		case 389:
			out = append(out, Finding{Rule: "scan.ldap_plain", Key: key, Severity: Low, Title: "LDAP ohne TLS erreichbar",
				Detail: "Verzeichnisabfragen und einfache Anmeldungen über Port 389 laufen im Klartext, wenn kein StartTLS erzwungen ist. LDAPS (636) bevorzugen.", Evidence: evidence(svc)})
		case 10000:
			out = append(out, Finding{Rule: "scan.webmin", Key: key, Severity: Medium, Title: "Verwaltungsoberfläche auf Port 10000",
				Detail: "Port 10000 ist üblicherweise Webmin, eine Verwaltung mit Root-Rechten. Nur über VPN erreichbar machen und aktuell halten.", Evidence: evidence(svc)})
		}
		if svc.TLS != nil {
			out = append(out, tlsFindings(svc, key, in.Now)...)
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

func tlsFindings(svc Service, key string, now time.Time) []Finding {
	var out []Finding
	t := svc.TLS
	ev := evidence(svc)
	ev["subject"], ev["issuer"], ev["not_after"], ev["tls_version"] = t.Subject, t.Issuer, t.NotAfter.Format(time.RFC3339), t.Version
	if !t.NotAfter.IsZero() {
		switch days := int(t.NotAfter.Sub(now).Hours() / 24); {
		case t.NotAfter.Before(now):
			out = append(out, Finding{Rule: "scan.cert_expired", Key: key, Severity: High, Title: fmt.Sprintf("Zertifikat auf Port %d ist abgelaufen", svc.Port),
				Detail: fmt.Sprintf("Das Zertifikat (%s) ist seit %s abgelaufen. Browser und Clients warnen oder verweigern; Nutzer gewöhnen sich ans Wegklicken. Erneuern.", orDash(t.Subject), t.NotAfter.Format("02.01.2006")), Evidence: ev})
		case days <= CertWarnDays:
			out = append(out, Finding{Rule: "scan.cert_expiring", Key: key, Severity: Medium, Title: fmt.Sprintf("Zertifikat auf Port %d läuft in %d Tagen ab", svc.Port, days),
				Detail: fmt.Sprintf("Das Zertifikat (%s) läuft am %s ab. Rechtzeitig erneuern, sonst warnen Browser und Clients.", orDash(t.Subject), t.NotAfter.Format("02.01.2006")), Evidence: ev})
		}
	}
	if t.Version == "1.0" || t.Version == "1.1" {
		out = append(out, Finding{Rule: "scan.tls_old", Key: key, Severity: Medium, Title: fmt.Sprintf("Nur altes TLS %s auf Port %d", t.Version, svc.Port),
			Detail: "Der Dienst handelt höchstens TLS " + t.Version + " aus. Diese Versionen gelten seit 2021 als unsicher; TLS 1.2 oder 1.3 aktivieren, meist ein Update des Geräts.", Evidence: ev})
	}
	if t.SelfSigned && !strings.Contains(strings.ToLower(svc.Title), "fritz") {
		out = append(out, Finding{Rule: "scan.cert_selfsigned", Key: key, Severity: Low, Title: fmt.Sprintf("Selbstsigniertes Zertifikat auf Port %d", svc.Port),
			Detail: "Nutzer müssen die Warnung wegklicken und lernen so, Warnungen zu ignorieren. Ein Zertifikat der eigenen CA oder von Let's Encrypt hinterlegen, wo das Gerät es kann.", Evidence: ev})
	}
	return out
}

func evidence(svc Service) map[string]any {
	ev := map[string]any{"port": svc.Port, "proto": svc.Proto, "service": svc.Name}
	if svc.Product != "" {
		ev["product"] = svc.Product
	}
	if svc.Version != "" {
		ev["version"] = svc.Version
	}
	if svc.Banner != "" {
		ev["banner"] = svc.Banner
	}
	if svc.Title != "" {
		ev["title"] = svc.Title
	}
	return ev
}
