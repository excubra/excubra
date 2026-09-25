package rules

import (
	"fmt"
	"time"
)

// Applications that report themselves (ADR-0023). The source says what happened
// in its own words; the rules decide what deserves a look. Three kinds: single
// events that always do, counts in a window, and the state of the source — silent,
// or its certificate running out. The kinds are the source's side of the
// contract (VIIDOC ADR-0082); an unknown kind is kept in the logs and judged by
// nobody.

// AppEvent is one event a source reported, as the rules see it.
type AppEvent struct {
	Kind    string
	Actor   string
	IP      string
	Target  string
	Summary string
	At      time.Time
}

// The kinds the rules know.
const (
	AppSignInRefused = "auth.refused"
	AppEmergency     = "auth.emergency"
	AppNewDevice     = "auth.device.new"
	AppAdminGranted  = "user.admin"
	AppAccountClosed = "user.closed"
	AppBankChanged   = "settings.bank"
	AppSecretChanged = "settings.secret"
	AppHRViewed      = "hr.viewed"
	AppDenied        = "access.denied"
	AppDownload      = "download"
	AppLinkBrake     = "link.brake"
)

// Windows and how much in them is too much.
const (
	RefusedWindow  = 15 * time.Minute
	RefusedPerIP   = 10
	RefusedOverall = 30
	DeniedWindow   = 10 * time.Minute
	DeniedMax      = 20
	DownloadWindow = 10 * time.Minute
	DownloadMax    = 50
	// SourceSilentAfter is how long a source may say nothing.
	SourceSilentAfter = 10 * time.Minute
	appCertWarn       = 14 * 24 * time.Hour
)

// EvaluateAppEvent judges one event on its own. loc is the house's time zone:
// "outside working hours" means its clock, not UTC.
func EvaluateAppEvent(ev AppEvent, loc *time.Location) (Finding, bool) {
	evidence := map[string]any{"kind": ev.Kind, "actor": ev.Actor, "ip": ev.IP, "target": ev.Target,
		"summary": ev.Summary, "at": ev.At.UTC().Format(time.RFC3339), "count": 1}
	who := ev.Actor
	if who == "" {
		who = "Jemand"
	}
	switch ev.Kind {
	case AppEmergency:
		return Finding{Rule: "app.emergency", Key: ev.Actor, Severity: High, Title: "Notzugang benutzt",
			Detail:   fmt.Sprintf("%s hat sich über den Notzugang angemeldet, von %s. Er ist für den Fall gedacht, dass die normale Anmeldung nicht geht — jeder Gebrauch gehört geklärt.", who, ev.IP),
			Evidence: evidence}, true
	case AppNewDevice:
		return Finding{Rule: "app.new_device", Key: ev.Actor, Severity: Medium, Title: "Anmeldung von einem neuen Gerät",
			Detail:   fmt.Sprintf("%s hat sich von einem Gerät angemeldet, das die Anwendung noch nicht kannte (%s, Adresse %s). Die Person hat dazu eine Mail bekommen; war sie es nicht, ist das Konto in fremder Hand.", who, ev.Summary, ev.IP),
			Evidence: evidence}, true
	case AppAdminGranted:
		return Finding{Rule: "app.admin", Key: ev.Target, Severity: High, Title: "Adminrechte vergeben",
			Detail:   fmt.Sprintf("%s hat %s Adminrechte gegeben (%s). Wer Admin ist, kann alles — auch Spuren verwischen.", who, ev.Target, ev.Summary),
			Evidence: evidence}, true
	case AppBankChanged:
		return Finding{Rule: "app.bank", Key: ev.Target, Severity: High, Title: "Bankverbindung geändert",
			Detail:   fmt.Sprintf("%s hat %s geändert: %s. Die Bankverbindung steht auf jeder Rechnung; wer sie ändert, lenkt Zahlungen um.", who, ev.Target, ev.Summary),
			Evidence: evidence}, true
	case AppSecretChanged:
		return Finding{Rule: "app.secret", Key: ev.Target, Severity: Medium, Title: "Zugang zu einem anderen Dienst geändert",
			Detail:   fmt.Sprintf("%s hat %s geändert (%s). Ein neuer Schlüssel oder eine neue Adresse lenkt, wohin die Anwendung spricht.", who, ev.Target, ev.Summary),
			Evidence: evidence}, true
	case AppAccountClosed:
		return Finding{Rule: "app.closed", Key: ev.Target, Severity: Low, Title: "Zugang geschlossen",
			Detail:   fmt.Sprintf("Die Anwendung hat den Zugang von %s geschlossen: %s.", ev.Target, ev.Summary),
			Evidence: evidence}, true
	case AppLinkBrake:
		return Finding{Rule: "app.link_brake", Key: ev.IP, Severity: Medium, Title: "Kundenlinks durchprobiert",
			Detail:   fmt.Sprintf("Von %s kamen so viele Aufrufe öffentlicher Links ins Leere, dass die Anwendung die Adresse gebremst hat (%s).", ev.IP, ev.Summary),
			Evidence: evidence}, true
	case AppHRViewed:
		local := ev.At.In(loc)
		if !offHours(local) {
			return Finding{}, false
		}
		evidence["local"] = local.Format("Mon 15:04")
		return Finding{Rule: "app.hr_off_hours", Key: ev.Actor, Severity: Medium, Title: "Personalakte außerhalb der Arbeitszeit geöffnet",
			Detail:   fmt.Sprintf("%s hat am %s um %s Uhr %s geöffnet.", who, weekdayDE(local.Weekday()), local.Format("15:04"), ev.Target),
			Evidence: evidence}, true
	}
	return Finding{}, false
}

// offHours is outside Monday to Friday, 07:00 to 20:00.
func offHours(t time.Time) bool {
	if t.Weekday() == time.Saturday || t.Weekday() == time.Sunday {
		return true
	}
	return t.Hour() < 7 || t.Hour() >= 20
}

func weekdayDE(d time.Weekday) string {
	return [...]string{"Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"}[d]
}

// EvaluateAppWindow judges counts over a source's recent events: refused
// sign-ins from one address and overall, denied requests and downloads by one
// person. Each count only looks at its own window before now.
func EvaluateAppWindow(events []AppEvent, now time.Time) []Finding {
	refusedByIP, deniedBy, downloadsBy := map[string]int{}, map[string]int{}, map[string]int{}
	refused := 0
	for _, ev := range events {
		age := now.Sub(ev.At)
		switch ev.Kind {
		case AppSignInRefused:
			if age <= RefusedWindow {
				refused++
				refusedByIP[ev.IP]++
			}
		case AppDenied:
			if age <= DeniedWindow {
				deniedBy[ev.Actor]++
			}
		case AppDownload:
			if age <= DownloadWindow {
				downloadsBy[ev.Actor]++
			}
		}
	}
	var out []Finding
	for ip, n := range refusedByIP {
		if n >= RefusedPerIP {
			out = append(out, Finding{Rule: "app.refused", Key: ip, Severity: High, Title: "Viele abgewiesene Anmeldungen von einer Adresse",
				Detail:   fmt.Sprintf("Von %s wurden in %d Minuten %d Anmeldungen abgewiesen. So sieht Durchprobieren aus.", ip, int(RefusedWindow.Minutes()), n),
				Evidence: map[string]any{"ip": ip, "count": n}})
		}
	}
	if refused >= RefusedOverall {
		out = append(out, Finding{Rule: "app.refused", Key: "*", Severity: High, Title: "Viele abgewiesene Anmeldungen",
			Detail:   fmt.Sprintf("In %d Minuten wurden %d Anmeldungen abgewiesen, von %d Adressen. Verteiltes Durchprobieren sieht so aus.", int(RefusedWindow.Minutes()), refused, len(refusedByIP)),
			Evidence: map[string]any{"count": refused, "addresses": len(refusedByIP)}})
	}
	for who, n := range deniedBy {
		if n >= DeniedMax {
			out = append(out, Finding{Rule: "app.denied", Key: who, Severity: Medium, Title: "Viele verweigerte Zugriffe",
				Detail:   fmt.Sprintf("%s ist in %d Minuten %d-mal an Rechten gescheitert. Wer sich umsieht, wo er nicht hindarf, sieht so aus.", who, int(DeniedWindow.Minutes()), n),
				Evidence: map[string]any{"actor": who, "count": n}})
		}
	}
	for who, n := range downloadsBy {
		if n >= DownloadMax {
			out = append(out, Finding{Rule: "app.downloads", Key: who, Severity: High, Title: "Viele Downloads in kurzer Zeit",
				Detail:   fmt.Sprintf("%s hat in %d Minuten %d Dateien geholt. So sieht Abziehen aus.", who, int(DownloadWindow.Minutes()), n),
				Evidence: map[string]any{"actor": who, "count": n}})
		}
	}
	return out
}

// EvaluateAppState judges the source itself: silent since its last contact, or
// its own certificate running out (zero certNotAfter: the source does not say).
func EvaluateAppState(name string, lastContact, certNotAfter, now time.Time) []Finding {
	var out []Finding
	if silent := now.Sub(lastContact); silent > SourceSilentAfter {
		out = append(out, Finding{Rule: "app.silent", Severity: High, Title: name + " meldet sich nicht",
			Detail:   fmt.Sprintf("Seit %s hat %s nichts geschickt. Entweder läuft sie nicht, oder der Weg hierher ist weg — beides will jemand wissen.", lastContact.UTC().Format("02.01.2006 15:04 UTC"), name),
			Evidence: map[string]any{"last_contact": lastContact.UTC().Format(time.RFC3339), "silent_minutes": int(silent.Minutes())}})
	}
	if !certNotAfter.IsZero() {
		left := certNotAfter.Sub(now)
		ev := map[string]any{"not_after": certNotAfter.UTC().Format(time.RFC3339), "days_left": int(left.Hours() / 24)}
		switch {
		case left <= 0:
			out = append(out, Finding{Rule: "app.cert_expired", Severity: High, Title: "Zertifikat von " + name + " abgelaufen",
				Detail: "Das Zertifikat ist am " + certNotAfter.Format("02.01.2006") + " abgelaufen. Browser warnen, und wer die Warnung wegklickt, ist nicht mehr geschützt.", Evidence: ev})
		case left <= appCertWarn:
			out = append(out, Finding{Rule: "app.cert_expiring", Severity: Medium, Title: "Zertifikat von " + name + " läuft ab",
				Detail: fmt.Sprintf("Das Zertifikat gilt noch %d Tage, bis %s. Es erneuert sich sonst von selbst — dass es das hier nicht tut, ist der Befund.", int(left.Hours()/24), certNotAfter.Format("02.01.2006")), Evidence: ev})
		}
	}
	return out
}
