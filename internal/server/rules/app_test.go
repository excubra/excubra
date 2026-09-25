package rules

import (
	"strings"
	"testing"
	"time"
)

func berlin(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func TestEvaluateAppEvent(t *testing.T) {
	loc := berlin(t)
	// Thursday 24.09.2026, in Berlin time
	thu := func(h, m int) time.Time { return time.Date(2026, 9, 24, h, m, 0, 0, loc) }
	sat := time.Date(2026, 9, 26, 11, 0, 0, 0, loc)
	cases := []struct {
		ev       AppEvent
		rule     string
		key      string
		severity string
		title    string
		ok       bool
	}{
		{AppEvent{Kind: AppEmergency, Actor: "chef@viico.test", IP: "198.51.100.7"}, "app.emergency", "chef@viico.test", High, "Notzugang", true},
		{AppEvent{Kind: AppNewDevice, Actor: "anna@viico.test", IP: "198.51.100.7", Summary: "Safari auf einem iPhone"}, "app.new_device", "anna@viico.test", Medium, "neuen Gerät", true},
		{AppEvent{Kind: AppAdminGranted, Actor: "chef@viico.test", Target: "tim@viico.test", Summary: "Technik → Verwaltung"}, "app.admin", "tim@viico.test", High, "Adminrechte", true},
		{AppEvent{Kind: AppBankChanged, Actor: "chef@viico.test", Target: "company.bank1_iban", Summary: "DE02… → DE89…"}, "app.bank", "company.bank1_iban", High, "Bankverbindung", true},
		{AppEvent{Kind: AppSecretChanged, Actor: "chef@viico.test", Target: "ex0.base_url"}, "app.secret", "ex0.base_url", Medium, "anderen Dienst", true},
		{AppEvent{Kind: AppAccountClosed, Target: "leaver@viico.test", Summary: "in Entra abgeschaltet"}, "app.closed", "leaver@viico.test", Low, "geschlossen", true},
		{AppEvent{Kind: AppLinkBrake, IP: "203.0.113.9", Summary: "Fehlgriffe"}, "app.link_brake", "203.0.113.9", Medium, "Kundenlinks", true},
		// an HR file during the day is work; at night or on a Saturday it is a finding
		{AppEvent{Kind: AppHRViewed, Actor: "chef@viico.test", Target: "Personalakte Tim", At: thu(10, 30)}, "", "", "", "", false},
		{AppEvent{Kind: AppHRViewed, Actor: "chef@viico.test", Target: "Personalakte Tim", At: thu(22, 15)}, "app.hr_off_hours", "chef@viico.test", Medium, "Arbeitszeit", true},
		{AppEvent{Kind: AppHRViewed, Actor: "chef@viico.test", Target: "Personalakte Tim", At: thu(6, 59)}, "app.hr_off_hours", "chef@viico.test", Medium, "Arbeitszeit", true},
		{AppEvent{Kind: AppHRViewed, Actor: "chef@viico.test", Target: "Personalakte Tim", At: sat}, "app.hr_off_hours", "chef@viico.test", Medium, "Arbeitszeit", true},
		// what the rules do not know stays in the logs
		{AppEvent{Kind: "ticket.create", Actor: "anna@viico.test"}, "", "", "", "", false},
		{AppEvent{Kind: "auth.login", Actor: "anna@viico.test"}, "", "", "", "", false},
	}
	for _, c := range cases {
		if c.ev.At.IsZero() {
			c.ev.At = thu(12, 0)
		}
		f, ok := EvaluateAppEvent(c.ev, loc)
		if ok != c.ok {
			t.Fatalf("%s at %s: ok=%v", c.ev.Kind, c.ev.At.In(loc).Format("Mon 15:04"), ok)
		}
		if !ok {
			continue
		}
		if f.Rule != c.rule || f.Key != c.key || f.Severity != c.severity || !strings.Contains(f.Title, c.title) || f.Detail == "" {
			t.Errorf("%s: %+v", c.ev.Kind, f)
		}
	}
}

func TestEvaluateAppWindow(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	many := func(n int, kind, actor, ip string, ago time.Duration) []AppEvent {
		var out []AppEvent
		for range n {
			out = append(out, AppEvent{Kind: kind, Actor: actor, IP: ip, At: now.Add(-ago)})
		}
		return out
	}
	cases := []struct {
		name   string
		events []AppEvent
		want   map[string]string // rule → key
	}{
		{"nine refusals are not yet a pattern", many(9, AppSignInRefused, "", "203.0.113.9", time.Minute), nil},
		{"ten from one address are", many(10, AppSignInRefused, "", "203.0.113.9", time.Minute), map[string]string{"app.refused": "203.0.113.9"}},
		{"old refusals do not count", many(10, AppSignInRefused, "", "203.0.113.9", RefusedWindow+time.Minute), nil},
		{"spread over many addresses counts overall", func() []AppEvent {
			var out []AppEvent
			for i := range 30 {
				out = append(out, AppEvent{Kind: AppSignInRefused, IP: "198.51.100." + string(rune('a'+i%26)), At: now.Add(-time.Minute)})
			}
			return out
		}(), map[string]string{"app.refused": "*"}},
		{"denied twenty times", many(20, AppDenied, "anna@viico.test", "", time.Minute), map[string]string{"app.denied": "anna@viico.test"}},
		{"fifty downloads", many(50, AppDownload, "anna@viico.test", "", 2*time.Minute), map[string]string{"app.downloads": "anna@viico.test"}},
		{"forty-nine downloads", many(49, AppDownload, "anna@viico.test", "", 2*time.Minute), nil},
	}
	for _, c := range cases {
		got := map[string]string{}
		for _, f := range EvaluateAppWindow(c.events, now) {
			got[f.Rule] = f.Key
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
			continue
		}
		for rule, key := range c.want {
			if got[rule] != key {
				t.Errorf("%s: %s key %q, want %q", c.name, rule, got[rule], key)
			}
		}
	}
}

func TestEvaluateAppState(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		lastContact time.Time
		certNot     time.Time
		want        []string
	}{
		{"talking, certificate fine", now.Add(-time.Minute), now.AddDate(0, 2, 0), nil},
		{"no word for eleven minutes", now.Add(-11 * time.Minute), time.Time{}, []string{"app.silent"}},
		{"certificate in ten days", now.Add(-time.Minute), now.AddDate(0, 0, 10), []string{"app.cert_expiring"}},
		{"certificate gone", now.Add(-time.Minute), now.Add(-time.Hour), []string{"app.cert_expired"}},
		{"silent and expired", now.Add(-time.Hour), now.Add(-time.Hour), []string{"app.silent", "app.cert_expired"}},
	}
	for _, c := range cases {
		var got []string
		for _, f := range EvaluateAppState("VIIDOC", c.lastContact, c.certNot, now) {
			got = append(got, f.Rule)
			if !strings.Contains(f.Title, "VIIDOC") {
				t.Errorf("%s: the title does not name the source: %q", c.name, f.Title)
			}
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
