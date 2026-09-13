package console

import (
	"testing"
	"time"

	"github.com/excubra/excubra/internal/server/store"
)

// The rule an operator is trusting when they press one button instead of fifty
// switches: what stays put and is missed when it is gone gets a check, what
// comes and goes does not.
func TestSuggestWatch(t *testing.T) {
	gone := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	dev := func(kind, ip string, f func(*deviceCard)) deviceCard {
		c := deviceCard{Device: store.Device{ID: "dev_" + kind + ip, IP: ip}, Kind: kind, Name: kind + " " + ip}
		if f != nil {
			f(&c)
		}
		return c
	}
	in := []deviceCard{
		dev("fw", "192.0.2.1", nil),
		dev("rt", "192.0.2.2", nil),
		dev("srv", "192.0.2.3", nil),
		dev("vm", "192.0.2.4", nil),
		dev("tel", "192.0.2.5", nil),
		dev("prn", "192.0.2.6", nil),
		dev("lap", "192.0.2.7", nil),    // a laptop leaves at five
		dev("mob", "192.0.2.8", nil),    // so does a phone
		dev("q", "192.0.2.9", nil),      // unidentified: not guessed at
		dev("srv", "169.254.13.7", nil), // DHCP failed, that address is temporary
		dev("srv", "", nil),             // never showed an IPv4
		dev("srv", "192.0.2.10", func(c *deviceCard) { c.Monitored = true }), // already on
		dev("box", "192.0.2.11", func(c *deviceCard) { c.IsBox = true }),     // the box does not check itself
		dev("prn", "192.0.2.12", func(c *deviceCard) { c.Ignored = true }),   // deliberately hidden
		dev("srv", "192.0.2.13", func(c *deviceCard) { c.GoneAt = &gone }),   // gone for a fortnight
	}
	got := suggestWatch(in)
	if len(got.Add) != 6 {
		var names []string
		for _, c := range got.Add {
			names = append(names, c.Name)
		}
		t.Fatalf("expected the six stationary devices, got %d: %v", len(got.Add), names)
	}
	for _, c := range got.Add {
		if !worthWatching[c.Kind] {
			t.Fatalf("%s should not have been picked", c.Name)
		}
	}
	// the way out is marked as an uplink, so one cut line is one outage
	for kind, want := range map[string]bool{"fw": true, "rt": true, "srv": false, "vm": false, "tel": false, "prn": false} {
		if got := isUplinkKind(kind); got != want {
			t.Errorf("isUplinkKind(%q) = %v, want %v", kind, got, want)
		}
	}
	for _, want := range []string{"schon beobachtet", "die Box selbst", "ausgeblendet", "keine IPv4-Adresse", "Adresse nicht dauerhaft", "länger nicht gesehen"} {
		if got.Skipped[want] != 1 {
			t.Fatalf("reason %q should be counted once: %+v", want, got.Skipped)
		}
	}
	if s := explainSkipped(got.Skipped); s == "" || s == "nichts" {
		t.Fatalf("the skipped reasons should read as a sentence, got %q", s)
	}
	if s := explainSkipped(map[string]int{}); s != "nichts" {
		t.Fatalf("an empty set reads %q", s)
	}
}

func TestStableAddress(t *testing.T) {
	for _, c := range []struct {
		ip   string
		want bool
	}{
		{"192.0.2.5", true},
		{"10.1.2.3", true},
		{"169.254.99.1", false}, // self-assigned, gone with the next lease
		{"127.0.0.1", false},
		{"0.0.0.0", false},
		{"224.0.0.1", false},
		{"2001:db8::1", false}, // the checks are IPv4
		{"", false},
		{"nonsense", false},
	} {
		if got := stableAddress(c.ip); got != c.want {
			t.Errorf("stableAddress(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}
