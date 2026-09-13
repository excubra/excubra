package store

import (
	"testing"
	"time"
)

// The star is a toggle, so pinning twice and unpinning what is not pinned are
// both normal, not errors. And a pin whose target was deleted must not survive as
// a dead entry in somebody's sidebar.
func TestPins(t *testing.T) {
	s := open(t)
	seed(t, s)
	must(t, s.CreateUser(ctx, User{ID: "usr_a", Name: "a", PasswordHash: "x", TOTPSecret: "y", CreatedAt: t0}))
	must(t, s.CreateUser(ctx, User{ID: "usr_b", Name: "b", PasswordHash: "x", TOTPSecret: "y", CreatedAt: t0}))
	must(t, s.CreateSite(ctx, Site{ID: "site_b", TenantID: "ten_a", Name: "Zweitwerk", CreatedAt: t0}))

	if p, err := s.Pins(ctx, "usr_a"); err != nil || len(p) != 0 {
		t.Fatalf("a fresh user has nothing pinned: %+v %v", p, err)
	}
	must(t, s.AddPin(ctx, "usr_a", PinTenant, "ten_a", t0))
	must(t, s.AddPin(ctx, "usr_a", PinSite, "site_a", t0.Add(time.Minute)))
	must(t, s.AddPin(ctx, "usr_a", PinTenant, "ten_a", t0)) // twice is a double click, not a failure

	pins, err := s.Pins(ctx, "usr_a")
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 {
		t.Fatalf("pinning twice should not duplicate: %+v", pins)
	}
	// oldest first, so the list does not reshuffle under the pointer
	if pins[0].Kind != PinTenant || pins[0].Name != "Kunde A" {
		t.Fatalf("first pin: %+v", pins[0])
	}
	if pins[1].Kind != PinSite || pins[1].Name != "Ludwigshafen" || pins[1].Sub != "Kunde A" {
		t.Fatalf("a site carries its customer: %+v", pins[1])
	}

	// one operator's list is not another's
	if p, _ := s.Pins(ctx, "usr_b"); len(p) != 0 {
		t.Fatalf("pins are per user: %+v", p)
	}

	if on, _ := s.IsPinned(ctx, "usr_a", PinSite, "site_a"); !on {
		t.Fatal("the star should be lit")
	}
	if on, _ := s.IsPinned(ctx, "usr_a", PinSite, "site_b"); on {
		t.Fatal("an unpinned site should not be lit")
	}

	must(t, s.RemovePin(ctx, "usr_a", PinSite, "site_a"))
	must(t, s.RemovePin(ctx, "usr_a", PinSite, "site_a")) // removing twice is fine too
	if p, _ := s.Pins(ctx, "usr_a"); len(p) != 1 {
		t.Fatalf("after unpinning: %+v", p)
	}

	// a pin to something that no longer exists leaves no dead entry behind
	must(t, s.AddPin(ctx, "usr_a", PinSite, "site_weg", t0.Add(2*time.Minute)))
	if p, _ := s.Pins(ctx, "usr_a"); len(p) != 1 {
		t.Fatalf("a pin to a site that is gone should not be listed: %+v", p)
	}

	if err := s.AddPin(ctx, "usr_a", "gerät", "dev_1", t0); err == nil {
		t.Fatal("only customers and sites can be pinned")
	}
}
