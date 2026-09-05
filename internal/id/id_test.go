package id

import (
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	re := regexp.MustCompile(`^box_[0-9a-hjkmnp-tv-z]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s := New("box")
		if !re.MatchString(s) {
			t.Fatalf("bad id %q", s)
		}
		if seen[s] {
			t.Fatalf("duplicate id %q", s)
		}
		seen[s] = true
	}
}

func TestNewSortable(t *testing.T) {
	re := regexp.MustCompile(`^evt_[0-9a-hjkmnp-tv-z]{26}$`)
	base := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	var ids []string
	for i := 0; i < 50; i++ {
		s := NewSortable("evt", base.Add(time.Duration(i)*time.Second))
		if !re.MatchString(s) {
			t.Fatalf("bad id %q", s)
		}
		ids = append(ids, s)
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatal("sortable ids are not in time order")
	}
	// Same millisecond: still unique.
	a, b := NewSortable("evt", base), NewSortable("evt", base)
	if a == b {
		t.Fatal("two ids in the same millisecond collided")
	}
}

func TestFromSlug(t *testing.T) {
	good := []string{"kundea", "site-ludwigshafen", "a", "Fw01"}
	for _, s := range good {
		if _, err := FromSlug("ten", s); err != nil {
			t.Errorf("FromSlug(%q): %v", s, err)
		}
	}
	bad := []string{"", "-x", "with space", "ünïcode", "a_b", string(make([]byte, 41))}
	for _, s := range bad {
		if _, err := FromSlug("ten", s); err == nil {
			t.Errorf("FromSlug(%q) accepted", s)
		}
	}
	if got, _ := FromSlug("ten", "KundeA"); got != "ten_kundea" {
		t.Errorf("slug not lower-cased: %q", got)
	}
}

func TestSecret(t *testing.T) {
	if s := Secret(20); len(s) != 32 {
		t.Fatalf("Secret(20) has %d chars, want 32", len(s))
	}
	if s := Secret(32); len(s) != 52 {
		t.Fatalf("Secret(32) has %d chars, want 52", len(s))
	}
}

func TestTimeOf(t *testing.T) {
	at := time.Date(2026, 9, 5, 10, 0, 0, 123_000_000, time.UTC)
	s := NewSortable("evt", at)
	got, ok := TimeOf(s)
	if !ok || !got.Equal(at) {
		t.Fatalf("TimeOf(%s) = %v, %v; want %v", s, got, ok, at)
	}
	if _, ok := TimeOf("box_k7m2x9q4t8r3"); ok {
		t.Fatal("random id decoded as sortable")
	}
	if _, ok := TimeOf("evt_" + strings.Repeat("u", 26)); ok {
		t.Fatal("invalid alphabet accepted")
	}
}
