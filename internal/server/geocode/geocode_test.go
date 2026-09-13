package geocode

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLookup(t *testing.T) {
	var gotUA, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotQuery = r.Header.Get("User-Agent"), r.URL.Query().Get("q")
		switch {
		case strings.Contains(gotQuery, "nirgendwo"):
			_, _ = w.Write([]byte(`[]`))
		case strings.Contains(gotQuery, "kaputt"):
			w.WriteHeader(http.StatusBadGateway)
		default:
			// one usable hit, one with coordinates off the planet
			_, _ = w.Write([]byte(`[{"display_name":"Musterweg 1, Musterstadt","lat":"52.5163","lon":"13.3777"},
				{"display_name":"Unsinn","lat":"999","lon":"0"}]`))
		}
	}))
	defer srv.Close()

	c := New(srv.URL)
	c.Now = time.Now
	ctx := context.Background()

	places, err := c.Lookup(ctx, "  Musterweg 1, Musterstadt  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(places) != 1 || places[0].Lat != 52.5163 || places[0].Lon != 13.3777 || places[0].Label != "Musterweg 1, Musterstadt" {
		t.Fatalf("places: %+v", places)
	}
	if gotQuery != "Musterweg 1, Musterstadt" {
		t.Fatalf("the address should be trimmed, got %q", gotQuery)
	}
	if !strings.Contains(gotUA, "excubra") {
		t.Fatalf("the service asks callers to identify themselves, got %q", gotUA)
	}

	if _, err := c.Lookup(ctx, "nirgendwo"); !errors.Is(err, ErrNothingFound) {
		t.Fatalf("empty answer: %v", err)
	}
	if _, err := c.Lookup(ctx, "kaputt"); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("a failing service should say so: %v", err)
	}
	if _, err := c.Lookup(ctx, "   "); err == nil {
		t.Fatal("an empty address is not a question")
	}
	if _, err := c.Lookup(ctx, strings.Repeat("x", 400)); err == nil {
		t.Fatal("an overlong address should be refused before it leaves the house")
	}
}

// The service asks for at most one request per second; the client holds itself
// to that instead of trusting an operator to click slowly.
func TestKeepsOneSecondBetweenLookups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"display_name":"da","lat":"1","lon":"2"}]`))
	}))
	defer srv.Close()

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	c := New(srv.URL)
	c.Now = func() time.Time { return now }
	if _, err := c.Lookup(context.Background(), "erste"); err != nil {
		t.Fatal(err)
	}
	// the clock does not move, so the second lookup must wait — and a cancelled
	// context must end that wait rather than hang the request
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Lookup(ctx, "zweite"); !errors.Is(err, context.Canceled) {
		t.Fatalf("a waiting lookup should honour the context: %v", err)
	}
}
