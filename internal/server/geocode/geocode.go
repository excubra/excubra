// Package geocode turns an address an operator typed into coordinates, so the
// console can put a site on a map.
//
// It runs on the server rather than in the browser for two reasons. Nominatim's
// usage policy asks every caller to identify itself in the User-Agent, which a
// browser will not let a page set; and keeping the request here lets the console
// keep `connect-src 'self'` instead of opening its content policy to a foreign
// host. Nothing is looked up in the background: a lookup happens when an operator
// clicks, once per site, and the answer is stored so it never has to be asked
// again.
package geocode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultService is Nominatim, the geocoder of the OpenStreetMap project.
const DefaultService = "https://nominatim.openstreetmap.org/search"

// SettingService lets an operator point at their own Nominatim instance.
const SettingService = "map.geocoder"

// Limits. Nominatim asks for at most one request per second from a single
// source, so the client enforces that itself rather than trusting the operator
// to click slowly.
const (
	timeout   = 20 * time.Second
	minGap    = time.Second
	maxHits   = 5
	userAgent = "excubra (EX0 console, site geocoding)"
)

// Place is one candidate for an address.
type Place struct {
	Label string  `json:"label"` // what Nominatim calls the place, for the operator to pick from
	Lat   float64 `json:"lat"`
	Lon   float64 `json:"lon"`
}

// Client looks addresses up. The zero value is not usable; use New.
type Client struct {
	URL  string
	HTTP *http.Client
	Now  func() time.Time

	mu   sync.Mutex
	last time.Time
}

// New returns a client for the given service ("" means Nominatim).
func New(service string) *Client {
	if service == "" {
		service = DefaultService
	}
	return &Client{URL: service, HTTP: &http.Client{Timeout: timeout}, Now: time.Now}
}

// ErrNothingFound means the service understood the question and had no answer.
var ErrNothingFound = errors.New("geocode: no place matches that address")

// Lookup returns the candidates for an address, best first.
func (c *Client) Lookup(ctx context.Context, address string) ([]Place, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, errors.New("geocode: no address given")
	}
	if len(address) > 300 {
		return nil, errors.New("geocode: that is not an address, it is an essay")
	}
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	q := url.Values{"q": {address}, "format": {"jsonv2"}, "limit": {strconv.Itoa(maxHits)}, "addressdetails": {"0"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("geocode: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("geocode: the service answered %s", resp.Status)
	}
	var hits []struct {
		DisplayName string `json:"display_name"`
		Lat         string `json:"lat"`
		Lon         string `json:"lon"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&hits); err != nil {
		return nil, fmt.Errorf("geocode: unreadable answer: %w", err)
	}
	out := make([]Place, 0, len(hits))
	for _, h := range hits {
		lat, err1 := strconv.ParseFloat(h.Lat, 64)
		lon, err2 := strconv.ParseFloat(h.Lon, 64)
		if err1 != nil || err2 != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
			continue
		}
		out = append(out, Place{Label: h.DisplayName, Lat: lat, Lon: lon})
	}
	if len(out) == 0 {
		return nil, ErrNothingFound
	}
	return out, nil
}

// wait keeps at least minGap between two lookups, as the service asks.
func (c *Client) wait(ctx context.Context) error {
	c.mu.Lock()
	gap := minGap - c.Now().Sub(c.last)
	c.last = c.Now().Add(max(gap, 0))
	c.mu.Unlock()
	if gap <= 0 {
		return nil
	}
	t := time.NewTimer(gap)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
