package console

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/server/geocode"
)

// The map: a site carries an address an operator typed and the coordinates that
// were looked up for it once. Fifty sites in a list answer "which ones exist";
// the same fifty on a map answer "where is it burning", which is the question an
// operator actually has.

// Map settings. The tile source is a setting so an operator can point at their
// own tile server — theirs, ours, or none at all — instead of being wired to one
// provider. The default is the OpenStreetMap project's own.
const (
	settingTiles       = "map.tiles"
	settingAttribution = "map.attribution"

	defaultTiles       = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"
	defaultAttribution = "© OpenStreetMap"
)

// mapConfig is what the console needs to draw a map.
type mapConfig struct {
	Tiles       string `json:"tiles"`       // Leaflet URL template
	Attribution string `json:"attribution"` // what the map must say about where it came from
}

// mapConfig reads the tile settings, falling back to OpenStreetMap. Every
// response carries a content policy derived from it, so the answer is held for a
// few seconds rather than read from the database on every request; a changed
// setting takes effect on the next reload either way.
func (s *Server) mapConfig(r *http.Request) mapConfig {
	s.mapMu.Lock()
	defer s.mapMu.Unlock()
	if s.Now().Before(s.mapUntil) {
		return s.mapCfg
	}
	c := mapConfig{Tiles: defaultTiles, Attribution: defaultAttribution}
	if v, err := s.Store.Setting(r.Context(), settingTiles); err == nil && v != "" {
		c.Tiles = v
	}
	if v, err := s.Store.Setting(r.Context(), settingAttribution); err == nil && v != "" {
		c.Attribution = v
	}
	if c.Tiles == "off" {
		c.Tiles = ""
	}
	s.mapCfg, s.mapUntil = c, s.Now().Add(mapCacheFor)
	return c
}

// mapCacheFor is how long the tile settings are held before they are read again.
const mapCacheFor = 10 * time.Second

// tileOrigin is the scheme and host of the tile template, for the content policy.
// A template with no usable origin contributes nothing, which is the safe answer.
func tileOrigin(tiles string) string {
	if tiles == "" {
		return ""
	}
	// {z}/{x}/{y} are not legal URL characters everywhere, but they never appear
	// in the origin, so parsing the part before the first brace is enough.
	if i := strings.IndexByte(tiles, '{'); i >= 0 {
		tiles = tiles[:i]
	}
	u, err := url.Parse(tiles)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// siteGeocode asks the geocoder what an address might mean and returns the
// candidates. It stores nothing: the operator picks, and the pick is saved by
// siteLocationSet.
func (s *Server) siteGeocode(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	if _, err := s.Store.Site(r.Context(), siteID); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	service, _ := s.Store.Setting(r.Context(), geocode.SettingService)
	if service == "off" {
		s.fail(w, r, errors.New("die Adresssuche ist abgeschaltet (Einstellung map.geocoder); Koordinaten lassen sich von Hand eintragen"), http.StatusConflict)
		return
	}
	places, err := geocode.New(service).Lookup(r.Context(), r.PostForm.Get("address"))
	if errors.Is(err, geocode.ErrNothingFound) {
		s.fail(w, r, errors.New("zu dieser Adresse findet der Dienst nichts; kürzer schreiben (Straße, Ort) oder die Koordinaten von Hand eintragen"), http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, err, http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, places)
}

// siteLocationSet stores the address and, when coordinates come with it, the
// place. Empty coordinates clear the location and keep the address, so an
// operator can correct a wrong address and search again.
func (s *Server) siteLocationSet(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID
	address := strings.TrimSpace(r.PostForm.Get("address"))
	latS, lonS := strings.TrimSpace(r.PostForm.Get("lat")), strings.TrimSpace(r.PostForm.Get("lon"))
	if len(address) > 300 {
		s.fail(w, r, errors.New("die Adresse ist zu lang"), http.StatusBadRequest)
		return
	}
	if latS == "" || lonS == "" {
		if err := s.Store.SetSiteLocation(r.Context(), siteID, address, 0, 0, false); err != nil {
			s.fail(w, r, err, statusFor(err))
			return
		}
		_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "site.location", siteID, "ohne Koordinaten")
		s.flash(w, r, "Adresse gespeichert. Ohne Koordinaten erscheint der Standort noch nicht auf der Karte.", back)
		return
	}
	lat, err1 := strconv.ParseFloat(latS, 64)
	lon, err2 := strconv.ParseFloat(lonS, 64)
	if err1 != nil || err2 != nil {
		s.fail(w, r, errors.New("Koordinaten müssen Zahlen sein, etwa 52.5163 und 13.3777"), http.StatusBadRequest)
		return
	}
	if err := s.Store.SetSiteLocation(r.Context(), siteID, address, lat, lon, true); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "site.location", siteID, address)
	s.flash(w, r, "Standort gesetzt. Er steht ab sofort auf der Karte.", back)
}
