package console

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/server/geocode"
	"github.com/excubra/excubra/internal/server/maptiles"
)

// The map: a site carries an address an operator typed and the coordinates that
// were looked up for it once. Fifty sites in a list answer "which ones exist";
// the same fifty on a map answer "where is it burning", which is the question an
// operator actually has.
//
// The background is drawn from country outlines compiled into the console, so by
// default the map talks to nobody and the content policy stays at `img-src
// 'self'`. An operator who wants streets sets map.tiles; the tiles then come
// through this server (internal/server/maptiles), never straight from the
// browser, so the policy still names no foreign host and the tile provider never
// learns which customer is being looked at.

// mapConfig is what the console needs to draw a map.
type mapConfig struct {
	Tiles       bool   `json:"tiles"`       // a background is configured and proxied at /api/map/tiles
	Attribution string `json:"attribution"` // what the map must say about where it came from
}

// mapCacheFor is how long the tile settings are held before they are read again.
const mapCacheFor = 10 * time.Second

// mapSettings reads the tile settings, briefly cached: the map's status travels
// with every /api/me and the value changes about once a year.
func (s *Server) mapSettings(r *http.Request) maptiles.Settings {
	s.mapMu.Lock()
	defer s.mapMu.Unlock()
	if s.Now().Before(s.mapUntil) {
		return s.mapSet
	}
	var set maptiles.Settings
	if v, err := s.Store.Setting(r.Context(), maptiles.SettingTiles); err == nil {
		set.Template = v
	}
	if v, err := s.Store.Setting(r.Context(), maptiles.SettingAttribution); err == nil {
		set.Attribution = v
	}
	if set.Attribution == "" && set.Enabled() {
		set.Attribution = "Kartenhintergrund vom eingestellten Kachel-Server"
	}
	s.mapSet, s.mapUntil = set, s.Now().Add(mapCacheFor)
	return set
}

func (s *Server) mapConfig(r *http.Request) mapConfig {
	set := s.mapSettings(r)
	return mapConfig{Tiles: set.Enabled(), Attribution: set.Attribution}
}

// mapTile serves one tile of the configured background. The browser only ever
// asks this server; see internal/server/maptiles for why.
func (s *Server) mapTile(w http.ResponseWriter, r *http.Request) {
	if s.Tiles == nil {
		http.NotFound(w, r)
		return
	}
	z, err1 := strconv.Atoi(r.PathValue("z"))
	x, err2 := strconv.Atoi(r.PathValue("x"))
	y, err3 := strconv.Atoi(strings.TrimSuffix(r.PathValue("y"), ".png"))
	if err1 != nil || err2 != nil || err3 != nil || !maptiles.Valid(z, x, y) {
		http.NotFound(w, r)
		return
	}
	body, ct, err := s.Tiles.Tile(r.Context(), s.mapSettings(r), z, x, y)
	if errors.Is(err, maptiles.ErrDisabled) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.Log.Warn("map tile", "z", z, "x", x, "y", y, "err", err)
		http.Error(w, "tile unavailable", http.StatusBadGateway)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	// The console sets Cache-Control: no-store for everything; a tile is a
	// picture of a coastline and may sit in the browser for a day.
	h.Set("Cache-Control", "private, max-age=86400")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
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
