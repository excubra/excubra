package console

// Remote access (salt: Vollausbau B): the operator stack's settings and the switch
// per site. The token never leaves the server; the console only says whether one
// is set.

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/excubra/excubra/internal/server/remote"
	"github.com/excubra/excubra/internal/server/store"
)

// remoteView is a site's remote access as the app shows it.
type remoteView struct {
	Configured  bool                `json:"configured"`  // the operator stack is set up
	Access      *store.RemoteAccess `json:"access"`      // nil when never enabled
	Suggested   string              `json:"suggested"`   // the LAN the devices suggest
	BoxOperator string              `json:"boxOperator"` // status of the box's second client
	BoxOpIP     string              `json:"boxOpIp"`
	Labels      map[string]string   `json:"labels"`
	// A LAN outside RFC 1918 (ADR-0024): Other is what the box reports sitting
	// in, Declared what an operator said is this site's own. A network in Other
	// that is not declared needs the declaration before it can be switched on.
	Other    []string `json:"other"`
	Declared []string `json:"declared"`
}

var remoteLabels = map[string]string{
	store.RemoteKey: "wartet auf die Box im Techniker-Stack", store.RemoteJoining: "Box tritt dem Techniker-Stack bei", store.RemoteWiring: "Netzwerk wird angelegt",
	store.RemoteActive: "aktiv", store.RemoteOff: "abgeschaltet", store.RemoteError: "Fehler",
}

func (s *Server) apiSiteRemote(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := r.PathValue("id")
	if _, err := s.Store.Site(ctx, siteID); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	v := remoteView{Labels: remoteLabels}
	if s.Remote != nil {
		st := s.Remote.Settings(ctx)
		v.Configured = st.URL != "" && st.HasToken
	}
	if ra, err := s.Store.RemoteAccess(ctx, siteID); err == nil {
		v.Access = &ra
	}
	if box, err := s.siteBox(ctx, siteID); err == nil && box != nil {
		v.BoxOperator, v.BoxOpIP = box.NetbirdOpStatus, box.NetbirdOpIP
		v.Other = box.LANOther
	}
	if site, err := s.Store.Site(ctx, siteID); err == nil {
		v.Declared = site.LocalNets
	}
	v.Suggested = s.suggestLAN(ctx, siteID)
	writeJSON(w, http.StatusOK, v)
}

// suggestLAN is the network the box reports — a private one first, else the
// one outside RFC 1918 it sits in — else the /24 most of the site's devices
// live in.
func (s *Server) suggestLAN(ctx context.Context, siteID string) string {
	if box, err := s.siteBox(ctx, siteID); err == nil && box != nil {
		if len(box.LAN) > 0 {
			return box.LAN[0]
		}
		if len(box.LANOther) > 0 {
			return box.LANOther[0]
		}
	}
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return ""
	}
	devs, err := s.Store.Devices(ctx, site.TenantID, siteID, time.Time{})
	if err != nil {
		return ""
	}
	count := map[string]int{}
	for _, d := range devs {
		if a, err := netip.ParseAddr(d.IP); err == nil && a.Is4() && a.IsPrivate() {
			p, _ := a.Prefix(24)
			count[p.String()]++
		}
	}
	best, n := "", 0
	for p, c := range count {
		if c > n || (c == n && p < best) {
			best, n = p, c
		}
	}
	return best
}

func (s *Server) remoteEnable(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=technik"
	if s.Remote == nil {
		s.flashErr(w, r, "Fernzugriff ist auf diesem Server nicht aktiv.", back)
		return
	}
	var ra store.RemoteAccess
	var err error
	if r.PostForm.Get("declare") == "1" {
		// the operator's statement: this network is the customer's LAN although it
		// is not RFC 1918 (ADR-0024)
		ra, err = s.Remote.Declare(r.Context(), siteID, r.PostForm.Get("cidr"), actor(r))
	} else {
		ra, err = s.Remote.Enable(r.Context(), siteID, r.PostForm.Get("cidr"), actor(r))
	}
	switch {
	case errors.Is(err, remote.ErrNotConfigured):
		s.flashErr(w, r, "Erst den Techniker-Stack unter Verwaltung → Einstellungen eintragen (Management-URL und API-Token).", back)
	case errors.Is(err, remote.ErrBadCIDR):
		s.flashErr(w, r, "Das LAN muss ein IPv4-Netz in CIDR-Schreibweise sein, z. B. 192.168.10.0/24.", back)
	case errors.Is(err, remote.ErrNotDeclared):
		s.flashErr(w, r, "Dieses Netz ist kein privater Adressbereich (RFC 1918). Ist es trotzdem das LAN dieses Kunden, das Einschalten mit der Bestätigung darunter wiederholen: Die Route im Techniker-Stack nimmt den echten Internetverkehr für diesen Bereich mit.", back)
	case errors.Is(err, remote.ErrNotAttached):
		s.flashErr(w, r, "Nur ein Netz, in dem die Box selbst steht, lässt sich zum LAN des Standorts erklären: "+err.Error(), back)
	case errors.Is(err, remote.ErrOverlap):
		s.flashErr(w, r, "Dieses Netz überschneidet sich mit einem anderen Standort im Techniker-Stack: "+err.Error(), back)
	case errors.Is(err, remote.ErrNoBox):
		s.flashErr(w, r, "Diesem Standort ist keine Box zugeordnet.", back)
	case err != nil:
		s.flashErr(w, r, "Fernzugriff nicht eingeschaltet: "+err.Error(), back)
	case ra.State == store.RemoteActive:
		s.flash(w, r, "Fernzugriff aktiv: "+ra.CIDR+" ist im Techniker-Stack erreichbar.", back)
	default:
		s.flash(w, r, "Fernzugriff wird eingeschaltet. Sobald die Box im Techniker-Stack ist, legt EX0 das Netzwerk an. Dauert zwei bis drei Minuten.", back)
	}
}

func (s *Server) remoteDisable(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=technik"
	if s.Remote == nil {
		s.flashErr(w, r, "Fernzugriff ist auf diesem Server nicht aktiv.", back)
		return
	}
	if _, err := s.Remote.Disable(r.Context(), siteID, actor(r)); err != nil {
		s.flashErr(w, r, "Nicht abgeschaltet: "+err.Error(), back)
		return
	}
	s.flash(w, r, "Fernzugriff abgeschaltet; das LAN ist aus dem Techniker-Stack nicht mehr erreichbar. Die Box bleibt Peer.", back)
}

func (s *Server) remoteRemove(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=technik"
	if s.Remote == nil {
		s.flashErr(w, r, "Fernzugriff ist auf diesem Server nicht aktiv.", back)
		return
	}
	if err := s.Remote.Remove(r.Context(), siteID, actor(r)); err != nil {
		s.flashErr(w, r, "Nicht entfernt: "+err.Error(), back)
		return
	}
	s.flash(w, r, "Fernzugriff entfernt: Netzwerk im Techniker-Stack gelöscht.", back)
}

// ---- settings ----------------------------------------------------------------------------

func (s *Server) apiRemoteSettings(w http.ResponseWriter, r *http.Request) {
	if s.Remote == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	st := s.Remote.Settings(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "settings": st})
}

func (s *Server) remoteSettingsSave(w http.ResponseWriter, r *http.Request) {
	if s.Remote == nil {
		s.flashErr(w, r, "Fernzugriff ist auf diesem Server nicht aktiv.", "/settings")
		return
	}
	f := r.PostForm
	if err := s.Remote.SaveSettings(r.Context(), f.Get("url"), f.Get("token"), f.Get("tech_group"), f.Get("lan_group"), f.Get("box_group")); err != nil {
		s.flashErr(w, r, err.Error(), "/settings")
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "settings.netbird", f.Get("url"), "")
	s.flash(w, r, "Techniker-Stack gespeichert.", "/settings")
}

func (s *Server) remoteSettingsTest(w http.ResponseWriter, r *http.Request) {
	if s.Remote == nil {
		s.flashErr(w, r, "Fernzugriff ist auf diesem Server nicht aktiv.", "/settings")
		return
	}
	n, err := s.Remote.Test(r.Context())
	if err != nil {
		s.flashErr(w, r, "Verbindung fehlgeschlagen: "+err.Error(), "/settings")
		return
	}
	s.flash(w, r, "Verbindung steht: "+itoa(n)+" Gruppen im Techniker-Stack.", "/settings")
}
