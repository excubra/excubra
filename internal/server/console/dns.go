package console

// The DNS sensor (ADR-0020): the switches per site, what the box reports, the
// day's totals, and the blocklist with the operator's own domains.

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/server/blocklist"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

type dnsView struct {
	Enabled   bool             `json:"enabled"`
	Block     bool             `json:"block"`
	Upstreams []string         `json:"upstreams"`
	HasBox    bool             `json:"hasBox"`
	BoxIP     string           `json:"boxIp"`  // what to enter in the router
	Report    *wire.DNSReport  `json:"report"` // the box's last report
	ReportAt  *time.Time       `json:"reportAt"`
	Days      []store.DNSDay   `json:"days"`
	Findings  int              `json:"findings"` // open findings of the DNS kinds
	List      blocklist.Status `json:"list"`
	ListOff   bool             `json:"listOff"`
}

func (s *Server) apiSiteDNS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := r.PathValue("id")
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	v := dnsView{Enabled: site.DNSEnabled, Block: site.DNSBlock, Upstreams: site.DNSUpstreams, Days: []store.DNSDay{}, List: s.Blocklist.Status(), ListOff: s.Blocklist == nil}
	if v.Upstreams == nil {
		v.Upstreams = []string{}
	}
	if box, err := s.siteBox(ctx, siteID); err == nil && box != nil {
		v.HasBox = true
		v.BoxIP = boxLANAddress(box)
		v.Report = box.DNS
		if box.DNS != nil {
			at := box.LastSeen
			v.ReportAt = &at
		}
	}
	if days, err := s.Store.DNSDays(ctx, siteID, 14); err == nil && days != nil {
		v.Days = days
	}
	if open, err := s.Store.OpenFindings(ctx, site.TenantID); err == nil {
		for _, f := range open {
			if f.SiteID == siteID && strings.HasPrefix(f.Rule, "signal.dns_") {
				v.Findings++
			}
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// boxLANAddress is the address the box reports as its own on the LAN: what the
// router must hand out as the DNS server.
func boxLANAddress(box *store.Box) string {
	if box.LANIP != "" {
		return box.LANIP
	}
	if box.DNS != nil && box.DNS.Listening != "" {
		if h, _, err := net.SplitHostPort(box.DNS.Listening); err == nil {
			return h
		}
	}
	return ""
}

func (s *Server) siteDNSSet(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=technik"
	f := r.PostForm
	enabled, block := f.Get("enabled") == "1", f.Get("block") == "1"
	var ups []string
	for _, u := range strings.FieldsFunc(f.Get("upstreams"), func(c rune) bool { return c == ',' || c == '\n' || c == ' ' || c == ';' }) {
		if u = strings.TrimSpace(u); u != "" {
			ups = append(ups, u)
		}
	}
	if len(ups) > 4 {
		s.flashErr(w, r, "Höchstens vier Upstream-Resolver.", back)
		return
	}
	if err := s.Engine.SetSiteDNS(r.Context(), siteID, enabled, block, ups, actor(r)); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	switch {
	case !enabled:
		s.flash(w, r, "DNS-Sensor abgeschaltet. Die Box schließt Port 53 mit dem nächsten Heartbeat; im Router den DNS-Server wieder umstellen, sonst bleiben die Geräte ohne Namensauflösung.", back)
	case block:
		s.flash(w, r, "DNS-Sensor eingeschaltet, bekannte Schad-Domains werden geblockt. Jetzt im Router die Box als DNS-Server eintragen.", back)
	default:
		s.flash(w, r, "DNS-Sensor eingeschaltet, Schad-Domains werden gemeldet. Jetzt im Router die Box als DNS-Server eintragen.", back)
	}
}

func (s *Server) apiDNSSettings(w http.ResponseWriter, r *http.Request) {
	if s.Blocklist == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	extra, _ := s.Store.Setting(r.Context(), blocklist.SettingExtra)
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "status": s.Blocklist.Status(), "extra": extra})
}

func (s *Server) dnsSettingsSave(w http.ResponseWriter, r *http.Request) {
	if s.Blocklist == nil {
		s.flashErr(w, r, "Die Blockliste ist auf diesem Server nicht aktiv.", "/settings")
		return
	}
	extra := strings.TrimSpace(r.PostForm.Get("extra"))
	if err := s.Store.SetSetting(r.Context(), blocklist.SettingExtra, extra); err != nil {
		s.flashErr(w, r, err.Error(), "/settings")
		return
	}
	changed, err := s.Blocklist.Refresh(r.Context(), false)
	if err != nil {
		s.flashErr(w, r, "Gespeichert, aber die Listen antworten nicht: "+err.Error(), "/settings")
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "settings.dns", "block_extra", map[bool]string{true: "changed", false: "unchanged"}[changed])
	s.flash(w, r, "Eigene Domains gespeichert; die Boxen holen die neue Liste mit dem nächsten Config-Pull.", "/settings")
}
