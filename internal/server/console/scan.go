package console

// The service scan (ADR-0018): the switch per site, what the last rounds saw, and
// the services the scan found on a device.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// newServiceDays is how long a service counts as "new" on the device page.
const newServiceDays = 7

type serviceView struct {
	store.Service
	TLSInfo *wire.TLSInfo `json:"TLSInfo"`
	New     bool          `json:"New"` // first seen within the last days
}

func (s *Server) deviceServices(ctx context.Context, deviceID string) []serviceView {
	svcs, err := s.Store.ServicesForDevice(ctx, deviceID)
	if err != nil {
		return nil
	}
	now := s.Now()
	out := make([]serviceView, 0, len(svcs))
	for _, v := range svcs {
		row := serviceView{Service: v, New: v.GoneAt == nil && now.Sub(v.FirstSeen) < newServiceDays*24*time.Hour}
		if len(v.TLS) > 0 {
			var t wire.TLSInfo
			if json.Unmarshal(v.TLS, &t) == nil {
				row.TLSInfo = &t
			}
		}
		row.TLS = nil
		out = append(out, row)
	}
	return out
}

// scanView is a site's scan as the app shows it.
type scanView struct {
	Enabled  bool              `json:"enabled"`
	HasBox   bool              `json:"hasBox"`
	Last     *store.ScanRound  `json:"last"`
	Rounds   []store.ScanRound `json:"rounds"`
	Services int               `json:"services"` // open services on the site's devices
	Devices  int               `json:"devices"`  // devices with at least one service
	Findings int               `json:"findings"` // open findings from the scan
}

func (s *Server) apiSiteScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := r.PathValue("id")
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	v := scanView{Enabled: site.ScanEnabled}
	if box, err := s.siteBox(ctx, siteID); err == nil && box != nil {
		v.HasBox = true
	}
	if rounds, err := s.Store.ScanRounds(ctx, siteID, 5); err == nil && len(rounds) > 0 {
		v.Rounds = rounds
		v.Last = &rounds[0]
	}
	if svcs, err := s.Store.OpenServicesForSite(ctx, siteID); err == nil {
		devs := map[string]bool{}
		for _, sv := range svcs {
			devs[sv.DeviceID] = true
		}
		v.Services, v.Devices = len(svcs), len(devs)
	}
	if open, err := s.Store.OpenFindings(ctx, site.TenantID); err == nil {
		for _, f := range open {
			if f.SiteID == siteID && f.ConnectorID == "scan" {
				v.Findings++
			}
		}
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) siteScanSet(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=technik"
	enabled := r.PostForm.Get("enabled") == "1"
	if err := s.Engine.SetSiteScan(r.Context(), siteID, enabled, actor(r)); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	if enabled {
		s.flash(w, r, "Schwachstellen-Scan eingeschaltet. Die Box holt die Einstellung mit dem nächsten Heartbeat und beginnt die erste Runde innerhalb weniger Minuten; danach täglich.", back)
		return
	}
	s.flash(w, r, "Schwachstellen-Scan abgeschaltet. Gefundene Dienste und Findings bleiben stehen, bis eine neue Runde läuft.", back)
}
