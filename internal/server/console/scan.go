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

// scanView is a site's scan as the app shows it: the inside (the box in the LAN)
// and the outside (an outpost at the site's public address).
type scanView struct {
	Enabled  bool              `json:"enabled"`
	HasBox   bool              `json:"hasBox"`
	Canary   bool              `json:"canary"`  // the live detection switch (ADR-0018 §7)
	Armed    []int             `json:"armed"`   // decoy ports the box reports as listening
	Signals  int               `json:"signals"` // open findings from the live detection
	Last     *store.ScanRound  `json:"last"`
	Rounds   []store.ScanRound `json:"rounds"`
	Services int               `json:"services"` // open services on the site's devices
	Devices  int               `json:"devices"`  // devices with at least one service
	Findings int               `json:"findings"` // open findings from the scan
	WAN      *wanView          `json:"wan"`      // nil until an outpost looked
}

type wanView struct {
	IP       string           `json:"ip"`
	DeviceID string           `json:"deviceId"`
	Last     *store.ScanRound `json:"last"`
	Services int              `json:"services"`
	Findings int              `json:"findings"`
	Outpost  bool             `json:"outpost"` // an outpost exists that will look
}

func (s *Server) apiSiteScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := r.PathValue("id")
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	v := scanView{Enabled: site.ScanEnabled, Canary: site.CanaryEnabled, Armed: []int{}}
	if box, err := s.siteBox(ctx, siteID); err == nil && box != nil {
		v.HasBox = true
		if box.Canary != nil {
			v.Armed = box.Canary
		}
	}
	wan := &wanView{}
	if boxes, err := s.Store.Boxes(ctx, siteID); err == nil {
		for _, b := range boxes {
			if b.RevokedAt == nil && b.PublicIP != "" {
				wan.IP = b.PublicIP
			}
		}
	}
	if all, err := s.Store.Boxes(ctx, ""); err == nil {
		for _, b := range all {
			if b.RevokedAt == nil && b.Role == store.RoleOutpost {
				wan.Outpost = true
			}
		}
	}
	if rounds, err := s.Store.ScanRounds(ctx, siteID, 10); err == nil {
		for i := range rounds {
			switch {
			case rounds[i].External && wan.Last == nil:
				wan.Last = &rounds[i]
			case !rounds[i].External:
				v.Rounds = append(v.Rounds, rounds[i])
				if v.Last == nil {
					v.Last = &rounds[i]
				}
			}
		}
	}
	ext, extErr := s.Store.ExternalDevice(ctx, siteID)
	if extErr == nil {
		wan.DeviceID = ext.ID
	}
	if svcs, err := s.Store.OpenServicesForSite(ctx, siteID); err == nil {
		devs := map[string]bool{}
		for _, sv := range svcs {
			if extErr == nil && sv.DeviceID == ext.ID {
				wan.Services++
				continue
			}
			devs[sv.DeviceID] = true
			v.Services++
		}
		v.Devices = len(devs)
	}
	if open, err := s.Store.OpenFindings(ctx, site.TenantID); err == nil {
		for _, f := range open {
			if f.SiteID != siteID {
				continue
			}
			switch f.ConnectorID {
			case "scan":
				v.Findings++
			case "wan":
				wan.Findings++
			case "signal":
				v.Signals++
			}
		}
	}
	if wan.IP != "" || wan.Last != nil {
		v.WAN = wan
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

func (s *Server) siteCanarySet(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=technik"
	enabled := r.PostForm.Get("enabled") == "1"
	if err := s.Engine.SetSiteCanary(r.Context(), siteID, enabled, actor(r)); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	if enabled {
		s.flash(w, r, "Live-Erkennung eingeschaltet. Die Box öffnet ihre Köder-Ports mit dem nächsten Heartbeat und meldet ab dann, wer anklopft.", back)
		return
	}
	s.flash(w, r, "Live-Erkennung abgeschaltet. Die Box schließt ihre Köder-Ports; offene Findings bleiben, bis sie quittiert sind oder einen Tag still waren.", back)
}
