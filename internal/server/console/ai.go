package console

// The AI assessment (ADR-0019): provider settings, the switch per tenant, the
// briefs per site and the button that asks for one now.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/excubra/excubra/internal/server/ai"
	"github.com/excubra/excubra/internal/server/store"
)

func (s *Server) apiAISettings(w http.ResponseWriter, r *http.Request) {
	if s.AI == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "settings": s.AI.Settings(r.Context())})
}

func (s *Server) aiSettingsSave(w http.ResponseWriter, r *http.Request) {
	if s.AI == nil {
		s.flashErr(w, r, "KI-Auswertung ist auf diesem Server nicht aktiv.", "/settings")
		return
	}
	f := r.PostForm
	if err := s.AI.SaveSettings(r.Context(), f.Get("provider"), f.Get("url"), f.Get("model"), f.Get("key")); err != nil {
		s.flashErr(w, r, err.Error(), "/settings")
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "settings.ai", f.Get("provider"), f.Get("model"))
	s.flash(w, r, "KI-Einstellungen gespeichert.", "/settings")
}

func (s *Server) aiSettingsTest(w http.ResponseWriter, r *http.Request) {
	if s.AI == nil {
		s.flashErr(w, r, "KI-Auswertung ist auf diesem Server nicht aktiv.", "/settings")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	reply, err := s.AI.Test(ctx)
	if err != nil {
		s.flashErr(w, r, "Verbindung fehlgeschlagen: "+err.Error(), "/settings")
		return
	}
	s.flash(w, r, "Verbindung steht, das Modell antwortet: „"+reply+"“", "/settings")
}

// siteAIView is a site's assessments as the app shows them.
type siteAIView struct {
	Available bool              `json:"available"` // a provider is configured
	Scope     string            `json:"scope"`     // the tenant's switch
	Latest    *briefView        `json:"latest"`
	History   []briefView       `json:"history"`
	Busy      bool              `json:"busy"`
	Findings  int               `json:"findings"` // open findings the AI wrote for this site
	Provider  string            `json:"provider"`
	Model     string            `json:"model"`
	Labels    map[string]string `json:"labels"`
}

type briefView struct {
	store.AIBrief
	Result ai.Result `json:"Result"`
}

func (s *Server) apiSiteAI(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := r.PathValue("id")
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	tenant, _ := s.Store.Tenant(ctx, site.TenantID)
	v := siteAIView{Scope: tenant.AIScope, History: []briefView{}, Labels: map[string]string{"hoch": "hoch", "mittel": "mittel", "niedrig": "niedrig"}}
	if s.AI != nil {
		set := s.AI.Settings(ctx)
		v.Available = set.Provider != "off" && set.Provider != ""
		v.Provider, v.Model = set.Provider, set.Model
		v.Busy = s.AI.Busy(siteID)
	}
	if briefs, err := s.Store.AIBriefs(ctx, siteID, 10); err == nil {
		for i, b := range briefs {
			bv := briefView{AIBrief: b}
			_ = json.Unmarshal(b.Body, &bv.Result)
			bv.Body = nil
			if i == 0 {
				bv := bv
				v.Latest = &bv
			}
			v.History = append(v.History, bv)
		}
	}
	if open, err := s.Store.OpenFindings(ctx, site.TenantID); err == nil {
		for _, f := range open {
			if f.SiteID == siteID && f.ConnectorID == "ki" {
				v.Findings++
			}
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// siteAIAssess asks for an assessment now; it runs in the background and the
// card picks the result up.
func (s *Server) siteAIAssess(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=ki"
	if s.AI == nil {
		s.flashErr(w, r, "KI-Auswertung ist auf diesem Server nicht aktiv.", back)
		return
	}
	if _, err := s.Store.Site(r.Context(), siteID); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	who := actor(r)
	base := context.WithoutCancel(r.Context()) // the request returns at once; the assessment keeps running
	go func() {
		ctx, cancel := context.WithTimeout(base, 5*time.Minute)
		defer cancel()
		if _, err := s.AI.Assess(ctx, siteID, who); err != nil {
			s.Log.Warn("ai: assess", "site", siteID, "err", err)
		}
	}()
	s.flash(w, r, "Einschätzung läuft. Das Modell liest das Lagebild; das Ergebnis erscheint hier in etwa einer Minute.", back)
}

func (s *Server) tenantAISet(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("id")
	scope := r.PostForm.Get("scope")
	if err := s.Store.SetTenantAI(r.Context(), tenantID, scope); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(w, r, err, http.StatusNotFound)
			return
		}
		s.flashErr(w, r, err.Error(), "/tenants/"+tenantID)
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "tenant.ai", tenantID, scope)
	if scope == store.AIScopeFacts {
		s.flash(w, r, "KI-Auswertung für diesen Kunden an: Inventar, Dienste, Findings, Ereignisse und Konnektor-Facts gehen an das Modell, keine Zugangsdaten, keine Logs.", "/tenants/"+tenantID)
		return
	}
	s.flash(w, r, "KI-Auswertung für diesen Kunden aus. Nichts von diesem Kunden verlässt den Server.", "/tenants/"+tenantID)
}
