package console

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/excubra/excubra/internal/server/action1"
	"github.com/excubra/excubra/internal/server/patches"
	"github.com/excubra/excubra/internal/server/store"
)

// The endpoint manager's patch state, and the one thing about it a person must
// decide: which organization over there is which customer over here. Five
// organizations and one wrong row would put one customer's machines on another
// customer's page, so the console offers a list to pick from and never guesses.

type patchesData struct {
	Configured bool             `json:"configured"`
	BaseURL    string           `json:"baseUrl"`
	HasSecret  bool             `json:"hasSecret"`
	Status     patches.Status   `json:"status"`
	Links      []store.PatchOrg `json:"links"`
	Orgs       []action1.Org    `json:"orgs"` // what the credential can see, empty when it cannot
	OrgErr     string           `json:"orgErr"`
}

func (s *Server) apiPatches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := patchesData{Links: []store.PatchOrg{}, Orgs: []action1.Org{}}
	d.BaseURL, _ = s.Store.Setting(ctx, action1.SettingBaseURL)
	if d.BaseURL == "" {
		d.BaseURL = action1.DefaultBaseURL
	}
	if sec, _ := s.Store.Setting(ctx, action1.SettingClientSecret); sec != "" {
		d.HasSecret = true
	}
	if links, err := s.Store.PatchOrgs(ctx); err == nil {
		d.Links = links
	}
	c := s.patchClient(ctx)
	d.Configured = c.Configured()
	if d.Configured {
		d.Status = s.patchStatus()
		orgs, err := c.Orgs(ctx)
		if err != nil {
			d.OrgErr = err.Error()
		} else {
			d.Orgs = orgs
		}
	}
	writeJSON(w, http.StatusOK, d)
}

// patchClient builds a reader from the stored credentials. It is cheap and
// stateless enough to make per request; the running service keeps its own.
func (s *Server) patchClient(ctx context.Context) *action1.Client {
	base, _ := s.Store.Setting(ctx, action1.SettingBaseURL)
	cid, _ := s.Store.Setting(ctx, action1.SettingClientID)
	sec, _ := s.Store.Setting(ctx, action1.SettingClientSecret)
	return action1.New(base, cid, sec)
}

// kickPatches asks the running sync to look again, so a change an operator just
// made shows its result in a moment instead of at the next full hour.
func (s *Server) kickPatches() {
	if s.Patches != nil {
		s.Patches.Kick()
	}
}

func (s *Server) patchStatus() patches.Status {
	if s.Patches == nil {
		return patches.Status{}
	}
	return s.Patches.Status()
}

// patchesCredentials stores the API credentials. An empty secret keeps the one
// that is stored, so an operator can change the base URL without retyping it.
func (s *Server) patchesCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	base := strings.TrimSpace(r.PostForm.Get("baseUrl"))
	cid := strings.TrimSpace(r.PostForm.Get("clientId"))
	sec := strings.TrimSpace(r.PostForm.Get("clientSecret"))
	if err := s.Store.SetSetting(ctx, action1.SettingBaseURL, base); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if err := s.Store.SetSetting(ctx, action1.SettingClientID, cid); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if sec != "" {
		if err := s.Store.SetSetting(ctx, action1.SettingClientSecret, sec); err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "settings.patches", patches.Provider, base)
	s.kickPatches()
	if cid == "" {
		s.flash(w, r, "Zugangsdaten entfernt; es wird nichts mehr gelesen.", "/settings")
		return
	}
	s.flash(w, r, "Zugangsdaten gespeichert. Die Prüfung läuft stündlich und liest nur.", "/settings")
}

// patchesLink ties one customer to one organization, or unties them.
func (s *Server) patchesLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := strings.TrimSpace(r.PostForm.Get("tenant"))
	orgID := strings.TrimSpace(r.PostForm.Get("org"))
	t, err := s.Store.Tenant(ctx, tenantID)
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	// The way back is built from the id the store handed out, not from the one
	// the form carried: a redirect target should never be a request's own text.
	back := "/tenants/" + t.ID
	if orgID == "" {
		if err := s.Store.ClearPatchOrg(ctx, tenantID); err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		_ = s.Store.Audit(ctx, s.Now(), actor(r), "patches.unlink", tenantID, t.Name)
		s.kickPatches()
		s.flash(w, r, "Verknüpfung gelöst. Für diesen Kunden wird keine Patch-Lage mehr gelesen.", back)
		return
	}
	// Only an organization the credential really sees: a typed id nobody checked
	// is how a customer ends up looking at another customer's machines.
	orgs, err := s.patchClient(ctx).Orgs(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusBadGateway)
		return
	}
	name := ""
	for _, o := range orgs {
		if o.ID == orgID {
			name = o.Name
			break
		}
	}
	if name == "" {
		s.fail(w, r, errors.New("diese Organisation gibt es im Endpunkt-Manager nicht"), http.StatusBadRequest)
		return
	}
	link := store.PatchOrg{TenantID: tenantID, Provider: patches.Provider, OrgID: orgID, OrgName: name, LinkedBy: actor(r)}
	if err := s.Store.SetPatchOrg(ctx, link, s.Now()); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "patches.link", tenantID, name)
	s.kickPatches()
	s.flash(w, r, t.Name+" ist jetzt mit „"+name+"“ verknüpft. Die Patch-Lage erscheint bei den Geräten unter Prävention.", back)
}
