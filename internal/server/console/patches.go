package console

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

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

// apiPatchMachines lists a customer's machines: what the manager knows, and
// which device each one is here. Machines without a device come first — they
// are the ones waiting for somebody to decide.
func (s *Server) apiPatchMachines(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := s.Store.PatchMachines(ctx, r.URL.Query().Get("tenant"))
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	names := map[string]string{}
	for i, m := range rows {
		if m.DeviceID == "" {
			continue
		}
		if n, ok := names[m.DeviceID]; ok {
			rows[i].DeviceName = n
			continue
		}
		if d, err := s.Store.Device(ctx, m.DeviceID); err == nil {
			names[m.DeviceID] = deviceName(d)
			rows[i].DeviceName = names[m.DeviceID]
		}
	}
	out := map[string]any{"machines": rows}
	// The devices to choose from, so the assignment happens here and not in a
	// text field somebody types an id into.
	if tenant := r.URL.Query().Get("tenant"); tenant != "" {
		devs, err := s.Store.Devices(ctx, tenant, "", time.Time{})
		if err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		type option struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			IP   string `json:"ip"`
		}
		opts := make([]option, 0, len(devs))
		for _, d := range devs {
			if d.Ignored {
				continue
			}
			opts = append(opts, option{ID: d.ID, Name: deviceName(d), IP: d.IP})
		}
		sort.Slice(opts, func(i, j int) bool { return strings.ToLower(opts[i].Name) < strings.ToLower(opts[j].Name) })
		out["devices"] = opts
	}
	writeJSON(w, http.StatusOK, out)
}

// apiDevicePatch is one device's patch state, inventory included. This is the
// answer to "do I have to open the other portal": no.
func (s *Server) apiDevicePatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.Store.Device(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	out := map[string]any{"linked": false}
	if m, ok, err := s.Store.PatchMachineForDevice(ctx, dev.ID); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	} else if ok {
		m.DeviceName = deviceName(dev)
		out = map[string]any{"linked": true, "machine": m}
	} else {
		// Nothing tied to this device yet. Offer what this customer has that is
		// still free, so the choice is made here instead of in the other portal.
		rows, _ := s.Store.PatchMachines(ctx, dev.TenantID)
		free := []store.PatchMachine{}
		for _, m := range rows {
			if m.DeviceID == "" {
				m.CVEs, m.Updates = nil, nil
				free = append(free, m)
			}
		}
		out["free"] = free
	}
	writeJSON(w, http.StatusOK, out)
}

// patchesAssign ties one machine to one device by hand, or lets go again.
func (s *Server) patchesAssign(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	endpoint := strings.TrimSpace(r.PostForm.Get("endpoint"))
	deviceID := strings.TrimSpace(r.PostForm.Get("device"))
	m, err := s.Store.PatchMachine(ctx, patches.Provider, endpoint)
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	back := "/tenants/" + m.TenantID
	if deviceID == "" {
		if err := s.Store.PinPatchMachine(ctx, patches.Provider, endpoint, ""); err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		_ = s.Store.Audit(ctx, s.Now(), actor(r), "patches.unassign", endpoint, m.Name)
		s.kickPatches()
		s.flash(w, r, "Zuweisung gelöst. „"+m.Name+"“ sucht sich beim nächsten Abgleich wieder selbst ein Gerät über den Namen.", back)
		return
	}
	// Only a device of the same customer: a machine on another customer's device
	// would put one customer's patch state on another customer's page.
	dev, err := s.Store.Device(ctx, deviceID)
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	if dev.TenantID != m.TenantID {
		s.fail(w, r, errors.New("dieses Gerät gehört einem anderen Kunden"), http.StatusBadRequest)
		return
	}
	if err := s.Store.PinPatchMachine(ctx, patches.Provider, endpoint, dev.ID); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "patches.assign", endpoint, dev.ID)
	s.kickPatches()
	s.flash(w, r, "„"+m.Name+"“ gehört jetzt zu "+deviceName(dev)+". Die Zuweisung bleibt, auch wenn die Namen nie zusammenpassen.", "/devices/"+dev.ID+"?tab=patch")
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
		// Nothing of this customer is read any more, so nothing of it stays on
		// the page either.
		if err := s.Store.DropPatchMachinesOfTenant(ctx, tenantID); err != nil {
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
