package console

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/event"
	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/api"
	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// ---- view models ------------------------------------------------------------------

type hostRow struct {
	core.HostView
	StateClass string
	StateLabel string
	Checks     string
}

type boxRow struct {
	store.Box
	State      state.Box
	SiteName   string
	TenantName string
	Assigned   bool
}

type siteBlock struct {
	Site  store.Site
	Boxes []boxRow
	Hosts []hostRow
}

type tenantBlock struct {
	Tenant store.Tenant
	Sites  []siteBlock
}

type statusData struct {
	Tenants []tenantBlock
	Up      int
	Down    int
	Unknown int
	Maint   int
	Silent  int
	Total   int
	Boxes   int
	Recent  []recentEvent

	Cards        []siteCard
	Unassigned   []boxRow
	Devices      int
	SitesOnline  int
	SitesWithBox int
	SitesTotal   int
	Events24h    int
}

// recentEvent is an event with the names the dashboard shows.
type recentEvent struct {
	event.Event
	TenantName string
	SiteName   string
	Class      string // ok | down | warn | muted
	Title      string
	Info       string // the one detail worth a line: failed checks, silence duration
}

func eventInfo(ev event.Event) string {
	if ev.Details == nil {
		return ""
	}
	switch ev.Type {
	case event.HostDown:
		if f, ok := ev.Details["checks_failed"].([]any); ok && len(f) > 0 {
			parts := make([]string, 0, len(f))
			for _, x := range f {
				parts = append(parts, fmt.Sprint(x))
			}
			return "fehlgeschlagen: " + strings.Join(parts, ", ")
		}
		if f, ok := ev.Details["checks_failed"].([]string); ok && len(f) > 0 {
			return "fehlgeschlagen: " + strings.Join(f, ", ")
		}
	case event.HostUp:
		if d, ok := ev.Details["down_for_s"]; ok {
			return fmt.Sprintf("war %s nicht erreichbar", humanDur(time.Duration(toInt64(d))*time.Second))
		}
	case event.BoxBack:
		if d, ok := ev.Details["silent_for_s"]; ok {
			return fmt.Sprintf("war %s still", humanDur(time.Duration(toInt64(d))*time.Second))
		}
	case event.BoxSilent:
		if d, ok := ev.Details["missed_heartbeats"]; ok {
			return fmt.Sprintf("%d Heartbeats ausgeblieben", toInt64(d))
		}
	}
	return ""
}

func toInt64(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	}
	return 0
}

// hourBucket is one hour of a host's check history for the availability bars.
type hourBucket struct {
	Label  string
	Rounds int
	Failed int
	Pct    float64 // -1 when there is no data
	Class  string  // ok | warn | down | empty
	Height int     // 4..100, bar height in percent of the chart
}

// availability is the last 24 hours of a host's check rounds, for cards and the host page.
type availability struct {
	Rounds int
	Failed int
	Pct    float64
	Hours  []hourBucket
}

func (s *Server) availability(ctx context.Context, tenantID, hostID string, now time.Time) (availability, error) {
	var a availability
	rollups, err := s.Store.Rollups(ctx, tenantID, hostID, now.Add(-24*time.Hour), now)
	if err != nil {
		return a, err
	}
	byHour := map[time.Time]store.Rollup{}
	for _, ru := range rollups {
		a.Rounds += ru.Rounds
		a.Failed += ru.Failed
		cur := byHour[ru.Hour]
		cur.Rounds += ru.Rounds
		cur.Failed += ru.Failed
		byHour[ru.Hour] = cur
	}
	a.Pct = 100
	if a.Rounds > 0 {
		a.Pct = 100 * float64(a.Rounds-a.Failed) / float64(a.Rounds)
	}
	start := now.UTC().Truncate(time.Hour).Add(-23 * time.Hour)
	for i := 0; i < 24; i++ {
		h := start.Add(time.Duration(i) * time.Hour)
		b := hourBucket{Label: h.In(s.Loc).Format("15:04"), Pct: -1, Class: "empty", Height: 4}
		if ru, ok := byHour[h]; ok && ru.Rounds > 0 {
			b.Rounds, b.Failed = ru.Rounds, ru.Failed
			b.Pct = 100 * float64(ru.Rounds-ru.Failed) / float64(ru.Rounds)
			b.Height = int(b.Pct)
			if b.Height < 6 {
				b.Height = 6
			}
			switch {
			case b.Pct >= 99.5:
				b.Class = "ok"
			case b.Pct >= 90:
				b.Class = "warn"
			default:
				b.Class = "down"
			}
		}
		a.Hours = append(a.Hours, b)
	}
	return a, nil
}

func classify(v core.HostView) (string, string) {
	switch {
	case v.Suppressed == "maintenance":
		return "maint", "Wartung"
	case v.Suppressed == "box_silent":
		return "suppressed", "Box schweigt"
	case strings.HasPrefix(v.Suppressed, "uplink:"):
		return "suppressed", "Uplink ausgefallen"
	case v.State.Observed == state.Up:
		return "up", "erreichbar"
	case v.State.Observed == state.Down:
		return "down", "ausgefallen"
	default:
		return "unknown", "unbekannt"
	}
}

func checksSummary(v core.HostView) string {
	if len(v.State.LastChecks) == 0 {
		return "noch kein Ergebnis"
	}
	parts := make([]string, 0, len(v.State.LastChecks))
	for _, c := range v.State.LastChecks {
		mark := "✓"
		if !c.OK {
			mark = "✗"
		}
		p := c.Type + " " + mark
		if c.OK && c.LatencyMS != nil {
			p += fmt.Sprintf(" %d ms", *c.LatencyMS)
		}
		if !c.OK && c.Error != "" {
			p += " " + c.Error
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " · ")
}

func (s *Server) hostRow(v core.HostView) hostRow {
	c, l := classify(v)
	return hostRow{HostView: v, StateClass: c, StateLabel: l, Checks: checksSummary(v)}
}

func (s *Server) boxRow(b store.Box, sites map[string]store.Site, tenants map[string]store.Tenant) boxRow {
	r := boxRow{Box: b}
	if st, ok := s.Engine.BoxState(b.ID); ok {
		r.State = st
	}
	if site, ok := sites[b.SiteID]; ok {
		r.SiteName = site.Name
		r.Assigned = true
		if t, ok := tenants[site.TenantID]; ok {
			r.TenantName = t.Name
		}
	}
	return r
}

func (s *Server) lookups(ctx context.Context) (map[string]store.Tenant, map[string]store.Site, error) {
	tenants, err := s.Store.Tenants(ctx)
	if err != nil {
		return nil, nil, err
	}
	sites, err := s.Store.Sites(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	tm := map[string]store.Tenant{}
	for _, t := range tenants {
		tm[t.ID] = t
	}
	sm := map[string]store.Site{}
	for _, st := range sites {
		sm[st.ID] = st
	}
	return tm, sm, nil
}

// ---- status ------------------------------------------------------------------------

func (s *Server) buildStatus(ctx context.Context) (statusData, error) {
	var d statusData
	tenants, err := s.Store.Tenants(ctx)
	if err != nil {
		return d, err
	}
	sites, err := s.Store.Sites(ctx, "")
	if err != nil {
		return d, err
	}
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		return d, err
	}
	views, err := s.Engine.HostViews(ctx, "")
	if err != nil {
		return d, err
	}
	tm, sm, err := s.lookups(ctx)
	if err != nil {
		return d, err
	}
	boxesBySite := map[string][]boxRow{}
	for _, b := range boxes {
		if b.RevokedAt != nil || b.SiteID == "" {
			continue
		}
		r := s.boxRow(b, sm, tm)
		if r.State.Status == state.Silent {
			d.Silent++
		}
		boxesBySite[b.SiteID] = append(boxesBySite[b.SiteID], r)
	}
	d.Boxes = len(boxesBySite)
	hostsBySite := map[string][]hostRow{}
	for _, v := range views {
		r := s.hostRow(v)
		switch r.StateClass {
		case "up":
			d.Up++
		case "down":
			d.Down++
		case "maint":
			d.Maint++
		default:
			d.Unknown++
		}
		d.Total++
		hostsBySite[v.SiteID] = append(hostsBySite[v.SiteID], r)
	}
	now := s.Now()
	for _, t := range tenants {
		tb := tenantBlock{Tenant: t}
		for _, st := range sites {
			if st.TenantID != t.ID {
				continue
			}
			tb.Sites = append(tb.Sites, siteBlock{Site: st, Boxes: boxesBySite[st.ID], Hosts: hostsBySite[st.ID]})
		}
		d.Tenants = append(d.Tenants, tb)
		evs, err := s.Store.Events(ctx, t.ID, now.Add(-24*time.Hour), now.Add(time.Minute), "", 50)
		if err != nil {
			return d, err
		}
		for _, ev := range evs {
			re := recentEvent{Event: ev, TenantName: t.Name, Class: eventClass(ev.Type), Title: eventTitle(ev), Info: eventInfo(ev)}
			if site, ok := sm[ev.SiteID]; ok {
				re.SiteName = site.Name
			}
			d.Recent = append(d.Recent, re)
		}
	}
	sort.Slice(d.Recent, func(i, j int) bool { return d.Recent[i].OccurredAt.After(d.Recent[j].OccurredAt) })
	d.Events24h = len(d.Recent)
	if len(d.Recent) > 20 {
		d.Recent = d.Recent[:20]
	}
	if err := s.siteCards(ctx, &d); err != nil {
		return d, err
	}
	return d, nil
}

func eventClass(t event.Type) string {
	switch t {
	case event.HostDown, event.BoxSilent:
		return "down"
	case event.HostUp, event.BoxBack:
		return "ok"
	case event.MaintenanceStarted, event.MaintenanceEnded, event.DeviceNew:
		return "warn"
	default:
		return "muted"
	}
}

func eventTitle(ev event.Event) string {
	name := ev.HostID
	if ev.Host != nil && ev.Host.Name != "" {
		name = ev.Host.Name
	}
	switch ev.Type {
	case event.HostDown:
		return name + " ist ausgefallen"
	case event.HostUp:
		return name + " ist wieder erreichbar"
	case event.BoxSilent:
		return "Box " + ev.BoxID + " schweigt"
	case event.BoxBack:
		return "Box " + ev.BoxID + " meldet sich wieder"
	case event.DeviceNew:
		if ev.Device != nil {
			return "Neues Gerät " + firstNonEmpty(ev.Device.Hostname, ev.Device.IP)
		}
		return "Neues Gerät"
	case event.DeviceGone:
		if ev.Device != nil {
			return "Gerät verschwunden: " + firstNonEmpty(ev.Device.Hostname, ev.Device.IP)
		}
		return "Gerät verschwunden"
	case event.MaintenanceStarted:
		return "Wartung begonnen"
	case event.MaintenanceEnded:
		return "Wartung beendet"
	case event.TestPing:
		return "Test-Ereignis"
	}
	return string(ev.Type)
}

func (s *Server) statusPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildStatus(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	s.render(w, r, "status", "Status", d)
}

func (s *Server) statusTable(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildStatus(r.Context())
	if err != nil {
		http.Error(w, "Fehler", http.StatusInternalServerError)
		return
	}
	s.renderPartial(w, "status_table", d)
}

// ---- hosts --------------------------------------------------------------------------

type checkForm struct {
	ICMP    bool
	TCPPort int
	HTTPURL string
}

func checksToForm(cs []wire.CheckConfig) checkForm {
	var f checkForm
	for _, c := range cs {
		switch c.Type {
		case wire.CheckICMP:
			f.ICMP = true
		case wire.CheckTCP:
			f.TCPPort = c.Port
		case wire.CheckHTTP:
			f.HTTPURL = c.URL
		}
	}
	return f
}

func checksFromForm(r *http.Request) ([]wire.CheckConfig, error) {
	var cs []wire.CheckConfig
	if r.PostForm.Get("icmp") == "1" {
		cs = append(cs, wire.CheckConfig{Type: wire.CheckICMP})
	}
	if p := strings.TrimSpace(r.PostForm.Get("tcp_port")); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("TCP-Port muss zwischen 1 und 65535 liegen")
		}
		cs = append(cs, wire.CheckConfig{Type: wire.CheckTCP, Port: port})
	}
	if u := strings.TrimSpace(r.PostForm.Get("http_url")); u != "" {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return nil, errors.New("HTTP-URL muss mit http:// oder https:// beginnen")
		}
		cs = append(cs, wire.CheckConfig{Type: wire.CheckHTTP, URL: u})
	}
	if len(cs) == 0 {
		return nil, errors.New("mindestens ein Check ist nötig")
	}
	return cs, nil
}

type hostData struct {
	View         core.HostView
	Row          hostRow
	Box          store.Box
	Site         store.Site
	Tenant       store.Tenant
	Siblings     []store.Host
	Windows      []state.Maintenance
	Form         checkForm
	Rounds       int
	Failed       int
	Availability float64
	Events       []recentEvent
	Hours        []hourBucket
	Tab          string
}

func (s *Server) hostPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.Engine.HostView(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	d := hostData{View: v, Row: s.hostRow(v), Form: checksToForm(v.Checks)}
	if d.Box, err = s.Store.Box(ctx, v.BoxID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if d.Site, err = s.Store.Site(ctx, v.SiteID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	d.Tenant, _ = s.Store.Tenant(ctx, v.TenantID)
	all, err := s.Store.Hosts(ctx, "", v.BoxID)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	for _, h := range all {
		if h.ID != v.ID {
			d.Siblings = append(d.Siblings, h)
		}
	}
	for _, target := range []string{v.ID, v.SiteID, v.TenantID} {
		d.Windows = append(d.Windows, s.Engine.MaintenanceFor(target)...)
	}
	now := s.Now()
	av, err := s.availability(ctx, v.TenantID, v.ID, now)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	d.Rounds, d.Failed, d.Availability, d.Hours = av.Rounds, av.Failed, av.Pct, av.Hours
	evs, err := s.Store.Events(ctx, v.TenantID, now.Add(-24*time.Hour), now.Add(time.Minute), v.ID, 100)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	for i := len(evs) - 1; i >= 0; i-- { // newest first
		d.Events = append(d.Events, recentEvent{Event: evs[i], TenantName: d.Tenant.Name, SiteName: d.Site.Name, Class: eventClass(evs[i].Type), Title: eventTitle(evs[i]), Info: eventInfo(evs[i])})
	}
	d.Tab = r.URL.Query().Get("tab")
	if d.Tab != "verlauf" && d.Tab != "einstellungen" {
		d.Tab = "allgemein"
	}
	s.render(w, r, "host", v.Name, d)
}

func (s *Server) hostUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := s.Store.Host(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	checks, err := checksFromForm(r)
	if err != nil {
		s.flash(w, r, "Nicht gespeichert: "+err.Error(), "/hosts/"+h.ID)
		return
	}
	h.Name = strings.TrimSpace(r.PostForm.Get("name"))
	h.Address = strings.TrimSpace(r.PostForm.Get("address"))
	h.ParentID = strings.TrimSpace(r.PostForm.Get("parent_id"))
	h.IsUplink = r.PostForm.Get("is_uplink") == "1"
	h.Checks = checks
	if h.Name == "" || h.Address == "" {
		s.flash(w, r, "Name und Adresse sind Pflicht.", "/hosts/"+h.ID)
		return
	}
	if err := s.Engine.UpdateHost(ctx, h, actor(r)); err != nil {
		s.flash(w, r, "Nicht gespeichert: "+err.Error(), "/hosts/"+h.ID)
		return
	}
	s.flash(w, r, "Gespeichert.", "/hosts/"+h.ID)
}

func (s *Server) hostDelete(w http.ResponseWriter, r *http.Request) {
	back := "/status"
	if v, err := s.Engine.HostView(r.Context(), r.PathValue("id")); err == nil && v.SiteID != "" {
		back = "/sites/" + v.SiteID + "?tab=ueberwachung"
	}
	if err := s.Engine.DeleteHost(r.Context(), r.PathValue("id"), actor(r)); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	s.flash(w, r, "Host wird nicht mehr überwacht.", back)
}

func (s *Server) hostMaintenance(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := s.Store.Host(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	if r.PostForm.Get("action") == "end" {
		for _, wnd := range s.Engine.MaintenanceFor(h.ID) {
			if err := s.Engine.EndMaintenance(ctx, wnd.ID, actor(r)); err != nil && !errors.Is(err, store.ErrNotFound) {
				s.fail(w, r, err, http.StatusInternalServerError)
				return
			}
		}
		s.flash(w, r, "Wartung beendet.", "/hosts/"+h.ID)
		return
	}
	until, err := formTime(r.PostForm.Get("until"), s.Loc)
	if err != nil {
		s.flash(w, r, err.Error(), "/hosts/"+h.ID)
		return
	}
	m := store.Maintenance{TenantID: h.TenantID, SiteID: h.SiteID, Scope: "host", TargetID: h.ID, Until: until, Reason: strings.TrimSpace(r.PostForm.Get("reason"))}
	if err := s.Engine.StartMaintenance(ctx, m, actor(r)); err != nil {
		s.flash(w, r, "Wartung nicht gesetzt: "+err.Error(), "/hosts/"+h.ID)
		return
	}
	s.flash(w, r, "Wartung gesetzt bis "+until.In(s.Loc).Format("02.01.2006 15:04")+".", "/hosts/"+h.ID)
}

// ---- boxes -------------------------------------------------------------------------

type boxesData struct {
	Unassigned []boxRow
	Assigned   []boxRow
}

func (s *Server) boxesPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	tm, sm, err := s.lookups(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	var d boxesData
	for _, b := range boxes {
		if b.RevokedAt != nil {
			continue
		}
		row := s.boxRow(b, sm, tm)
		if row.Assigned {
			d.Assigned = append(d.Assigned, row)
		} else {
			d.Unassigned = append(d.Unassigned, row)
		}
	}
	s.render(w, r, "boxes", "Boxen", d)
}

type boxData struct {
	Row         boxRow
	Sites       []store.Site
	TenantNames map[string]string
	Hosts       []store.Host
	Netbird     *store.NetbirdKey
	Fingerprint string
	Subnets     string
}

func (s *Server) boxPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	b, err := s.Store.Box(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	tm, sm, err := s.lookups(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	d := boxData{Row: s.boxRow(b, sm, tm), Fingerprint: s.CA.Fingerprint(), TenantNames: map[string]string{}, Subnets: strings.Join(b.DiscoverySubnets, "\n")}
	for _, t := range tm {
		d.TenantNames[t.ID] = t.Name
	}
	if d.Sites, err = s.Store.Sites(ctx, ""); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if d.Hosts, err = s.Store.Hosts(ctx, "", b.ID); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if nk, err := s.Store.NetbirdKey(ctx, b.ID); err == nil {
		d.Netbird = &nk
	}
	title := b.Name
	if title == "" {
		title = b.ID
	}
	s.render(w, r, "box", title, d)
}

func (s *Server) boxAssign(w http.ResponseWriter, r *http.Request) {
	boxID := r.PathValue("id")
	siteID := strings.TrimSpace(r.PostForm.Get("site_id"))
	if err := s.Engine.AssignBox(r.Context(), boxID, siteID, actor(r)); err != nil {
		s.flash(w, r, "Zuordnung fehlgeschlagen: "+err.Error(), "/boxes/"+boxID)
		return
	}
	if siteID == "" {
		s.flash(w, r, "Box ist nicht mehr zugeordnet.", "/boxes/"+boxID)
		return
	}
	s.flash(w, r, "Box zugeordnet. Die Box holt die neue Konfiguration mit dem nächsten Heartbeat.", "/boxes/"+boxID)
}

func (s *Server) boxSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	boxID := r.PathValue("id")
	if _, err := s.Store.Box(ctx, boxID); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	channel := r.PostForm.Get("channel")
	if channel != wire.ChannelStable && channel != wire.ChannelCanary {
		channel = wire.ChannelStable
	}
	mode := r.PostForm.Get("discovery_mode")
	if mode != wire.DiscoveryPassive && mode != wire.DiscoverySweep {
		mode = wire.DiscoverySweep
	}
	var subnets []string
	for _, line := range strings.FieldsFunc(r.PostForm.Get("discovery_subnets"), func(c rune) bool { return c == '\n' || c == ',' || c == ' ' }) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(line, "/") {
			s.flash(w, r, "Subnetze in CIDR-Schreibweise angeben, z. B. 192.168.10.0/24", "/boxes/"+boxID)
			return
		}
		subnets = append(subnets, line)
	}
	if len(subnets) > 8 {
		s.flash(w, r, "Höchstens acht zusätzliche Subnetze.", "/boxes/"+boxID)
		return
	}
	if err := errors.Join(
		s.Store.RenameBox(ctx, boxID, strings.TrimSpace(r.PostForm.Get("name"))),
		s.Store.SetBoxChannel(ctx, boxID, channel),
		s.Store.SetBoxDiscovery(ctx, boxID, mode, subnets),
	); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "box.settings", boxID, fmt.Sprintf("channel=%s discovery=%s subnets=%s", channel, mode, strings.Join(subnets, ",")))
	s.flash(w, r, "Einstellungen gespeichert.", "/boxes/"+boxID)
}

func (s *Server) boxNetbird(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	boxID := r.PathValue("id")
	if _, err := s.Store.Box(ctx, boxID); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	if r.PostForm.Get("action") == "clear" {
		if err := s.Store.DeleteNetbirdKey(ctx, boxID); err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		_ = s.Store.Audit(ctx, s.Now(), actor(r), "netbird.clear", boxID, "")
		s.flash(w, r, "NetBird-Schlüssel entfernt.", "/boxes/"+boxID)
		return
	}
	u := strings.TrimSpace(r.PostForm.Get("management_url"))
	k := strings.TrimSpace(r.PostForm.Get("setup_key"))
	if !strings.HasPrefix(u, "https://") || k == "" {
		s.flash(w, r, "Management-URL (https://…) und Setup-Key sind Pflicht.", "/boxes/"+boxID)
		return
	}
	if err := s.Store.SetNetbirdKey(ctx, store.NetbirdKey{BoxID: boxID, ManagementURL: u, SetupKey: k, CreatedAt: s.Now()}); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "netbird.set", boxID, u)
	s.flash(w, r, "NetBird-Übergabe hinterlegt; die Box holt den Schlüssel einmalig mit dem nächsten Config-Pull.", "/boxes/"+boxID)
}

func (s *Server) boxRevoke(w http.ResponseWriter, r *http.Request) {
	boxID := r.PathValue("id")
	if err := s.Engine.RevokeBox(r.Context(), boxID, actor(r)); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	s.flash(w, r, "Box widerrufen — ihr Zertifikat wird ab sofort abgewiesen.", "/boxes")
}

func (s *Server) boxDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Engine.DeleteBox(r.Context(), r.PathValue("id"), actor(r)); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	s.flash(w, r, "Box gelöscht; das Zertifikat bleibt gesperrt.", "/boxes")
}

// ---- tenants and sites -------------------------------------------------------------------

type siteRow struct {
	store.Site
	Boxes int
	Hosts int
}

type tenantRow struct {
	store.Tenant
	Sites []siteRow
}

func (s *Server) tenantsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenants, err := s.Store.Tenants(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	sites, err := s.Store.Sites(ctx, "")
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	hosts, err := s.Store.Hosts(ctx, "", "")
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	nb, nh := map[string]int{}, map[string]int{}
	for _, b := range boxes {
		if b.RevokedAt == nil {
			nb[b.SiteID]++
		}
	}
	for _, h := range hosts {
		nh[h.SiteID]++
	}
	var rows []tenantRow
	for _, t := range tenants {
		tr := tenantRow{Tenant: t}
		for _, st := range sites {
			if st.TenantID == t.ID {
				tr.Sites = append(tr.Sites, siteRow{Site: st, Boxes: nb[st.ID], Hosts: nh[st.ID]})
			}
		}
		rows = append(rows, tr)
	}
	s.render(w, r, "tenants", "Mandanten & Standorte", rows)
}

func (s *Server) tenantCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tid, err := id.FromSlug("ten", r.PostForm.Get("slug"))
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if err != nil || name == "" {
		s.flash(w, r, "Kürzel (a-z, 0-9, Bindestrich) und Name sind Pflicht.", "/tenants")
		return
	}
	if err := s.Store.CreateTenant(ctx, store.Tenant{ID: tid, Name: name, CreatedAt: s.Now()}); err != nil {
		s.flash(w, r, "Mandant nicht angelegt: "+err.Error(), "/tenants")
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "tenant.create", tid, name)
	s.flash(w, r, "Mandant "+tid+" angelegt.", "/tenants")
}

func (s *Server) siteCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := r.PathValue("id")
	if _, err := s.Store.Tenant(ctx, tenantID); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	sid, err := id.FromSlug("site", r.PostForm.Get("slug"))
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if err != nil || name == "" {
		s.flash(w, r, "Kürzel (a-z, 0-9, Bindestrich) und Name sind Pflicht.", "/tenants")
		return
	}
	if err := s.Engine.CreateSite(ctx, store.Site{ID: sid, TenantID: tenantID, Name: name, CreatedAt: s.Now()}, actor(r)); err != nil {
		s.flash(w, r, "Standort nicht angelegt: "+err.Error(), "/tenants")
		return
	}
	s.flash(w, r, "Standort "+sid+" angelegt.", "/tenants")
}

// ---- inventory ----------------------------------------------------------------------------

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (s *Server) deviceRedirect(w http.ResponseWriter, r *http.Request) {
	dev, err := s.Store.Device(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/sites/"+dev.SiteID+"?tab=netz", http.StatusFound)
}

func (s *Server) deviceMonitor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.Store.Device(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	back := "/sites/" + dev.SiteID + "?tab=netz"
	checks, err := checksFromForm(r)
	if err != nil {
		s.flash(w, r, err.Error(), back)
		return
	}
	boxID := strings.TrimSpace(r.PostForm.Get("box_id"))
	box, err := s.Store.Box(ctx, boxID)
	if err != nil || box.SiteID != dev.SiteID || box.RevokedAt != nil {
		s.flash(w, r, "Bitte eine Box dieses Standorts wählen.", back)
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		name = firstNonEmpty(dev.Hostname, dev.IP)
	}
	hostID := id.New("host")
	if slug := strings.TrimSpace(r.PostForm.Get("slug")); slug != "" {
		if hostID, err = id.FromSlug("host", slug); err != nil {
			s.flash(w, r, err.Error(), back)
			return
		}
	}
	h := store.Host{ID: hostID, TenantID: dev.TenantID, SiteID: dev.SiteID, BoxID: box.ID, DeviceID: dev.ID, Name: name, Address: dev.IP,
		MAC: dev.MAC, Vendor: dev.Vendor, IsUplink: r.PostForm.Get("is_uplink") == "1", Checks: checks, CreatedAt: s.Now()}
	if h.Address == "" {
		s.flash(w, r, "Gerät hat keine IP-Adresse; erst abwarten, bis eine gesehen wurde.", back)
		return
	}
	if err := s.Engine.CreateHost(ctx, h, actor(r)); err != nil {
		s.flash(w, r, "Nicht angelegt: "+err.Error(), back)
		return
	}
	s.flash(w, r, "Host wird überwacht.", "/hosts/"+h.ID)
}

func (s *Server) deviceIgnore(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.Store.Device(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	ignore := r.PostForm.Get("ignored") == "1"
	if err := s.Store.SetDeviceIgnored(ctx, dev.ID, ignore); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "device.ignore", dev.ID, strconv.FormatBool(ignore))
	http.Redirect(w, r, "/sites/"+dev.SiteID+"?tab=netz", http.StatusSeeOther)
}

// ---- maintenance -----------------------------------------------------------------------------

type windowRow struct {
	state.Maintenance
	TargetName string
}

type maintenanceData struct {
	Windows []windowRow
	Tenants []store.Tenant
	Sites   []store.Site
	Hosts   []store.Host
}

func (s *Server) maintenancePage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var d maintenanceData
	var err error
	if d.Tenants, err = s.Store.Tenants(ctx); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if d.Sites, err = s.Store.Sites(ctx, ""); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if d.Hosts, err = s.Store.Hosts(ctx, "", ""); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	names := map[string]string{}
	for _, t := range d.Tenants {
		names[t.ID] = t.Name
	}
	for _, st := range d.Sites {
		names[st.ID] = st.Name
	}
	for _, h := range d.Hosts {
		names[h.ID] = h.Name
	}
	for _, wnd := range s.Engine.Maintenances() {
		d.Windows = append(d.Windows, windowRow{Maintenance: wnd, TargetName: firstNonEmpty(names[wnd.TargetID], wnd.TargetID)})
	}
	s.render(w, r, "maintenance", "Wartung", d)
}

func (s *Server) maintenanceCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	scope, target := r.PostForm.Get("scope"), strings.TrimSpace(r.PostForm.Get("target_id"))
	until, err := formTime(r.PostForm.Get("until"), s.Loc)
	if err != nil {
		s.flash(w, r, err.Error(), "/maintenance")
		return
	}
	m := store.Maintenance{Scope: scope, TargetID: target, Until: until, Reason: strings.TrimSpace(r.PostForm.Get("reason"))}
	switch scope {
	case "tenant":
		if _, err := s.Store.Tenant(ctx, target); err != nil {
			s.flash(w, r, "Mandant nicht gefunden.", "/maintenance")
			return
		}
		m.TenantID = target
	case "site":
		site, err := s.Store.Site(ctx, target)
		if err != nil {
			s.flash(w, r, "Standort nicht gefunden.", "/maintenance")
			return
		}
		m.TenantID, m.SiteID = site.TenantID, site.ID
	case "host":
		h, err := s.Store.Host(ctx, target)
		if err != nil {
			s.flash(w, r, "Host nicht gefunden.", "/maintenance")
			return
		}
		m.TenantID, m.SiteID = h.TenantID, h.SiteID
	default:
		s.flash(w, r, "Bereich muss Mandant, Standort oder Host sein.", "/maintenance")
		return
	}
	if err := s.Engine.StartMaintenance(ctx, m, actor(r)); err != nil {
		s.flash(w, r, "Wartung nicht gesetzt: "+err.Error(), "/maintenance")
		return
	}
	s.flash(w, r, "Wartung gesetzt.", "/maintenance")
}

func (s *Server) maintenanceEnd(w http.ResponseWriter, r *http.Request) {
	if err := s.Engine.EndMaintenance(r.Context(), r.PathValue("id"), actor(r)); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	s.flash(w, r, "Wartung beendet.", "/maintenance")
}

// ---- webhooks -----------------------------------------------------------------------------------

type failedRow struct {
	store.Delivery
	TargetName string
}

type webhooksData struct {
	Targets   []store.WebhookTarget
	Failed    []failedRow
	Tenants   []store.Tenant
	NewSecret string
	NewTarget *store.WebhookTarget
}

func (s *Server) webhooksData(ctx context.Context) (webhooksData, error) {
	var d webhooksData
	var err error
	if d.Targets, err = s.Store.WebhookTargets(ctx); err != nil {
		return d, err
	}
	if d.Tenants, err = s.Store.Tenants(ctx); err != nil {
		return d, err
	}
	names := map[string]string{}
	for _, t := range d.Targets {
		names[t.ID] = t.Name
	}
	for _, t := range d.Tenants {
		failed, err := s.Store.DeliveriesByState(ctx, t.ID, store.DeliveryFailed, 7, s.Now())
		if err != nil {
			return d, err
		}
		for _, f := range failed {
			d.Failed = append(d.Failed, failedRow{Delivery: f, TargetName: firstNonEmpty(names[f.TargetID], f.TargetID)})
			if len(d.Failed) >= 50 {
				break
			}
		}
	}
	return d, nil
}

func (s *Server) webhooksPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.webhooksData(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	s.render(w, r, "webhooks", "Webhook-Ziele", d)
}

func validTargetForm(r *http.Request) (string, string, string, error) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	u := strings.TrimSpace(r.PostForm.Get("url"))
	scope := strings.TrimSpace(r.PostForm.Get("tenant_scope"))
	if scope == "" {
		scope = "*"
	}
	if name == "" || (!strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://")) {
		return "", "", "", errors.New("Name und URL (http:// oder https://) sind Pflicht")
	}
	return name, u, scope, nil
}

func (s *Server) webhookCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, u, scope, err := validTargetForm(r)
	if err != nil {
		s.flash(w, r, err.Error(), "/webhooks")
		return
	}
	t := store.WebhookTarget{ID: id.New("tgt"), Name: name, URL: u, Secret: id.Secret(32), TenantScope: scope, Enabled: true, CreatedAt: s.Now()}
	if err := s.Store.CreateWebhookTarget(ctx, t); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "webhook.create", t.ID, name+" "+u)
	d, err := s.webhooksData(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	d.NewSecret, d.NewTarget = t.Secret, &t
	s.render(w, r, "webhooks", "Webhook-Ziele", d)
}

func (s *Server) webhookUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := s.Store.WebhookTarget(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	name, u, scope, err := validTargetForm(r)
	if err != nil {
		s.flash(w, r, err.Error(), "/webhooks")
		return
	}
	t.Name, t.URL, t.TenantScope, t.Enabled, t.Secret = name, u, scope, r.PostForm.Get("enabled") == "1", ""
	rotated := ""
	if r.PostForm.Get("rotate_secret") == "1" {
		rotated = id.Secret(32)
		t.Secret = rotated
	}
	if err := s.Store.UpdateWebhookTarget(ctx, t); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "webhook.update", t.ID, fmt.Sprintf("%s %s enabled=%v rotated=%v", name, u, t.Enabled, rotated != ""))
	if rotated == "" {
		s.flash(w, r, "Ziel gespeichert.", "/webhooks")
		return
	}
	d, err := s.webhooksData(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	d.NewSecret, d.NewTarget = rotated, &t
	s.render(w, r, "webhooks", "Webhook-Ziele", d)
}

func (s *Server) webhookDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tid := r.PathValue("id")
	if err := s.Store.DeleteWebhookTarget(ctx, tid); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "webhook.delete", tid, "")
	s.flash(w, r, "Ziel gelöscht.", "/webhooks")
}

func (s *Server) webhookTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, err := s.Store.WebhookTarget(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	tenantID := strings.TrimSpace(r.PostForm.Get("tenant_id"))
	if tenantID == "" && t.TenantScope != "*" {
		tenantID = t.TenantScope
	}
	if tenantID == "" {
		s.flash(w, r, "Für den Test einen Mandanten wählen.", "/webhooks")
		return
	}
	ev, err := s.Engine.TestPing(ctx, tenantID, t.ID, actor(r))
	if err != nil {
		s.flash(w, r, "Test nicht ausgelöst: "+err.Error(), "/webhooks")
		return
	}
	s.flash(w, r, "test.ping "+ev.ID+" eingereiht — Zustellstatus erscheint unten, falls sie fehlschlägt.", "/webhooks")
}

// ---- enrollment keys and API tokens ---------------------------------------------------------------

type keysData struct {
	Keys   []store.EnrollmentKey
	New    []string
	Ingest string
}

func (s *Server) keysPage(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Store.EnrollmentKeys(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	s.render(w, r, "keys", "Enrollment-Keys", keysData{Keys: keys, Ingest: fmt.Sprintf("%s:%d", s.Ingest, s.IngestPt)})
}

func (s *Server) keysCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	count, _ := strconv.Atoi(r.PostForm.Get("count"))
	days, _ := strconv.Atoi(r.PostForm.Get("days"))
	if count < 1 || count > 100 {
		count = 1
	}
	if days < 1 || days > 365 {
		days = 30
	}
	note := strings.TrimSpace(r.PostForm.Get("note"))
	now := s.Now()
	var created []string
	for i := 0; i < count; i++ {
		k, err := pki.NewEnrollmentKey(s.Ingest, s.IngestPt, s.CA.Fingerprint())
		if err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		rec := store.EnrollmentKey{ID: id.New("key"), SecretHash: k.SecretHash(), Note: note, CreatedAt: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour)}
		if err := s.Store.CreateEnrollmentKey(ctx, rec); err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		_ = s.Store.Audit(ctx, now, actor(r), "key.new", rec.ID, note)
		created = append(created, rec.ID+"  "+k.String())
	}
	keys, err := s.Store.EnrollmentKeys(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	s.render(w, r, "keys", "Enrollment-Keys", keysData{Keys: keys, New: created, Ingest: fmt.Sprintf("%s:%d", s.Ingest, s.IngestPt)})
}

func (s *Server) keyRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.Store.RevokeEnrollmentKey(ctx, r.PathValue("id"), s.Now()); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "key.revoke", r.PathValue("id"), "")
	s.flash(w, r, "Key widerrufen.", "/keys")
}

type tokensData struct {
	Tokens   []store.APIToken
	Tenants  []store.Tenant
	NewToken string
	NewName  string
}

func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.tokensData(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	s.render(w, r, "tokens", "API-Tokens", d)
}

func (s *Server) tokensData(ctx context.Context) (tokensData, error) {
	var d tokensData
	var err error
	if d.Tokens, err = s.Store.APITokens(ctx); err != nil {
		return d, err
	}
	d.Tenants, err = s.Store.Tenants(ctx)
	return d, err
}

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		s.flash(w, r, "Name ist Pflicht.", "/tokens")
		return
	}
	tenants := r.PostForm["tenants"]
	if len(tenants) == 0 {
		tenants = []string{"*"}
	}
	raw := "ex0_" + id.Secret(32)
	t := store.APIToken{ID: id.New("tok"), Name: name, TokenHash: api.HashToken(raw), Tenants: tenants, CreatedAt: s.Now()}
	if err := s.Store.CreateAPIToken(ctx, t); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "token.new", t.ID, name+" "+strings.Join(tenants, ","))
	d, err := s.tokensData(ctx)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	d.NewToken, d.NewName = raw, name
	s.render(w, r, "tokens", "API-Tokens", d)
}

func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.Store.RevokeAPIToken(ctx, r.PathValue("id"), s.Now()); err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "token.revoke", r.PathValue("id"), "")
	s.flash(w, r, "Token widerrufen.", "/tokens")
}

// ---- audit ------------------------------------------------------------------------------------------

type auditData struct {
	Entries []store.AuditEntry
	Next    int64
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := s.Store.AuditEntries(r.Context(), 100, before)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	d := auditData{Entries: entries}
	if len(entries) == 100 {
		d.Next = entries[len(entries)-1].ID
	}
	s.render(w, r, "audit", "Audit-Log", d)
}
