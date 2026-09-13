package console

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/state"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// ---- layout chrome -------------------------------------------------------------------

// crumb is one breadcrumb in the top bar; the last one has no Href.
type crumb struct{ Label, Href string }

type pageOpts struct {
	Crumbs []crumb
	Search bool // show the device search in the top bar
}

// navCounts are the small numbers next to the sidebar entries.
type navCounts struct {
	Tenants    int
	Sites      int
	Boxes      int
	Unassigned int
	Attention  int // hosts down + assigned boxes silent: what needs a person now
	Findings   int // open findings of the rules
}

func (s *Server) navCounts(ctx context.Context) navCounts {
	var n navCounts
	acks, _ := s.Store.Acks(ctx)
	if ts, err := s.Store.Tenants(ctx); err == nil {
		n.Tenants = len(ts)
	}
	if ss, err := s.Store.Sites(ctx, ""); err == nil {
		n.Sites = len(ss)
	}
	if bs, err := s.Store.Boxes(ctx, ""); err == nil {
		for _, b := range bs {
			if b.RevokedAt != nil {
				continue
			}
			n.Boxes++
			if b.SiteID == "" {
				n.Unassigned++
			} else if st, ok := s.Engine.BoxState(b.ID); ok && st.Status == state.Silent {
				since := st.SilentSince
				if since.IsZero() {
					since = st.LastHeartbeat
				}
				if ackFor(acks, "box_silent", b.ID, since) == nil {
					n.Attention++
				}
			}
		}
	}
	if vs, err := s.Engine.HostViews(ctx, ""); err == nil {
		for _, v := range vs {
			if c, _ := classify(v); c == "down" && ackFor(acks, "host_down", v.ID, v.State.Since) == nil {
				n.Attention++
			}
		}
	}
	if counts, err := s.Store.FindingCounts(ctx); err == nil {
		for _, c := range counts {
			n.Findings += c
		}
	}
	return n
}

// ---- device kinds --------------------------------------------------------------------

// devKind groups inventory devices by what they are, from the OUI vendor and the name
// the device announces. Key doubles as the icon id in static/icons.svg.
type devKind struct{ Key, Label string }

var devKinds = []devKind{
	{"fw", "Firewall"}, {"rt", "Netzwerk"}, {"srv", "Server"}, {"vm", "VM"}, {"tel", "Telefonie"},
	{"prn", "Drucker"}, {"lap", "Client"}, {"mob", "Mobil"}, {"box", "EX0-Box"}, {"wan", "Internet-Adresse"}, {"q", "Unbekannt"},
}

func kindLabel(key string) string {
	for _, k := range devKinds {
		if k.Key == key {
			return k.Label
		}
	}
	return "Unbekannt"
}

var vendorKinds = []struct{ match, kind string }{
	{"fortinet", "fw"}, {"sophos", "fw"}, {"watchguard", "fw"}, {"palo alto", "fw"}, {"sonicwall", "fw"}, {"securepoint", "fw"},
	{"avm", "rt"}, {"fritz", "rt"}, {"tp-link", "rt"}, {"netgear", "rt"}, {"ubiquiti", "rt"}, {"mikrotik", "rt"}, {"lancom", "rt"},
	{"zyxel", "rt"}, {"draytek", "rt"}, {"aruba", "rt"}, {"cisco", "rt"}, {"juniper", "rt"}, {"d-link", "rt"}, {"telekom", "rt"},
	{"proxmox", "vm"}, {"vmware", "vm"}, {"qemu", "vm"}, {"xensource", "vm"}, {"parallels", "vm"}, {"nutanix", "vm"},
	{"hewlett packard enterprise", "srv"}, {"supermicro", "srv"}, {"synology", "srv"}, {"qnap", "srv"}, {"fujitsu", "srv"}, {"thomas-krenn", "srv"},
	{"innovaphone", "tel"}, {"snom", "tel"}, {"yealink", "tel"}, {"gigaset", "tel"}, {"grandstream", "tel"}, {"polycom", "tel"},
	{"avaya", "tel"}, {"mitel", "tel"}, {"auerswald", "tel"}, {"starface", "tel"}, {"unify", "tel"},
	{"brother", "prn"}, {"canon", "prn"}, {"epson", "prn"}, {"kyocera", "prn"}, {"zebra", "prn"}, {"evolis", "prn"}, {"lexmark", "prn"},
	{"ricoh", "prn"}, {"konica", "prn"}, {"xerox", "prn"}, {"oki ", "prn"}, {"sharp", "prn"}, {"toshiba tec", "prn"}, {"utax", "prn"}, {"develop", "prn"},
	{"xiaomi", "mob"}, {"samsung", "mob"}, {"huawei", "mob"}, {"oneplus", "mob"}, {"oppo", "mob"}, {"vivo", "mob"}, {"realme", "mob"}, {"honor", "mob"}, {"fairphone", "mob"},
	{"lcfc", "lap"}, {"lenovo", "lap"}, {"hp inc", "lap"}, {"dell", "lap"}, {"apple", "lap"}, {"intel corporate", "lap"}, {"asus", "lap"}, {"acer", "lap"},
	{"micro-star", "lap"}, {"framework", "lap"}, {"azurewave", "lap"}, {"liteon", "lap"}, {"realtek", "lap"}, {"microsoft", "lap"}, {"wistron", "lap"}, {"compal", "lap"}, {"quanta", "lap"},
}

// classifyDevice picks a kind. boxNames are the site's box names/ids, lowercased.
func classifyDevice(vendor, hostname string, boxNames map[string]bool) string {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(hostname, ".local"), ".lan"))
	if h != "" && boxNames[h] {
		return "box"
	}
	v := strings.ToLower(vendor)
	for _, m := range vendorKinds {
		if strings.Contains(v, m.match) {
			return m.kind
		}
	}
	switch {
	case strings.Contains(h, "print") || strings.HasPrefix(h, "npi") || strings.HasPrefix(h, "brn"):
		return "prn"
	case strings.Contains(h, "phone") || strings.Contains(h, "ip2") || strings.Contains(h, "sip"):
		return "tel"
	case strings.Contains(h, "srv") || strings.Contains(h, "server") || strings.Contains(h, "-dc") || strings.Contains(h, "nas"):
		return "srv"
	}
	return "q"
}

var vendorNames = map[string]string{"lcfc": "Lenovo", "hewlett packard enterprise": "HPE", "hp inc": "HP", "proxmox": "Proxmox VM", "avm": "AVM", "xiaomi": "Xiaomi", "innovaphone": "innovaphone", "canon": "Canon", "evolis": "Evolis", "zebra": "Zebra", "brother": "Brother", "fortinet": "Fortinet"}
var vendorStop = map[string]bool{"inc": true, "inc.": true, "gmbh": true, "ltd": true, "ltd.": true, "ag": true, "co": true, "co.": true, "corp": true, "corp.": true, "corporation": true,
	"communications": true, "industries": true, "technologies": true, "technology": true, "electronics": true, "server": true, "solutions": true, "audiovisuelles": true, "limited": true, "llc": true}

// vendorShort turns an OUI registrant like "Brother Industries, LTD." into "Brother".
func vendorShort(v string) string {
	l := strings.ToLower(strings.TrimSpace(v))
	for k, n := range vendorNames {
		if strings.HasPrefix(l, k) {
			return n
		}
	}
	var out []string
	for _, w := range strings.Fields(strings.NewReplacer(",", " ", "(", " ", ")", " ").Replace(v)) {
		if vendorStop[strings.ToLower(w)] {
			break
		}
		out = append(out, w)
		if len(out) == 2 {
			break
		}
	}
	name := strings.Join(out, " ")
	if name != "" && name == strings.ToUpper(name) && len(name) > 3 { // "INNOVAPHONE AG" → "Innovaphone"
		name = strings.ToUpper(name[:1]) + strings.ToLower(name[1:])
	}
	return name
}

// deviceName is what a device is called before a person names it: what it announces,
// else its maker, else its address.
func deviceName(dev store.Device) string {
	if dev.External {
		return "Internet-Adresse " + dev.IP
	}
	return firstNonEmpty(cleanHostname(dev.Hostname), vendorShort(dev.Vendor), dev.IP, "nur IPv6")
}

// cleanHostname turns "MUSTER-RDS.local" into "MUSTER-RDS".
func cleanHostname(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(h, ".local")
	return strings.TrimSuffix(h, ".lan")
}

// ---- site page --------------------------------------------------------------------------

type deviceCard struct {
	store.Device
	Kind       string
	KindLabel  string
	Name       string // what the card is called: announced name, else the address
	Monitored  bool
	HostID     string
	IsUplink   bool
	StateClass string
	StateLabel string
	IsBox      bool
	Text       string // lowercase haystack for the client-side filter
	// Ports the scan found open, so the console can offer the right way in
	// (https, ssh, rdp …) instead of making an operator copy an address.
	Ports []int
}

type kindCount struct {
	Key, Label string
	N          int
}

type hostCard struct {
	hostRow
	UplinkName string
	Avail      availability
}

type siteData struct {
	Site   store.Site
	Tenant store.Tenant
	Boxes  []boxRow
	Box    *boxRow // the site's box, when there is exactly one that matters
	Online bool

	Devices []deviceCard
	Kinds   []kindCount
	Ignored int

	Hosts                               []hostCard
	Up, Down, Unknown, Maint, Monitored int

	Events []recentEvent
	Red    int
	Tab    string
	Chart  chartData

	// Box & Technik
	Sites       []store.Site
	TenantNames map[string]string
	Fingerprint string
	Netbird     *store.NetbirdKey
	Subnets     string
}

func (s *Server) buildSite(ctx context.Context, siteID, tab, rng string) (siteData, error) {
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return siteData{}, err
	}
	d := siteData{Site: site, TenantNames: map[string]string{}, Fingerprint: s.CA.Fingerprint()}
	d.Tenant, _ = s.Store.Tenant(ctx, site.TenantID)
	tm, sm, err := s.lookups(ctx)
	if err != nil {
		return siteData{}, err
	}
	for _, t := range tm {
		d.TenantNames[t.ID] = t.Name
	}
	boxes, err := s.Store.Boxes(ctx, site.ID)
	if err != nil {
		return siteData{}, err
	}
	boxNames := map[string]bool{}
	for _, b := range boxes {
		if b.RevokedAt != nil {
			continue
		}
		row := s.boxRow(b, sm, tm)
		d.Boxes = append(d.Boxes, row)
		boxNames[strings.ToLower(b.ID)] = true
		if b.Name != "" {
			boxNames[strings.ToLower(b.Name)] = true
		}
	}
	if len(d.Boxes) > 0 {
		d.Box = &d.Boxes[0]
		d.Online = d.Box.State.Status != state.Silent && !d.Box.State.LastHeartbeat.IsZero()
		d.Subnets = strings.Join(d.Box.DiscoverySubnets, "\n")
		if nk, err := s.Store.NetbirdKey(ctx, d.Box.ID); err == nil {
			d.Netbird = &nk
		}
	}
	if d.Sites, err = s.Store.Sites(ctx, ""); err != nil {
		return siteData{}, err
	}

	views, err := s.Engine.HostViews(ctx, site.TenantID)
	if err != nil {
		return siteData{}, err
	}
	byHostID := map[string]hostRow{}
	names := map[string]string{}
	byDevice, byMAC, byIP := map[string]string{}, map[string]string{}, map[string]string{}
	for _, v := range views {
		if v.SiteID != site.ID {
			continue
		}
		row := s.hostRow(v)
		byHostID[v.ID] = row
		names[v.ID] = v.Name
		if v.DeviceID != "" {
			byDevice[v.DeviceID] = v.ID
		}
		if v.MAC != "" {
			byMAC[strings.ToLower(v.MAC)] = v.ID
		}
		byIP[v.Address] = v.ID
		switch row.StateClass {
		case "up":
			d.Up++
		case "down":
			d.Down++
		case "maint":
			d.Maint++
		default:
			d.Unknown++
		}
		d.Monitored++
	}
	now := s.Now()
	for _, v := range views {
		if v.SiteID != site.ID {
			continue
		}
		hc := hostCard{hostRow: byHostID[v.ID]}
		if v.ParentID != "" {
			hc.UplinkName = names[v.ParentID]
		}
		if hc.Avail, err = s.availability(ctx, v.TenantID, v.ID, now); err != nil {
			return siteData{}, err
		}
		d.Hosts = append(d.Hosts, hc)
	}
	sort.SliceStable(d.Hosts, func(i, j int) bool { // down first, then uplinks, then by name
		a, b := d.Hosts[i], d.Hosts[j]
		if (a.StateClass == "down") != (b.StateClass == "down") {
			return a.StateClass == "down"
		}
		if a.IsUplink != b.IsUplink {
			return a.IsUplink
		}
		return a.Name < b.Name
	})

	devices, err := s.Store.Devices(ctx, site.TenantID, site.ID, time.Time{})
	if err != nil {
		return siteData{}, err
	}
	// What the scan found open, per device: the console turns it into a link.
	ports := map[string][]int{}
	if svcs, err := s.Store.OpenServicesForSite(ctx, site.ID); err == nil {
		for _, sv := range svcs {
			if sv.Proto == "" || sv.Proto == "tcp" {
				ports[sv.DeviceID] = append(ports[sv.DeviceID], sv.Port)
			}
		}
	}
	counts := map[string]int{}
	for _, dev := range devices {
		c := deviceCard{Device: dev, Ports: ports[dev.ID]}
		c.Kind = classifyDevice(dev.Vendor, dev.Hostname, boxNames)
		if dev.External {
			c.Kind = "wan"
		}
		c.KindLabel = kindLabel(c.Kind)
		c.IsBox = c.Kind == "box"
		c.Name = deviceName(dev)
		if hid := firstNonEmpty(byDevice[dev.ID], byMAC[strings.ToLower(dev.MAC)], byIP[dev.IP]); hid != "" {
			if row, ok := byHostID[hid]; ok {
				c.Monitored, c.HostID, c.IsUplink = true, hid, row.IsUplink
				c.StateClass, c.StateLabel = row.StateClass, row.StateLabel
				c.Name = row.Name
			}
		}
		if dev.Ignored {
			d.Ignored++
		}
		c.Text = strings.ToLower(strings.Join([]string{c.Name, dev.Hostname, dev.IP, dev.MAC, dev.Vendor, c.KindLabel}, " "))
		counts[c.Kind]++
		d.Devices = append(d.Devices, c)
	}
	sort.SliceStable(d.Devices, func(i, j int) bool { // monitored first, then by kind order, then by address
		a, b := d.Devices[i], d.Devices[j]
		if a.Ignored != b.Ignored {
			return !a.Ignored
		}
		if a.Monitored != b.Monitored {
			return a.Monitored
		}
		if ka, kb := kindIndex(a.Kind), kindIndex(b.Kind); ka != kb {
			return ka < kb
		}
		return ipLess(a.IP, b.IP)
	})
	for _, k := range devKinds {
		if counts[k.Key] > 0 {
			d.Kinds = append(d.Kinds, kindCount{Key: k.Key, Label: k.Label, N: counts[k.Key]})
		}
	}

	evs, err := s.Store.Events(ctx, site.TenantID, now.Add(-24*time.Hour), now.Add(time.Minute), "", 300)
	if err != nil {
		return siteData{}, err
	}
	for i := len(evs) - 1; i >= 0; i-- {
		ev := evs[i]
		if ev.SiteID != "" && ev.SiteID != site.ID {
			continue
		}
		re := recentEvent{Event: ev, TenantName: d.Tenant.Name, SiteName: site.Name, Class: eventClass(ev), Title: eventTitle(ev), Info: eventInfo(ev)}
		if re.Class == "down" {
			d.Red++
		}
		d.Events = append(d.Events, re)
	}
	sort.SliceStable(d.Events, func(i, j int) bool { return d.Events[i].OccurredAt.After(d.Events[j].OccurredAt) })

	if d.Chart, err = s.buildChart(ctx, []string{site.TenantID}, "", rng, now); err != nil {
		return siteData{}, err
	}
	d.Tab = tab
	switch d.Tab {
	case "ueberwachung", "ereignisse", "technik":
	default:
		d.Tab = "netz"
	}
	return d, nil
}

func kindIndex(key string) int {
	for i, k := range devKinds {
		if k.Key == key {
			return i
		}
	}
	return len(devKinds)
}

// ipLess orders dotted IPv4 numerically; anything else sorts after and by string.
func ipLess(a, b string) bool {
	pa, pb := ipParts(a), ipParts(b)
	switch {
	case pa == nil && pb == nil:
		return a < b
	case pa == nil:
		return false
	case pb == nil:
		return true
	}
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

func ipParts(s string) []int {
	f := strings.Split(s, ".")
	if len(f) != 4 {
		return nil
	}
	out := make([]int, 4)
	for i, p := range f {
		n := 0
		if p == "" {
			return nil
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}

// deviceWatch is the one-click "beobachten": ICMP every minute from the site's box.
func (s *Server) deviceWatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	dev, err := s.Store.Device(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	back := "/sites/" + dev.SiteID + "?tab=netz"
	if dev.IP == "" {
		s.flashErr(w, r, "Das Gerät hat noch keine IPv4-Adresse gezeigt; ohne Adresse kann die Box es nicht prüfen.", back)
		return
	}
	boxes, err := s.Store.Boxes(ctx, dev.SiteID)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	var box *store.Box
	for i := range boxes {
		if boxes[i].RevokedAt == nil {
			box = &boxes[i]
			break
		}
	}
	if box == nil {
		s.flashErr(w, r, "Diesem Standort ist keine Box zugeordnet; erst eine Box zuordnen.", back)
		return
	}
	name := deviceName(dev)
	h := store.Host{ID: id.New("host"), TenantID: dev.TenantID, SiteID: dev.SiteID, BoxID: box.ID, DeviceID: dev.ID, Name: name, Address: dev.IP,
		MAC: dev.MAC, Vendor: dev.Vendor, IsUplink: r.PostForm.Get("uplink") == "1", Checks: []wire.CheckConfig{{Type: wire.CheckICMP}}, CreatedAt: s.Now()}
	if err := s.Engine.CreateHost(ctx, h, actor(r)); err != nil {
		s.flashErr(w, r, "Nicht eingeschaltet: "+err.Error(), back)
		return
	}
	s.flash(w, r, name+" wird jetzt jede Minute geprüft.", back)
}

// hostUnwatch ends monitoring from the device card; the device stays in the inventory.
func (s *Server) hostUnwatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.Engine.HostView(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	back := "/sites/" + v.SiteID + "?tab=netz"
	if err := s.Engine.DeleteHost(ctx, v.ID, actor(r)); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	s.flash(w, r, v.Name+" wird nicht mehr beobachtet.", back)
}

// hostUplink toggles the uplink flag from the device card.
func (s *Server) hostUplink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := s.Store.Host(ctx, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, http.StatusNotFound)
		return
	}
	h.IsUplink = !h.IsUplink
	if err := s.Engine.UpdateHost(ctx, h, actor(r)); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	msg := h.Name + " ist jetzt der Uplink: fällt er aus, wird nur er gemeldet."
	if !h.IsUplink {
		msg = h.Name + " ist kein Uplink mehr."
	}
	s.flash(w, r, msg, backTo(r, "/sites/"+h.SiteID+"?tab=ueberwachung"))
}

func backTo(r *http.Request, def string) string {
	if b := r.PostForm.Get("back"); strings.HasPrefix(b, "/") && !strings.HasPrefix(b, "//") {
		return b
	}
	return def
}

// ---- events page ----------------------------------------------------------------------

// ---- users page ---------------------------------------------------------------------------

// ---- status (Übersicht) cards ---------------------------------------------------------

type siteCard struct {
	Site      store.Site
	Tenant    store.Tenant
	Box       *boxRow
	HasBox    bool
	Online    bool
	Monitored int
	Up        int
	Down      int
	Devices   int
	Class     string // ok | bad | (empty for no box)
	Last      *recentEvent
	Hosts     []hostRow // down first, then uplinks, then by name
}

// siteCards derives the Übersicht cards from an already built statusData.
func (s *Server) siteCards(ctx context.Context, d *statusData) error {
	for ti := range d.Tenants {
		tb := d.Tenants[ti]
		for _, sb := range tb.Sites {
			c := siteCard{Site: sb.Site, Tenant: tb.Tenant}
			d.SitesTotal++
			if len(sb.Boxes) > 0 {
				b := sb.Boxes[0]
				c.Box, c.HasBox = &b, true
				c.Online = b.State.Status != state.Silent && !b.State.LastHeartbeat.IsZero()
			}
			c.Hosts = append(c.Hosts, sb.Hosts...)
			sort.SliceStable(c.Hosts, func(i, j int) bool {
				a, b := c.Hosts[i], c.Hosts[j]
				if (a.StateClass == "down") != (b.StateClass == "down") {
					return a.StateClass == "down"
				}
				if a.IsUplink != b.IsUplink {
					return a.IsUplink
				}
				return a.Name < b.Name
			})
			for _, h := range sb.Hosts {
				c.Monitored++
				switch h.StateClass {
				case "up":
					c.Up++
				case "down":
					c.Down++
				}
			}
			devs, err := s.Store.Devices(ctx, sb.Site.TenantID, sb.Site.ID, time.Time{})
			if err != nil {
				return err
			}
			for _, dev := range devs {
				if !dev.Ignored {
					c.Devices++
				}
			}
			d.Devices += c.Devices
			if c.HasBox {
				d.SitesWithBox++
				if c.Online {
					d.SitesOnline++
				}
			}
			switch {
			case !c.HasBox:
				c.Class = ""
			case c.Down > 0 || !c.Online:
				c.Class = "bad"
			default:
				c.Class = "ok"
			}
			for i := range d.Recent {
				if d.Recent[i].SiteID == sb.Site.ID {
					c.Last = &d.Recent[i]
					break
				}
			}
			d.Cards = append(d.Cards, c)
		}
	}
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		return err
	}
	for _, b := range boxes {
		if b.RevokedAt == nil && b.SiteID == "" {
			d.Unassigned = append(d.Unassigned, s.boxRow(b, nil, nil))
		}
	}
	return nil
}
