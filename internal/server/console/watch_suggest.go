package console

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/server/watch"
	"github.com/excubra/excubra/internal/wire"
)

// Switching a site on, device by device, is the kind of work nobody finishes:
// a site with fifty devices has fifty switches and an operator flips the obvious
// ones and forgets the rest. So the console can propose the set instead, and the
// rule lives here rather than in the browser — the same answer for the API, a
// future CLI, and anyone reading why a device is watched.
//
// What earns a check: something that stays put, keeps its address, and is missed
// when it is gone. Firewalls, network gear, servers, virtual machines, telephony
// and printers qualify. Laptops, phones and anything unidentified do not — they
// come and go by design, and a check on them produces an outage every evening
// at five.
var worthWatching = map[string]bool{
	"fw": true, "rt": true, "srv": true, "vm": true, "tel": true, "prn": true,
}

// suggestedForWatch is the set the rule picks from a site's devices, together
// with the reason a device was left out — the console shows both, because a
// proposal an operator cannot check is just a different kind of guessing.
type suggestedForWatch struct {
	Add     []deviceCard
	Skipped map[string]int // reason → count
}

func suggestWatch(devices []deviceCard) suggestedForWatch {
	out := suggestedForWatch{Skipped: map[string]int{}}
	for _, c := range devices {
		switch {
		case c.Monitored:
			out.Skipped["schon beobachtet"]++
		case c.IsBox:
			out.Skipped["die Box selbst"]++
		case c.Ignored:
			out.Skipped["ausgeblendet"]++
		case c.IP == "":
			out.Skipped["keine IPv4-Adresse"]++
		case !stableAddress(c.IP):
			out.Skipped["Adresse nicht dauerhaft"]++
		case c.GoneAt != nil:
			out.Skipped["länger nicht gesehen"]++
		case !worthWatching[c.Kind]:
			out.Skipped[kindLabel(c.Kind)+": kommt und geht"]++
		default:
			out.Add = append(out.Add, c)
		}
	}
	return out
}

// isUplinkKind marks what other hosts can sit behind: a firewall, a router. The
// mark alone suppresses nothing. The state machine suppresses a host while the
// host it sits behind is down (ParentID), and which host sits behind which is
// something a person knows — a branch behind a tunnel, a hall behind a bridge.
// A cut line needs none of it: the box falls silent, and that is one event.
func isUplinkKind(kind string) bool { return kind == "fw" || kind == "rt" }

// stableAddress rejects what will not still be the same host tomorrow: link-local
// addresses a device gave itself when DHCP failed, and loopback.
func stableAddress(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return false
	}
	return !a.IsLinkLocalUnicast() && !a.IsLoopback() && !a.IsUnspecified() && !a.IsMulticast()
}

// WatchProposal answers what the rule would switch on at a site, what it leaves
// out and why, and what is watched already — for the console's button and for a
// session that sets a site up (ADR-0024).
func (s *Server) WatchProposal(ctx context.Context, siteID string) (watch.Proposal, error) {
	d, err := s.buildSite(ctx, siteID, "netz", "24h")
	if err != nil {
		return watch.Proposal{}, err
	}
	sug := suggestWatch(d.Devices)
	checks, behind := map[string][]string{}, map[string]string{}
	for _, h := range d.Hosts {
		for _, c := range h.Host.Checks {
			checks[h.ID] = append(checks[h.ID], c.Label())
		}
		behind[h.ID] = h.UplinkName
	}
	out := watch.Proposal{HasBox: d.Box != nil, Add: []watch.Device{}, Skipped: sug.Skipped, Watched: []watch.Device{}}
	for _, c := range sug.Add {
		out.Add = append(out.Add, watch.Device{DeviceID: c.ID, Name: c.Name, IP: c.IP, Kind: c.KindLabel, Uplink: isUplinkKind(c.Kind)})
	}
	for _, c := range d.Devices {
		if c.Monitored {
			out.Watched = append(out.Watched, watch.Device{DeviceID: c.ID, Name: c.Name, IP: c.IP, Kind: c.KindLabel, Uplink: c.IsUplink, Behind: behind[c.HostID], HostID: c.HostID, Checks: checks[c.HostID], State: c.StateLabel})
		}
	}
	return out, nil
}

// WatchSuggested switches monitoring on for everything the rule picks.
func (s *Server) WatchSuggested(ctx context.Context, siteID, actor string) (watch.Outcome, error) {
	d, err := s.buildSite(ctx, siteID, "netz", "24h")
	if err != nil {
		return watch.Outcome{}, err
	}
	box, err := s.activeBox(ctx, siteID)
	if err != nil {
		return watch.Outcome{}, errNoBox
	}
	sug := suggestWatch(d.Devices)
	out := watch.Outcome{Added: []string{}, Skipped: sug.Skipped}
	for _, c := range sug.Add {
		h := store.Host{
			ID: id.New("host"), TenantID: c.TenantID, SiteID: c.SiteID, BoxID: box.ID, DeviceID: c.ID,
			Name: c.Name, Address: c.IP, MAC: c.MAC, Vendor: c.Vendor,
			IsUplink: isUplinkKind(c.Kind),
			Checks:   []wire.CheckConfig{{Type: wire.CheckICMP}}, CreatedAt: s.Now(),
		}
		if err := s.Engine.CreateHost(ctx, h, actor); err != nil {
			out.Failed = append(out.Failed, c.Name+": "+err.Error())
			s.Log.Warn("suggested watch", "device", c.ID, "err", err)
			continue
		}
		out.Added = append(out.Added, c.Name)
	}
	if len(sug.Add) > 0 {
		_ = s.Store.Audit(ctx, s.Now(), actor, "site.watch.suggested", siteID, fmt.Sprintf("%d aufgenommen, %d fehlgeschlagen", len(out.Added), len(out.Failed)))
	}
	return out, nil
}

// errNoBox: a site without a box has nobody to do the checking.
var errNoBox = errors.New("diesem Standort ist keine Box zugeordnet")

// WatchDevices switches monitoring on for the devices named, with the checks
// named — and for a device that is watched already, changes its checks, its
// uplink mark or the device it sits behind. It is the console's device card and
// host form in one call, for a session that knows which devices matter and how
// to ask them.
func (s *Server) WatchDevices(ctx context.Context, siteID, actor string, picks []watch.Pick) (watch.Outcome, error) {
	d, err := s.buildSite(ctx, siteID, "netz", "24h")
	if err != nil {
		return watch.Outcome{}, err
	}
	box, err := s.activeBox(ctx, siteID)
	if err != nil {
		return watch.Outcome{}, errNoBox
	}
	cards := map[string]deviceCard{}
	for _, c := range d.Devices {
		cards[c.ID] = c
	}
	out := watch.Outcome{Added: []string{}}
	// hostOf: the host a device is watched as — also one this very call made
	hostOf := map[string]string{}
	for _, c := range d.Devices {
		if c.Monitored {
			hostOf[c.ID] = c.HostID
		}
	}
	for _, p := range picks {
		c, ok := cards[p.DeviceID]
		switch {
		case !ok:
			out.Failed = append(out.Failed, p.DeviceID+": kein Gerät dieses Standorts")
			continue
		case c.IsBox:
			out.Failed = append(out.Failed, c.Name+": die Box beobachtet sich nicht selbst")
			continue
		}
		parentID, err := s.behind(ctx, p, c, cards, hostOf, actor)
		if err != nil {
			out.Failed = append(out.Failed, c.Name+": "+err.Error())
			continue
		}
		if hostID := hostOf[c.ID]; hostID != "" {
			h, err := s.Store.Host(ctx, hostID)
			if err != nil {
				out.Failed = append(out.Failed, c.Name+": "+err.Error())
				continue
			}
			if len(p.Checks) > 0 {
				h.Checks = p.Checks
			}
			if p.Uplink != nil {
				h.IsUplink = *p.Uplink
			}
			if p.Behind != nil {
				h.ParentID = parentID
			}
			if err := s.Engine.UpdateHost(ctx, h, actor); err != nil {
				out.Failed = append(out.Failed, c.Name+": "+err.Error())
				continue
			}
			out.Updated = append(out.Updated, c.Name)
			continue
		}
		if c.IP == "" {
			out.Failed = append(out.Failed, c.Name+": das Gerät hat keine IPv4-Adresse gezeigt, ohne Adresse kann die Box es nicht prüfen")
			continue
		}
		h := store.Host{ID: id.New("host"), TenantID: c.TenantID, SiteID: c.SiteID, BoxID: box.ID, DeviceID: c.ID,
			Name: c.Name, Address: c.IP, MAC: c.MAC, Vendor: c.Vendor, IsUplink: isUplinkKind(c.Kind),
			Checks: []wire.CheckConfig{{Type: wire.CheckICMP}}, CreatedAt: s.Now()}
		if len(p.Checks) > 0 {
			h.Checks = p.Checks
		}
		if p.Uplink != nil {
			h.IsUplink = *p.Uplink
		}
		h.ParentID = parentID
		if err := s.Engine.CreateHost(ctx, h, actor); err != nil {
			out.Failed = append(out.Failed, c.Name+": "+err.Error())
			continue
		}
		hostOf[c.ID] = h.ID
		out.Added = append(out.Added, c.Name)
	}
	return out, nil
}

// behind resolves the device a pick wants to sit behind into that device's host,
// and marks it as an uplink so the console shows the relation from both ends.
// Refused: a device that is not watched (nobody would notice it going down), the
// device itself, and a circle.
func (s *Server) behind(ctx context.Context, p watch.Pick, c deviceCard, cards map[string]deviceCard, hostOf map[string]string, actor string) (string, error) {
	if p.Behind == nil || *p.Behind == "" {
		return "", nil
	}
	pc, ok := cards[*p.Behind]
	switch {
	case !ok:
		return "", errors.New("behind: " + *p.Behind + " ist kein Gerät dieses Standorts")
	case pc.ID == c.ID:
		return "", errors.New("behind: ein Gerät hängt nicht hinter sich selbst")
	case hostOf[pc.ID] == "":
		return "", errors.New("behind: " + pc.Name + " wird selbst nicht beobachtet — erst aufnehmen, dann dahinter hängen")
	}
	parent, err := s.Store.Host(ctx, hostOf[pc.ID])
	if err != nil {
		return "", err
	}
	// a circle: the device it wants to sit behind sits behind it already
	self := hostOf[c.ID]
	for id, hops := parent.ParentID, 0; id != "" && self != "" && hops < 64; hops++ {
		if id == self {
			return "", errors.New("behind: " + pc.Name + " hängt selbst hinter " + c.Name)
		}
		up, err := s.Store.Host(ctx, id)
		if err != nil {
			break
		}
		id = up.ParentID
	}
	if !parent.IsUplink {
		parent.IsUplink = true
		if err := s.Engine.UpdateHost(ctx, parent, actor); err != nil {
			return "", err
		}
	}
	return parent.ID, nil
}

// siteWatchSuggested is the console's button for WatchSuggested.
func (s *Server) siteWatchSuggested(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=netz"
	out, err := s.WatchSuggested(ctx, siteID, actor(r))
	switch {
	case errors.Is(err, errNoBox):
		s.flashErr(w, r, "Diesem Standort ist keine Box zugeordnet; erst eine Box zuordnen.", back)
		return
	case err != nil:
		s.fail(w, r, err, statusFor(err))
		return
	}
	added, failed := len(out.Added), len(out.Failed)
	if added == 0 && failed == 0 {
		s.flash(w, r, "Nichts hinzuzufügen: "+explainSkipped(out.Skipped), back)
		return
	}
	msg := fmt.Sprintf("%d Gerät%s aufgenommen; die Box prüft sie ab der nächsten Minute.", added, plural(added, "", "e"))
	if failed > 0 {
		msg += fmt.Sprintf(" %d konnten nicht aufgenommen werden.", failed)
	}
	if len(out.Skipped) > 0 {
		msg += " Übergangen: " + explainSkipped(out.Skipped) + "."
	}
	s.flash(w, r, msg, back)
}

// apiSiteWatchSuggestion answers what the rule would do, without doing it.
func (s *Server) apiSiteWatchSuggestion(w http.ResponseWriter, r *http.Request) {
	p, err := s.WatchProposal(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	names := make([]string, 0, len(p.Add))
	for _, c := range p.Add {
		names = append(names, c.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(p.Add),
		"names":   names,
		"skipped": p.Skipped,
		"hasBox":  p.HasBox,
	})
}

// activeBox returns the site's box that is not revoked.
func (s *Server) activeBox(ctx context.Context, siteID string) (store.Box, error) {
	boxes, err := s.Store.Boxes(ctx, siteID)
	if err != nil {
		return store.Box{}, err
	}
	for i := range boxes {
		if boxes[i].RevokedAt == nil {
			return boxes[i], nil
		}
	}
	return store.Box{}, store.ErrNotFound
}

func explainSkipped(m map[string]int) string {
	if len(m) == 0 {
		return "nichts"
	}
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%d× %s", m[k], k))
	}
	return strings.Join(parts, ", ")
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// biggest group first: that is the sentence an operator reads
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && (m[out[j]] > m[out[j-1]] || (m[out[j]] == m[out[j-1]] && out[j] < out[j-1])); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
