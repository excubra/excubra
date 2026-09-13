package console

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/server/store"
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

// isUplinkKind marks the way out of the site. A firewall or router carries
// everything behind it, and the state machine suppresses the children of a dead
// uplink — so one cut line becomes one outage instead of forty.
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

// siteWatchSuggested switches monitoring on for everything the rule picks.
func (s *Server) siteWatchSuggested(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	siteID := r.PathValue("id")
	back := "/sites/" + siteID + "?tab=netz"
	d, err := s.buildSite(ctx, siteID, "netz", "24h")
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	box, err := s.activeBox(ctx, siteID)
	if err != nil {
		s.flashErr(w, r, "Diesem Standort ist keine Box zugeordnet; erst eine Box zuordnen.", back)
		return
	}
	sug := suggestWatch(d.Devices)
	if len(sug.Add) == 0 {
		s.flash(w, r, "Nichts hinzuzufügen: "+explainSkipped(sug.Skipped), back)
		return
	}
	var added, failed int
	for _, c := range sug.Add {
		h := store.Host{
			ID: id.New("host"), TenantID: c.TenantID, SiteID: c.SiteID, BoxID: box.ID, DeviceID: c.ID,
			Name: c.Name, Address: c.IP, MAC: c.MAC, Vendor: c.Vendor,
			IsUplink: isUplinkKind(c.Kind),
			Checks:   []wire.CheckConfig{{Type: wire.CheckICMP}}, CreatedAt: s.Now(),
		}
		if err := s.Engine.CreateHost(ctx, h, actor(r)); err != nil {
			failed++
			s.Log.Warn("suggested watch", "device", c.ID, "err", err)
			continue
		}
		added++
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "site.watch.suggested", siteID, fmt.Sprintf("%d aufgenommen, %d fehlgeschlagen", added, failed))
	msg := fmt.Sprintf("%d Gerät%s aufgenommen; die Box prüft sie ab der nächsten Minute.", added, plural(added, "", "e"))
	if failed > 0 {
		msg += fmt.Sprintf(" %d konnten nicht aufgenommen werden.", failed)
	}
	if len(sug.Skipped) > 0 {
		msg += " Übergangen: " + explainSkipped(sug.Skipped) + "."
	}
	s.flash(w, r, msg, back)
}

// apiSiteWatchSuggestion answers what the rule would do, without doing it.
func (s *Server) apiSiteWatchSuggestion(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildSite(r.Context(), r.PathValue("id"), "netz", "24h")
	if err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	sug := suggestWatch(d.Devices)
	names := make([]string, 0, len(sug.Add))
	for _, c := range sug.Add {
		names = append(names, c.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(sug.Add),
		"names":   names,
		"skipped": sug.Skipped,
		"hasBox":  d.Box != nil,
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
