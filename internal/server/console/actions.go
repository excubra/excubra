package console

// Operator actions beyond editing records: tasks for a box (ADR-0014), release
// channels and rollouts, and acknowledging a problem. Everything here is a POST that
// answers the app with {ok, message} and the templates with a redirect.

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/server/core"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// taskLabels are the German names of the closed task list.
var taskLabels = map[string]string{
	wire.TaskSweep:   "Netz absuchen",
	wire.TaskRecheck: "Hosts jetzt prüfen",
	wire.TaskUpdate:  "Update holen",
	wire.TaskRestart: "Agent neu starten",
}

// TaskLabel names a task kind for people.
func TaskLabel(kind string) string {
	if l, ok := taskLabels[kind]; ok {
		return l
	}
	return kind
}

// boxTask queues one task for a box.
func (s *Server) boxTask(w http.ResponseWriter, r *http.Request) {
	boxID := r.PathValue("id")
	s.queueTask(w, r, boxID, r.PostForm.Get("kind"), "/boxes/"+boxID)
}

// siteTask queues one task for the box of a site.
func (s *Server) siteTask(w http.ResponseWriter, r *http.Request) {
	siteID := r.PathValue("id")
	back := "/sites/" + siteID
	boxes, err := s.Store.Boxes(r.Context(), siteID)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	for _, b := range boxes {
		if b.RevokedAt == nil {
			s.queueTask(w, r, b.ID, r.PostForm.Get("kind"), back)
			return
		}
	}
	s.flashErr(w, r, "Diesem Standort ist keine Box zugeordnet.", back)
}

func (s *Server) queueTask(w http.ResponseWriter, r *http.Request, boxID, kind, back string) {
	t, err := s.Engine.QueueTask(r.Context(), boxID, kind, actor(r))
	switch {
	case errors.Is(err, core.ErrTaskPending):
		s.flashErr(w, r, TaskLabel(kind)+" wartet bereits seit "+humanDur(s.Now().Sub(t.IssuedAt))+" auf die Box.", back)
	case errors.Is(err, core.ErrBadTask):
		s.flashErr(w, r, "Unbekannte Aufgabe.", back)
	case err != nil:
		s.fail(w, r, err, statusFor(err))
	default:
		s.flash(w, r, TaskLabel(kind)+" eingereiht. Die Box holt die Aufgabe mit dem nächsten Heartbeat (bis zu einer Minute) und meldet das Ergebnis mit dem übernächsten.", back)
	}
}

// boxChannel moves one box to a release channel without touching its other settings.
func (s *Server) boxChannel(w http.ResponseWriter, r *http.Request) {
	boxID, ch := r.PathValue("id"), r.PostForm.Get("channel")
	if ch != wire.ChannelStable && ch != wire.ChannelCanary {
		s.flashErr(w, r, "Kanal muss stable oder canary sein.", "/updates")
		return
	}
	if err := s.Store.SetBoxChannel(r.Context(), boxID, ch); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "box.channel", boxID, ch)
	s.flash(w, r, "Box auf Kanal "+ch+" gestellt; sie prüft beim nächsten täglichen Tick oder über „Update holen“.", "/updates")
}

// ---- updates ---------------------------------------------------------------------------------

// updateRow is one box on the updates page.
type updateRow struct {
	boxRow
	Target   string         // the version its channel points at ("" = nothing configured)
	Behind   bool           // running something other than Target
	LastNote *store.BoxNote // newest heartbeat note, if any
	Pending  []store.BoxTask
}

// updatesData feeds the updates page.
type updatesData struct {
	Boxes    []updateRow
	Releases []store.Release
	Channels map[string]string // channel → version
	Versions []string          // distinct release versions, newest first
	Behind   int
	Current  int
	NoTarget int
}

func (s *Server) buildUpdates(ctx context.Context) (updatesData, error) {
	d := updatesData{Channels: map[string]string{}}
	for _, ch := range []string{wire.ChannelStable, wire.ChannelCanary} {
		v, err := s.Store.ChannelVersion(ctx, ch)
		if err != nil {
			return d, err
		}
		d.Channels[ch] = v
	}
	rels, err := s.Store.Releases(ctx)
	if err != nil {
		return d, err
	}
	d.Releases = rels
	seen := map[string]bool{}
	for _, rel := range rels {
		if !seen[rel.Version] {
			seen[rel.Version] = true
			d.Versions = append(d.Versions, rel.Version)
		}
	}
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		return d, err
	}
	tm, sm, err := s.lookups(ctx)
	if err != nil {
		return d, err
	}
	notes, err := s.Store.LatestBoxNotes(ctx)
	if err != nil {
		return d, err
	}
	now := s.Now()
	for _, b := range boxes {
		if b.RevokedAt != nil {
			continue
		}
		row := updateRow{boxRow: s.boxRow(b, sm, tm)}
		ch := b.Channel
		if ch == "" {
			ch = wire.ChannelStable
		}
		row.Target = d.Channels[ch]
		row.Behind = row.Target != "" && strings.TrimPrefix(b.AgentVersion, "v") != row.Target
		if n, ok := notes[b.ID]; ok {
			n := n
			row.LastNote = &n
		}
		if p, err := s.Store.PendingBoxTasks(ctx, b.ID, now); err == nil {
			row.Pending = p
		}
		switch {
		case row.Target == "":
			d.NoTarget++
		case row.Behind:
			d.Behind++
		default:
			d.Current++
		}
		d.Boxes = append(d.Boxes, row)
	}
	sort.SliceStable(d.Boxes, func(i, j int) bool { // behind first, then by customer and name
		if d.Boxes[i].Behind != d.Boxes[j].Behind {
			return d.Boxes[i].Behind
		}
		if d.Boxes[i].TenantName != d.Boxes[j].TenantName {
			return d.Boxes[i].TenantName < d.Boxes[j].TenantName
		}
		return d.Boxes[i].Name < d.Boxes[j].Name
	})
	return d, nil
}

func (s *Server) apiUpdates(w http.ResponseWriter, r *http.Request) {
	d, err := s.buildUpdates(r.Context())
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// updatesChannel points a channel at a stored release (or at nothing).
func (s *Server) updatesChannel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ch, v := r.PostForm.Get("channel"), strings.TrimPrefix(strings.TrimSpace(r.PostForm.Get("version")), "v")
	if ch != wire.ChannelStable && ch != wire.ChannelCanary {
		s.flashErr(w, r, "Kanal muss stable oder canary sein.", "/updates")
		return
	}
	if v != "" {
		rels, err := s.Store.Releases(ctx)
		if err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		known := false
		for _, rel := range rels {
			if rel.Version == v {
				known = true
				break
			}
		}
		if !known {
			s.flashErr(w, r, "Version "+v+" ist nicht als Release hinterlegt.", "/updates")
			return
		}
	}
	if err := s.Store.SetChannelVersion(ctx, ch, v); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(ctx, s.Now(), actor(r), "release.channel", ch, v)
	if v == "" {
		s.flash(w, r, "Kanal "+ch+" zeigt auf keine Version mehr; Boxen auf diesem Kanal bekommen kein Update angeboten.", "/updates")
		return
	}
	s.flash(w, r, "Kanal "+ch+" zeigt jetzt auf "+v+". Boxen prüfen täglich, oder sofort über „Update holen“.", "/updates")
}

// updatesRollout queues an update task for every box on a channel.
func (s *Server) updatesRollout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ch := r.PostForm.Get("channel")
	if ch != wire.ChannelStable && ch != wire.ChannelCanary {
		s.flashErr(w, r, "Kanal muss stable oder canary sein.", "/updates")
		return
	}
	if v, err := s.Store.ChannelVersion(ctx, ch); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	} else if v == "" {
		s.flashErr(w, r, "Kanal "+ch+" zeigt auf keine Version; erst ein Release wählen.", "/updates")
		return
	}
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	queued, waiting := 0, 0
	for _, b := range boxes {
		bc := b.Channel
		if bc == "" {
			bc = wire.ChannelStable
		}
		if b.RevokedAt != nil || bc != ch {
			continue
		}
		_, err := s.Engine.QueueTask(ctx, b.ID, wire.TaskUpdate, actor(r))
		switch {
		case errors.Is(err, core.ErrTaskPending):
			waiting++
		case err != nil:
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		default:
			queued++
		}
	}
	msg := "Update holen an " + itoa(queued) + " Boxen eingereiht"
	if waiting > 0 {
		msg += ", " + itoa(waiting) + " warteten schon"
	}
	s.flash(w, r, msg+".", "/updates")
}

// ---- acknowledgements --------------------------------------------------------------------------

var ackKinds = map[string]bool{"host_down": true, "box_silent": true, "box_unassigned": true}

// ackSet marks a problem as seen. The problem is identified by kind, object and the
// start of the outage, so a new outage of the same object is not covered.
func (s *Server) ackSet(w http.ResponseWriter, r *http.Request) {
	kind, target := r.PostForm.Get("kind"), r.PostForm.Get("id")
	since, err := time.Parse(time.RFC3339Nano, r.PostForm.Get("since"))
	if !ackKinds[kind] || target == "" || err != nil {
		s.flashErr(w, r, "Störung nicht erkannt; Seite neu laden.", "/")
		return
	}
	note := strings.TrimSpace(r.PostForm.Get("note"))
	if len(note) > 200 {
		note = note[:200]
	}
	a := store.Ack{Kind: kind, TargetID: target, Since: since, Actor: displayName(r), At: s.Now(), Note: note}
	if err := s.Store.SetAck(r.Context(), a); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "ack", kind+"/"+target, note)
	s.flash(w, r, "Quittiert. Die Störung bleibt sichtbar, zählt aber nicht mehr als offen.", "/")
}

// ackDelete takes an acknowledgement back.
func (s *Server) ackDelete(w http.ResponseWriter, r *http.Request) {
	kind, target := r.PostForm.Get("kind"), r.PostForm.Get("id")
	if !ackKinds[kind] || target == "" {
		s.flashErr(w, r, "Störung nicht erkannt.", "/")
		return
	}
	if err := s.Store.DeleteAck(r.Context(), kind, target); err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	_ = s.Store.Audit(r.Context(), s.Now(), actor(r), "ack.undo", kind+"/"+target, "")
	s.flash(w, r, "Quittierung zurückgenommen.", "/")
}

// ackView is what the app shows next to an acknowledged problem.
type ackView struct {
	Actor string    `json:"actor"`
	At    time.Time `json:"at"`
	Note  string    `json:"note"`
}

// ackFor returns the acknowledgement of a problem, if it matches this outage.
func ackFor(acks map[string]store.Ack, kind, target string, since time.Time) *ackView {
	a, ok := acks[kind+"/"+target]
	if !ok || a.Since.Unix() != since.Unix() {
		return nil
	}
	return &ackView{Actor: a.Actor, At: a.At, Note: a.Note}
}

func itoa(n int) string { return strconv.Itoa(n) }

// displayName is the logged-in user's name as people know it; audit keeps actor(r).
func displayName(r *http.Request) string {
	if u := userFrom(r); u != nil && u.Name != "" {
		return u.Name
	}
	return actor(r)
}
