package console

import (
	"errors"
	"net/http"

	"github.com/excubra/excubra/internal/server/store"
)

var (
	errNoUser = errors.New("keine Sitzung")
	errBadPin = errors.New("angeheftet werden können nur Kunden und Standorte")
)

// The pinned list in the sidebar. A person who looks after fifty customers works
// with three of them today, and which three changes; a star is cheaper than a
// scroll through every group.

// pinToggle pins or unpins a customer or a site for the operator who asked.
func (s *Server) pinToggle(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if u == nil {
		s.fail(w, r, errNoUser, http.StatusUnauthorized)
		return
	}
	kind, id := r.PostForm.Get("kind"), r.PostForm.Get("id")
	if kind != store.PinTenant && kind != store.PinSite {
		s.fail(w, r, errBadPin, http.StatusBadRequest)
		return
	}
	back := "/tenants/" + id
	what := "Kunde"
	if kind == store.PinSite {
		back, what = "/sites/"+id, "Standort"
	}
	on, err := s.Store.IsPinned(r.Context(), u.ID, kind, id)
	if err != nil {
		s.fail(w, r, err, http.StatusInternalServerError)
		return
	}
	if on {
		if err := s.Store.RemovePin(r.Context(), u.ID, kind, id); err != nil {
			s.fail(w, r, err, http.StatusInternalServerError)
			return
		}
		s.flash(w, r, what+" ist nicht mehr angeheftet.", back)
		return
	}
	if err := s.Store.AddPin(r.Context(), u.ID, kind, id, s.Now()); err != nil {
		s.fail(w, r, err, statusFor(err))
		return
	}
	s.flash(w, r, what+" oben in der Seitenleiste angeheftet.", back)
}

// pinsFor is what the sidebar draws; an empty list is not an error, it is a
// sidebar without a pinned section.
func (s *Server) pinsFor(r *http.Request) []store.Pin {
	u := userFrom(r)
	if u == nil {
		return nil
	}
	pins, err := s.Store.Pins(r.Context(), u.ID)
	if err != nil {
		s.Log.Warn("pins", "user", u.ID, "err", err)
		return nil
	}
	return pins
}
