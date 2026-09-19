package mcp

// The three things a person had to click before a box could be born: a
// customer, a site, an enrollment key. They are setup, not action on a
// customer's systems — nothing here reaches a customer network, and the key is
// made on the server exactly as the console makes it (ADR-0017: the box assigns
// itself from the key, never from anything it sends). So a session may do them,
// audited under the actor it runs as.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/id"
	"github.com/excubra/excubra/internal/pki"
	"github.com/excubra/excubra/internal/server/geocode"
	"github.com/excubra/excubra/internal/server/installer"
	"github.com/excubra/excubra/internal/server/store"
)

const (
	keyDaysDefault = 30
	keyDaysMax     = 365
)

func (s *Server) createTenant(ctx context.Context, slug, name string) (string, error) {
	tid, err := id.FromSlug("ten", slug)
	if err != nil {
		return "", errors.New("Kürzel: a-z, 0-9, Bindestrich, 1-40 Zeichen")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("name required")
	}
	if _, err := s.Store.Tenant(ctx, tid); err == nil {
		return "", fmt.Errorf("%s gibt es schon", tid)
	}
	now := s.Now()
	if err := s.Store.CreateTenant(ctx, store.Tenant{ID: tid, Name: name, CreatedAt: now}); err != nil {
		return "", err
	}
	_ = s.Store.Audit(ctx, now, s.Actor, "tenant.create", tid, name)
	return pretty(map[string]any{"tenant_id": tid, "name": name, "next": "ex0_create_site mit tenant_id " + tid}), nil
}

// createSite makes a site and, when an address is given, puts it on the map the
// way the console does: looked up on the server, best candidate taken. A site
// without an address is fine; it is only missing from the map.
func (s *Server) createSite(ctx context.Context, tenantID, slug, name, address string) (string, error) {
	if _, err := s.Store.Tenant(ctx, tenantID); err != nil {
		return "", fmt.Errorf("tenant %q: %w", tenantID, err)
	}
	sid, err := id.FromSlug("site", slug)
	if err != nil {
		return "", errors.New("Kürzel: a-z, 0-9, Bindestrich, 1-40 Zeichen")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("name required")
	}
	if _, err := s.Store.Site(ctx, sid); err == nil {
		return "", fmt.Errorf("%s gibt es schon", sid)
	}
	now := s.Now()
	if err := s.Store.CreateSite(ctx, store.Site{ID: sid, TenantID: tenantID, Name: name, CreatedAt: now}); err != nil {
		return "", err
	}
	_ = s.Store.Audit(ctx, now, s.Actor, "site.create", sid, name)
	out := map[string]any{"site_id": sid, "tenant_id": tenantID, "name": name, "next": "ex0_new_box mit site_id " + sid}

	address = strings.TrimSpace(address)
	if address == "" {
		out["map"] = "ohne Adresse; der Standort fehlt auf der Karte, bis eine eingetragen ist"
		return pretty(out), nil
	}
	if len(address) > 300 {
		return "", errors.New("die Adresse ist zu lang")
	}
	service, _ := s.Store.Setting(ctx, geocode.SettingService)
	places, err := geocode.New(service).Lookup(ctx, address)
	switch {
	case errors.Is(err, geocode.ErrNothingFound), err == nil && len(places) == 0:
		// Keep the address text so a person sees what was asked; no coordinates.
		_ = s.Store.SetSiteLocation(ctx, sid, address, 0, 0, false)
		out["map"] = "Adresse gespeichert, aber nicht gefunden — in der Konsole unter Standort → Adresse nachbessern"
	case err != nil:
		_ = s.Store.SetSiteLocation(ctx, sid, address, 0, 0, false)
		out["map"] = "Adresse gespeichert; das Nachschlagen ist fehlgeschlagen (" + err.Error() + ") — später in der Konsole nachholen"
	default:
		p := places[0]
		if err := s.Store.SetSiteLocation(ctx, sid, address, p.Lat, p.Lon, true); err != nil {
			return "", err
		}
		_ = s.Store.Audit(ctx, now, s.Actor, "site.location", sid, address)
		out["map"] = map[string]any{"placed_as": p.Label, "lat": p.Lat, "lon": p.Lon}
	}
	return pretty(out), nil
}

// newBox mints one enrollment key for a site and returns the two one-liners,
// exactly what the console shows once. The key is a one-time secret: it goes
// into the command and nowhere else, is consumed on enrollment, and can be
// revoked in the console until then.
func (s *Server) newBox(ctx context.Context, siteID, note string, days int) (string, error) {
	if s.CA == nil || s.Ingest == "" {
		return "", errors.New("this MCP server was started without the CA and ingest address; enrollment keys need both")
	}
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return "", fmt.Errorf("site %q: %w", siteID, err)
	}
	tenant, err := s.Store.Tenant(ctx, site.TenantID)
	if err != nil {
		return "", err
	}
	if days < 1 || days > keyDaysMax {
		days = keyDaysDefault
	}
	note = strings.TrimSpace(note)
	if note == "" {
		note = tenant.Name + " · " + site.Name
	}
	k, err := pki.NewEnrollmentKey(s.Ingest, s.IngestPt, s.CA.Fingerprint())
	if err != nil {
		return "", err
	}
	now := s.Now()
	rec := store.EnrollmentKey{ID: id.New("key"), SecretHash: k.SecretHash(), Note: note, SiteID: siteID, CreatedAt: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour)}
	if err := s.Store.CreateEnrollmentKey(ctx, rec); err != nil {
		return "", err
	}
	_ = s.Store.Audit(ctx, now, s.Actor, "key.new", rec.ID, note+" site="+siteID)
	hostname := installer.Hostname(tenant.Name, site.Name)
	_, ver := installer.Base()
	return pretty(map[string]any{
		"key_id":     rec.ID,
		"site_id":    siteID,
		"expires_at": rec.ExpiresAt.UTC().Format(time.RFC3339),
		"hostname":   hostname,
		"version":    ver,
		"commands":   installer.Commands(k.String(), hostname),
		"note":       "Der Key steht nur im Befehl. Nicht in salt, nicht in ein Ticket. Beim Proxmox-Einzeiler bei Bedarf --ctid, --bridge, --ip/--gw, --storage, --disk, --memory anhängen (siehe image/README.md). Bis die Box ihn verbraucht hat, lässt er sich in der Konsole unter Enrollment-Keys widerrufen.",
	}), nil
}
