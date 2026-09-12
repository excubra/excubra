// Package remote brings a customer LAN into the operator's own overlay (salt:
// Vollausbau, Stufe B). The box becomes a second peer there and routes its LAN as a
// network resource; technicians reach it from their one tunnel. EX0 creates the
// pieces through the NetBird API of our stack (group, one-off setup key, network,
// resource, router, policy), hands the key to the box through the usual claim, and
// keeps the row in remote_access honest. Nothing here touches a customer system.
package remote

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/server/netbird"
	"github.com/excubra/excubra/internal/server/store"
	"github.com/excubra/excubra/internal/wire"
)

// Settings keys for the operator stack.
const (
	SettingURL       = "netbird.operator.url"
	SettingToken     = "netbird.operator.token" //nolint:gosec // a settings key, not a credential
	SettingTechGroup = "netbird.operator.tech_group"
	SettingLANGroup  = "netbird.operator.lan_group"
	SettingBoxGroup  = "netbird.operator.box_group"
	PolicyName       = "ex0: Techniker → Kunden-LANs"
)

// Defaults match the stack the NetBird runbook creates.
const (
	DefaultTechGroup = "viico"
	DefaultLANGroup  = "kunden-lan"
	DefaultBoxGroup  = "kunden-box"
	keyTTL           = time.Hour
	joinTimeout      = 2 * time.Hour
)

// Errors a caller can explain to a person.
var (
	ErrNotConfigured = errors.New("remote: operator stack not configured")
	ErrNoBox         = errors.New("remote: the site has no box")
	ErrOverlap       = errors.New("remote: LAN overlaps another site's")
	ErrBadCIDR       = errors.New("remote: LAN must be a private IPv4 network")
)

// Service runs remote access for all sites.
type Service struct {
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	// NewClient builds the API client from settings; tests replace it.
	NewClient func(url, token string) *netbird.Client

	mu   sync.Mutex
	busy map[string]bool
}

// New returns a service.
func New(st *store.Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{Store: st, Log: log, Now: time.Now, NewClient: netbird.New, busy: map[string]bool{}}
}

// Settings is the operator stack configuration as the console shows it.
type Settings struct {
	URL       string `json:"url"`
	HasToken  bool   `json:"hasToken"`
	TechGroup string `json:"techGroup"`
	LANGroup  string `json:"lanGroup"`
	BoxGroup  string `json:"boxGroup"`
}

func (s *Service) setting(ctx context.Context, key, def string) string {
	v, err := s.Store.Setting(ctx, key)
	if err != nil || v == "" {
		return def
	}
	return v
}

// Settings returns the configuration without the token.
func (s *Service) Settings(ctx context.Context) Settings {
	return Settings{URL: s.setting(ctx, SettingURL, ""), HasToken: s.setting(ctx, SettingToken, "") != "",
		TechGroup: s.setting(ctx, SettingTechGroup, DefaultTechGroup), LANGroup: s.setting(ctx, SettingLANGroup, DefaultLANGroup), BoxGroup: s.setting(ctx, SettingBoxGroup, DefaultBoxGroup)}
}

// SaveSettings stores URL, groups and, when given, a new token.
func (s *Service) SaveSettings(ctx context.Context, url, token, techGroup, lanGroup, boxGroup string) error {
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url != "" && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://127.0.0.1") && !strings.HasPrefix(url, "http://localhost") {
		return errors.New("remote: the management URL must start with https://")
	}
	if err := s.Store.SetSetting(ctx, SettingURL, url); err != nil {
		return err
	}
	if token = strings.TrimSpace(token); token != "" {
		if err := s.Store.SetSetting(ctx, SettingToken, token); err != nil {
			return err
		}
	}
	for k, v := range map[string]string{SettingTechGroup: techGroup, SettingLANGroup: lanGroup, SettingBoxGroup: boxGroup} {
		if v = strings.TrimSpace(v); v != "" {
			if err := s.Store.SetSetting(ctx, k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// client returns an API client for the operator stack, or ErrNotConfigured.
func (s *Service) client(ctx context.Context) (*netbird.Client, error) {
	c := s.NewClient(s.setting(ctx, SettingURL, ""), s.setting(ctx, SettingToken, ""))
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	return c, nil
}

// Test checks URL and token by listing groups.
func (s *Service) Test(ctx context.Context) (int, error) {
	c, err := s.client(ctx)
	if err != nil {
		return 0, err
	}
	gs, err := c.Groups(ctx)
	return len(gs), err
}

// Enable switches remote access on for a site: validates the LAN, creates the
// groups and policy if missing, mints a one-off key and hands it to the box. The
// rest (peer, network, resource, router) happens in Reconcile once the box joined.
func (s *Service) Enable(ctx context.Context, siteID, cidr, actor string) (store.RemoteAccess, error) {
	prefix, err := parseLAN(cidr)
	if err != nil {
		return store.RemoteAccess{}, err
	}
	site, err := s.Store.Site(ctx, siteID)
	if err != nil {
		return store.RemoteAccess{}, err
	}
	box, err := s.siteBox(ctx, siteID)
	if err != nil {
		return store.RemoteAccess{}, err
	}
	rows, err := s.Store.RemoteAccesses(ctx)
	if err != nil {
		return store.RemoteAccess{}, err
	}
	for _, r := range rows {
		if r.SiteID != siteID && r.Enabled && r.State != store.RemoteError {
			if other, err := netip.ParsePrefix(r.CIDR); err == nil && other.Overlaps(prefix) {
				return store.RemoteAccess{}, fmt.Errorf("%w: %s (Standort %s)", ErrOverlap, r.CIDR, r.SiteID)
			}
		}
	}
	c, err := s.client(ctx)
	if err != nil {
		return store.RemoteAccess{}, err
	}
	now := s.Now()
	ra := store.RemoteAccess{SiteID: siteID, TenantID: site.TenantID, BoxID: box.ID, CIDR: prefix.String(), Enabled: true, State: store.RemoteKey, RequestedBy: actor, CreatedAt: now, UpdatedAt: now}
	if old, err := s.Store.RemoteAccess(ctx, siteID); err == nil {
		ra.CreatedAt = old.CreatedAt
		ra.NetworkID, ra.ResourceID, ra.RouterID, ra.PeerID, ra.PeerIP = old.NetworkID, old.ResourceID, old.RouterID, old.PeerID, old.PeerIP
	}
	// a LAN somebody routed by hand in our stack (a bridge container) must not get a second router
	if foreign, err := s.foreignRoute(ctx, c, prefix, ra.NetworkID); err != nil {
		return store.RemoteAccess{}, err
	} else if foreign != "" {
		return store.RemoteAccess{}, fmt.Errorf("%w: im Techniker-Stack routet bereits das Netzwerk „%s“ dieses Netz", ErrOverlap, foreign)
	}
	// already a peer in our stack (switched off earlier, or re-enabled): no new key
	if box.NetbirdOpStatus == wire.NetbirdConnected && box.NetbirdOpIP != "" {
		ra.State, ra.Detail = store.RemoteJoining, "Box ist bereits im Techniker-Stack, Netzwerk wird angelegt"
		if err := s.Store.SetRemoteAccess(ctx, ra); err != nil {
			return ra, err
		}
		return s.wire(ctx, c, ra, box)
	}
	boxGroup, err := c.EnsureGroup(ctx, s.setting(ctx, SettingBoxGroup, DefaultBoxGroup))
	if err != nil {
		return s.failed(ctx, ra, "Gruppe anlegen: "+err.Error())
	}
	tenant, _ := s.Store.Tenant(ctx, site.TenantID)
	key, err := c.CreateSetupKey(ctx, "ex0 "+firstNonEmpty(tenant.Name, site.TenantID)+" · "+site.Name+" · "+firstNonEmpty(box.Name, box.ID), []string{boxGroup.ID}, keyTTL)
	if err != nil {
		return s.failed(ctx, ra, "Setup-Key: "+err.Error())
	}
	if err := s.Store.SetNetbirdKey(ctx, store.NetbirdKey{BoxID: box.ID, Profile: wire.NetbirdProfileOperator, ManagementURL: s.setting(ctx, SettingURL, ""), SetupKey: key.Key, CreatedAt: now}); err != nil {
		return ra, err
	}
	ra.Detail = "Setup-Key erzeugt; die Box holt ihn mit dem nächsten Heartbeat und tritt dem Techniker-Stack bei"
	if err := s.Store.SetRemoteAccess(ctx, ra); err != nil {
		return ra, err
	}
	_ = s.Store.Audit(ctx, now, actor, "remote.enable", siteID, prefix.String())
	return ra, nil
}

// Disable switches the resource off; the peer stays, the network stays, nothing is
// reachable until Enable again.
func (s *Service) Disable(ctx context.Context, siteID, actor string) (store.RemoteAccess, error) {
	ra, err := s.Store.RemoteAccess(ctx, siteID)
	if err != nil {
		return ra, err
	}
	if ra.NetworkID != "" && ra.ResourceID != "" {
		c, err := s.client(ctx)
		if err != nil {
			return ra, err
		}
		lan, err := c.EnsureGroup(ctx, s.setting(ctx, SettingLANGroup, DefaultLANGroup))
		if err != nil {
			return ra, err
		}
		if err := c.SetResourceEnabled(ctx, ra.NetworkID, ra.ResourceID, resourceName(ra), ra.CIDR, []string{lan.ID}, false); err != nil {
			return s.failed(ctx, ra, "Ressource abschalten: "+err.Error())
		}
	}
	ra.Enabled, ra.State, ra.Detail, ra.UpdatedAt = false, store.RemoteOff, "abgeschaltet von "+actor, s.Now()
	_ = s.Store.Audit(ctx, s.Now(), actor, "remote.disable", siteID, ra.CIDR)
	return ra, s.Store.SetRemoteAccess(ctx, ra)
}

// Remove deletes the network in our stack and the row; the box stays a peer.
func (s *Service) Remove(ctx context.Context, siteID, actor string) error {
	ra, err := s.Store.RemoteAccess(ctx, siteID)
	if err != nil {
		return err
	}
	if ra.NetworkID != "" {
		c, err := s.client(ctx)
		if err != nil {
			return err
		}
		if err := c.DeleteNetwork(ctx, ra.NetworkID); err != nil && !strings.Contains(err.Error(), "404") {
			return err
		}
	}
	_ = s.Store.DeleteNetbirdKeyProfile(ctx, ra.BoxID, wire.NetbirdProfileOperator)
	_ = s.Store.Audit(ctx, s.Now(), actor, "remote.remove", siteID, ra.CIDR)
	return s.Store.DeleteRemoteAccess(ctx, siteID)
}

// Reconcile moves every row forward: a box that joined gets its network, an active
// row gets its peer state refreshed, a key nobody fetched in time expires.
func (s *Service) Reconcile(ctx context.Context) {
	rows, err := s.Store.RemoteAccesses(ctx)
	if err != nil {
		s.Log.Error("remote access", "err", err)
		return
	}
	for _, ra := range rows {
		if !ra.Enabled || ra.State == store.RemoteError || ra.State == store.RemoteOff {
			continue
		}
		s.mu.Lock()
		if s.busy[ra.SiteID] {
			s.mu.Unlock()
			continue
		}
		s.busy[ra.SiteID] = true
		s.mu.Unlock()
		s.step(ctx, ra)
		s.mu.Lock()
		delete(s.busy, ra.SiteID)
		s.mu.Unlock()
	}
}

// Run reconciles every interval until ctx ends.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Reconcile(ctx)
		}
	}
}

func (s *Service) step(ctx context.Context, ra store.RemoteAccess) {
	box, err := s.Store.Box(ctx, ra.BoxID)
	if err != nil {
		_, _ = s.failed(ctx, ra, "Box nicht mehr vorhanden")
		return
	}
	c, err := s.client(ctx)
	if err != nil {
		return
	}
	switch ra.State {
	case store.RemoteKey, store.RemoteJoining:
		if box.NetbirdOpStatus == wire.NetbirdConnected && box.NetbirdOpIP != "" {
			_, _ = s.wire(ctx, c, ra, box)
			return
		}
		if k, err := s.Store.NetbirdKeyProfile(ctx, ra.BoxID, wire.NetbirdProfileOperator); err == nil && k.ClaimedAt != nil && ra.State == store.RemoteKey {
			ra.State, ra.Detail, ra.UpdatedAt = store.RemoteJoining, "Box hat den Schlüssel, verbindet sich mit dem Techniker-Stack", s.Now()
			_ = s.Store.SetRemoteAccess(ctx, ra)
		}
		if s.Now().Sub(ra.UpdatedAt) > joinTimeout {
			_, _ = s.failed(ctx, ra, "Box ist dem Techniker-Stack nicht beigetreten; läuft der Operator-Daemon auf der Box (provision-box.sh)?")
		}
	case store.RemoteActive:
		peers, err := c.Peers(ctx)
		if err != nil {
			return
		}
		for _, p := range peers {
			if p.ID == ra.PeerID {
				detail := "Peer verbunden"
				if !p.Connected {
					detail = "Peer nicht verbunden, zuletzt " + p.LastSeen.Local().Format("02.01. 15:04")
				}
				if detail != ra.Detail {
					ra.Detail, ra.UpdatedAt = detail, s.Now()
					_ = s.Store.SetRemoteAccess(ctx, ra)
				}
				return
			}
		}
		_, _ = s.failed(ctx, ra, "Peer der Box ist im Techniker-Stack verschwunden")
	}
}

// wire creates network, resource and router for a box that is a peer in our stack.
func (s *Service) wire(ctx context.Context, c *netbird.Client, ra store.RemoteAccess, box store.Box) (store.RemoteAccess, error) {
	ra.State, ra.UpdatedAt = store.RemoteWiring, s.Now()
	_ = s.Store.SetRemoteAccess(ctx, ra)
	peers, err := c.Peers(ctx)
	if err != nil {
		return s.failed(ctx, ra, "Peers lesen: "+err.Error())
	}
	var peer *netbird.Peer
	for i := range peers {
		if peers[i].IP == box.NetbirdOpIP {
			peer = &peers[i]
		}
	}
	if peer == nil {
		ra.State, ra.Detail = store.RemoteJoining, "Box meldet Overlay-Adresse "+box.NetbirdOpIP+", Peer noch nicht in der API sichtbar"
		return ra, s.Store.SetRemoteAccess(ctx, ra)
	}
	ra.PeerID, ra.PeerIP = peer.ID, peer.IP
	lan, err := c.EnsureGroup(ctx, s.setting(ctx, SettingLANGroup, DefaultLANGroup))
	if err != nil {
		return s.failed(ctx, ra, "Gruppe: "+err.Error())
	}
	tech, err := c.EnsureGroup(ctx, s.setting(ctx, SettingTechGroup, DefaultTechGroup))
	if err != nil {
		return s.failed(ctx, ra, "Gruppe: "+err.Error())
	}
	if _, err := c.EnsurePolicy(ctx, PolicyName, []string{tech.ID}, []string{lan.ID}); err != nil {
		return s.failed(ctx, ra, "Richtlinie: "+err.Error())
	}
	site, _ := s.Store.Site(ctx, ra.SiteID)
	tenant, _ := s.Store.Tenant(ctx, ra.TenantID)
	if ra.NetworkID == "" {
		n, err := c.CreateNetwork(ctx, firstNonEmpty(tenant.Name, ra.TenantID)+" · "+firstNonEmpty(site.Name, ra.SiteID), "EX0 remote access "+ra.SiteID)
		if err != nil {
			return s.failed(ctx, ra, "Netzwerk: "+err.Error())
		}
		ra.NetworkID = n.ID
		_ = s.Store.SetRemoteAccess(ctx, ra)
	}
	if ra.ResourceID == "" {
		r, err := c.CreateResource(ctx, ra.NetworkID, resourceName(ra), ra.CIDR, []string{lan.ID}, true)
		if err != nil {
			return s.failed(ctx, ra, "Ressource: "+err.Error())
		}
		ra.ResourceID = r.ID
		_ = s.Store.SetRemoteAccess(ctx, ra)
	} else if err := c.SetResourceEnabled(ctx, ra.NetworkID, ra.ResourceID, resourceName(ra), ra.CIDR, []string{lan.ID}, true); err != nil {
		return s.failed(ctx, ra, "Ressource einschalten: "+err.Error())
	}
	if ra.RouterID == "" {
		rt, err := c.CreateRouter(ctx, ra.NetworkID, peer.ID, true, 100)
		if err != nil {
			return s.failed(ctx, ra, "Router: "+err.Error())
		}
		ra.RouterID = rt.ID
	}
	ra.State, ra.Detail, ra.UpdatedAt = store.RemoteActive, "Peer verbunden", s.Now()
	_ = s.Store.Audit(ctx, s.Now(), "server", "remote.active", ra.SiteID, ra.CIDR+" via "+peer.IP)
	return ra, s.Store.SetRemoteAccess(ctx, ra)
}

func (s *Service) failed(ctx context.Context, ra store.RemoteAccess, detail string) (store.RemoteAccess, error) {
	ra.State, ra.Detail, ra.UpdatedAt = store.RemoteError, detail, s.Now()
	s.Log.Warn("remote access", "site", ra.SiteID, "err", detail)
	if err := s.Store.SetRemoteAccess(ctx, ra); err != nil {
		return ra, err
	}
	return ra, errors.New(detail)
}

func (s *Service) siteBox(ctx context.Context, siteID string) (store.Box, error) {
	boxes, err := s.Store.Boxes(ctx, siteID)
	if err != nil {
		return store.Box{}, err
	}
	for _, b := range boxes {
		if b.RevokedAt == nil {
			return b, nil
		}
	}
	return store.Box{}, ErrNoBox
}

// foreignRoute names a network in our stack, other than ours, whose resource
// overlaps the LAN; "" when there is none.
func (s *Service) foreignRoute(ctx context.Context, c *netbird.Client, lan netip.Prefix, ownNetwork string) (string, error) {
	nets, err := c.Networks(ctx)
	if err != nil {
		return "", err
	}
	for _, n := range nets {
		if n.ID == ownNetwork {
			continue
		}
		res, err := c.Resources(ctx, n.ID)
		if err != nil {
			return "", err
		}
		for _, r := range res {
			if p, err := netip.ParsePrefix(r.Address); err == nil && p.Overlaps(lan) {
				return n.Name, nil
			}
			if a, err := netip.ParseAddr(r.Address); err == nil && lan.Contains(a) {
				return n.Name, nil
			}
		}
	}
	return "", nil
}

func resourceName(ra store.RemoteAccess) string { return "LAN " + ra.CIDR }

// parseLAN accepts a private IPv4 network in CIDR notation.
func parseLAN(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() || p.Bits() < 8 || p.Bits() > 30 {
		return netip.Prefix{}, ErrBadCIDR
	}
	return p.Masked(), nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
