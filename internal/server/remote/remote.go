// Package remote brings a customer LAN into the operator's own overlay (salt:
// Vollausbau, Stufe B). The box image is one package — agent, operator peer,
// prepared customer peer — so every assigned box that runs the operator daemon
// becomes a peer in our stack by itself: EX0 mints its one-off setup key and hands
// it over through the usual claim. Switching a site on then routes its LAN as a
// network resource, and technicians reach LAN and box from the one tunnel they
// already sit in. Everything goes through the NetBird API of our stack (groups,
// keys, policies, network, resource, router), and the row in remote_access stays
// honest. Nothing here touches a customer system.
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
	// SettingAutoLAN ("1" by default) lets the server switch a site's LAN on by
	// itself once its box is a peer and reports its network (ADR-0017); "0" keeps
	// the switch manual.
	SettingAutoLAN = "remote.auto_lan"
	// PolicyName lets technicians into every switched-on LAN; PolicyBoxName lets
	// them onto the boxes themselves (SSH at the box's overlay address, ADR-0016).
	PolicyName    = "ex0: Techniker → Kunden-LANs"
	PolicyBoxName = "ex0: Techniker → Kunden-Boxen"
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

// Enable switches remote access on for a site: validates the LAN, then either wires
// the network right away (the box is already a peer) or leaves the row waiting for
// the box to join — the peer side runs by itself, see ensurePeer.
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
	// already a peer in our stack (the image joined it, or switched off earlier): wire now
	if box.NetbirdOpStatus == wire.NetbirdConnected && box.NetbirdOpIP != "" {
		ra.State, ra.Detail = store.RemoteJoining, "Box ist bereits im Techniker-Stack, Netzwerk wird angelegt"
		if err := s.Store.SetRemoteAccess(ctx, ra); err != nil {
			return ra, err
		}
		_ = s.Store.Audit(ctx, now, actor, "remote.enable", siteID, prefix.String())
		return s.wire(ctx, c, ra, box)
	}
	ra.Detail = "Box holt ihren Schlüssel für den Techniker-Stack mit dem nächsten Heartbeat"
	if k, err := s.Store.NetbirdKeyProfile(ctx, box.ID, wire.NetbirdProfileOperator); err == nil && k.ClaimedAt != nil {
		ra.State, ra.Detail = store.RemoteJoining, "Box hat den Schlüssel, verbindet sich mit dem Techniker-Stack"
	}
	if box.NetbirdOpStatus == "" {
		ra.Detail = "Box meldet keinen Operator-Daemon; mit dem Box-Image (provision-box.sh) bekommt sie ihren Schlüssel von selbst"
	}
	s.ensurePeer(ctx, c, box) // no need to wait for the next tick
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

// Remove deletes the network in our stack. The row stays, switched off, so the
// automatic switch does not put the LAN straight back; the box stays a peer — that
// is part of the box image, not of the site's switch.
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
	_ = s.Store.Audit(ctx, s.Now(), actor, "remote.remove", siteID, ra.CIDR)
	ra.NetworkID, ra.ResourceID, ra.RouterID, ra.PeerID, ra.PeerIP = "", "", "", "", ""
	ra.Enabled, ra.State, ra.Detail, ra.UpdatedAt = false, store.RemoteOff, "entfernt von "+actor+"; Einschalten legt das Netzwerk neu an", s.Now()
	return s.Store.SetRemoteAccess(ctx, ra)
}

// Reconcile moves everything forward: boxes that run the operator daemon get their
// key, a box that joined gets its network, an active row gets its peer state
// refreshed, a site whose box never joins runs into the timeout.
func (s *Service) Reconcile(ctx context.Context) {
	if c, err := s.client(ctx); err == nil {
		s.ensurePeers(ctx, c)
		s.ensureLANs(ctx)
	}
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

// ---- the peer side: every box with the operator daemon joins our stack ------------------

// ensurePeers hands every assigned box that runs the operator daemon a setup key for
// our stack, so the box is a peer there before anyone switches a LAN on.
func (s *Service) ensurePeers(ctx context.Context, c *netbird.Client) {
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		s.Log.Error("remote peers", "err", err)
		return
	}
	for _, b := range boxes {
		s.ensurePeer(ctx, c, b)
	}
}

// ensurePeer mints a key for one box when it needs one: it reports an operator
// daemon, is assigned, is not connected, and has no key in flight. A key nobody
// fetched within its lifetime is replaced; so is one the box fetched but whose
// daemon is still unconfigured two hours later (the up failed, or the daemon was
// reset). A daemon that has its config and is merely disconnected is left alone.
func (s *Service) ensurePeer(ctx context.Context, c *netbird.Client, box store.Box) {
	if box.RevokedAt != nil || box.SiteID == "" || box.NetbirdOpStatus == "" || box.NetbirdOpStatus == wire.NetbirdConnected {
		return
	}
	now := s.Now()
	k, err := s.Store.NetbirdKeyProfile(ctx, box.ID, wire.NetbirdProfileOperator)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		s.Log.Error("remote peer", "box", box.ID, "err", err)
		return
	case k.ClaimedAt == nil && now.Sub(k.CreatedAt) < keyTTL:
		return // the box has not fetched it yet
	case k.ClaimedAt != nil && (now.Sub(*k.ClaimedAt) < joinTimeout || box.NetbirdOpStatus != wire.NetbirdNotConfigured):
		return // fetched; the daemon is connecting, or has its config and retries on its own
	}
	if err := s.mintKey(ctx, c, box); err != nil {
		s.Log.Warn("remote peer key", "box", box.ID, "err", err)
	}
}

// mintKey creates a one-off setup key in the box group and stores it for the claim.
func (s *Service) mintKey(ctx context.Context, c *netbird.Client, box store.Box) error {
	_, boxGroup, err := s.ensurePolicies(ctx, c)
	if err != nil {
		return err
	}
	site, _ := s.Store.Site(ctx, box.SiteID)
	tenant, _ := s.Store.Tenant(ctx, site.TenantID)
	name := "ex0 " + firstNonEmpty(tenant.Name, site.TenantID) + " · " + firstNonEmpty(site.Name, box.SiteID) + " · " + firstNonEmpty(box.Name, box.ID)
	key, err := c.CreateSetupKey(ctx, name, []string{boxGroup.ID}, keyTTL)
	if err != nil {
		return fmt.Errorf("setup key: %w", err)
	}
	now := s.Now()
	if err := s.Store.SetNetbirdKey(ctx, store.NetbirdKey{BoxID: box.ID, Profile: wire.NetbirdProfileOperator, ManagementURL: s.setting(ctx, SettingURL, ""), SetupKey: key.Key, CreatedAt: now}); err != nil {
		return err
	}
	_ = s.Store.Audit(ctx, now, "server", "remote.peer_key", box.ID, name)
	s.Log.Info("remote peer key minted", "box", box.ID, "site", box.SiteID)
	return nil
}

// ensurePolicies makes sure the three groups and the two policies exist —
// technicians → LANs, technicians → boxes — and returns the LAN and box groups.
func (s *Service) ensurePolicies(ctx context.Context, c *netbird.Client) (lan, box netbird.Group, err error) {
	tech, err := c.EnsureGroup(ctx, s.setting(ctx, SettingTechGroup, DefaultTechGroup))
	if err != nil {
		return lan, box, fmt.Errorf("Gruppe: %w", err)
	}
	if lan, err = c.EnsureGroup(ctx, s.setting(ctx, SettingLANGroup, DefaultLANGroup)); err != nil {
		return lan, box, fmt.Errorf("Gruppe: %w", err)
	}
	if box, err = c.EnsureGroup(ctx, s.setting(ctx, SettingBoxGroup, DefaultBoxGroup)); err != nil {
		return lan, box, fmt.Errorf("Gruppe: %w", err)
	}
	if _, err = c.EnsurePolicy(ctx, PolicyName, []string{tech.ID}, []string{lan.ID}); err != nil {
		return lan, box, fmt.Errorf("Richtlinie: %w", err)
	}
	if _, err = c.EnsurePolicy(ctx, PolicyBoxName, []string{tech.ID}, []string{box.ID}); err != nil {
		return lan, box, fmt.Errorf("Richtlinie: %w", err)
	}
	return lan, box, nil
}

// ensureLANs switches remote access on for every site whose box is a peer and
// reports its network — unless the site has a row already: a person switched it
// off, or an earlier attempt left its reason there. Nobody types a LAN any more;
// the console shows what happened and lets a person change it.
func (s *Service) ensureLANs(ctx context.Context) {
	if s.setting(ctx, SettingAutoLAN, "1") != "1" {
		return
	}
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		return
	}
	for _, b := range boxes {
		if b.RevokedAt != nil || b.SiteID == "" || b.NetbirdOpStatus != wire.NetbirdConnected || b.NetbirdOpIP == "" || len(b.LAN) == 0 {
			continue
		}
		if _, err := s.Store.RemoteAccess(ctx, b.SiteID); err == nil {
			continue
		}
		lan := b.LAN[0]
		ra, err := s.Enable(ctx, b.SiteID, lan, "auto")
		if err != nil {
			// leave the reason where a person looks: the site's card
			site, _ := s.Store.Site(ctx, b.SiteID)
			now := s.Now()
			_ = s.Store.SetRemoteAccess(ctx, store.RemoteAccess{SiteID: b.SiteID, TenantID: site.TenantID, BoxID: b.ID, CIDR: lan, Enabled: false, State: store.RemoteError,
				Detail: "nicht automatisch eingeschaltet: " + err.Error(), RequestedBy: "auto", CreatedAt: now, UpdatedAt: now})
			s.Log.Warn("remote access not switched on automatically", "site", b.SiteID, "lan", lan, "err", err)
			continue
		}
		s.Log.Info("remote access switched on automatically", "site", b.SiteID, "lan", lan, "state", ra.State)
	}
}

// PeerState is one box's standing in the operator stack, as the CLI lists it.
type PeerState struct {
	BoxID   string
	BoxName string
	SiteID  string
	Status  string // what the box reports for its operator daemon
	IP      string
	Key     string // none | waiting since … | fetched …
}

// PeerStates lists every assigned box with what it reports and where its key stands.
func (s *Service) PeerStates(ctx context.Context) ([]PeerState, error) {
	boxes, err := s.Store.Boxes(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []PeerState
	for _, b := range boxes {
		if b.RevokedAt != nil || b.SiteID == "" {
			continue
		}
		p := PeerState{BoxID: b.ID, BoxName: b.Name, SiteID: b.SiteID, Status: b.NetbirdOpStatus, IP: b.NetbirdOpIP, Key: "none"}
		if p.Status == "" {
			p.Status = "no operator daemon"
		}
		if k, err := s.Store.NetbirdKeyProfile(ctx, b.ID, wire.NetbirdProfileOperator); err == nil {
			p.Key = "waiting since " + k.CreatedAt.Local().Format("02.01. 15:04")
			if k.ClaimedAt != nil {
				p.Key = "fetched " + k.ClaimedAt.Local().Format("02.01. 15:04")
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// ---- the site side: the LAN as a network resource ---------------------------------------

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
	lan, _, err := s.ensurePolicies(ctx, c)
	if err != nil {
		return s.failed(ctx, ra, err.Error())
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
