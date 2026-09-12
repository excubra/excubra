// Package discovery finds the devices in a box's LAN the gentle way (ADR-0007):
// listen to ARP and NDP, sweep the own subnet with ARP requests every fifteen
// minutes, optionally ping configured additional subnets, look vendors up in an
// embedded OUI table and names up in DNS and mDNS. There is no port scan in this
// package and no hook to add one.
package discovery

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/agent/guard"
	"github.com/excubra/excubra/internal/wire"
)

//go:embed oui.tsv.gz
var ouiData []byte

// Limits from ADR-0007.
const (
	MaxSubnets      = 8
	MaxPrefixBits   = 22 // never sweep more than a /22 (1024 addresses)
	DefaultMaxPPS   = 50
	HardMaxPPS      = 100
	DefaultInterval = 15 * time.Minute
	nameTTL         = time.Hour
	nameTimeout     = time.Second
	nameWorkers     = 8
)

// ErrUnsupported is returned by platform functions on non-Linux builds.
var ErrUnsupported = errors.New("discovery: raw sockets need Linux")

// ---- OUI ------------------------------------------------------------------------------

// OUI maps the first three bytes of a MAC to a vendor name.
type OUI struct {
	once    sync.Once
	vendors map[string]string
	err     error
}

// Lookup returns the vendor for a MAC ("" if unknown or malformed).
func (o *OUI) Lookup(mac string) string {
	o.once.Do(o.load)
	if o.err != nil {
		return ""
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < 3 {
		return ""
	}
	return o.vendors[fmt.Sprintf("%02X%02X%02X", hw[0], hw[1], hw[2])]
}

func (o *OUI) load() {
	gz, err := gzip.NewReader(bytes.NewReader(ouiData))
	if err != nil {
		o.err = err
		return
	}
	o.vendors = make(map[string]string, 40000)
	sc := bufio.NewScanner(gz)
	for sc.Scan() {
		prefix, vendor, ok := strings.Cut(sc.Text(), "\t")
		if ok {
			o.vendors[prefix] = vendor
		}
	}
	o.err = sc.Err()
}

// ---- names ------------------------------------------------------------------------------

// LookupFunc resolves an IP to a hostname; the default combines DNS and mDNS.
type LookupFunc func(ctx context.Context, ip string) string

// Names caches hostnames per IP so that a device is not resolved on every sighting.
type Names struct {
	Lookup LookupFunc
	mu     sync.Mutex
	cache  map[string]nameEntry
	sem    chan struct{}
}

type nameEntry struct {
	name string
	at   time.Time
}

// NewNames returns a resolver with the default DNS+mDNS lookup.
func NewNames() *Names {
	return &Names{Lookup: defaultLookup, cache: map[string]nameEntry{}, sem: make(chan struct{}, nameWorkers)}
}

// Get returns the cached name or resolves it (bounded concurrency, 1 s timeout).
func (n *Names) Get(ctx context.Context, ip string) string {
	if ip == "" {
		return ""
	}
	n.mu.Lock()
	if e, ok := n.cache[ip]; ok && time.Since(e.at) < nameTTL {
		n.mu.Unlock()
		return e.name
	}
	n.mu.Unlock()
	select {
	case n.sem <- struct{}{}:
	case <-ctx.Done():
		return ""
	}
	defer func() { <-n.sem }()
	cctx, cancel := context.WithTimeout(ctx, nameTimeout)
	defer cancel()
	name := ""
	if n.Lookup != nil {
		name = n.Lookup(cctx, ip)
	}
	n.mu.Lock()
	n.cache[ip] = nameEntry{name: name, at: time.Now()}
	if len(n.cache) > 4096 { // a site does not have more devices than that; drop the oldest half
		type kv struct {
			k string
			t time.Time
		}
		all := make([]kv, 0, len(n.cache))
		for k, v := range n.cache {
			all = append(all, kv{k, v.at})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
		for _, e := range all[:len(all)/2] {
			delete(n.cache, e.k)
		}
	}
	n.mu.Unlock()
	return name
}

func defaultLookup(ctx context.Context, ip string) string {
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	if name := mdnsLookup(ctx, ip); name != "" {
		return name
	}
	return ""
}

// ---- sighting table --------------------------------------------------------------------

type entry struct {
	MAC      string
	IP       string
	IPv6     map[string]struct{}
	Hostname string
	Vendor   string
	LastSeen time.Time
}

func (e *entry) key() string {
	if e.MAC != "" {
		return e.MAC
	}
	return "ip:" + e.IP
}

// Table collects sightings between heartbeats. Drain hands them out, Ack forgets
// them once the server has them, Nack keeps them for the next try.
type Table struct {
	mu       sync.Mutex
	entries  map[string]*entry
	dirty    map[string]struct{}
	inflight map[string]struct{}
	now      func() time.Time
}

// NewTable returns an empty table.
func NewTable() *Table {
	return &Table{entries: map[string]*entry{}, dirty: map[string]struct{}{}, inflight: map[string]struct{}{}, now: time.Now}
}

// See records that a device was seen. mac may be empty (ICMP sweep of another
// subnet), ip may be empty (an IPv6-only neighbor).
func (t *Table) See(mac, ip, ip6 string) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if mac == "" && ip == "" {
		return
	}
	// link-local addresses are plumbing (the veth pair into the operator namespace,
	// a client without DHCP), not devices of the customer's network
	if a, err := netip.ParseAddr(ip); err == nil && a.IsLinkLocalUnicast() {
		return
	}
	if mac != "" {
		if _, err := net.ParseMAC(mac); err != nil {
			return
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := &entry{MAC: mac, IP: ip}
	if cur, ok := t.entries[e.key()]; ok {
		e = cur
		if ip != "" {
			e.IP = ip
		}
	} else {
		t.entries[e.key()] = e
	}
	if ip6 != "" {
		if e.IPv6 == nil {
			e.IPv6 = map[string]struct{}{}
		}
		e.IPv6[ip6] = struct{}{}
	}
	e.LastSeen = t.now()
	t.dirty[e.key()] = struct{}{}
}

// Annotate fills vendor and hostname where missing, for entries about to be sent.
func (t *Table) Annotate(ctx context.Context, oui *OUI, names *Names) {
	t.mu.Lock()
	var todo []*entry
	for k := range t.dirty {
		if e, ok := t.entries[k]; ok && (e.Vendor == "" || e.Hostname == "") {
			todo = append(todo, e)
		}
	}
	t.mu.Unlock()
	for _, e := range todo {
		vendor, host := e.Vendor, e.Hostname
		if vendor == "" && e.MAC != "" && oui != nil {
			vendor = oui.Lookup(e.MAC)
		}
		if host == "" && e.IP != "" && names != nil {
			host = names.Get(ctx, e.IP)
		}
		t.mu.Lock()
		e.Vendor, e.Hostname = vendor, host
		t.mu.Unlock()
	}
}

// Drain returns every device seen since the last Ack, at most wire.MaxSightings,
// most recent first, and marks them in flight.
func (t *Table) Drain() []wire.Sighting {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k := range t.dirty {
		t.inflight[k] = struct{}{}
	}
	t.dirty = map[string]struct{}{}
	out := make([]wire.Sighting, 0, len(t.inflight))
	for k := range t.inflight {
		e, ok := t.entries[k]
		if !ok {
			continue
		}
		s := wire.Sighting{MAC: e.MAC, IP: e.IP, Vendor: e.Vendor, Hostname: e.Hostname, LastSeen: e.LastSeen.UTC()}
		for v6 := range e.IPv6 {
			s.IPv6 = append(s.IPv6, v6)
		}
		sort.Strings(s.IPv6)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > wire.MaxSightings {
		out = out[:wire.MaxSightings]
	}
	return out
}

// Ack forgets what was in flight: the server has it.
func (t *Table) Ack() {
	t.mu.Lock()
	t.inflight = map[string]struct{}{}
	t.mu.Unlock()
}

// Nack keeps in-flight sightings for the next heartbeat.
func (t *Table) Nack() {
	t.mu.Lock()
	for k := range t.inflight {
		t.dirty[k] = struct{}{}
	}
	t.inflight = map[string]struct{}{}
	t.mu.Unlock()
}

// Address is a known device's IPv4 address with its MAC, for the service scan.
type Address struct {
	IP  string
	MAC string
}

// Addresses lists every known device with an IPv4 address.
func (t *Table) Addresses() []Address {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Address, 0, len(t.entries))
	for _, e := range t.entries {
		if e.IP != "" {
			out = append(out, Address{IP: e.IP, MAC: e.MAC})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Len returns the number of known devices.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// ---- the discovery service -------------------------------------------------------------

// Config is the effective discovery configuration.
type Config struct {
	Mode     string
	Subnets  []netip.Prefix
	Interval time.Duration
	MaxPPS   int
}

// ParseConfig validates the pulled configuration and returns what the agent can
// do plus the reasons for what it refuses (for config_errors).
func ParseConfig(c wire.DiscoveryConfig) (Config, []string) {
	var errs []string
	cfg := Config{Mode: wire.DiscoveryPassive, Interval: DefaultInterval, MaxPPS: DefaultMaxPPS}
	switch c.Mode {
	case wire.DiscoveryPassive, "":
	case wire.DiscoverySweep:
		cfg.Mode = wire.DiscoverySweep
	default:
		errs = append(errs, fmt.Sprintf("discovery: unknown mode %q, using passive", c.Mode))
	}
	if c.SweepIntervalS > 0 {
		cfg.Interval = time.Duration(c.SweepIntervalS) * time.Second
		if cfg.Interval < 5*time.Minute {
			cfg.Interval = 5 * time.Minute
			errs = append(errs, "discovery: sweep interval below 5 minutes, using 5 minutes")
		}
	}
	if c.MaxPPS > 0 {
		cfg.MaxPPS = c.MaxPPS
		if cfg.MaxPPS > HardMaxPPS {
			cfg.MaxPPS = HardMaxPPS
			errs = append(errs, fmt.Sprintf("discovery: max_pps above %d, capped", HardMaxPPS))
		}
	}
	for i, s := range c.Subnets {
		if i >= MaxSubnets {
			errs = append(errs, fmt.Sprintf("discovery: more than %d subnets, ignoring the rest", MaxSubnets))
			break
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil || !p.Addr().Is4() {
			errs = append(errs, fmt.Sprintf("discovery: subnet %q is not an IPv4 CIDR", s))
			continue
		}
		if p.Bits() < MaxPrefixBits {
			errs = append(errs, fmt.Sprintf("discovery: subnet %s is larger than a /%d, ignored", s, MaxPrefixBits))
			continue
		}
		cfg.Subnets = append(cfg.Subnets, p.Masked())
	}
	return cfg, errs
}

// Discovery runs the passive listener and the sweeps and feeds one Table.
type Discovery struct {
	Log   *slog.Logger
	Table *Table
	OUI   *OUI
	Names *Names
	// ARP, when set, gets every ARP frame the passive listener reads (the sentinel).
	ARP func(ARPFrame)

	mu  sync.Mutex
	cfg Config
	// platform hooks, replaced in tests
	passive   func(ctx context.Context, see func(mac, ip, ip6 string), observe func(ARPFrame)) error
	arpSweep  func(ctx context.Context, maxPPS int, see func(mac, ip, ip6 string)) error
	icmpSweep func(ctx context.Context, prefixes []netip.Prefix, maxPPS int, see func(mac, ip, ip6 string)) error
	neighbors func(see func(mac, ip, ip6 string)) error
}

// New returns a discovery service with the platform implementation.
func New(log *slog.Logger) *Discovery {
	if log == nil {
		log = slog.Default()
	}
	d := &Discovery{Log: log, Table: NewTable(), OUI: &OUI{}, Names: NewNames(), cfg: Config{Mode: wire.DiscoveryPassive, Interval: DefaultInterval, MaxPPS: DefaultMaxPPS}}
	d.passive, d.arpSweep, d.icmpSweep, d.neighbors = platformPassive, platformARPSweep, platformICMPSweep, platformNeighbors
	return d
}

// Apply installs a new configuration; the sweep loop picks it up at its next tick.
func (d *Discovery) Apply(c Config) {
	d.mu.Lock()
	d.cfg = c
	d.mu.Unlock()
}

func (d *Discovery) config() Config {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg
}

// Run keeps the passive listener alive and runs sweeps until ctx ends. The
// listener is restarted after errors with a backoff; a box without raw-socket
// rights still works, it just discovers less and says so in the log.
func (d *Discovery) Run(ctx context.Context) {
	go d.runPassive(ctx)
	// first sweep shortly after start, then every interval
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		cfg := d.config()
		d.sweep(ctx, cfg)
		timer.Reset(cfg.Interval)
	}
}

func (d *Discovery) runPassive(ctx context.Context) {
	backoff := 5 * time.Second
	for {
		err := d.passiveGuarded(ctx)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrUnsupported) {
			d.Log.Warn("discovery: passive listening not available on this platform")
			return
		}
		d.Log.Warn("discovery: passive listener stopped", "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 5*time.Minute {
			backoff *= 2
		}
	}
}

// observe hands a frame to the ARP observer, if there is one; a frame that
// trips an observer is dropped, the listener goes on.
func (d *Discovery) observe(f ARPFrame) {
	if d.ARP != nil {
		defer guard.Recover(d.Log, "arp frame")
		d.ARP(f)
	}
}

// passiveGuarded runs the platform listener; a panic in it (a frame the parser
// did not expect) becomes an error, and the loop restarts the listener.
func (d *Discovery) passiveGuarded(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("passive listener panicked: %v", r)
		}
	}()
	return d.passive(ctx, d.Table.See, d.observe)
}

// sweep does one round: neighbor tables always, ARP and ICMP only in sweep mode.
func (d *Discovery) sweep(ctx context.Context, cfg Config) {
	if err := d.neighbors(d.Table.See); err != nil && !errors.Is(err, ErrUnsupported) {
		d.Log.Debug("discovery: neighbor table", "err", err)
	}
	if cfg.Mode != wire.DiscoverySweep {
		return
	}
	if err := d.arpSweep(ctx, cfg.MaxPPS, d.Table.See); err != nil && !errors.Is(err, ErrUnsupported) {
		d.Log.Warn("discovery: arp sweep", "err", err)
	}
	if len(cfg.Subnets) > 0 {
		if err := d.icmpSweep(ctx, cfg.Subnets, cfg.MaxPPS, d.Table.See); err != nil && !errors.Is(err, ErrUnsupported) {
			d.Log.Warn("discovery: icmp sweep", "err", err)
		}
	}
}

// SweepNow runs one sweep round immediately with the current configuration and
// returns how many devices the table holds afterwards (the "sweep" task, ADR-0014).
func (d *Discovery) SweepNow(ctx context.Context) int {
	d.sweep(ctx, d.config())
	return d.Table.Len()
}

// Sightings annotates and drains the table for a heartbeat.
func (d *Discovery) Sightings(ctx context.Context) []wire.Sighting {
	d.Table.Annotate(ctx, d.OUI, d.Names)
	return d.Table.Drain()
}

// rateLimiter paces packet sends to at most pps per second.
type rateLimiter struct {
	interval time.Duration
	next     time.Time
}

func newRateLimiter(pps int) *rateLimiter {
	if pps <= 0 {
		pps = DefaultMaxPPS
	}
	return &rateLimiter{interval: time.Second / time.Duration(pps)}
}

func (r *rateLimiter) wait(ctx context.Context) bool {
	now := time.Now()
	if r.next.After(now) {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(r.next.Sub(now)):
		}
	}
	r.next = time.Now().Add(r.interval)
	return true
}

// clampPrefix shrinks a prefix to at most /MaxPrefixBits around addr.
func clampPrefix(p netip.Prefix) netip.Prefix {
	if p.Bits() >= MaxPrefixBits {
		return p.Masked()
	}
	return netip.PrefixFrom(p.Addr(), MaxPrefixBits).Masked()
}

// hosts enumerates the usable addresses of an IPv4 prefix (without network and
// broadcast for prefixes shorter than /31).
func hosts(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	var out []netip.Addr
	first := p.Addr()
	n := 1 << (32 - p.Bits())
	for i := 0; i < n; i++ {
		a := first
		for j := 0; j < i; j++ {
			a = a.Next()
		}
		if p.Bits() < 31 && (i == 0 || i == n-1) {
			continue
		}
		out = append(out, a)
	}
	return out
}
