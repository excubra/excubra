// Package sentinel is the box's live detection (ADR-0018 §7): decoy ports that
// look like the services an intruder goes for, a watcher that counts every SYN
// the box receives, and the ARP signals the passive listener hands in. It
// reports. It never answers a byte of protocol and never sends a packet of its
// own — a listener that accepts, waits and closes is all the "service" there is.
package sentinel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/agent/discovery"
	"github.com/excubra/excubra/internal/wire"
)

// Thresholds and bounds. A healthy LAN never reaches them; a scanner does within
// its first second.
const (
	window       = time.Minute      // the sliding window of the counters
	scanPorts    = 8                // distinct ports of the box within the window: a port scan
	arpScanHosts = 100              // distinct addresses asked within the window: the network is being searched
	flapWindow   = 10 * time.Minute // an address changing its MAC this often is spoofed, not re-leased
	flapChanges  = 3
	maxSources   = 2048            // per-source windows kept; beyond that the stalest goes
	maxPending   = wire.MaxSignals // signals waiting for a heartbeat; beyond that the oldest goes (ADR-0007: drop oldest)
	maxPorts     = 16
	maxConns     = 32              // decoy connections held at once
	connLinger   = 3 * time.Second // how long a decoy holds a connection before closing it
	rebindEvery  = 30 * time.Second
	detailPorts  = 12 // ports named in a port_scan signal
)

// DefaultPorts are the decoys: what ransomware, worms and a hand on the keyboard
// look for first. 22 is never a decoy — the box may run real SSH there.
var DefaultPorts = []int{445, 3389, 23, 1433, 5900}

// Config is the effective live-detection configuration.
type Config struct {
	Enabled bool
	Ports   []int
}

// ParseConfig validates the pulled configuration and returns what the box will do
// plus the reasons for what it refuses (for config_errors).
func ParseConfig(c wire.CanaryConfig) (Config, []string) {
	cfg := Config{Enabled: c.Enabled, Ports: append([]int(nil), DefaultPorts...)}
	var errs []string
	if len(c.Ports) > 0 {
		cfg.Ports = nil
		seen := map[int]bool{}
		for i, p := range c.Ports {
			if i >= maxPorts {
				errs = append(errs, fmt.Sprintf("canary: more than %d ports, ignoring the rest", maxPorts))
				break
			}
			switch {
			case p < 1 || p > 65535:
				errs = append(errs, fmt.Sprintf("canary: port %d is not a port", p))
			case p == 22:
				errs = append(errs, "canary: port 22 is never a decoy (real SSH may live there)")
			case !seen[p]:
				seen[p] = true
				cfg.Ports = append(cfg.Ports, p)
			}
		}
	}
	sort.Ints(cfg.Ports)
	return cfg, errs
}

// Self is what the box knows about itself on the LAN: its own frames are never a
// signal, and the gateway is the address whose MAC must not change.
type Self struct {
	IP      string
	MAC     string
	Gateway string
}

// Sentinel holds the counters and the decoy listeners.
type Sentinel struct {
	Log *slog.Logger
	Now func() time.Time
	// Listen opens a decoy listener; replaced in tests.
	Listen func(ctx context.Context, addr string) (net.Listener, error)
	// LAN returns the box's own address, MAC and gateway; the platform default
	// reads the route table, tests set it.
	LAN func() Self
	// watch is the platform SYN watcher (raw_linux.go); replaced in tests.
	watch func(ctx context.Context, observe func(frame []byte)) error

	mu       sync.Mutex
	cfg      Config
	self     Self
	decoys   map[int]bool
	armed    map[int]*decoy // listeners by port
	failed   map[int]bool   // ports that could not be bound, logged once
	raw      bool           // the SYN watcher runs; then the listeners only look open and do not count
	stopRaw  context.CancelFunc
	sem      chan struct{}
	syn      map[string]*counter // by source IP: distinct destination ports
	arp      map[string]*counter // by source MAC: distinct addresses asked for
	claims   map[string]*claim   // by IP: the MAC that claims it, and its changes
	pending  map[string]*wire.Signal
	order    []string // pending keys, oldest first
	inflight map[string]*wire.Signal
}

type decoy struct {
	ln net.Listener
	ip string
}

// counter is a sliding window of distinct keys per source.
type counter struct {
	items  map[string]time.Time
	pruned time.Time
	alarm  bool // over the threshold; cleared once the window has emptied
}

type claim struct {
	mac     string
	changes []time.Time
	seen    time.Time
}

// New returns a sentinel with the platform watcher.
func New(log *slog.Logger) *Sentinel {
	if log == nil {
		log = slog.Default()
	}
	s := &Sentinel{Log: log, Now: time.Now, LAN: platformSelf, watch: platformWatch,
		decoys: map[int]bool{}, armed: map[int]*decoy{}, failed: map[int]bool{}, sem: make(chan struct{}, maxConns),
		syn: map[string]*counter{}, arp: map[string]*counter{}, claims: map[string]*claim{},
		pending: map[string]*wire.Signal{}, inflight: map[string]*wire.Signal{}}
	s.Listen = func(ctx context.Context, addr string) (net.Listener, error) {
		return (&net.ListenConfig{}).Listen(ctx, "tcp4", addr)
	}
	return s
}

// Apply installs a new configuration; the loop picks it up at its next tick.
// Every method tolerates a nil sentinel (an agent built without one, in tests).
func (s *Sentinel) Apply(c Config) {
	if s == nil {
		return
	}
	s.mu.Lock()
	changed := c.Enabled != s.cfg.Enabled || !slices.Equal(c.Ports, s.cfg.Ports)
	s.cfg = c
	s.decoys = map[int]bool{}
	for _, p := range c.Ports {
		s.decoys[p] = true
	}
	if changed {
		s.failed = map[int]bool{} // a port that failed to bind gets another try (and another log line) only when the config changed
	}
	s.mu.Unlock()
}

func (s *Sentinel) config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Run keeps the SYN watcher and the decoy listeners alive while the detection is
// switched on, until ctx ends. Switched off, nothing listens and nothing counts.
func (s *Sentinel) Run(ctx context.Context) {
	if s == nil {
		return
	}
	t := time.NewTicker(rebindEvery)
	defer t.Stop()
	for {
		s.rebind(ctx)
		select {
		case <-ctx.Done():
			s.disarm(nil)
			s.stopWatch()
			return
		case <-t.C:
		}
	}
}

// startWatch runs the platform SYN watcher in the background once.
func (s *Sentinel) startWatch(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopRaw != nil {
		return
	}
	wctx, cancel := context.WithCancel(ctx)
	s.stopRaw = cancel
	go s.runWatch(wctx)
}

func (s *Sentinel) stopWatch() {
	s.mu.Lock()
	stop := s.stopRaw
	s.stopRaw = nil
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// runWatch runs the platform SYN watcher and restarts it after errors with a
// backoff; a box without raw-socket rights still has its listeners.
func (s *Sentinel) runWatch(ctx context.Context) {
	backoff := 5 * time.Second
	for {
		s.setRaw(true)
		err := s.watch(ctx, s.observeFrame)
		s.setRaw(false)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, discovery.ErrUnsupported) {
			s.Log.Warn("sentinel: SYN watcher not available on this platform; decoys count on their own")
			return
		}
		s.Log.Warn("sentinel: SYN watcher stopped", "err", err, "retry_in", backoff)
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

func (s *Sentinel) setRaw(on bool) {
	s.mu.Lock()
	s.raw = on
	s.mu.Unlock()
}

// rebind opens the decoys the config wants on the LAN address and closes the
// rest; a changed address (DHCP) moves them. The watcher follows the switch.
func (s *Sentinel) rebind(ctx context.Context) {
	cfg := s.config()
	self := s.LAN()
	s.mu.Lock()
	s.self = self
	s.mu.Unlock()
	if cfg.Enabled {
		s.startWatch(ctx)
	} else {
		s.stopWatch()
	}
	want := map[int]bool{}
	if cfg.Enabled && self.IP != "" {
		for _, p := range cfg.Ports {
			want[p] = true
		}
	}
	s.disarm(func(port int, d *decoy) bool { return !want[port] || d.ip != self.IP })
	for _, p := range cfg.Ports {
		if !want[p] {
			continue
		}
		s.mu.Lock()
		_, armed := s.armed[p]
		failed := s.failed[p]
		s.mu.Unlock()
		if armed || failed {
			continue
		}
		ln, err := s.Listen(ctx, net.JoinHostPort(self.IP, strconv.Itoa(p)))
		if err != nil {
			s.mu.Lock()
			s.failed[p] = true
			s.mu.Unlock()
			s.Log.Warn("sentinel: decoy port not bound", "port", p, "err", err)
			continue
		}
		s.mu.Lock()
		s.armed[p] = &decoy{ln: ln, ip: self.IP}
		s.mu.Unlock()
		go s.accept(ctx, ln, p)
	}
}

// disarm closes the listeners the predicate selects (all of them for nil).
func (s *Sentinel) disarm(drop func(port int, d *decoy) bool) {
	s.mu.Lock()
	var closing []net.Listener
	for p, d := range s.armed {
		if drop == nil || drop(p, d) {
			closing = append(closing, d.ln)
			delete(s.armed, p)
		}
	}
	s.mu.Unlock()
	for _, ln := range closing {
		_ = ln.Close()
	}
}

// accept holds every connection to a decoy for a moment and closes it. Without
// the SYN watcher, the connection itself is the signal.
func (s *Sentinel) accept(ctx context.Context, ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case s.sem <- struct{}{}:
		default:
			_ = conn.Close() // over the bound: a flood; the watcher counts it anyway
			continue
		}
		go func() {
			defer func() { <-s.sem; _ = conn.Close() }()
			if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
				s.mu.Lock()
				raw := s.raw
				s.mu.Unlock()
				if !raw {
					s.touch(host, "", port, s.Now())
				}
			}
			_ = conn.SetDeadline(time.Now().Add(connLinger))
			buf := make([]byte, 64)
			_, _ = conn.Read(buf) // whatever they say, it is discarded
			select {
			case <-ctx.Done():
			case <-time.After(connLinger):
			}
		}()
	}
}

// Armed lists the decoy ports currently listening, for the heartbeat.
func (s *Sentinel) Armed() []int {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]int, 0, len(s.armed))
	for p := range s.armed {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// ---- observations -------------------------------------------------------------------------

// ObserveARP is the discovery's ARP observer: requests count towards a search of
// the network, and every sender claims its address — a claim that moves to
// another MAC is the spoofing signal.
func (s *Sentinel) ObserveARP(f discovery.ARPFrame) {
	if s == nil {
		return
	}
	mac := strings.ToLower(f.SenderMAC)
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cfg.Enabled || mac == "" || mac == s.self.MAC || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return
	}
	if f.Op == 1 && f.TargetIP != "" && f.TargetIP != f.SenderIP {
		c := s.counterFor(s.arp, mac, now)
		n := c.add(f.TargetIP, now)
		if n >= arpScanHosts {
			c.alarm = true
			s.record(wire.Signal{Kind: wire.SignalARPScan, IP: f.SenderIP, MAC: mac, Count: n}, false, now)
		}
	}
	if f.SenderIP == "" || f.SenderIP == "0.0.0.0" {
		return
	}
	cl, ok := s.claims[f.SenderIP]
	if !ok {
		if len(s.claims) >= maxSources*2 {
			s.dropClaim()
		}
		s.claims[f.SenderIP] = &claim{mac: mac, seen: now}
		return
	}
	cl.seen = now
	if cl.mac == mac {
		return
	}
	old := cl.mac
	cl.mac = mac
	kept := cl.changes[:0]
	for _, t := range cl.changes {
		if now.Sub(t) <= flapWindow {
			kept = append(kept, t)
		}
	}
	cl.changes = append(kept, now)
	switch {
	case f.SenderIP == s.self.Gateway:
		s.record(wire.Signal{Kind: wire.SignalARPSpoof, IP: f.SenderIP, MAC: mac, Count: len(cl.changes), Detail: "gateway " + old + " → " + mac}, false, now)
	case len(cl.changes) >= flapChanges:
		s.record(wire.Signal{Kind: wire.SignalARPSpoof, IP: f.SenderIP, MAC: mac, Count: len(cl.changes), Detail: "flapping " + old + " → " + mac}, false, now)
	}
}

// observeFrame is the SYN watcher's callback: an Ethernet+IPv4+TCP frame with SYN
// set and ACK clear, addressed to the box.
func (s *Sentinel) observeFrame(f []byte) {
	srcMAC, src, dst, port, ok := parseSYN(f)
	if !ok {
		return
	}
	s.mu.Lock()
	self := s.self
	s.mu.Unlock()
	if dst != self.IP || src == self.IP || src == "" {
		return
	}
	if a, err := netip.ParseAddr(src); err != nil || a.IsLinkLocalUnicast() {
		return
	}
	s.observeSYN(srcMAC, src, port, s.Now())
}

// observeSYN counts one SYN from a source to a port of the box.
func (s *Sentinel) observeSYN(srcMAC, src string, port int, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decoys[port] {
		s.record(wire.Signal{Kind: wire.SignalCanary, IP: src, MAC: srcMAC, Port: port, Count: 1}, true, now)
	}
	c := s.counterFor(s.syn, src, now)
	n := c.add(strconv.Itoa(port), now)
	if n >= scanPorts {
		c.alarm = true
		s.recordScan(wire.Signal{Kind: wire.SignalPortScan, IP: src, MAC: srcMAC, Count: n, Detail: c.detail()}, now)
	}
}

// touch is a decoy connection without the SYN watcher.
func (s *Sentinel) touch(src, srcMAC string, port int, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if src == s.self.IP {
		return
	}
	s.record(wire.Signal{Kind: wire.SignalCanary, IP: src, MAC: srcMAC, Port: port, Count: 1}, true, now)
}

// Record files signals another sensor produced (a connector reading a device's
// logs, the DNS sensor): they travel with the box's own, merged per source and
// kind, counts adding up.
func (s *Sentinel) Record(sigs []wire.Signal) {
	if s == nil {
		return
	}
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sg := range sigs {
		if sg.Kind == "" {
			continue
		}
		s.record(sg, additive(sg.Kind), now)
	}
}

// recordScan is record for a signal whose Detail changes as it grows (the port
// list of a scan): merged by source, the newest detail wins.
func (s *Sentinel) recordScan(sg wire.Signal, now time.Time) {
	detail := sg.Detail
	sg.Detail = ""
	s.record(sg, false, now)
	if cur, ok := s.pending[sg.Kind+"|"+sg.DeviceID+"|"+sg.IP+"|"+sg.MAC+"|"+strconv.Itoa(sg.Port)+"|"]; ok {
		cur.Detail = detail
	}
}

// record files a signal for the next heartbeat. Signals of one key merge: touches
// add up, counts of a search take the latest value. Beyond the bound the oldest
// pending signal goes.
func (s *Sentinel) record(sg wire.Signal, accumulate bool, now time.Time) {
	key := sg.Kind + "|" + sg.DeviceID + "|" + sg.IP + "|" + sg.MAC + "|" + strconv.Itoa(sg.Port) + "|" + sg.Detail
	if cur, ok := s.pending[key]; ok {
		if accumulate {
			cur.Count += sg.Count
		} else {
			cur.Count = sg.Count
		}
		if sg.Detail != "" {
			cur.Detail = sg.Detail
		}
		cur.LastAt = now.UTC()
		if !sg.LastAt.IsZero() && sg.LastAt.After(cur.LastAt) {
			cur.LastAt = sg.LastAt.UTC()
		}
		return
	}
	for len(s.pending) >= maxPending && len(s.order) > 0 {
		delete(s.pending, s.order[0])
		s.order = s.order[1:]
	}
	if sg.FirstAt.IsZero() {
		sg.FirstAt = now.UTC()
	}
	if sg.LastAt.IsZero() {
		sg.LastAt = now.UTC()
	}
	s.pending[key] = &sg
	s.order = append(s.order, key)
}

func (s *Sentinel) counterFor(m map[string]*counter, source string, now time.Time) *counter {
	c, ok := m[source]
	if ok {
		return c
	}
	if len(m) >= maxSources {
		stalest, at := "", now
		for k, v := range m {
			if v.pruned.Before(at) {
				stalest, at = k, v.pruned
			}
		}
		delete(m, stalest)
	}
	c = &counter{items: map[string]time.Time{}, pruned: now}
	m[source] = c
	return c
}

func (s *Sentinel) dropClaim() {
	stalest, at := "", time.Time{}
	for k, v := range s.claims {
		if stalest == "" || v.seen.Before(at) {
			stalest, at = k, v.seen
		}
	}
	delete(s.claims, stalest)
}

// add records one key and returns the distinct keys within the window.
func (c *counter) add(key string, now time.Time) int {
	c.items[key] = now
	if now.Sub(c.pruned) > window/4 {
		for k, t := range c.items {
			if now.Sub(t) > window {
				delete(c.items, k)
			}
		}
		c.pruned = now
		if len(c.items) == 0 {
			c.alarm = false
		}
	}
	return len(c.items)
}

// detail names the first ports of a scan, numerically.
func (c *counter) detail() string {
	ports := make([]int, 0, len(c.items))
	for k := range c.items {
		if p, err := strconv.Atoi(k); err == nil {
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	parts := make([]string, 0, detailPorts+1)
	for i, p := range ports {
		if i == detailPorts {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ", ")
}

// ---- the heartbeat side -------------------------------------------------------------------

// Drain hands the pending signals to a heartbeat, oldest first, and marks them in
// flight; nothing new is drained while a batch is in flight.
func (s *Sentinel) Drain() []wire.Signal {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 || len(s.inflight) > 0 {
		return nil
	}
	out := make([]wire.Signal, 0, len(s.order))
	for _, k := range s.order {
		if sg, ok := s.pending[k]; ok {
			out = append(out, *sg)
			s.inflight[k] = sg
		}
	}
	s.pending = map[string]*wire.Signal{}
	s.order = nil
	return out
}

// Ack forgets what was in flight: the server has it.
func (s *Sentinel) Ack() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.inflight = map[string]*wire.Signal{}
	s.mu.Unlock()
}

// Nack merges what was in flight back into the pending signals for the next try.
func (s *Sentinel) Nack() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.inflight))
	for k := range s.inflight {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return s.inflight[keys[i]].FirstAt.Before(s.inflight[keys[j]].FirstAt) })
	order := make([]string, 0, len(keys)+len(s.order))
	for _, k := range keys {
		old := s.inflight[k]
		if cur, ok := s.pending[k]; ok {
			if additive(old.Kind) {
				cur.Count += old.Count
			}
			cur.FirstAt = old.FirstAt
			continue
		}
		s.pending[k] = old
		order = append(order, k)
	}
	s.order = append(order, s.order...)
	s.inflight = map[string]*wire.Signal{}
}

// additive reports whether a kind's Count is a number of events (which add up)
// rather than a size (which is replaced).
func additive(kind string) bool {
	switch kind {
	case wire.SignalCanary, wire.SignalFGTAdminFail, wire.SignalFGTVPNFail, wire.SignalFGTIPS, wire.SignalDNSBlock:
		return true
	}
	return false
}

// parseSYN decodes an Ethernet+IPv4+TCP frame and reports source MAC, source and
// destination address and destination port when it is a SYN without ACK.
func parseSYN(f []byte) (srcMAC, src, dst string, port int, ok bool) {
	if len(f) < 54 || f[12] != 0x08 || f[13] != 0x00 {
		return "", "", "", 0, false
	}
	ihl := int(f[14]&0x0f) * 4
	if ihl < 20 || len(f) < 14+ihl+20 || f[23] != 6 {
		return "", "", "", 0, false
	}
	if int(f[20]&0x1f)<<8|int(f[21]) != 0 { // a fragment other than the first
		return "", "", "", 0, false
	}
	tcp := f[14+ihl:]
	if tcp[13]&0x12 != 0x02 { // SYN set, ACK clear
		return "", "", "", 0, false
	}
	return net.HardwareAddr(f[6:12]).String(), net.IP(f[26:30]).String(), net.IP(f[30:34]).String(), int(tcp[2])<<8 | int(tcp[3]), true
}
