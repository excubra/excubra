// Package scan is the box's service scan (ADR-0018, decision E20): a rate-limited
// TCP connect scan of the devices the discovery knows, reading banners, HTTP titles
// and TLS certificates. It enumerates and reads. It never exploits, never tries a
// credential, and runs only on the schedule the configuration sets — never on a
// call from the server.
package scan

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// Limits and defaults.
const (
	DefaultInterval = 24 * time.Hour
	MinInterval     = time.Hour
	DefaultMaxPPS   = 20
	HardMaxPPS      = 50
	MaxPorts        = 128
	MaxTargets      = 1024
	dialTimeout     = 1500 * time.Millisecond
	probeTimeout    = 3 * time.Second
	parallel        = 16
	firstRoundAfter = 3 * time.Minute
)

// DefaultPorts is the built-in list: what small networks run and what an attacker
// looks for first. Order does not matter; every port is tried on every host.
var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 515, 548, 554, 587, 631, 636, 873, 993, 995,
	1433, 1521, 1723, 2049, 2375, 3000, 3306, 3389, 4443, 5000, 5060, 5061, 5432, 5900, 5985, 5986, 6379,
	8000, 8006, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 9443, 10000, 27017, 62078,
}

// DefaultExternalPorts is what an outpost asks a customer's public address: the
// doors an attacker tries first.
var DefaultExternalPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631, 636, 873, 993, 995, 1194, 1433, 1521, 1723, 2049, 2375,
	3306, 3389, 4443, 5000, 5060, 5061, 5432, 5900, 5985, 5986, 6379, 8000, 8006, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 9443, 10000, 27017,
}

// Config is the effective scan configuration.
type Config struct {
	Enabled  bool
	Interval time.Duration
	MaxPPS   int
	Ports    []int
	Exclude  []netip.Prefix
	External []Target // set: scan these public addresses instead of the LAN
}

// ParseConfig validates the pulled configuration and returns what the box will do
// plus the reasons for what it refuses (for config_errors).
func ParseConfig(c wire.ScanConfig) (Config, []string) {
	var errs []string
	cfg := Config{Enabled: c.Enabled, Interval: DefaultInterval, MaxPPS: DefaultMaxPPS, Ports: DefaultPorts}
	if c.IntervalS > 0 {
		cfg.Interval = time.Duration(c.IntervalS) * time.Second
		if cfg.Interval < MinInterval {
			cfg.Interval = MinInterval
			errs = append(errs, "scan: interval below an hour, using an hour")
		}
	}
	if c.MaxPPS > 0 {
		cfg.MaxPPS = c.MaxPPS
		if cfg.MaxPPS > HardMaxPPS {
			cfg.MaxPPS = HardMaxPPS
			errs = append(errs, fmt.Sprintf("scan: max_pps above %d, capped", HardMaxPPS))
		}
	}
	if len(c.Ports) > 0 {
		seen := map[int]bool{}
		var ports []int
		for _, p := range c.Ports {
			if p < 1 || p > 65535 || seen[p] {
				continue
			}
			seen[p] = true
			ports = append(ports, p)
			if len(ports) >= MaxPorts {
				errs = append(errs, fmt.Sprintf("scan: more than %d ports, ignoring the rest", MaxPorts))
				break
			}
		}
		if len(ports) > 0 {
			cfg.Ports = ports
		}
	}
	for _, t := range c.External {
		a, err := netip.ParseAddr(strings.TrimSpace(t.IP))
		if err != nil || !a.Is4() || a.IsPrivate() || a.IsLoopback() || t.SiteID == "" {
			errs = append(errs, fmt.Sprintf("scan: external target %q for %q is not a public IPv4 address", t.IP, t.SiteID))
			continue
		}
		cfg.External = append(cfg.External, Target{IP: a.String(), SiteID: t.SiteID})
		if len(cfg.External) >= MaxTargets {
			errs = append(errs, fmt.Sprintf("scan: more than %d external targets, ignoring the rest", MaxTargets))
			break
		}
	}
	if len(cfg.External) > 0 && len(c.Ports) == 0 {
		cfg.Ports = DefaultExternalPorts
	}
	for _, x := range c.Exclude {
		x = strings.TrimSpace(x)
		if p, err := netip.ParsePrefix(x); err == nil {
			cfg.Exclude = append(cfg.Exclude, p)
		} else if a, err := netip.ParseAddr(x); err == nil {
			cfg.Exclude = append(cfg.Exclude, netip.PrefixFrom(a, a.BitLen()))
		} else {
			errs = append(errs, fmt.Sprintf("scan: exclude %q is neither an address nor a network", x))
		}
	}
	return cfg, errs
}

// Target is a device to scan: from the discovery (IP and MAC), or a site's public
// address (IP and SiteID) when the box is an outpost.
type Target struct {
	IP     string
	MAC    string
	SiteID string
}

// Scanner runs rounds and hands the results to the heartbeat in chunks.
type Scanner struct {
	Log     *slog.Logger
	Targets func() []Target
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Now     func() time.Time

	mu       sync.Mutex
	cfg      Config
	round    string
	started  time.Time
	scanned  int
	errors   int
	pending  []wire.ScanHost // results waiting to be sent
	inflight []wire.ScanHost // sent, not yet acknowledged
	sent     int             // hosts of the round already acknowledged
	running  bool
}

// New returns a scanner that takes its targets from the given function.
func New(log *slog.Logger, targets func() []Target) *Scanner {
	if log == nil {
		log = slog.Default()
	}
	d := &net.Dialer{Timeout: dialTimeout}
	return &Scanner{Log: log, Targets: targets, Dial: d.DialContext, Now: time.Now, cfg: Config{Interval: DefaultInterval, MaxPPS: DefaultMaxPPS, Ports: DefaultPorts}}
}

// Apply installs a new configuration; the loop picks it up at its next tick.
// Every method tolerates a nil scanner (an agent built without one, in tests).
func (s *Scanner) Apply(c Config) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
}

func (s *Scanner) config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Run scans on the configured schedule until ctx ends. A round does not start
// while results of the previous one are still waiting to be sent.
func (s *Scanner) Run(ctx context.Context) {
	if s == nil {
		return
	}
	timer := time.NewTimer(firstRoundAfter)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		cfg := s.config()
		if cfg.Enabled && !s.busy() {
			s.Round(ctx, cfg)
		}
		wait := cfg.Interval
		if !cfg.Enabled {
			wait = 5 * time.Minute // check again soon; the switch may be flipped
		}
		timer.Reset(wait)
	}
}

func (s *Scanner) busy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running || len(s.pending) > 0 || len(s.inflight) > 0
}

// Round scans every target once with the given configuration and queues the
// results for the heartbeat. Exported for the tests and the selftest.
func (s *Scanner) Round(ctx context.Context, cfg Config) {
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()
	targets := s.targets(cfg)
	if len(targets) == 0 {
		return
	}
	started := s.Now()
	s.Log.Info("scan: round starting", "hosts", len(targets), "ports", len(cfg.Ports), "max_pps", cfg.MaxPPS)
	limiter := newLimiter(cfg.MaxPPS)
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]*wire.ScanHost, len(targets))
	var errs int
	for _, t := range targets {
		results[t.IP] = &wire.ScanHost{IP: t.IP, MAC: t.MAC, SiteID: t.SiteID, Services: []wire.ScanService{}}
	}
	for _, t := range targets {
		for _, port := range cfg.Ports {
			if ctx.Err() != nil {
				break
			}
			if !limiter.wait(ctx) {
				break
			}
			sem <- struct{}{}
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				svc, err := probe(ctx, s.Dial, ip, port)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs++
					return
				}
				if svc != nil && len(results[ip].Services) < wire.MaxScanServices {
					results[ip].Services = append(results[ip].Services, *svc)
				}
			}(t.IP, port)
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	hosts := make([]wire.ScanHost, 0, len(results))
	found := 0
	for _, h := range results {
		sort.Slice(h.Services, func(i, j int) bool { return h.Services[i].Port < h.Services[j].Port })
		found += len(h.Services)
		hosts = append(hosts, *h)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].IP < hosts[j].IP })
	s.mu.Lock()
	s.round, s.started, s.scanned, s.errors, s.sent = fmt.Sprintf("scan_%d", started.UnixNano()), started.UTC(), len(hosts), errs, 0
	s.pending = hosts
	s.mu.Unlock()
	s.Log.Info("scan: round done", "hosts", len(hosts), "services", found, "errors", errs, "took", s.Now().Sub(started).Round(time.Second))
}

// targets is the outpost's list when there is one, else the discovery's devices:
// IPv4 only, nothing excluded, capped.
func (s *Scanner) targets(cfg Config) []Target {
	var list []Target
	switch {
	case len(cfg.External) > 0:
		list = cfg.External
	case s.Targets != nil:
		list = s.Targets()
	}
	var out []Target
	seen := map[string]bool{}
	for _, t := range list {
		a, err := netip.ParseAddr(t.IP)
		if err != nil || !a.Is4() || seen[t.IP] || a.IsLinkLocalUnicast() {
			continue
		}
		if excluded(cfg.Exclude, a) {
			continue
		}
		seen[t.IP] = true
		out = append(out, t)
		if len(out) >= MaxTargets {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func excluded(ex []netip.Prefix, a netip.Addr) bool {
	for _, p := range ex {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// Drain returns the next chunk of the round for a heartbeat, or nil.
func (s *Scanner) Drain() *wire.ScanReport {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.pending) == 0 || len(s.inflight) > 0 {
		return nil
	}
	n := len(s.pending)
	if n > wire.MaxScanHosts {
		n = wire.MaxScanHosts
	}
	s.inflight, s.pending = s.pending[:n], s.pending[n:]
	rep := &wire.ScanReport{Round: s.round, StartedAt: s.started, Hosts: s.inflight, Final: len(s.pending) == 0, Errors: s.errors}
	if rep.Final {
		rep.Scanned = s.scanned
	}
	return rep
}

// Ack forgets the chunk in flight: the server has it.
func (s *Scanner) Ack() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.sent += len(s.inflight)
	s.inflight = nil
	s.mu.Unlock()
}

// Nack puts the chunk in flight back for the next heartbeat.
func (s *Scanner) Nack() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if len(s.inflight) > 0 {
		s.pending = append(append([]wire.ScanHost{}, s.inflight...), s.pending...)
		s.inflight = nil
	}
	s.mu.Unlock()
}

// limiter paces connection attempts to at most pps per second.
type limiter struct {
	tick *time.Ticker
}

func newLimiter(pps int) *limiter {
	if pps <= 0 {
		pps = DefaultMaxPPS
	}
	return &limiter{tick: time.NewTicker(time.Second / time.Duration(pps))}
}

func (l *limiter) wait(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-l.tick.C:
		return true
	}
}
