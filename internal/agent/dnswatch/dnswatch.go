// Package dnswatch is the box's DNS sensor (ADR-0020): a forwarding resolver on
// the LAN address that the customer's router hands out, watching what the
// devices ask for. It forwards every query untouched to the upstream resolvers
// and reports three things: a query for a domain on the blocklist (answered
// with NXDOMAIN when blocking is on), a client that asks for random names that
// do not exist (a domain generation algorithm looking for its server), and a
// client that pushes long or TXT queries to one domain (a tunnel). It keeps no
// log of who asked what.
package dnswatch

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// Bounds.
const (
	rebindEvery     = 30 * time.Second
	maxInflight     = 128
	upstreamTimeout = 2500 * time.Millisecond
	maxMsg          = 4096 // a UDP message with EDNS
	maxTCPMsg       = 65535
	maxUpstreams    = 4
	maxListBytes    = 8 << 20
	listFile        = "blocklist.txt"
	listVersionFile = "blocklist.version"
	tcpIdle         = 30 * time.Second
)

// DefaultUpstreams are used when neither the config nor the box names a resolver
// that is not itself: Quad9 and Cloudflare.
var DefaultUpstreams = []string{"9.9.9.9:53", "1.1.1.1:53"}

// Config is the effective sensor configuration.
type Config struct {
	Enabled     bool
	Block       bool
	Upstreams   []string // host:port
	ListVersion string
}

// ParseConfig validates the pulled configuration and returns what the box will do
// plus the reasons for what it refuses (for config_errors).
func ParseConfig(c wire.DNSConfig) (Config, []string) {
	cfg := Config{Enabled: c.Enabled, Block: c.Block, ListVersion: c.ListVersion}
	var errs []string
	for i, u := range c.Upstreams {
		if i >= maxUpstreams {
			errs = append(errs, fmt.Sprintf("dns: more than %d upstreams, ignoring the rest", maxUpstreams))
			break
		}
		u = strings.TrimSpace(u)
		host, port := u, "53"
		if h, p, err := net.SplitHostPort(u); err == nil {
			host, port = h, p
		}
		a, err := netip.ParseAddr(host)
		if err != nil {
			errs = append(errs, fmt.Sprintf("dns: upstream %q is not an address", u))
			continue
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			errs = append(errs, fmt.Sprintf("dns: upstream %q has no usable port", u))
			continue
		}
		cfg.Upstreams = append(cfg.Upstreams, net.JoinHostPort(a.String(), port))
	}
	return cfg, errs
}

// Watch is the sensor.
type Watch struct {
	Log *slog.Logger
	Now func() time.Time
	Dir string // where the blocklist is kept between runs
	// LAN returns the address to listen on; the platform default reads the route table.
	LAN func() string
	// System returns the box's own resolvers, used when the config names none.
	System func() []string
	// Fetch gets the blocklist from the server: body, version, not-modified, error.
	Fetch func(ctx context.Context, version string) ([]byte, string, bool, error)
	// Signals takes what the sensor saw (the sentinel's queue).
	Signals func([]wire.Signal)
	// Note tells the operator something once (the agent's notes).
	Note func(string)
	// The sockets, replaced in tests.
	ListenPacket func(ctx context.Context, network, addr string) (net.PacketConn, error)
	Listen       func(ctx context.Context, network, addr string) (net.Listener, error)
	Dial         func(ctx context.Context, network, addr string) (net.Conn, error)

	mu        sync.Mutex
	cfg       Config
	list      map[string]bool
	listVer   string
	udp       net.PacketConn
	tcp       net.Listener
	bound     string
	errText   string
	upIdx     int
	upstream  string
	clients   map[string]*client
	pending   wire.DNSReport
	seen      map[string]bool
	inflight  *wire.DNSReport
	loopNoted map[string]bool
	portNoted bool
	sem       chan struct{}
}

// New returns a sensor with the platform defaults and the blocklist restored
// from dir, if there is one.
func New(log *slog.Logger, dir string) *Watch {
	if log == nil {
		log = slog.Default()
	}
	w := &Watch{Log: log, Now: time.Now, Dir: dir, LAN: platformLAN, System: systemResolvers,
		clients: map[string]*client{}, seen: map[string]bool{}, loopNoted: map[string]bool{}, sem: make(chan struct{}, maxInflight)}
	w.ListenPacket = func(ctx context.Context, network, addr string) (net.PacketConn, error) {
		return (&net.ListenConfig{}).ListenPacket(ctx, network, addr)
	}
	w.Listen = func(ctx context.Context, network, addr string) (net.Listener, error) {
		return (&net.ListenConfig{}).Listen(ctx, network, addr)
	}
	w.Dial = (&net.Dialer{Timeout: upstreamTimeout}).DialContext
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, listFile)); err == nil {
			w.list = parseList(b)
			v, _ := os.ReadFile(filepath.Join(dir, listVersionFile))
			w.listVer = strings.TrimSpace(string(v))
		}
	}
	return w
}

// Apply installs a new configuration; the loop picks it up at its next tick.
// Every method tolerates a nil sensor (an agent built without one, in tests).
func (w *Watch) Apply(c Config) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.cfg = c
	w.mu.Unlock()
}

func (w *Watch) config() Config {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cfg
}

// Run keeps the sockets and the blocklist in line with the config until ctx ends.
func (w *Watch) Run(ctx context.Context) {
	if w == nil {
		return
	}
	t := time.NewTicker(rebindEvery)
	defer t.Stop()
	for {
		w.rebind(ctx)
		w.refreshList(ctx)
		select {
		case <-ctx.Done():
			w.close()
			return
		case <-t.C:
		}
	}
}

// rebind opens the sockets on the LAN address when the sensor is on and closes
// them when it is off or the address moved.
func (w *Watch) rebind(ctx context.Context) {
	cfg := w.config()
	ip := ""
	if cfg.Enabled && w.LAN != nil {
		ip = w.LAN()
	}
	w.mu.Lock()
	bound, hasUDP := w.bound, w.udp != nil
	w.mu.Unlock()
	if ip == "" {
		if bound != "" {
			w.close()
		}
		w.mu.Lock()
		w.errText = ""
		w.mu.Unlock()
		return
	}
	if bound == ip && hasUDP {
		return
	}
	w.close()
	addr := net.JoinHostPort(ip, "53")
	pc, err := w.ListenPacket(ctx, "udp4", addr)
	if err != nil {
		w.fail(err)
		return
	}
	ln, err := w.Listen(ctx, "tcp4", addr)
	if err != nil {
		_ = pc.Close()
		w.fail(err)
		return
	}
	w.mu.Lock()
	w.udp, w.tcp, w.bound, w.errText = pc, ln, ip, ""
	w.mu.Unlock()
	w.Log.Info("dns: listening", "addr", addr)
	go w.serveUDP(ctx, pc)
	go w.serveTCP(ctx, ln)
}

func (w *Watch) fail(err error) {
	w.mu.Lock()
	w.errText = err.Error()
	noted := w.portNoted
	w.portNoted = true
	w.mu.Unlock()
	if !noted {
		msg := "DNS-Sensor: Port 53 lässt sich nicht öffnen: " + err.Error()
		if strings.Contains(err.Error(), "permission denied") {
			msg += " — die Agent-Unit braucht CAP_NET_BIND_SERVICE (Box neu provisionieren, oder die Unit-Zeilen CapabilityBoundingSet/AmbientCapabilities um CAP_NET_BIND_SERVICE ergänzen)"
		}
		if w.Note != nil {
			w.Note(msg)
		} else {
			w.Log.Warn(msg)
		}
	}
}

func (w *Watch) close() {
	w.mu.Lock()
	pc, ln := w.udp, w.tcp
	w.udp, w.tcp, w.bound = nil, nil, ""
	w.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
	if ln != nil {
		_ = ln.Close()
	}
}

// refreshList fetches the blocklist when the server has a version the box has not.
func (w *Watch) refreshList(ctx context.Context) {
	cfg := w.config()
	w.mu.Lock()
	have := w.listVer
	w.mu.Unlock()
	if !cfg.Enabled || w.Fetch == nil || cfg.ListVersion == "" || cfg.ListVersion == have {
		return
	}
	body, version, unchanged, err := w.Fetch(ctx, have)
	if err != nil {
		w.Log.Warn("dns: blocklist", "err", err)
		return
	}
	if unchanged {
		return
	}
	list := parseList(body)
	w.mu.Lock()
	w.list, w.listVer = list, version
	w.mu.Unlock()
	if w.Dir != "" {
		_ = os.WriteFile(filepath.Join(w.Dir, listFile), body, 0o600)
		_ = os.WriteFile(filepath.Join(w.Dir, listVersionFile), []byte(version+"\n"), 0o600)
	}
	w.Log.Info("dns: blocklist updated", "version", version, "domains", len(list))
}

// parseList reads one domain per line; hosts-file lines ("0.0.0.0 domain") work too.
func parseList(b []byte) map[string]bool {
	if len(b) > maxListBytes {
		b = b[:maxListBytes]
	}
	out := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		d := strings.ToLower(strings.TrimSuffix(f[len(f)-1], "."))
		if d == "" || d == "localhost" || !strings.Contains(d, ".") {
			continue
		}
		out[d] = true
	}
	return out
}

// listed returns the entry of the blocklist a name falls under ("" for none):
// the name itself or one of its parents.
func (w *Watch) listed(name string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.list) == 0 {
		return ""
	}
	labels := strings.Split(name, ".")
	for i := 0; i+1 < len(labels); i++ {
		d := strings.Join(labels[i:], ".")
		if w.list[d] {
			return d
		}
	}
	return ""
}

// ---- serving --------------------------------------------------------------------------------

func (w *Watch) serveUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, maxMsg)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		select {
		case w.sem <- struct{}{}:
		default:
			continue // over the bound: the client asks again
		}
		go func() {
			defer func() { <-w.sem }()
			if resp := w.handle(ctx, msg, hostOf(addr), "udp"); resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}()
	}
}

func (w *Watch) serveTCP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case w.sem <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-w.sem; _ = conn.Close() }()
			src := hostOf(conn.RemoteAddr())
			for {
				_ = conn.SetDeadline(time.Now().Add(tcpIdle))
				msg, err := readTCP(conn)
				if err != nil {
					return
				}
				resp := w.handle(ctx, msg, src, "tcp")
				if resp == nil || writeTCP(conn, resp) != nil {
					return
				}
			}
		}()
	}
}

func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func readTCP(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < headerLen || n > maxTCPMsg {
		return nil, errMalformed
	}
	msg := make([]byte, n)
	_, err := io.ReadFull(r, msg)
	return msg, err
}

func writeTCP(wr io.Writer, msg []byte) error {
	if len(msg) > maxTCPMsg {
		return errMalformed
	}
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[:2], uint16(len(msg))) //nolint:gosec // bounded by maxTCPMsg above
	copy(out[2:], msg)
	_, err := wr.Write(out)
	return err
}

// handle answers one query: from the blocklist, from an upstream, or with an
// error when nothing answers. src is the client's address.
func (w *Watch) handle(ctx context.Context, msg []byte, src, network string) []byte {
	q, err := parseQuestion(msg)
	if err != nil {
		return nil
	}
	cfg := w.config()
	ups := w.upstreams(cfg)
	if isUpstream(ups, src) {
		w.noteLoop(src)
		return answer(msg, q, rcodeFail)
	}
	now := w.Now()
	w.mu.Lock()
	w.pending.Queries++
	w.seen[src] = true
	w.mu.Unlock()
	if d := w.listed(q.Name); d != "" {
		verdict := "reported"
		if cfg.Block {
			verdict = "blocked"
			w.mu.Lock()
			w.pending.Blocked++
			w.mu.Unlock()
		}
		w.signal(wire.Signal{Kind: wire.SignalDNSBlock, IP: src, Count: 1, Detail: d + "|" + q.Name + "|" + verdict, FirstAt: now, LastAt: now})
		if cfg.Block {
			return answer(msg, q, rcodeNX)
		}
	}
	resp, up, err := w.forward(ctx, msg, network, ups)
	if err != nil {
		w.mu.Lock()
		w.pending.Failed++
		w.mu.Unlock()
		return answer(msg, q, rcodeFail)
	}
	w.mu.Lock()
	w.upstream = up
	nx := rcode(resp) == rcodeNX
	if nx {
		w.pending.NXDomain++
	}
	w.mu.Unlock()
	if nx && randomLooking(q.Name) {
		w.dga(src, q.Name, now)
	}
	if tunnelLike(q.Name, q.Type) {
		w.tunnel(src, q.Name, now)
	}
	return resp
}

// upstreams picks the resolvers: the config's, else the box's own that are not
// loopback, else the defaults.
func (w *Watch) upstreams(cfg Config) []string {
	if len(cfg.Upstreams) > 0 {
		return cfg.Upstreams
	}
	if w.System != nil {
		var out []string
		for _, s := range w.System() {
			h, _, err := net.SplitHostPort(s)
			if err != nil {
				h, s = s, net.JoinHostPort(s, "53")
			}
			if a, err := netip.ParseAddr(h); err == nil && !a.IsLoopback() {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return DefaultUpstreams
}

func isUpstream(ups []string, src string) bool {
	for _, u := range ups {
		if h, _, err := net.SplitHostPort(u); err == nil && h == src {
			return true
		}
	}
	return false
}

func (w *Watch) noteLoop(src string) {
	w.mu.Lock()
	noted := w.loopNoted[src]
	w.loopNoted[src] = true
	w.mu.Unlock()
	if !noted && w.Note != nil {
		w.Note(fmt.Sprintf("DNS-Sensor: Schleife — %s fragt die Box, und die Box fragt %s. Im Portal einen anderen Upstream eintragen (z. B. 9.9.9.9), oder den Router nicht auf die Box zeigen lassen", src, src))
	}
}

// forward sends the query to the first upstream that answers, starting with the
// one that answered last time.
func (w *Watch) forward(ctx context.Context, msg []byte, network string, ups []string) ([]byte, string, error) {
	if len(ups) == 0 {
		return nil, "", errors.New("no upstream")
	}
	w.mu.Lock()
	start := w.upIdx % len(ups)
	w.mu.Unlock()
	var last error
	for i := 0; i < len(ups); i++ {
		idx := (start + i) % len(ups)
		resp, err := w.exchange(ctx, msg, network, ups[idx])
		if err == nil {
			w.mu.Lock()
			w.upIdx = idx
			w.mu.Unlock()
			return resp, ups[idx], nil
		}
		last = err
	}
	return nil, "", last
}

func (w *Watch) exchange(ctx context.Context, msg []byte, network, upstream string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	conn, err := w.Dial(cctx, network, upstream)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(upstreamTimeout))
	if network == "tcp" {
		if err := writeTCP(conn, msg); err != nil {
			return nil, err
		}
		return readTCP(conn)
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, maxMsg)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= headerLen && binary.BigEndian.Uint16(buf[0:2]) == binary.BigEndian.Uint16(msg[0:2]) {
			out := make([]byte, n)
			copy(out, buf[:n])
			return out, nil
		}
	}
}

// ---- detectors --------------------------------------------------------------------------------

func (w *Watch) clientFor(src string, now time.Time) *client {
	c, ok := w.clients[src]
	if ok {
		c.seen = now
		return c
	}
	if len(w.clients) >= maxClients {
		stalest, at := "", now
		for k, v := range w.clients {
			if v.seen.Before(at) {
				stalest, at = k, v.seen
			}
		}
		delete(w.clients, stalest)
	}
	c = &client{nx: newCounter(now), tunnels: map[string]*counter{}, seen: now}
	w.clients[src] = c
	return c
}

func (w *Watch) dga(src, name string, now time.Time) {
	w.mu.Lock()
	c := w.clientFor(src, now)
	n := c.nx.add(name, now)
	fire := n >= dgaThreshold
	sample := ""
	if fire {
		c.nx.alarm = true
		sample = c.nx.sample(3)
	}
	w.mu.Unlock()
	if fire {
		w.signal(wire.Signal{Kind: wire.SignalDNSDGA, IP: src, Count: n, Detail: sample, FirstAt: now, LastAt: now})
	}
}

func (w *Watch) tunnel(src, name string, now time.Time) {
	base := registrable(name)
	w.mu.Lock()
	c := w.clientFor(src, now)
	t, ok := c.tunnels[base]
	if !ok {
		if len(c.tunnels) >= maxDomains {
			for k := range c.tunnels {
				delete(c.tunnels, k)
				break
			}
		}
		t = newCounter(now)
		c.tunnels[base] = t
	}
	n := t.add(name, now)
	fire := n >= tunnelThreshold
	if fire {
		t.alarm = true
	}
	w.mu.Unlock()
	if fire {
		w.signal(wire.Signal{Kind: wire.SignalDNSTunnel, IP: src, Count: n, Detail: base, FirstAt: now, LastAt: now})
	}
}

func (w *Watch) signal(sg wire.Signal) {
	if w.Signals != nil {
		w.Signals([]wire.Signal{sg})
	}
}

// ---- the heartbeat side -----------------------------------------------------------------------

// Drain hands the sensor's state and counters to a heartbeat and marks them in
// flight; nil while a report is in flight or when the sensor is off and idle.
func (w *Watch) Drain() *wire.DNSReport {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.inflight != nil {
		return nil
	}
	rep := w.pending
	rep.Clients = len(w.seen)
	if w.bound != "" {
		rep.Listening = net.JoinHostPort(w.bound, "53")
	}
	rep.Error, rep.ListVersion, rep.ListSize, rep.Upstream = w.errText, w.listVer, len(w.list), w.upstream
	if !w.cfg.Enabled && rep.Queries == 0 && rep.Listening == "" && rep.Error == "" {
		return nil
	}
	w.pending = wire.DNSReport{}
	w.seen = map[string]bool{}
	w.inflight = &rep
	return &rep
}

// Ack forgets the report in flight: the server has it.
func (w *Watch) Ack() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.inflight = nil
	w.mu.Unlock()
}

// Nack adds the counters in flight back for the next heartbeat.
func (w *Watch) Nack() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if r := w.inflight; r != nil {
		w.pending.Queries += r.Queries
		w.pending.Blocked += r.Blocked
		w.pending.NXDomain += r.NXDomain
		w.pending.Failed += r.Failed
		if r.Clients > len(w.seen) {
			// distinctness across the two intervals is lost; keep the larger count
			for i := len(w.seen); i < r.Clients; i++ {
				w.seen[fmt.Sprintf("~%d", i)] = true
			}
		}
		w.inflight = nil
	}
}

// systemResolvers reads the nameservers of /etc/resolv.conf.
func systemResolvers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, net.JoinHostPort(a.String(), "53"))
			}
		}
	}
	return out
}
