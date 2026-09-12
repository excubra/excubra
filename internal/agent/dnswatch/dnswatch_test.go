package dnswatch

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// query builds a DNS query for name and type.
func query(id uint16, name string, qtype uint16) []byte {
	m := make([]byte, headerLen)
	binary.BigEndian.PutUint16(m[0:2], id)
	binary.BigEndian.PutUint16(m[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(m[4:6], 1)
	for _, l := range strings.Split(name, ".") {
		m = append(m, byte(len(l)))
		m = append(m, l...)
	}
	m = append(m, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return m
}

// upstream is a fake resolver on the IPv6 loopback (the client sits on the IPv4
// one, so it never looks like a loop): names ending in .nx do not exist.
type upstream struct {
	addr string
	mu   sync.Mutex
	seen int
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; i < 5; i++ {
		var err error
		pc, err = net.ListenPacket("udp", "[::1]:0")
		if err != nil {
			t.Skip("no IPv6 loopback:", err)
		}
		_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
		if ln, err = net.Listen("tcp", "[::1]:"+port); err == nil {
			break
		}
		_ = pc.Close()
	}
	if ln == nil {
		t.Fatal("no port for the fake upstream")
	}
	u := &upstream{addr: ln.Addr().String()}
	t.Cleanup(func() { _ = pc.Close(); _ = ln.Close() })
	go func() {
		buf := make([]byte, maxMsg)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(u.reply(buf[:n]), addr)
		}
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				for {
					msg, err := readTCP(conn)
					if err != nil {
						return
					}
					if writeTCP(conn, u.reply(msg)) != nil {
						return
					}
				}
			}()
		}
	}()
	return u
}

func (u *upstream) reply(msg []byte) []byte {
	u.mu.Lock()
	u.seen++
	u.mu.Unlock()
	q, err := parseQuestion(msg)
	if err != nil {
		return nil
	}
	code := 0
	if strings.HasSuffix(q.Name, ".nx") {
		code = rcodeNX
	}
	out := answer(msg, q, code)
	if code == 0 {
		binary.BigEndian.PutUint16(out[6:8], 1) // pretend there is one answer record
	}
	return out
}

// sensor starts a Watch on the IPv4 loopback with the given upstreams and returns
// its UDP and TCP addresses plus the signals it emits.
func sensor(t *testing.T, cfg Config) (*Watch, string, string, *[]wire.Signal, *[]string) {
	t.Helper()
	now := time.Date(2026, 9, 12, 14, 0, 0, 0, time.UTC)
	w := New(slog.Default(), t.TempDir())
	w.Now = func() time.Time { return now }
	w.LAN = func() string { return "127.0.0.1" }
	var sigs []wire.Signal
	var notes []string
	var mu sync.Mutex
	w.Signals = func(s []wire.Signal) { mu.Lock(); sigs = append(sigs, s...); mu.Unlock() }
	w.Note = func(s string) { mu.Lock(); notes = append(notes, s); mu.Unlock() }
	var udpAddr, tcpAddr string
	w.ListenPacket = func(ctx context.Context, network, _ string) (net.PacketConn, error) {
		pc, err := (&net.ListenConfig{}).ListenPacket(ctx, network, "127.0.0.1:0")
		if err == nil {
			udpAddr = pc.LocalAddr().String()
		}
		return pc, err
	}
	w.Listen = func(ctx context.Context, network, _ string) (net.Listener, error) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, network, "127.0.0.1:0")
		if err == nil {
			tcpAddr = ln.Addr().String()
		}
		return ln, err
	}
	w.Apply(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	w.rebind(ctx)
	if udpAddr == "" || tcpAddr == "" {
		t.Fatalf("sensor not listening: %s", w.Drain().Error)
	}
	t.Cleanup(w.close)
	return w, udpAddr, tcpAddr, &sigs, &notes
}

func ask(t *testing.T, addr, name string, qtype uint16) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(query(0x1234, name, qtype)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxMsg)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return buf[:n]
}

func TestForwardsBlocksAndReports(t *testing.T) {
	up := newUpstream(t)
	w, udp, tcp, sigs, _ := sensor(t, Config{Enabled: true, Block: true, Upstreams: []string{up.addr}})
	w.mu.Lock()
	w.list, w.listVer = parseList([]byte("# malware\nevil.test\n0.0.0.0 bad.example\n")), "v1"
	w.mu.Unlock()

	if r := ask(t, udp, "ok.test", 1); rcode(r) != 0 || binary.BigEndian.Uint16(r[6:8]) != 1 {
		t.Fatalf("forwarded answer: %x", r)
	}
	if r := ask(t, udp, "gone.nx", 1); rcode(r) != rcodeNX {
		t.Fatalf("nxdomain passed through: %x", r)
	}
	if r := ask(t, udp, "www.evil.test", 1); rcode(r) != rcodeNX || r[2]&0x80 == 0 {
		t.Fatalf("listed name not blocked: %x", r)
	}
	if got := *sigs; len(got) != 1 || got[0].Kind != wire.SignalDNSBlock || got[0].IP != "127.0.0.1" || got[0].Detail != "evil.test|www.evil.test|blocked" {
		t.Fatalf("block signal: %+v", got)
	}
	// over TCP too
	conn, err := net.Dial("tcp", tcp)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeTCP(conn, query(7, "ok.test", 1)); err != nil {
		t.Fatal(err)
	}
	r, err := readTCP(conn)
	_ = conn.Close()
	if err != nil || rcode(r) != 0 || binary.BigEndian.Uint16(r[0:2]) != 7 {
		t.Fatalf("tcp: %v %x", err, r)
	}
	rep := w.Drain()
	if rep == nil || rep.Queries != 4 || rep.Blocked != 1 || rep.NXDomain != 1 || rep.Failed != 0 || rep.Clients != 1 || rep.ListSize != 2 || rep.ListVersion != "v1" || rep.Upstream != up.addr || !strings.HasPrefix(rep.Listening, "127.0.0.1:") {
		t.Fatalf("report: %+v", rep)
	}
	w.Nack()
	if again := w.Drain(); again == nil || again.Queries != 4 {
		t.Fatalf("after nack: %+v", again)
	}
	w.Ack()
	if again := w.Drain(); again == nil || again.Queries != 0 {
		t.Fatalf("after ack: %+v", again)
	}
	w.Ack()

	// reporting only: the listed name is forwarded, the signal still comes
	w.Apply(Config{Enabled: true, Block: false, Upstreams: []string{up.addr}})
	*sigs = nil
	if r := ask(t, udp, "evil.test", 1); rcode(r) != 0 {
		t.Fatalf("report mode blocked: %x", r)
	}
	if got := *sigs; len(got) != 1 || got[0].Detail != "evil.test|evil.test|reported" {
		t.Fatalf("report signal: %+v", got)
	}
	if up.seen != 4 {
		t.Fatalf("upstream saw %d queries, want 4", up.seen)
	}
}

func TestFailoverAndLoopGuard(t *testing.T) {
	up := newUpstream(t)
	dead := "[::1]:1"
	w, udp, _, _, notes := sensor(t, Config{Enabled: true, Upstreams: []string{dead, up.addr}})
	if r := ask(t, udp, "ok.test", 1); rcode(r) != 0 {
		t.Fatalf("failover: %x", r)
	}
	w.mu.Lock()
	idx := w.upIdx
	w.mu.Unlock()
	if idx != 1 {
		t.Fatalf("the answering upstream is not preferred: %d", idx)
	}
	w.Apply(Config{Enabled: true, Upstreams: []string{dead}})
	if r := ask(t, udp, "ok.test", 1); rcode(r) != rcodeFail {
		t.Fatalf("no upstream must be SERVFAIL: %x", r)
	}
	if rep := w.Drain(); rep.Failed != 1 || rep.Queries != 2 {
		t.Fatalf("report: %+v", rep)
	}
	// the client is the upstream: a loop, answered SERVFAIL and noted once
	w.Apply(Config{Enabled: true, Upstreams: []string{"127.0.0.1:1"}})
	for i := 0; i < 2; i++ {
		if r := ask(t, udp, "ok.test", 1); rcode(r) != rcodeFail {
			t.Fatalf("loop not refused: %x", r)
		}
	}
	if len(*notes) != 1 || !strings.Contains((*notes)[0], "Schleife") {
		t.Fatalf("notes: %v", *notes)
	}
}

func TestRandomNamesAndTunnels(t *testing.T) {
	up := newUpstream(t)
	w, udp, _, sigs, _ := sensor(t, Config{Enabled: true, Upstreams: []string{up.addr}})
	// real names that do not exist are not a DGA
	for _, n := range []string{"printer.nx", "intranet.nx", "fileserver01.nx"} {
		ask(t, udp, n, 1)
	}
	// twenty-one names without a vowel, as a generation algorithm makes them
	const consonants = "bcdfghjklmnpqrstvwxz"
	for i := 0; i < 21; i++ {
		rot := consonants[i%len(consonants):] + consonants[:i%len(consonants)]
		ask(t, udp, rot[:10]+strconv.Itoa(i)+".nx", 1)
	}
	var dga []wire.Signal
	for _, s := range *sigs {
		if s.Kind == wire.SignalDNSDGA {
			dga = append(dga, s)
		}
	}
	if len(dga) != 2 || dga[0].Count != 20 || dga[0].IP != "127.0.0.1" || !strings.Contains(dga[0].Detail, ".nx") {
		t.Fatalf("dga signals: %+v", dga)
	}
	// a tunnel: long labels to one domain
	*sigs = nil
	for i := 0; i < 31; i++ {
		ask(t, udp, strings.Repeat("a", 30)+strconv.Itoa(i)+"."+strings.Repeat("b", 25)+".tunnel.test", 1)
	}
	var tun []wire.Signal
	for _, s := range *sigs {
		if s.Kind == wire.SignalDNSTunnel {
			tun = append(tun, s)
		}
	}
	if len(tun) != 2 || tun[0].Count != 30 || tun[0].Detail != "tunnel.test" {
		t.Fatalf("tunnel signals: %+v", tun)
	}
	// TXT queries count as well, short names do not
	*sigs = nil
	for i := 0; i < 30; i++ {
		ask(t, udp, "c"+strconv.Itoa(i)+".txt.test", qtypeTXT)
	}
	if got := *sigs; len(got) != 1 || got[0].Kind != wire.SignalDNSTunnel || got[0].Detail != "txt.test" {
		t.Fatalf("txt tunnel: %+v", got)
	}
	_ = w
}

func TestBlocklistIsFetchedAndKept(t *testing.T) {
	dir := t.TempDir()
	w := New(slog.Default(), dir)
	calls := 0
	w.Fetch = func(_ context.Context, have string) ([]byte, string, bool, error) {
		calls++
		if have == "v2" {
			return nil, "", true, nil
		}
		return []byte("evil.test\nbad.example\n"), "v2", false, nil
	}
	w.Apply(Config{Enabled: true, ListVersion: "v2"})
	w.refreshList(context.Background())
	if calls != 1 || w.listed("a.b.evil.test") != "evil.test" || w.listed("notevil.test") != "" || w.listed("test") != "" {
		t.Fatalf("list: calls=%d %v", calls, w.list)
	}
	w.refreshList(context.Background())
	if calls != 1 {
		t.Fatal("fetched again although the version matched")
	}
	// a restart restores the list from disk
	w2 := New(slog.Default(), dir)
	if w2.listVer != "v2" || len(w2.list) != 2 {
		t.Fatalf("restored: %q %v", w2.listVer, w2.list)
	}
	// switched off: nothing is fetched
	w3 := New(slog.Default(), t.TempDir())
	w3.Fetch = w.Fetch
	w3.Apply(Config{Enabled: false, ListVersion: "v3"})
	w3.refreshList(context.Background())
	if calls != 1 {
		t.Fatal("fetched while off")
	}
}

func TestPureParts(t *testing.T) {
	q, err := parseQuestion(query(9, "Www.Example.Test", 28))
	if err != nil || q.ID != 9 || q.Name != "www.example.test" || q.Type != 28 || q.End != headerLen+18+4 {
		t.Fatalf("question: %+v %v", q, err)
	}
	if _, err := parseQuestion([]byte{1, 2, 3}); err == nil {
		t.Fatal("short message parsed")
	}
	short := query(9, "x.test", 1)
	qs, _ := parseQuestion(short)
	r := answer(short, qs, rcodeNX)
	if len(r) != qs.End || r[2]&0x80 == 0 || r[3]&0x0F != rcodeNX || binary.BigEndian.Uint16(r[6:8]) != 0 {
		t.Fatalf("answer: %x", r)
	}
	for name, want := range map[string]bool{"xkqzjvbtrp.nx": true, "printer.nx": false, "intranet.corp.nx": false, "a1b2c3d4e5f6.evil.nx": true, "_dmarc.example.nx": false, "1.0.168.192.in-addr.arpa": false, "sdfghjkl.com": true} {
		if got := randomLooking(name); got != want {
			t.Errorf("randomLooking(%s) = %v", name, got)
		}
	}
	for name, want := range map[string]string{"a.b.example.com": "example.com", "x.example.co.uk": "example.co.uk", "example.test": "example.test", "deep.sub.thing.org": "thing.org"} {
		if got := registrable(name); got != want {
			t.Errorf("registrable(%s) = %s", name, got)
		}
	}
	if !tunnelLike("x.test", qtypeTXT) || tunnelLike("short.test", 1) || !tunnelLike(strings.Repeat("a", 40)+"."+strings.Repeat("b", 20)+".t.test", 1) {
		t.Fatal("tunnelLike")
	}
	cfg, errs := ParseConfig(wire.DNSConfig{Enabled: true, Block: true, Upstreams: []string{"9.9.9.9", "192.168.1.1:5353", "nine.nine", "1.1.1.1:99999"}})
	if !cfg.Enabled || !cfg.Block || len(cfg.Upstreams) != 2 || cfg.Upstreams[0] != "9.9.9.9:53" || cfg.Upstreams[1] != "192.168.1.1:5353" || len(errs) != 2 {
		t.Fatalf("config: %+v %v", cfg, errs)
	}
	w := New(nil, "")
	w.System = func() []string { return []string{"127.0.0.53:53"} }
	if ups := w.upstreams(Config{}); len(ups) != 2 || ups[0] != "9.9.9.9:53" {
		t.Fatalf("loopback-only system resolvers must fall back: %v", ups)
	}
	w.System = func() []string { return []string{"192.168.1.1:53"} }
	if ups := w.upstreams(Config{}); len(ups) != 1 || ups[0] != "192.168.1.1:53" {
		t.Fatalf("system resolvers: %v", ups)
	}
}
