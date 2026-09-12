package sentinel

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

	"github.com/excubra/excubra/internal/agent/discovery"
	"github.com/excubra/excubra/internal/wire"
)

// synFrame builds an Ethernet+IPv4+TCP frame with the given flags.
func synFrame(srcMAC net.HardwareAddr, src, dst string, port int, flags byte) []byte {
	f := make([]byte, 54)
	copy(f[6:12], srcMAC)
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x45
	f[23] = 6
	copy(f[26:30], net.ParseIP(src).To4())
	copy(f[30:34], net.ParseIP(dst).To4())
	binary.BigEndian.PutUint16(f[36:38], uint16(port))
	f[47] = flags
	return f
}

func newTest(t *testing.T) (*Sentinel, *time.Time) {
	t.Helper()
	now := time.Date(2026, 9, 12, 14, 0, 0, 0, time.UTC)
	s := New(slog.Default())
	s.Now = func() time.Time { return now }
	s.watch = func(ctx context.Context, _ func([]byte)) error { <-ctx.Done(); return ctx.Err() }
	s.LAN = func() Self { return Self{IP: "192.168.1.9", MAC: "aa:aa:aa:00:00:09", Gateway: "192.168.1.1"} }
	s.mu.Lock()
	s.self = s.LAN()
	s.raw = true
	s.mu.Unlock()
	cfg, errs := ParseConfig(wire.CanaryConfig{Enabled: true})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	s.Apply(cfg)
	return s, &now
}

func kinds(sigs []wire.Signal) string {
	var out []string
	for _, sg := range sigs {
		out = append(out, sg.Kind+":"+sg.IP+":"+strconv.Itoa(sg.Port)+":"+strconv.Itoa(sg.Count))
	}
	return strings.Join(out, " ")
}

// Two SYNs to a decoy and one to a closed port from the same source: one canary
// signal with both touches. Eight distinct ports within a minute: a port scan.
func TestSYNsToDecoysAndPortScan(t *testing.T) {
	s, now := newTest(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	s.observeFrame(synFrame(mac, "192.168.1.50", "192.168.1.9", 445, 0x02))
	s.observeFrame(synFrame(mac, "192.168.1.50", "192.168.1.9", 445, 0x02))
	s.observeFrame(synFrame(mac, "192.168.1.50", "192.168.1.9", 8443, 0x02))
	s.observeFrame(synFrame(mac, "192.168.1.50", "192.168.1.9", 3389, 0x12)) // SYN-ACK: not a knock
	s.observeFrame(synFrame(mac, "192.168.1.50", "192.168.1.77", 445, 0x02)) // someone else's address
	s.observeFrame(synFrame(mac, "192.168.1.9", "192.168.1.9", 445, 0x02))   // ourselves
	s.observeFrame(synFrame(mac, "169.254.222.2", "192.168.1.9", 445, 0x02)) // the operator namespace
	got := s.Drain()
	if kinds(got) != "canary:192.168.1.50:445:2" || got[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("signals: %s %+v", kinds(got), got)
	}
	s.Ack()
	for p := 1000; p < 1008; p++ {
		*now = now.Add(time.Second)
		s.observeFrame(synFrame(mac, "192.168.1.50", "192.168.1.9", p, 0x02))
	}
	got = s.Drain() // the two earlier knocks are within the window and count
	if kinds(got) != "port_scan:192.168.1.50:0:10" || !strings.HasPrefix(got[0].Detail, "445, 1000, 1001") {
		t.Fatalf("port scan: %s %+v", kinds(got), got)
	}
	// not acknowledged: the same signal keeps growing and comes again
	*now = now.Add(time.Second)
	s.observeFrame(synFrame(mac, "192.168.1.50", "192.168.1.9", 1009, 0x02))
	s.Nack()
	got = s.Drain()
	if kinds(got) != "port_scan:192.168.1.50:0:11" {
		t.Fatalf("after nack: %s", kinds(got))
	}
	s.Ack()
	if got := s.Drain(); got != nil {
		t.Fatalf("drained again: %+v", got)
	}
}

// A source asking a hundred addresses within a minute is searching the network;
// the box's own sweep is not. The gateway claimed by a second MAC is spoofing at
// once, another address only when it keeps flapping.
func TestARPSearchAndSpoofing(t *testing.T) {
	s, now := newTest(t)
	for i := 0; i < 120; i++ {
		s.ObserveARP(discovery.ARPFrame{Op: 1, SenderMAC: "aa:aa:aa:00:00:09", SenderIP: "192.168.1.9", TargetIP: "192.168.1." + strconv.Itoa(i+10)})
	}
	if got := s.Drain(); got != nil {
		t.Fatalf("own sweep reported: %+v", got)
	}
	for i := 0; i < 99; i++ {
		s.ObserveARP(discovery.ARPFrame{Op: 1, SenderMAC: "00:11:22:33:44:55", SenderIP: "192.168.1.250", TargetIP: "192.168.1." + strconv.Itoa(i+10)})
	}
	if got := s.Drain(); got != nil {
		t.Fatalf("below the threshold reported: %+v", got)
	}
	s.ObserveARP(discovery.ARPFrame{Op: 1, SenderMAC: "00:11:22:33:44:55", SenderIP: "192.168.1.250", TargetIP: "192.168.1.200"})
	s.ObserveARP(discovery.ARPFrame{Op: 1, SenderMAC: "00:11:22:33:44:55", SenderIP: "192.168.1.250", TargetIP: "192.168.1.201"})
	got := s.Drain()
	if kinds(got) != "arp_scan:192.168.1.250:0:101" {
		t.Fatalf("arp scan: %s", kinds(got))
	}
	s.Ack()

	// the gateway answers from its MAC, then someone else claims it
	s.ObserveARP(discovery.ARPFrame{Op: 2, SenderMAC: "00:09:0f:aa:bb:cc", SenderIP: "192.168.1.1", TargetIP: "192.168.1.9"})
	s.ObserveARP(discovery.ARPFrame{Op: 2, SenderMAC: "00:09:0f:aa:bb:cc", SenderIP: "192.168.1.1", TargetIP: "192.168.1.9"})
	if got := s.Drain(); got != nil {
		t.Fatalf("steady gateway reported: %+v", got)
	}
	s.ObserveARP(discovery.ARPFrame{Op: 2, SenderMAC: "de:ad:be:ef:00:01", SenderIP: "192.168.1.1", TargetIP: "192.168.1.9"})
	got = s.Drain()
	if kinds(got) != "arp_spoof:192.168.1.1:0:1" || got[0].MAC != "de:ad:be:ef:00:01" || got[0].Detail != "gateway 00:09:0f:aa:bb:cc → de:ad:be:ef:00:01" {
		t.Fatalf("gateway spoof: %s %+v", kinds(got), got)
	}
	s.Ack()

	// a printer gets a new lease on another machine: one change is nothing
	s.ObserveARP(discovery.ARPFrame{Op: 1, SenderMAC: "00:00:00:00:01:01", SenderIP: "192.168.1.70", TargetIP: "192.168.1.1"})
	s.ObserveARP(discovery.ARPFrame{Op: 1, SenderMAC: "00:00:00:00:01:02", SenderIP: "192.168.1.70", TargetIP: "192.168.1.1"})
	if got := s.Drain(); got != nil {
		t.Fatalf("one change reported: %+v", got)
	}
	*now = now.Add(time.Minute)
	s.ObserveARP(discovery.ARPFrame{Op: 1, SenderMAC: "00:00:00:00:01:01", SenderIP: "192.168.1.70", TargetIP: "192.168.1.1"})
	*now = now.Add(time.Minute)
	s.ObserveARP(discovery.ARPFrame{Op: 1, SenderMAC: "00:00:00:00:01:02", SenderIP: "192.168.1.70", TargetIP: "192.168.1.1"})
	got = s.Drain()
	if kinds(got) != "arp_spoof:192.168.1.70:0:3" || !strings.HasPrefix(got[0].Detail, "flapping ") {
		t.Fatalf("flapping: %s %+v", kinds(got), got)
	}
}

// Without the SYN watcher the decoys count on their own: a connection to the
// listener is one touch, held for a moment and closed, whatever the client says.
func TestDecoysListenAndCountWithoutTheWatcher(t *testing.T) {
	s, _ := newTest(t)
	s.watch = func(context.Context, func([]byte)) error { return discovery.ErrUnsupported } // no raw sockets here
	s.mu.Lock()
	s.raw = false
	s.mu.Unlock()
	s.LAN = func() Self { return Self{IP: "127.0.0.1"} }
	var mu sync.Mutex
	lns := map[int]net.Listener{}
	s.Listen = func(ctx context.Context, addr string) (net.Listener, error) {
		_, p, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(p)
		if port == 23 {
			return nil, &net.OpError{Op: "listen", Err: net.UnknownNetworkError("permission denied")}
		}
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		mu.Lock()
		lns[port] = ln
		mu.Unlock()
		return ln, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.rebind(ctx)
	if armed := s.Armed(); len(armed) != 4 || armed[0] != 445 || armed[3] != 5900 {
		t.Fatalf("armed: %v", armed)
	}
	// the dialer below is on loopback too; it must not look like the box itself
	time.Sleep(50 * time.Millisecond) // the watcher goroutine has given up by now
	s.mu.Lock()
	s.self.IP = "192.0.2.9"
	if s.raw {
		t.Fatal("watcher counted as running without raw sockets")
	}
	s.mu.Unlock()
	mu.Lock()
	addr := lns[3389].Addr().String()
	mu.Unlock()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")) // an RDP hello
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := conn.Read(buf); err == nil || n > 0 {
		t.Fatalf("the decoy answered: %d bytes, %v", n, err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	var got []wire.Signal
	for time.Now().Before(deadline) {
		if got = s.Drain(); got != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if kinds(got) != "canary:127.0.0.1:3389:1" {
		t.Fatalf("touch: %s", kinds(got))
	}
	// the same config again does not retry the port that failed (no log line every 30 s)
	cfg, _ := ParseConfig(wire.CanaryConfig{Enabled: true})
	s.Apply(cfg)
	s.mu.Lock()
	stillFailed := s.failed[23]
	s.mu.Unlock()
	if !stillFailed {
		t.Fatal("an unchanged config forgot the failed port")
	}
	// switched off: the listeners close
	s.Apply(Config{Enabled: false})
	s.rebind(ctx)
	if armed := s.Armed(); len(armed) != 0 {
		t.Fatalf("still armed: %v", armed)
	}
	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Fatal("decoy still open after switching off")
	}
}

func TestParseConfig(t *testing.T) {
	cfg, errs := ParseConfig(wire.CanaryConfig{Enabled: true, Ports: []int{3389, 22, 0, 445, 445, 70000}})
	if !cfg.Enabled || len(cfg.Ports) != 2 || cfg.Ports[0] != 445 || cfg.Ports[1] != 3389 || len(errs) != 3 {
		t.Fatalf("cfg %+v errs %v", cfg, errs)
	}
	cfg, errs = ParseConfig(wire.CanaryConfig{})
	if cfg.Enabled || len(cfg.Ports) != len(DefaultPorts) || len(errs) != 0 {
		t.Fatalf("defaults: %+v %v", cfg, errs)
	}
}

// The pending signals are bounded: the oldest goes first.
func TestPendingIsBounded(t *testing.T) {
	s, now := newTest(t)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	for i := 0; i < maxPending+5; i++ {
		s.observeFrame(synFrame(mac, "10.0."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250+1), "192.168.1.9", 445, 0x02))
		*now = now.Add(time.Millisecond)
	}
	got := s.Drain()
	if len(got) != maxPending || got[0].IP != "10.0.0.6" {
		t.Fatalf("bound: %d first %s", len(got), got[0].IP)
	}
}

// Signals other sensors hand in merge by their kind's nature: events add up, sizes
// take the latest value.
func TestRecordedSignalsMergeByKind(t *testing.T) {
	s, _ := newTest(t)
	s.Record([]wire.Signal{{Kind: wire.SignalDNSBlock, IP: "192.168.1.50", Count: 1, Detail: "evil.test|a.evil.test|blocked"}})
	s.Record([]wire.Signal{{Kind: wire.SignalDNSBlock, IP: "192.168.1.50", Count: 2, Detail: "evil.test|a.evil.test|blocked"}})
	s.Record([]wire.Signal{{Kind: wire.SignalDNSDGA, IP: "192.168.1.50", Count: 20, Detail: "x.nx"}})
	s.Record([]wire.Signal{{Kind: wire.SignalDNSDGA, IP: "192.168.1.50", Count: 21, Detail: "x.nx, y.nx"}})
	got := s.Drain()
	if kinds(got) != "dns_block:192.168.1.50:0:3 dns_dga:192.168.1.50:0:21" || got[1].Detail != "x.nx, y.nx" {
		t.Fatalf("merged: %s %+v", kinds(got), got)
	}
}
