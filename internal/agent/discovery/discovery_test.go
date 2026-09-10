package discovery

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

func TestOUI(t *testing.T) {
	o := &OUI{}
	cases := map[string]string{
		"00:09:0f:aa:bb:cc": "Fortinet, Inc.",
		"B8:27:EB:00:00:01": "Raspberry Pi Foundation",
		"3c-2a-f4-11-22-33": "Brother Industries, LTD.",
		"02:00:00:00:00:01": "", // locally administered, no vendor
		"not a mac":         "",
	}
	for mac, want := range cases {
		if got := o.Lookup(mac); got != want {
			t.Errorf("Lookup(%q) = %q, want %q", mac, got, want)
		}
	}
	if len(o.vendors) < 30000 {
		t.Fatalf("only %d vendors loaded", len(o.vendors))
	}
}

func TestTableDrainAckNack(t *testing.T) {
	tb := NewTable()
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	tb.now = func() time.Time { return now }
	tb.See("AA:BB:CC:DD:EE:01", "192.168.1.1", "")
	tb.See("aa:bb:cc:dd:ee:01", "192.168.1.1", "fe80::1") // same device, upper/lower case, adds v6
	tb.See("", "192.168.10.5", "")                        // icmp sweep, no mac
	tb.See("", "", "")                                    // nothing: ignored
	tb.See("garbage", "192.168.1.9", "")                  // bad mac: ignored
	if tb.Len() != 2 {
		t.Fatalf("entries = %d", tb.Len())
	}
	s := tb.Drain()
	if len(s) != 2 {
		t.Fatalf("drained %d", len(s))
	}
	byKey := map[string]wire.Sighting{}
	for _, x := range s {
		byKey[x.MAC+"|"+x.IP] = x
	}
	dev := byKey["aa:bb:cc:dd:ee:01|192.168.1.1"]
	if dev.MAC == "" || len(dev.IPv6) != 1 || dev.IPv6[0] != "fe80::1" || !dev.LastSeen.Equal(now) {
		t.Fatalf("device: %+v", dev)
	}
	if _, ok := byKey["|192.168.10.5"]; !ok {
		t.Fatalf("ip-only device missing: %v", byKey)
	}
	// without an Ack the sightings stay in flight: a second drain repeats them (at-least-once)
	if len(tb.Drain()) != 2 {
		t.Fatal("unacknowledged sightings were forgotten")
	}
	tb.Nack() // heartbeat failed: everything comes back
	if len(tb.Drain()) != 2 {
		t.Fatal("nack did not restore the sightings")
	}
	tb.Ack()
	if len(tb.Drain()) != 0 {
		t.Fatal("ack did not clear the sightings")
	}
	now = now.Add(time.Minute)
	tb.See("aa:bb:cc:dd:ee:01", "192.168.1.2", "") // ip changed
	s = tb.Drain()
	if len(s) != 1 || s[0].IP != "192.168.1.2" || !s[0].LastSeen.Equal(now) {
		t.Fatalf("changed ip: %+v", s)
	}
}

func TestTableBounded(t *testing.T) {
	tb := NewTable()
	for i := 0; i < wire.MaxSightings+500; i++ {
		tb.See("", "10."+itoa(byte(i>>16))+"."+itoa(byte(i>>8))+"."+itoa(byte(i)), "")
	}
	if got := len(tb.Drain()); got != wire.MaxSightings {
		t.Fatalf("drain returned %d, want the cap %d", got, wire.MaxSightings)
	}
}

func TestAnnotate(t *testing.T) {
	tb := NewTable()
	tb.See("b8:27:eb:00:00:01", "192.168.1.20", "")
	calls := 0
	names := NewNames()
	names.Lookup = func(_ context.Context, ip string) string {
		calls++
		if ip == "192.168.1.20" {
			return "pi.lan"
		}
		return ""
	}
	tb.Annotate(context.Background(), &OUI{}, names)
	s := tb.Drain()
	if len(s) != 1 || s[0].Vendor != "Raspberry Pi Foundation" || s[0].Hostname != "pi.lan" {
		t.Fatalf("annotated: %+v", s)
	}
	tb.Ack()
	tb.See("b8:27:eb:00:00:01", "192.168.1.20", "")
	tb.Annotate(context.Background(), &OUI{}, names)
	if calls != 1 {
		t.Fatalf("name resolved %d times, cache not used", calls)
	}
}

func TestParseConfig(t *testing.T) {
	cfg, errs := ParseConfig(wire.DiscoveryConfig{Mode: "sweep", Subnets: []string{"192.168.10.0/24", "10.0.0.0/8", "nope", "2001:db8::/64"}, SweepIntervalS: 60, MaxPPS: 500})
	if cfg.Mode != wire.DiscoverySweep || cfg.Interval != 5*time.Minute || cfg.MaxPPS != HardMaxPPS || len(cfg.Subnets) != 1 || cfg.Subnets[0].String() != "192.168.10.0/24" {
		t.Fatalf("cfg: %+v", cfg)
	}
	joined := strings.Join(errs, "\n")
	for _, want := range []string{"10.0.0.0/8 is larger", `"nope" is not an IPv4 CIDR`, `"2001:db8::/64" is not an IPv4 CIDR`, "below 5 minutes", "max_pps above"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in errors:\n%s", want, joined)
		}
	}
	cfg, errs = ParseConfig(wire.DiscoveryConfig{Mode: "portscan"})
	if cfg.Mode != wire.DiscoveryPassive || len(errs) != 1 {
		t.Fatalf("unknown mode: %+v %v", cfg, errs)
	}
	var many []string
	for i := 0; i < MaxSubnets+2; i++ {
		many = append(many, "10.1."+itoa(byte(i))+".0/24")
	}
	cfg, errs = ParseConfig(wire.DiscoveryConfig{Mode: "sweep", Subnets: many})
	if len(cfg.Subnets) != MaxSubnets || len(errs) != 1 {
		t.Fatalf("subnet cap: %d subnets, %v", len(cfg.Subnets), errs)
	}
}

func TestHostsAndClamp(t *testing.T) {
	p := netip.MustParsePrefix("192.168.1.7/24")
	h := hosts(p)
	if len(h) != 254 || h[0].String() != "192.168.1.1" || h[253].String() != "192.168.1.254" {
		t.Fatalf("/24 hosts: %d %v", len(h), h[:2])
	}
	if got := hosts(netip.MustParsePrefix("10.0.0.0/30")); len(got) != 2 {
		t.Fatalf("/30: %v", got)
	}
	if got := hosts(netip.MustParsePrefix("10.0.0.0/31")); len(got) != 2 {
		t.Fatalf("/31: %v", got)
	}
	big := clampPrefix(netip.MustParsePrefix("10.5.7.9/16"))
	if big.Bits() != MaxPrefixBits || big.String() != "10.5.4.0/22" {
		t.Fatalf("clamp: %s", big)
	}
	if len(hosts(big)) != 1022 {
		t.Fatalf("/22 hosts: %d", len(hosts(big)))
	}
}

func TestRunWithFakes(t *testing.T) {
	d := New(slog.Default())
	passiveCalls, arpCalls, icmpCalls, neighCalls := 0, 0, 0, 0
	d.passive = func(ctx context.Context, see func(mac, ip, ip6 string)) error {
		passiveCalls++
		see("aa:bb:cc:00:00:01", "192.168.1.10", "")
		<-ctx.Done()
		return ctx.Err()
	}
	d.arpSweep = func(_ context.Context, pps int, see func(mac, ip, ip6 string)) error {
		arpCalls++
		if pps != 25 {
			t.Errorf("pps = %d", pps)
		}
		see("aa:bb:cc:00:00:02", "192.168.1.11", "")
		return nil
	}
	d.icmpSweep = func(_ context.Context, prefixes []netip.Prefix, _ int, see func(mac, ip, ip6 string)) error {
		icmpCalls++
		see("", prefixes[0].Addr().Next().String(), "")
		return nil
	}
	d.neighbors = func(see func(mac, ip, ip6 string)) error { neighCalls++; return nil }
	cfg, _ := ParseConfig(wire.DiscoveryConfig{Mode: "sweep", Subnets: []string{"192.168.10.0/24"}, MaxPPS: 25})
	d.Apply(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	d.sweep(ctx, d.config()) // the timer would do this after 30 s
	cancel()
	time.Sleep(20 * time.Millisecond)
	if passiveCalls != 1 || arpCalls != 1 || icmpCalls != 1 || neighCalls != 1 {
		t.Fatalf("calls: passive=%d arp=%d icmp=%d neigh=%d", passiveCalls, arpCalls, icmpCalls, neighCalls)
	}
	s := d.Sightings(context.Background())
	if len(s) != 3 {
		t.Fatalf("sightings: %+v", s)
	}
	// passive mode never sweeps
	d.Apply(Config{Mode: wire.DiscoveryPassive, Interval: time.Hour, MaxPPS: 50})
	d.sweep(context.Background(), d.config())
	if arpCalls != 1 || icmpCalls != 1 || neighCalls != 2 {
		t.Fatalf("passive mode swept: arp=%d icmp=%d neigh=%d", arpCalls, icmpCalls, neighCalls)
	}
}

func TestParseARPFrame(t *testing.T) {
	// ethernet + arp request from 192.168.1.1 / 00:09:0f:aa:bb:cc
	f := make([]byte, 42)
	f[12], f[13] = 0x08, 0x06
	a := f[14:]
	a[1], a[2], a[4], a[5], a[7] = 1, 8, 6, 4, 1 // htype 1, ptype 0x0800, hlen 6, plen 4, request
	copy(a[8:14], []byte{0x00, 0x09, 0x0f, 0xaa, 0xbb, 0xcc})
	copy(a[14:18], []byte{192, 168, 1, 1})
	mac, ip, ok := parseARPPortable(f)
	if !ok || mac != "00:09:0f:aa:bb:cc" || ip != "192.168.1.1" {
		t.Fatalf("parse: %s %s %v", mac, ip, ok)
	}
	copy(a[14:18], []byte{0, 0, 0, 0}) // probe
	if _, _, ok := parseARPPortable(f); ok {
		t.Fatal("arp probe reported as a device")
	}
	if _, _, ok := parseARPPortable(f[:30]); ok {
		t.Fatal("short frame parsed")
	}
}
