package agent

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func TestFilterLANPicksTheRealNetworksDefaultRouteFirst(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast
	rows := []ifaceNets{
		{Name: "lo", Index: 1, Flags: net.FlagUp | net.FlagLoopback, Nets: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth1", Index: 2, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("10.20.0.7/16")}},
		{Name: "eth0", Index: 3, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("192.168.20.60/24"), netip.MustParsePrefix("192.168.20.61/24")}},
		{Name: "wt0", Index: 4, Flags: up | net.FlagPointToPoint, Nets: []netip.Prefix{netip.MustParsePrefix("100.64.0.99/16")}},
		{Name: "veth-op", Index: 5, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("169.254.222.1/30")}},
		{Name: "docker0", Index: 6, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{Name: "eth2", Index: 7, Flags: net.FlagBroadcast, Nets: []netip.Prefix{netip.MustParsePrefix("10.30.0.1/24")}}, // down
		{Name: "eth3", Index: 8, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("203.0.113.5/24")}},              // public
		{Name: "vmbr0", Index: 9, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("10.40.0.2/24")}},
	}
	got, other := filterLAN(rows, "eth0")
	want := []string{"192.168.20.0/24", "10.20.0.0/16", "10.40.0.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// the public network is reported, apart: seen, and never a LAN by itself
	if !reflect.DeepEqual(other, []string{"203.0.113.0/24"}) {
		t.Fatalf("other: %v", other)
	}
	// without a known default route the lowest index wins
	if got, _ := filterLAN(rows, ""); got[0] != "10.20.0.0/16" {
		t.Fatalf("without default route: %v", got)
	}
	if got, other := filterLAN(nil, "eth0"); got != nil || other != nil {
		t.Fatalf("no interfaces: %v %v", got, other)
	}
}

// A customer whose LAN was numbered with public addresses long ago: the box
// sits in it and says so, apart from the private networks, and knows its own
// address there.
func TestALANOutsideRFC1918IsReportedApart(t *testing.T) {
	up := net.FlagUp | net.FlagBroadcast
	rows := []ifaceNets{
		{Name: "lo", Index: 1, Flags: net.FlagUp | net.FlagLoopback, Nets: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "eth0", Index: 2, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("192.0.2.79/24")}},
		{Name: "veth-op", Index: 3, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("169.254.222.1/30")}},
	}
	private, other := filterLAN(rows, "eth0")
	if len(private) != 0 || !reflect.DeepEqual(other, []string{"192.0.2.0/24"}) {
		t.Fatalf("private %v, other %v", private, other)
	}
	if got := pickLANAddress(rows, "eth0"); got != "192.0.2.79" {
		t.Fatalf("the box's own address in that LAN: %q", got)
	}

	// what is never a LAN, whatever its address: a single address (a server at a
	// hoster), a point-to-point link, link-local, multicast, the operator's veth
	never := []ifaceNets{
		{Name: "eth0", Index: 1, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("198.51.100.47/32")}},
		{Name: "eth1", Index: 2, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/31")}},
		{Name: "eth2", Index: 3, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("169.254.7.9/16")}},
		{Name: "eth3", Index: 4, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("224.0.0.5/24")}},
		{Name: "ppp0", Index: 5, Flags: up | net.FlagPointToPoint, Nets: []netip.Prefix{netip.MustParsePrefix("198.51.100.34/24")}},
		{Name: "wt1", Index: 6, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("100.90.0.9/16")}},
	}
	if private, other := filterLAN(never, "eth0"); private != nil || other != nil {
		t.Fatalf("none of these is a LAN: private %v, other %v", private, other)
	}
	if got := pickLANAddress(never, "eth0"); got != "" {
		t.Fatalf("no LAN, no LAN address: %q", got)
	}

	// a private network wins over a public one, whichever carries the default route
	both := []ifaceNets{
		{Name: "eth0", Index: 1, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("192.0.2.79/24")}},
		{Name: "eth1", Index: 2, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("192.168.5.9/24")}},
	}
	if got := pickLANAddress(both, "eth0"); got != "192.168.5.9" {
		t.Fatalf("private first: %q", got)
	}
}

func TestLanNetworksDoesNotPanicOnThisMachine(t *testing.T) {
	private, other := lanNetworks()
	for _, p := range append(private, other...) {
		if _, err := netip.ParsePrefix(p); err != nil {
			t.Fatalf("bad prefix %q", p)
		}
	}
	_ = lanAddress()
}
