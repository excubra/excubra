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
		{Name: "eth0", Index: 3, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("192.168.100.60/24"), netip.MustParsePrefix("192.168.100.61/24")}},
		{Name: "wt0", Index: 4, Flags: up | net.FlagPointToPoint, Nets: []netip.Prefix{netip.MustParsePrefix("100.112.91.255/16")}},
		{Name: "veth-op", Index: 5, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("169.254.222.1/30")}},
		{Name: "docker0", Index: 6, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("172.17.0.1/16")}},
		{Name: "eth2", Index: 7, Flags: net.FlagBroadcast, Nets: []netip.Prefix{netip.MustParsePrefix("10.30.0.1/24")}}, // down
		{Name: "eth3", Index: 8, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("203.0.113.5/24")}},              // public
		{Name: "vmbr0", Index: 9, Flags: up, Nets: []netip.Prefix{netip.MustParsePrefix("10.40.0.2/24")}},
	}
	got := filterLAN(rows, "eth0")
	want := []string{"192.168.100.0/24", "10.20.0.0/16", "10.40.0.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// without a known default route the lowest index wins
	if got := filterLAN(rows, ""); got[0] != "10.20.0.0/16" {
		t.Fatalf("without default route: %v", got)
	}
	if got := filterLAN(nil, "eth0"); got != nil {
		t.Fatalf("no interfaces: %v", got)
	}
}

func TestLanPrefixesDoesNotPanicOnThisMachine(t *testing.T) {
	for _, p := range lanPrefixes() {
		if _, err := netip.ParsePrefix(p); err != nil {
			t.Fatalf("bad prefix %q", p)
		}
	}
}
