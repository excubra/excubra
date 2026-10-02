package agent

import (
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// lanNetworks lists the IPv4 networks the box sits in, the interface with the
// default route first. Overlay, virtual and container interfaces are left out.
//
// private are the RFC 1918 networks; the server takes the first as the site's
// LAN (ADR-0017). other are directly attached networks that are not RFC 1918:
// a customer LAN somebody once numbered with public addresses. The box only
// says that it sits in one — whether that network is the customer's own is an
// operator's call on the server (ADR-0024), never the box's.
func lanNetworks() (private, other []string) {
	return filterLAN(interfaceNets(), defaultRouteInterface())
}

func interfaceNets() []ifaceNets {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var rows []ifaceNets
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		r := ifaceNets{Name: ifi.Name, Index: ifi.Index, Flags: ifi.Flags}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil {
				continue
			}
			ones, _ := ipn.Mask.Size()
			addr, _ := netip.AddrFromSlice(ip4)
			r.Nets = append(r.Nets, netip.PrefixFrom(addr, ones))
		}
		rows = append(rows, r)
	}
	return rows
}

type ifaceNets struct {
	Name  string
	Index int
	Flags net.Flags
	Nets  []netip.Prefix
}

// Interfaces that are never the LAN: loopback, both NetBird clients, the operator
// namespace's veth, container and VPN plumbing. A bridge with an address (vmbr0 on
// a hypervisor) is the LAN and stays.
var (
	notLANExact  = map[string]bool{"lo": true, "op0": true, "mvop": true, "veth-op": true}
	notLANPrefix = []string{"wt", "wg", "veth", "docker", "br-", "virbr", "tun", "tap", "tailscale", "zt", "lxc", "fwbr", "fwpr", "fwln"}
	maxLAN       = 4
)

// usableLAN says whether an interface's network can be a LAN at all: a real
// network of hosts, not a point-to-point link and not a single address.
func usableLAN(p netip.Prefix) bool {
	return p.Addr().Is4() && p.Bits() >= 8 && p.Bits() <= 30
}

// otherLAN says whether a usable network that is not RFC 1918 is worth
// reporting: ordinary unicast space. Loopback, link-local and multicast are
// never anybody's LAN.
func otherLAN(p netip.Prefix) bool {
	a := p.Addr()
	return usableLAN(p) && !a.IsPrivate() && a.IsGlobalUnicast()
}

func filterLAN(rows []ifaceNets, first string) (private, other []string) {
	sort.SliceStable(rows, func(i, j int) bool {
		if (rows[i].Name == first) != (rows[j].Name == first) {
			return rows[i].Name == first
		}
		return rows[i].Index < rows[j].Index
	})
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Flags&net.FlagLoopback != 0 || r.Flags&net.FlagUp == 0 || r.Flags&net.FlagPointToPoint != 0 || skipLAN(r.Name) {
			continue
		}
		for _, p := range r.Nets {
			if !usableLAN(p) {
				continue
			}
			m := p.Masked().String()
			if seen[m] {
				continue
			}
			seen[m] = true
			switch {
			case p.Addr().IsPrivate():
				if len(private) < maxLAN {
					private = append(private, m)
				}
			case otherLAN(p):
				if len(other) < maxLAN {
					other = append(other, m)
				}
			}
		}
	}
	return private, other
}

func skipLAN(name string) bool {
	if notLANExact[name] {
		return true
	}
	for _, pfx := range notLANPrefix {
		if strings.HasPrefix(name, pfx) {
			return true
		}
	}
	return false
}

// lanAddress is the box's own IPv4 address on the LAN: a private one, the
// default route's interface first. A box whose only network is outside RFC 1918
// reports its address there — it is the address a router would point at for
// the DNS sensor all the same. "" without any.
func lanAddress() string {
	return pickLANAddress(interfaceNets(), defaultRouteInterface())
}

func pickLANAddress(rows []ifaceNets, first string) string {
	sort.SliceStable(rows, func(i, j int) bool {
		if (rows[i].Name == first) != (rows[j].Name == first) {
			return rows[i].Name == first
		}
		return rows[i].Index < rows[j].Index
	})
	fallback := ""
	for _, r := range rows {
		if r.Flags&net.FlagUp == 0 || r.Flags&net.FlagLoopback != 0 || r.Flags&net.FlagPointToPoint != 0 || skipLAN(r.Name) {
			continue
		}
		for _, p := range r.Nets {
			switch {
			case p.Addr().IsPrivate():
				return p.Addr().String()
			case fallback == "" && otherLAN(p):
				fallback = p.Addr().String()
			}
		}
	}
	return fallback
}

// defaultRouteInterface names the interface of the IPv4 default route on Linux
// (/proc/net/route); "" elsewhere or without one.
func defaultRouteInterface() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}
