package agent

import (
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// lanPrefixes lists the private IPv4 networks the box sits in, the interface with
// the default route first. Overlay, virtual and container interfaces are left
// out. The server takes the first entry as the site's LAN (ADR-0017).
func lanPrefixes() []string {
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
	return filterLAN(rows, defaultRouteInterface())
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

func filterLAN(rows []ifaceNets, first string) []string {
	sort.SliceStable(rows, func(i, j int) bool {
		if (rows[i].Name == first) != (rows[j].Name == first) {
			return rows[i].Name == first
		}
		return rows[i].Index < rows[j].Index
	})
	var out []string
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Flags&net.FlagLoopback != 0 || r.Flags&net.FlagUp == 0 || r.Flags&net.FlagPointToPoint != 0 || skipLAN(r.Name) {
			continue
		}
		for _, p := range r.Nets {
			if !p.Addr().IsPrivate() || p.Bits() < 8 || p.Bits() > 30 {
				continue
			}
			m := p.Masked().String()
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
		if len(out) >= maxLAN {
			return out[:maxLAN]
		}
	}
	return out
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

// lanAddress is the box's own private IPv4 address on the LAN interface (the
// default route's, else the first that counts as LAN), "" without one.
func lanAddress() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	first := defaultRouteInterface()
	best := ""
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 || skipLAN(ifi.Name) {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			addr, _ := netip.AddrFromSlice(ipn.IP.To4())
			if !addr.IsPrivate() {
				continue
			}
			if ifi.Name == first {
				return addr.String()
			}
			if best == "" {
				best = addr.String()
			}
		}
	}
	return best
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
