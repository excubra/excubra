//go:build !linux

package discovery

import (
	"context"
	"net"
	"net/netip"
)

// On non-Linux builds discovery is inert: the agent runs for development, sees no
// devices and says so once in the log.

func platformPassive(context.Context, func(mac, ip, ip6 string), func(ARPFrame)) error {
	return ErrUnsupported
}
func platformARPSweep(context.Context, int, func(mac, ip, ip6 string)) error { return ErrUnsupported }
func platformICMPSweep(context.Context, []netip.Prefix, int, func(mac, ip, ip6 string)) error {
	return ErrUnsupported
}
func platformNeighbors(func(mac, ip, ip6 string)) error { return ErrUnsupported }

// LANInterface and DefaultGateway need the Linux route table.
func LANInterface() (*net.Interface, netip.Prefix, error) { return nil, netip.Prefix{}, ErrUnsupported }

// DefaultGateway is unknown off Linux.
func DefaultGateway() (netip.Addr, bool) { return netip.Addr{}, false }
