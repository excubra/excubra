//go:build linux

package checks

import (
	"fmt"

	"golang.org/x/net/icmp"
)

// ListenICMP4 opens an ICMP socket for echo requests. The unprivileged datagram
// socket needs the process group inside net.ipv4.ping_group_range; when that is
// not the case the raw socket is tried, which CAP_NET_RAW allows. Both deliver
// replies without the IP header, so callers parse them the same way.
func ListenICMP4() (*icmp.PacketConn, bool, error) {
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		return c, false, nil
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, false, fmt.Errorf("icmp socket (needs CAP_NET_RAW or net.ipv4.ping_group_range): %w", err)
	}
	return c, true, nil
}
