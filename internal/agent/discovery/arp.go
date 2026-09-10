package discovery

import (
	"encoding/binary"
	"net"
)

// parseARPPortable extracts sender MAC and IPv4 from an Ethernet+ARP frame. It is
// platform-independent so the frame layout is unit-tested everywhere; the Linux
// listener calls it for every frame it receives.
func parseARPPortable(f []byte) (string, string, bool) {
	if len(f) < 42 || binary.BigEndian.Uint16(f[12:14]) != 0x0806 {
		return "", "", false
	}
	a := f[14:]
	if binary.BigEndian.Uint16(a[0:2]) != 1 || binary.BigEndian.Uint16(a[2:4]) != 0x0800 || a[4] != 6 || a[5] != 4 {
		return "", "", false
	}
	sha := net.HardwareAddr(a[8:14])
	spa := net.IP(a[14:18])
	if spa.Equal(net.IPv4zero) || sha.String() == "00:00:00:00:00:00" {
		return "", "", false // ARP probe, no address yet
	}
	return sha.String(), spa.String(), true
}
