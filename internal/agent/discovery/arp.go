package discovery

import (
	"encoding/binary"
	"net"
)

// ARPFrame is what the passive listener hands to an observer for every ARP frame
// it reads: the operation (1 request, 2 reply), who sent it and whom it asks for.
// The sentinel counts these to see a network being searched or a gateway being
// impersonated (ADR-0018 §7).
type ARPFrame struct {
	Op        int
	SenderMAC string
	SenderIP  string // "0.0.0.0" for a probe of a client without an address yet
	TargetIP  string
}

// parseARP decodes an Ethernet+ARP frame (IPv4 over Ethernet only). It is
// platform-independent so the frame layout is unit-tested everywhere.
func parseARP(f []byte) (ARPFrame, bool) {
	if len(f) < 42 || binary.BigEndian.Uint16(f[12:14]) != 0x0806 {
		return ARPFrame{}, false
	}
	a := f[14:]
	if binary.BigEndian.Uint16(a[0:2]) != 1 || binary.BigEndian.Uint16(a[2:4]) != 0x0800 || a[4] != 6 || a[5] != 4 {
		return ARPFrame{}, false
	}
	return ARPFrame{
		Op:        int(binary.BigEndian.Uint16(a[6:8])),
		SenderMAC: net.HardwareAddr(a[8:14]).String(),
		SenderIP:  net.IP(a[14:18]).String(),
		TargetIP:  net.IP(a[24:28]).String(),
	}, true
}

// parseARPPortable extracts sender MAC and IPv4 from an Ethernet+ARP frame for
// the sighting table; probes without an address are not a device yet.
func parseARPPortable(f []byte) (string, string, bool) {
	fr, ok := parseARP(f)
	if !ok || fr.SenderIP == "0.0.0.0" || fr.SenderMAC == "00:00:00:00:00:00" {
		return "", "", false
	}
	return fr.SenderMAC, fr.SenderIP, true
}
