//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/excubra/excubra/internal/agent/checks"
)

// lanInterface picks the interface of the default IPv4 route from /proc/net/route,
// which is what "the box's LAN" means on a single-homed device.
func lanInterface() (*net.Interface, netip.Prefix, error) {
	name, _, err := defaultRoute()
	if err != nil {
		return nil, netip.Prefix{}, err
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, netip.Prefix{}, err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, netip.Prefix{}, err
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() == nil {
			continue
		}
		ones, _ := ipn.Mask.Size()
		addr, _ := netip.AddrFromSlice(ipn.IP.To4())
		return ifi, netip.PrefixFrom(addr, ones), nil
	}
	return nil, netip.Prefix{}, fmt.Errorf("interface %s has no IPv4 address", name)
}

// defaultRoute reads the IPv4 default route: its interface and its gateway (which
// /proc/net/route stores as little-endian hex).
func defaultRoute() (string, netip.Addr, error) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", netip.Addr{}, err
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == "00000000" {
			var gw netip.Addr
			if raw, err := hex.DecodeString(f[2]); err == nil && len(raw) == 4 {
				gw = netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
			}
			return f[0], gw, nil
		}
	}
	return "", netip.Addr{}, errors.New("no default route")
}

// LANInterface returns the interface of the default route with its IPv4 prefix,
// and DefaultGateway the address the default route points at — what the sentinel
// needs to know which frames are its own and which address is the gateway.
func LANInterface() (*net.Interface, netip.Prefix, error) { return lanInterface() }

// DefaultGateway returns the IPv4 gateway of the default route, if any.
func DefaultGateway() (netip.Addr, bool) {
	_, gw, err := defaultRoute()
	return gw, err == nil && gw.IsValid() && !gw.IsUnspecified()
}

// htons converts to network byte order for the AF_PACKET protocol field. Every
// Linux target we build (amd64, arm64) is little-endian.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

func arpSocket(ifi *net.Interface) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ARP)))
	if err != nil {
		return -1, fmt.Errorf("AF_PACKET socket (needs CAP_NET_RAW): %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: ifi.Index}); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("bind to %s: %w", ifi.Name, err)
	}
	return fd, nil
}

// platformPassive reads ARP frames on the LAN interface until ctx ends, reports
// every sender to the table and every frame to the observer. It never transmits.
func platformPassive(ctx context.Context, see func(mac, ip, ip6 string), observe func(ARPFrame)) error {
	ifi, _, err := lanInterface()
	if err != nil {
		return err
	}
	fd, err := arpSocket(ifi)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	// a read timeout lets the loop notice a cancelled context
	tv := unix.NsecToTimeval(int64(time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	buf := make([]byte, 1600)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		fr, ok := parseARP(buf[:n])
		if !ok {
			continue
		}
		if fr.SenderIP != "0.0.0.0" && fr.SenderMAC != "00:00:00:00:00:00" {
			see(fr.SenderMAC, fr.SenderIP, "")
		}
		if observe != nil {
			observe(fr)
		}
	}
	return ctx.Err()
}

// platformARPSweep sends one ARP request to every address of the own subnet
// (capped at a /22), paced by maxPPS. Replies arrive at the passive listener.
func platformARPSweep(ctx context.Context, maxPPS int, see func(mac, ip, ip6 string)) error {
	ifi, prefix, err := lanInterface()
	if err != nil {
		return err
	}
	if len(ifi.HardwareAddr) != 6 {
		return fmt.Errorf("interface %s has no MAC", ifi.Name)
	}
	fd, err := arpSocket(ifi)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	self := prefix.Addr().As4()
	dst := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ARP), Ifindex: ifi.Index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
	limiter := newRateLimiter(maxPPS)
	frame := make([]byte, 42)
	for i := range frame[:6] {
		frame[i] = 0xff
	}
	copy(frame[6:12], ifi.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)      // Ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // IPv4
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 1) // request
	copy(arp[8:14], ifi.HardwareAddr)
	copy(arp[14:18], self[:])
	for _, target := range hosts(clampPrefix(prefix)) {
		if target.As4() == self {
			continue
		}
		if !limiter.wait(ctx) {
			return ctx.Err()
		}
		t := target.As4()
		copy(arp[24:28], t[:])
		if err := unix.Sendto(fd, frame, 0, dst); err != nil {
			return fmt.Errorf("arp send: %w", err)
		}
	}
	// the listener sees the replies; also report ourselves so the box is in the inventory
	see(ifi.HardwareAddr.String(), prefix.Addr().String(), "")
	return nil
}

// platformICMPSweep pings every address of the configured subnets, paced by
// maxPPS, and reports the ones that answer (IP only: no MAC across a router).
func platformICMPSweep(ctx context.Context, prefixes []netip.Prefix, maxPPS int, see func(mac, ip, ip6 string)) error {
	conn, raw, err := checks.ListenICMP4()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	id := os.Getpid() & 0xffff
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-done:
					return
				default:
				}
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				return
			}
			msg, err := icmp.ParseMessage(1, buf[:n])
			if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			if echo, ok := msg.Body.(*icmp.Echo); ok && echo.ID == id {
				switch pa := peer.(type) {
				case *net.UDPAddr:
					see("", pa.IP.String(), "")
				case *net.IPAddr:
					see("", pa.IP.String(), "")
				}
			}
		}
	}()
	limiter := newRateLimiter(maxPPS)
	seq := 0
	for _, p := range prefixes {
		for _, a := range hosts(clampPrefix(p)) {
			if !limiter.wait(ctx) {
				return ctx.Err()
			}
			seq++
			wm := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq & 0xffff, Data: []byte("excubra")}}
			wb, _ := wm.Marshal(nil)
			ip := a.As4()
			var dst net.Addr = &net.UDPAddr{IP: net.IP(ip[:])}
			if raw {
				dst = &net.IPAddr{IP: net.IP(ip[:])}
			}
			if _, err := conn.WriteTo(wb, dst); err != nil {
				continue
			}
		}
	}
	// give the last replies a moment, then stop the reader
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
	}
	_ = conn.SetReadDeadline(time.Now())
	_ = conn.Close()
	<-done
	return nil
}

// platformNeighbors reads the kernel neighbor tables (IPv4 ARP cache and IPv6
// NDP cache) over netlink and reports every entry with a link-layer address.
func platformNeighbors(see func(mac, ip, ip6 string)) error {
	for _, family := range []int{unix.AF_INET6, unix.AF_INET} {
		tab, err := syscall.NetlinkRIB(unix.RTM_GETNEIGH, family)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(tab)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Type != unix.RTM_NEWNEIGH || len(m.Data) < 12 {
				continue
			}
			state := binary.LittleEndian.Uint16(m.Data[8:10])
			if state&(unix.NUD_REACHABLE|unix.NUD_STALE|unix.NUD_DELAY|unix.NUD_PROBE|unix.NUD_PERMANENT) == 0 {
				continue
			}
			var dst, lladdr []byte
			attrs := m.Data[12:]
			for len(attrs) >= 4 {
				l := int(binary.LittleEndian.Uint16(attrs[0:2]))
				t := binary.LittleEndian.Uint16(attrs[2:4])
				if l < 4 || l > len(attrs) {
					break
				}
				val := attrs[4:l]
				switch t {
				case unix.NDA_DST:
					dst = val
				case unix.NDA_LLADDR:
					lladdr = val
				}
				attrs = attrs[(l+3)&^3:]
			}
			if len(lladdr) != 6 || len(dst) == 0 {
				continue
			}
			mac := net.HardwareAddr(lladdr).String()
			ip := net.IP(dst)
			switch {
			case ip.To4() != nil:
				see(mac, ip.String(), "")
			case ip.IsLinkLocalUnicast():
				see(mac, "", ip.String())
			default:
				see(mac, "", ip.String())
			}
		}
	}
	return nil
}
