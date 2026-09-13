//go:build linux

package sentinel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/excubra/excubra/internal/agent/discovery"
)

// platformSelf reads the LAN interface and the default route.
func platformSelf() Self {
	ifi, prefix, err := discovery.LANInterface()
	if err != nil {
		return Self{}
	}
	self := Self{IP: prefix.Addr().String(), MAC: ifi.HardwareAddr.String()}
	if gw, ok := discovery.DefaultGateway(); ok {
		self.Gateway = gw.String()
	}
	return self
}

// synFilter is a classic BPF program that keeps IPv4 TCP frames with SYN set and
// ACK clear (no fragments) and drops everything else in the kernel, so the
// watcher costs nothing on a busy LAN. Offsets are from the Ethernet header.
// The array (not a slice) keeps len a compile-time constant, so the uint16 below
// is a constant conversion and cannot overflow.
var synFilter = [...]unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 12},              // ethertype
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 9, K: 0x0800},  // not IPv4: drop
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 23},              // ip protocol
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 7, K: 6},       // not TCP: drop
	{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 20},              // flags + fragment offset
	{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 5, K: 0x1fff}, // a later fragment: drop
	{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 14},             // x = ip header length
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, K: 27},              // tcp flags at 14 + x + 13
	{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0x12},           // SYN and ACK bits
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: 0x02},    // SYN without ACK: keep
	{Code: unix.BPF_RET | unix.BPF_K, K: 96},                            // enough for the headers
	{Code: unix.BPF_RET | unix.BPF_K, K: 0},                             // drop
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// platformWatch reads SYN frames on the LAN interface until ctx ends. Packet
// sockets see a frame before the firewall does, so a SYN the box drops still
// counts. It never transmits.
func platformWatch(ctx context.Context, observe func(frame []byte)) error {
	ifi, _, err := discovery.LANInterface()
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return fmt.Errorf("AF_PACKET socket (needs CAP_NET_RAW): %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	prog := unix.SockFprog{Len: uint16(len(synFilter)), Filter: &synFilter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("attach filter: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: ifi.Index}); err != nil {
		return fmt.Errorf("bind to %s: %w", ifi.Name, err)
	}
	tv := unix.NsecToTimeval(int64(time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}
	buf := make([]byte, 128)
	for ctx.Err() == nil {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		observe(buf[:n])
	}
	return ctx.Err()
}
