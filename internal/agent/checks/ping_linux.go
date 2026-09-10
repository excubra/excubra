//go:build linux

package checks

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPPinger sends echo requests from a datagram-oriented ICMP socket. With
// CAP_NET_RAW this works unprivileged; no raw IP socket and no NET_ADMIN.
type ICMPPinger struct {
	id int
}

// NewPinger returns the platform pinger.
func NewPinger() Pinger { return &ICMPPinger{id: os.Getpid() & 0xffff} }

// Ping sends one echo request and waits for its reply.
func (p *ICMPPinger) Ping(ctx context.Context, address string) (time.Duration, error) {
	ip, err := resolve(ctx, address)
	if err != nil {
		return 0, err
	}
	network, proto, listen := "udp4", 1, "0.0.0.0"
	msgType := icmp.Type(ipv4.ICMPTypeEcho)
	if ip.To4() == nil {
		network, proto, listen = "udp6", 58, "::"
		msgType = ipv6.ICMPTypeEchoRequest
	}
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return 0, fmt.Errorf("icmp socket (needs CAP_NET_RAW or net.ipv4.ping_group_range): %w", err)
	}
	defer func() { _ = conn.Close() }()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(Timeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, err
	}
	seq := int(rand.Uint32() & 0xffff) //nolint:gosec // a sequence number, not a secret
	body := &icmp.Echo{ID: p.id, Seq: seq, Data: []byte("excubra")}
	wm := icmp.Message{Type: msgType, Code: 0, Body: body}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := conn.WriteTo(wb, &net.UDPAddr{IP: ip}); err != nil {
		return 0, err
	}
	rb := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(rb)
		if err != nil {
			return 0, err
		}
		rm, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			continue
		}
		if echo, ok := rm.Body.(*icmp.Echo); ok && echo.Seq == seq {
			return time.Since(start), nil
		}
		if time.Now().After(deadline) {
			return 0, errors.New("timeout")
		}
	}
}

func resolve(ctx context.Context, address string) (net.IP, error) {
	if ip := net.ParseIP(address); ip != nil {
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", address)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("no such host %q", address)
	}
	return ips[0], nil
}
