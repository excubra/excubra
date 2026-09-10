package discovery

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// mdnsLookup asks the local multicast group for the PTR of an IPv4 address and
// returns the first answer within the context's deadline. Best effort; silence is
// the normal outcome for devices without mDNS.
func mdnsLookup(ctx context.Context, ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return ""
	}
	b := addr.As4()
	qname := strings.Join([]string{itoa(b[3]), itoa(b[2]), itoa(b[1]), itoa(b[0])}, ".") + ".in-addr.arpa."
	name, err := dnsmessage.NewName(qname)
	if err != nil {
		return ""
	}
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0, RecursionDesired: false},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return ""
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(nameTimeout)
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.WriteToUDP(packed, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}); err != nil {
		return ""
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return ""
		}
		var p dnsmessage.Parser
		if _, err := p.Start(buf[:n]); err != nil {
			continue
		}
		if err := p.SkipAllQuestions(); err != nil {
			continue
		}
		for {
			h, err := p.AnswerHeader()
			if err != nil {
				break
			}
			if h.Type == dnsmessage.TypePTR && strings.EqualFold(h.Name.String(), qname) {
				r, err := p.PTRResource()
				if err == nil {
					return strings.TrimSuffix(strings.TrimSuffix(r.PTR.String(), "."), ".local")
				}
			}
			if err := p.SkipAnswer(); err != nil {
				break
			}
		}
	}
}

func itoa(b byte) string {
	if b == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for b > 0 {
		i--
		buf[i] = '0' + b%10
		b /= 10
	}
	return string(buf[i:])
}
