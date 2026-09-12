package scan

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

// What a port usually is. Only the name; the banner says the rest.
var portNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
	143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 515: "lpd", 548: "afp", 554: "rtsp", 587: "submission", 631: "ipp",
	636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker",
	3000: "http", 3306: "mysql", 3389: "rdp", 4443: "https", 5000: "http", 5060: "sip", 5061: "sips", 5432: "postgres", 5900: "vnc",
	5985: "winrm", 5986: "winrm-https", 6379: "redis", 8000: "http", 8006: "https", 8080: "http", 8081: "http", 8443: "https", 8888: "http",
	9000: "http", 9090: "http", 9100: "jetdirect", 9200: "elasticsearch", 9443: "https", 10000: "https", 27017: "mongodb", 62078: "iphone-sync",
}

var (
	tlsPorts    = map[int]bool{443: true, 465: true, 636: true, 993: true, 995: true, 4443: true, 5061: true, 5986: true, 8006: true, 8443: true, 9443: true, 10000: true}
	httpPorts   = map[int]bool{80: true, 3000: true, 5000: true, 8000: true, 8080: true, 8081: true, 8888: true, 9000: true, 9090: true, 5985: true, 9200: true}
	httpsPorts  = map[int]bool{443: true, 4443: true, 5986: true, 8006: true, 8443: true, 9443: true, 10000: true}
	bannerPorts = map[int]bool{21: true, 22: true, 23: true, 25: true, 110: true, 143: true, 587: true, 5900: true}
)

// probe connects to ip:port. A closed or filtered port returns (nil, nil); an
// open one returns what the service said about itself.
func probe(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error), ip string, port int) (*wire.ScanService, error) {
	cctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := dial(cctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		if closedOrFiltered(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	svc := &wire.ScanService{Port: port, Proto: "tcp", Name: portNames[port]}
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	switch {
	case tlsPorts[port]:
		tc, info := handshake(conn, ip)
		if info == nil {
			return svc, nil // open, but not TLS as expected; leave it at the name
		}
		svc.TLS = info
		if httpsPorts[port] {
			httpProbe(tc, ip, svc)
		}
	case httpPorts[port]:
		httpProbe(conn, ip, svc)
	case bannerPorts[port]:
		svc.Banner = readBanner(conn)
	case port == 3306:
		svc.Banner, svc.Version = mysqlGreeting(conn)
		svc.Product = "MySQL"
		if strings.Contains(strings.ToLower(svc.Version), "mariadb") {
			svc.Product = "MariaDB"
		}
	}
	if svc.Product == "" {
		svc.Product, svc.Version = parseBanner(svc.Name, svc.Banner)
	}
	return svc, nil
}

func closedOrFiltered(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// handshake wraps the connection in TLS and reads the certificate. The scan reads
// the certificate; it does not trust it, and it offers old versions on purpose to
// learn whether the server still speaks them.
func handshake(conn net.Conn, ip string) (net.Conn, *wire.TLSInfo) {
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // we read the certificate, we do not trust it
	if err := tc.Handshake(); err != nil {
		return conn, nil
	}
	st := tc.ConnectionState()
	info := &wire.TLSInfo{Version: tlsVersion(st.Version)}
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		info.Subject, info.Issuer, info.NotAfter, info.DNSNames = c.Subject.String(), c.Issuer.String(), c.NotAfter.UTC(), c.DNSNames
		info.SelfSigned = len(st.PeerCertificates) == 1 && c.Subject.String() == c.Issuer.String()
		if len(info.DNSNames) > 8 {
			info.DNSNames = info.DNSNames[:8]
		}
	}
	_ = ip
	return tc, info
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	}
	return ""
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>\s*(.*?)\s*</title>`)

// httpProbe asks for / and keeps the status line, the Server header and the title.
func httpProbe(conn net.Conn, ip string, svc *wire.ScanService) {
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: EX0-Scan\r\nAccept: text/html\r\n\r\n", ip); err != nil {
		return
	}
	data, _ := io.ReadAll(io.LimitReader(conn, 32<<10))
	if len(data) == 0 {
		return
	}
	text := string(data)
	if !strings.HasPrefix(text, "HTTP/") {
		svc.Banner = clip(firstLine(text))
		return
	}
	head, body, _ := strings.Cut(text, "\r\n\r\n")
	for i, line := range strings.Split(head, "\r\n") {
		if i == 0 {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "Server") {
			svc.Banner = clip(strings.TrimSpace(v))
		}
	}
	if m := titleRe.FindStringSubmatch(body); m != nil {
		svc.Title = clip(strings.Join(strings.Fields(m[1]), " "))
	}
	if svc.Name == "http" || svc.Name == "https" || svc.Name == "" {
		if svc.TLS != nil {
			svc.Name = "https"
		} else {
			svc.Name = "http"
		}
	}
}

// readBanner reads what a service says first (SSH, FTP, SMTP, POP3, IMAP, VNC, telnet).
func readBanner(conn net.Conn) string {
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return clip(printable(line))
}

// mysqlGreeting parses the server's handshake packet: 4 bytes header, protocol
// byte, then the version as a NUL-terminated string.
func mysqlGreeting(conn net.Conn) (banner, version string) {
	buf := make([]byte, 128)
	n, _ := io.ReadFull(conn, buf[:5])
	if n < 5 {
		return "", ""
	}
	m, _ := conn.Read(buf[5:])
	rest := buf[5 : 5+m]
	if i := strings.IndexByte(string(rest), 0); i >= 0 {
		rest = rest[:i]
	}
	version = printable(string(rest))
	return clip(version), version
}

var (
	sshRe    = regexp.MustCompile(`^SSH-[\d.]+-([A-Za-z]+)[_ ]?([\w.]*)`)
	serverRe = regexp.MustCompile(`^([A-Za-z][\w!.-]*)/([\w.]+)`)
	ftpRe    = regexp.MustCompile(`^220[ -].*?\(?([A-Za-z][\w-]*[Ff][Tt][Pp][\w-]*)\)?\s*([\d.]*)`)
	smtpRe   = regexp.MustCompile(`(?i)^220[ -]\S+\s+(?:ESMTP\s+)?([A-Za-z][\w-]*)\s*([\d.]*)`)
	vncRe    = regexp.MustCompile(`^RFB (\d{3}\.\d{3})`)
)

// parseBanner pulls product and version out of a banner where the format is known.
func parseBanner(name, banner string) (product, version string) {
	if banner == "" {
		return "", ""
	}
	switch name {
	case "ssh":
		if m := sshRe.FindStringSubmatch(banner); m != nil {
			return m[1], m[2]
		}
	case "http", "https", "winrm", "winrm-https", "elasticsearch":
		if m := serverRe.FindStringSubmatch(banner); m != nil {
			return m[1], m[2]
		}
		if f := strings.Fields(banner); len(f) > 0 {
			return f[0], ""
		}
	case "ftp":
		if m := ftpRe.FindStringSubmatch(banner); m != nil {
			return m[1], m[2]
		}
	case "smtp", "submission":
		if m := smtpRe.FindStringSubmatch(banner); m != nil {
			return m[1], m[2]
		}
	case "vnc":
		if m := vncRe.FindStringSubmatch(banner); m != nil {
			return "VNC", m[1]
		}
	}
	return "", ""
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

func printable(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > wire.MaxScanBanner {
		return s[:wire.MaxScanBanner]
	}
	return s
}
