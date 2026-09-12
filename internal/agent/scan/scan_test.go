package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/excubra/excubra/internal/wire"
)

func portOf(t *testing.T, addr net.Addr) int {
	t.Helper()
	_, p, _ := net.SplitHostPort(addr.String())
	n, _ := strconv.Atoi(p)
	return n
}

// One round against loopback: an SSH-like banner, a web server with a title, a
// self-signed TLS server, and a closed port. The round reports every host it
// tried, services sorted by port, and hands the results out in chunks.
func TestRoundReadsBannersTitlesAndCertificates(t *testing.T) {
	// ssh-like banner
	ssh, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ssh.Close() }()
	go func() {
		for {
			c, err := ssh.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"))
			_ = c.Close()
		}
	}()
	// plain web server
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		_, _ = w.Write([]byte("<html><head><title>FRITZ!Box 7590</title></head><body></body></html>"))
	}))
	defer web.Close()
	// self-signed TLS web server
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pve.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 24 * time.Hour), DNSNames: []string{"pve.example.test"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "pve-api-daemon/3.0")
		_, _ = w.Write([]byte("<title>pve - Proxmox Virtual Environment</title>"))
	}))
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	secure.StartTLS()
	defer secure.Close()
	// a closed port
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := portOf(t, closed.Addr())
	_ = closed.Close()

	sshPort, webPort, tlsPort := portOf(t, ssh.Addr()), portOf(t, web.Listener.Addr()), portOf(t, secure.Listener.Addr())
	// the probes decide by port number; map the test ports onto well-known ones
	portNames[sshPort], bannerPorts[sshPort] = "ssh", true
	portNames[webPort], httpPorts[webPort] = "http", true
	portNames[tlsPort], tlsPorts[tlsPort], httpsPorts[tlsPort] = "https", true, true
	defer func() {
		delete(portNames, sshPort)
		delete(bannerPorts, sshPort)
		delete(portNames, webPort)
		delete(httpPorts, webPort)
		delete(portNames, tlsPort)
		delete(tlsPorts, tlsPort)
		delete(httpsPorts, tlsPort)
	}()

	s := New(nil, func() []Target {
		return []Target{{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:ff"}, {IP: "not-an-ip"}, {IP: "::1"}}
	})
	cfg, errs := ParseConfig(wire.ScanConfig{Enabled: true, MaxPPS: 50, Ports: []int{sshPort, webPort, tlsPort, closedPort}})
	if len(errs) != 0 || !cfg.Enabled || cfg.Interval != DefaultInterval || len(cfg.Ports) != 4 {
		t.Fatalf("config: %+v %v", cfg, errs)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.Round(ctx, cfg)

	rep := s.Drain()
	if rep == nil || len(rep.Hosts) != 1 || !rep.Final || rep.Scanned != 1 || rep.Errors != 0 || rep.Round == "" {
		t.Fatalf("report: %+v", rep)
	}
	h := rep.Hosts[0]
	if h.IP != "127.0.0.1" || h.MAC != "aa:bb:cc:dd:ee:ff" || len(h.Services) != 3 {
		t.Fatalf("host: %+v", h)
	}
	byPort := map[int]wire.ScanService{}
	for _, svc := range h.Services {
		byPort[svc.Port] = svc
	}
	if svc := byPort[sshPort]; svc.Name != "ssh" || svc.Product != "OpenSSH" || svc.Version != "9.2p1" || svc.Banner != "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3" {
		t.Fatalf("ssh: %+v", svc)
	}
	if svc := byPort[webPort]; svc.Name != "http" || svc.Product != "nginx" || svc.Version != "1.24.0" || svc.Title != "FRITZ!Box 7590" {
		t.Fatalf("http: %+v", svc)
	}
	if svc := byPort[tlsPort]; svc.Name != "https" || svc.TLS == nil || !svc.TLS.SelfSigned || svc.TLS.Subject != "CN=pve.example.test" || svc.TLS.Version == "" || svc.Title != "pve - Proxmox Virtual Environment" || svc.Product != "pve-api-daemon" {
		t.Fatalf("https: %+v tls=%+v", svc, svc.TLS)
	}
	if _, ok := byPort[closedPort]; ok {
		t.Fatal("closed port reported")
	}

	// nack puts the chunk back, ack forgets it, and the scanner is free again
	s.Nack()
	if again := s.Drain(); again == nil || len(again.Hosts) != 1 {
		t.Fatalf("after nack: %+v", again)
	}
	s.Ack()
	if s.Drain() != nil || s.busy() {
		t.Fatal("results left after ack")
	}
}

func TestParseConfigLimits(t *testing.T) {
	cfg, errs := ParseConfig(wire.ScanConfig{Enabled: true, IntervalS: 60, MaxPPS: 500, Ports: []int{0, 70000, 22, 22, 443}, Exclude: []string{"192.168.1.1", "10.0.0.0/8", "nope"}})
	if cfg.Interval != MinInterval || cfg.MaxPPS != HardMaxPPS || len(cfg.Ports) != 2 || len(cfg.Exclude) != 2 || len(errs) != 3 {
		t.Fatalf("cfg %+v errs %v", cfg, errs)
	}
	s := New(nil, func() []Target { return []Target{{IP: "192.168.1.1"}, {IP: "10.1.2.3"}, {IP: "192.168.1.9"}} })
	if got := s.targets(cfg); len(got) != 1 || got[0].IP != "192.168.1.9" {
		t.Fatalf("exclusions: %+v", got)
	}
	if cfg, _ := ParseConfig(wire.ScanConfig{}); cfg.Enabled || len(cfg.Ports) != len(DefaultPorts) || cfg.MaxPPS != DefaultMaxPPS {
		t.Fatalf("defaults: %+v", cfg)
	}
}

func TestParseBanner(t *testing.T) {
	cases := []struct{ name, banner, product, version string }{
		{"ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "OpenSSH", "8.9p1"},
		{"ssh", "SSH-2.0-dropbear_2022.83", "dropbear", "2022.83"},
		{"http", "Apache/2.4.57 (Debian)", "Apache", "2.4.57"},
		{"https", "Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"},
		{"http", "lighttpd", "lighttpd", ""},
		{"ftp", "220 (vsFTPd 3.0.3)", "vsFTPd", "3.0.3"},
		{"smtp", "220 mail.example.test ESMTP Postfix", "Postfix", ""},
		{"vnc", "RFB 003.008", "VNC", "003.008"},
		{"rdp", "", "", ""},
	}
	for _, c := range cases {
		p, v := parseBanner(c.name, c.banner)
		if p != c.product || v != c.version {
			t.Errorf("%s %q: got %q %q, want %q %q", c.name, c.banner, p, v, c.product, c.version)
		}
	}
}
