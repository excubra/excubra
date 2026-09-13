// Package certfile serves a TLS certificate from a pair of files and picks up a
// renewal without a restart.
//
// It exists so the console can carry a certificate from a public CA while the
// server itself stays out of the ACME business. Something on the host — lego in a
// systemd timer, say — proves the name over DNS and writes the pair; the console
// reads it. The ingest is untouched: boxes pin our own CA there (ADR-0002), and
// that is the stronger arrangement for a channel we control on both ends.
//
// A renewal replaces two files that are never written at the same instant. Half a
// pair must therefore never take the console down: a load that fails leaves the
// certificate that is already serving in place, and the next check tries again.
package certfile

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// checkEvery is how often the files are looked at. A renewal lands within the
// minute; looking on every handshake would stat twice per connection.
const checkEvery = 30 * time.Second

// Pair serves one certificate and reloads it when the files change.
type Pair struct {
	CertPath string
	KeyPath  string
	Log      *slog.Logger
	Now      func() time.Time

	mu      sync.Mutex
	cert    *tls.Certificate
	certMod time.Time
	keyMod  time.Time
	checked time.Time
}

// Load returns a pair that is already serving, or an error naming what is wrong —
// a server that starts with an unreadable certificate should say so at once
// rather than fail every handshake later.
func Load(certPath, keyPath string, log *slog.Logger) (*Pair, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("certfile: both a certificate and a key are needed")
	}
	if log == nil {
		log = slog.Default()
	}
	p := &Pair{CertPath: certPath, KeyPath: keyPath, Log: log, Now: time.Now}
	if err := p.reload(); err != nil {
		return nil, err
	}
	return p, nil
}

// GetCertificate is the tls.Config hook. It reloads at most every checkEvery and
// only when a file's modification time moved.
func (p *Pair) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.Lock()
	due := p.Now().Sub(p.checked) >= checkEvery
	cert := p.cert
	p.mu.Unlock()
	if !due {
		return cert, nil
	}
	if err := p.reload(); err != nil {
		// Keep serving what works. A renewal caught halfway is the normal case,
		// not an outage.
		p.Log.Warn("console certificate: keeping the one in use", "err", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cert, nil
}

// Reload re-reads the files now, whatever the clock says.
func (p *Pair) Reload() error { return p.reload() }

func (p *Pair) reload() error {
	certInfo, err := os.Stat(p.CertPath)
	if err != nil {
		return fmt.Errorf("certfile: %w", err)
	}
	keyInfo, err := os.Stat(p.KeyPath)
	if err != nil {
		return fmt.Errorf("certfile: %w", err)
	}
	p.mu.Lock()
	unchanged := p.cert != nil && certInfo.ModTime().Equal(p.certMod) && keyInfo.ModTime().Equal(p.keyMod)
	if unchanged {
		p.checked = p.Now()
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	cert, err := tls.LoadX509KeyPair(p.CertPath, p.KeyPath)
	if err != nil {
		return fmt.Errorf("certfile: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	first := p.cert == nil
	p.cert, p.certMod, p.keyMod, p.checked = &cert, certInfo.ModTime(), keyInfo.ModTime(), p.Now()
	if !first {
		p.Log.Info("console certificate reloaded", "cert", p.CertPath)
	}
	return nil
}

// NotAfter is when the certificate in use expires, for the console to show.
func (p *Pair) NotAfter() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cert == nil || p.cert.Leaf == nil {
		return time.Time{}
	}
	return p.cert.Leaf.NotAfter
}
