// Package pki is the internal certificate authority of an EX0 server and the
// certificate handling on both sides (ADR-0010): the CA issues the ingest server
// certificate and one client certificate per box; agents pin the CA by the
// fingerprint carried in their enrollment key.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/excubra/excubra/internal/secretbox"
)

// Validity periods and the renewal threshold.
const (
	CAValidity         = 10 * 365 * 24 * time.Hour
	BoxCertValidity    = 90 * 24 * time.Hour
	ServerCertValidity = 365 * 24 * time.Hour
	RenewBefore        = 30 * 24 * time.Hour
)

// File names inside the PKI directory.
const (
	CACertFile     = "ca.crt"
	CAKeyFile      = "ca.key"
	ServerCertFile = "ingest.crt"
	ServerKeyFile  = "ingest.key"
)

// BoxURIPrefix is the URI SAN scheme of box certificates.
const BoxURIPrefix = "urn:excubra:box:"

// CA is the internal certificate authority.
type CA struct {
	Cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// LoadOrCreateCA loads ca.crt/ca.key from dir or creates a new ECDSA P-256 root.
// If exactly one of the two files exists it refuses, rather than silently
// creating a second CA next to an orphaned one.
// KeySeal and KeyOpen wrap private key files at rest (ADR-0009 amendment):
// the server sets them from its secret key; nil keeps the files plain. A key
// file found plain while KeySeal is set is sealed on the spot, once.
var (
	KeySeal func(plain []byte) []byte
	KeyOpen func(data []byte) ([]byte, bool, error)
)

// readKey reads a private key file through the hooks.
func readKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if KeyOpen == nil {
		if secretbox.Sealed(string(data)) {
			return nil, fmt.Errorf("pki: %s is sealed; the secret key (EXCUBRA_SECRET_KEY_FILE) is needed to use it", path)
		}
		return data, nil
	}
	plain, sealed, err := KeyOpen(data)
	if err != nil {
		return nil, fmt.Errorf("pki: %s: %w", path, err)
	}
	if !sealed && KeySeal != nil {
		_ = writeFile(path, KeySeal(plain), 0o600)
	}
	return plain, nil
}

// writeKey writes a private key file through the hooks.
func writeKey(path string, plain []byte) error {
	if KeySeal != nil {
		return writeFile(path, KeySeal(plain), 0o600)
	}
	return writeFile(path, plain, 0o600)
}

func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	certPEM, errC := os.ReadFile(certPath)
	keyPEM, errK := readKey(keyPath)
	switch {
	case errC == nil && errK == nil:
		return LoadCA(certPEM, keyPEM)
	case errors.Is(errC, fs.ErrNotExist) && errors.Is(errK, fs.ErrNotExist):
		// create below
	default:
		return nil, fmt.Errorf("pki: CA files inconsistent in %s (cert: %w, key: %w)", dir, errC, errK)
	}

	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "EX0 Internal CA", Organization: []string{"excubra"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(CAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("pki: creating CA: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err = KeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := writeKey(keyPath, keyPEM); err != nil {
		return nil, err
	}
	if err := writeFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	return LoadCA(certPEM, keyPEM)
}

// LoadCA parses a CA from PEM.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: CA certificate: %w", err)
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: CA key: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("pki: CA certificate is not a CA")
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("pki: CA key does not match CA certificate")
	}
	return &CA{Cert: cert, key: key, certPEM: certPEM}, nil
}

// CertPEM returns the CA certificate in PEM.
func (ca *CA) CertPEM() []byte { return append([]byte(nil), ca.certPEM...) }

// Pool returns a pool containing only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// Fingerprint returns the pin of this CA (see FingerprintOf).
func (ca *CA) Fingerprint() string { return FingerprintOf(ca.Cert) }

// FingerprintOf returns the first 16 bytes of SHA-256 over the certificate's
// SubjectPublicKeyInfo as 32 lower-case hex characters. It is what enrollment keys
// carry and what agents pin.
func FingerprintOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:16])
}

// IssueBox signs a box client certificate for a CSR. The CSR's subject is ignored;
// the certificate's CN is the box id and it carries the URI SAN
// urn:excubra:box:<id>. Only ECDSA P-256 keys are accepted.
func (ca *CA) IssueBox(csrPEM []byte, boxID string, validity time.Duration) ([]byte, *x509.Certificate, error) {
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		return nil, nil, err
	}
	if !strings.HasPrefix(boxID, "box_") {
		return nil, nil, fmt.Errorf("pki: %q is not a box id", boxID)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: boxID, Organization: []string{"excubra"}},
		URIs:                  []*url.URL{{Scheme: "urn", Opaque: "excubra:box:" + boxID}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: issuing box certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("pki: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// IssueServer signs a server certificate for the ingest host (DNS name or IP) and
// returns it as a tls.Certificate whose chain includes the CA.
func (ca *CA) IssueServer(host string, validity time.Duration) (tls.Certificate, []byte, []byte, error) {
	return ca.IssueServerNames([]string{host}, validity)
}

// IssueServerNames is IssueServer for a certificate that must cover several names,
// e.g. the overlay IP and the console hostname. The first name is the subject.
func (ca *CA) IssueServerNames(hosts []string, validity time.Duration) (tls.Certificate, []byte, []byte, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, nil, nil, errors.New("pki: no host for the server certificate")
	}
	host := hosts[0]
	key, err := GenerateKey()
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"excubra"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("pki: issuing server certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := KeyPEM(key)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, certPEM, keyPEM, nil
}

// LoadOrCreateServerCert returns the ingest certificate from dir, issuing a new one
// when none exists, when it expires within RenewBefore, when it does not cover host,
// or when it was not issued by this CA.
func (ca *CA) LoadOrCreateServerCert(dir, host string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, ServerCertFile), filepath.Join(dir, ServerKeyFile)
	if certPEM, err := os.ReadFile(certPath); err == nil {
		if keyPEM, err := readKey(keyPath); err == nil {
			if tc, ok := ca.usableServerCert(certPEM, keyPEM, host); ok {
				return tc, nil
			}
		}
	}
	tc, certPEM, keyPEM, err := ca.IssueServer(host, ServerCertValidity)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writeKey(keyPath, keyPEM); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tc, nil
}

func (ca *CA) usableServerCert(certPEM, keyPEM []byte, host string) (tls.Certificate, bool) {
	leaf, err := ParseCertPEM(certPEM)
	if err != nil {
		return tls.Certificate{}, false
	}
	key, err := ParseKeyPEM(keyPEM)
	if err != nil || !key.PublicKey.Equal(leaf.PublicKey) {
		return tls.Certificate{}, false
	}
	if time.Until(leaf.NotAfter) < RenewBefore || leaf.VerifyHostname(host) != nil {
		return tls.Certificate{}, false
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return tls.Certificate{}, false
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}, true
}

// BoxIDFromCert extracts the box id from a verified client certificate: the CN must
// start with "box_" and the URI SAN must agree.
func BoxIDFromCert(cert *x509.Certificate) (string, error) {
	cn := cert.Subject.CommonName
	if !strings.HasPrefix(cn, "box_") {
		return "", fmt.Errorf("pki: certificate CN %q is not a box id", cn)
	}
	for _, u := range cert.URIs {
		if u.String() == BoxURIPrefix+cn {
			return cn, nil
		}
	}
	return "", fmt.Errorf("pki: certificate for %q lacks its URI SAN", cn)
}

// IngestTLSConfig is the server side of ADR-0002: TLS 1.3, client certificates
// verified against the CA when presented, enforced per route by the handlers.
func IngestTLSConfig(ca *CA, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.VerifyClientCertIfGiven,
		ClientCAs:      ca.Pool(),
		GetCertificate: getCert,
	}
}

// AgentTLSConfig is the client side: the server chain must contain the CA with the
// pinned fingerprint, the leaf must chain to it and match host. System roots are
// never consulted. clientCert may be nil before enrollment.
func AgentTLSConfig(caFingerprint, host string, clientCert *tls.Certificate) *tls.Config {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // verification is done in VerifyConnection against the pinned CA
		// VerifyConnection (not VerifyPeerCertificate) also runs for resumed sessions.
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, 0, len(cs.PeerCertificates))
			for _, c := range cs.PeerCertificates {
				raw = append(raw, c.Raw)
			}
			return VerifyPinned(raw, caFingerprint, host)
		},
	}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return cfg
}

// VerifyPinned checks a presented chain against a pinned CA fingerprint and host.
func VerifyPinned(rawCerts [][]byte, caFingerprint, host string) error {
	if len(rawCerts) == 0 {
		return errors.New("pki: server presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("pki: server certificate: %w", err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	if leaf.IsCA {
		return errors.New("pki: server presented a CA certificate as leaf")
	}
	roots := x509.NewCertPool()
	pinned := false
	for _, c := range certs[1:] {
		if c.IsCA && FingerprintOf(c) == caFingerprint {
			roots.AddCert(c)
			pinned = true
		}
	}
	if !pinned {
		return errors.New("pki: server chain does not contain the pinned CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("pki: server certificate does not chain to the pinned CA: %w", err)
	}
	if err := leaf.VerifyHostname(host); err != nil {
		return fmt.Errorf("pki: %w", err)
	}
	return nil
}

// ---- keys, CSRs, PEM ---------------------------------------------------------------

// GenerateKey creates an ECDSA P-256 key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generating key: %w", err)
	}
	return key, nil
}

// KeyPEM encodes a private key as PKCS#8 PEM.
func KeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKeyPEM parses a PKCS#8 (or SEC 1) ECDSA private key.
func ParseKeyPEM(p []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("pki: no PEM block in key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ek, ok := k.(*ecdsa.PrivateKey); ok {
			return ek, nil
		}
		return nil, errors.New("pki: key is not ECDSA")
	}
	ek, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	return ek, nil
}

// ParseCertPEM parses the first certificate in a PEM blob.
func ParseCertPEM(p []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(p)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("pki: no CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	return cert, nil
}

// CSRPEM creates a certificate request for key with the given CN.
func CSRPEM(key *ecdsa.PrivateKey, cn string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("pki: creating CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// ParseCSRPEM parses and validates a CSR: signature must verify and the key must be
// ECDSA P-256.
func ParseCSRPEM(p []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(p)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("pki: no CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("pki: CSR key must be ECDSA P-256")
	}
	return csr, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	return s, nil
}

// writeFile writes atomically (temp file + rename) with the given mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("pki: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("pki: %w", err)
	}
	return nil
}
