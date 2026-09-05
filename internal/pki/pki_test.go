package pki

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCACreateAndReload(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA || ca.Cert.Subject.CommonName != "EX0 Internal CA" {
		t.Fatalf("bad CA cert: %+v", ca.Cert.Subject)
	}
	if st, _ := os.Stat(filepath.Join(dir, CAKeyFile)); st.Mode().Perm() != 0o600 {
		t.Fatalf("ca.key mode = %o, want 600", st.Mode().Perm())
	}
	ca2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ca2.Fingerprint() != ca.Fingerprint() || len(ca.Fingerprint()) != 32 {
		t.Fatalf("fingerprint changed on reload: %s vs %s", ca.Fingerprint(), ca2.Fingerprint())
	}
	// one file missing → refuse
	if err := os.Remove(filepath.Join(dir, CAKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("orphaned ca.crt must not be silently replaced")
	}
}

func TestIssueBox(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, _ := GenerateKey()
	csr, err := CSRPEM(key, "hw-1234")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, cert, err := ca.IssueBox(csr, "box_k7m2x9q4t8r3", BoxCertValidity)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "box_k7m2x9q4t8r3" {
		t.Fatalf("CN = %q (CSR subject must be ignored)", cert.Subject.CommonName)
	}
	if got, err := BoxIDFromCert(cert); err != nil || got != "box_k7m2x9q4t8r3" {
		t.Fatalf("BoxIDFromCert = %q, %v", got, err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("box cert does not verify: %v", err)
	}
	if d := time.Until(cert.NotAfter); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("validity = %v", d)
	}
	if _, err := ParseCertPEM(certPEM); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ca.IssueBox(csr, "srv_x", BoxCertValidity); err == nil {
		t.Fatal("non-box id accepted")
	}
	if _, _, err := ca.IssueBox([]byte("garbage"), "box_x", BoxCertValidity); err == nil {
		t.Fatal("garbage CSR accepted")
	}
	// a certificate with a box CN but without the URI SAN is rejected
	other := &x509.Certificate{Subject: cert.Subject}
	if _, err := BoxIDFromCert(other); err == nil {
		t.Fatal("certificate without URI SAN accepted")
	}
}

func TestServerCertLifecycle(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := ca.LoadOrCreateServerCert(dir, "ingest.example.test")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := ca.LoadOrCreateServerCert(dir, "ingest.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if c1.Leaf.SerialNumber.Cmp(c2.Leaf.SerialNumber) != 0 {
		t.Fatal("valid server cert was reissued")
	}
	c3, err := ca.LoadOrCreateServerCert(dir, "other.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if c3.Leaf.SerialNumber.Cmp(c1.Leaf.SerialNumber) == 0 {
		t.Fatal("cert for a different host was reused")
	}
	if len(c3.Certificate) != 2 {
		t.Fatalf("chain length = %d, want leaf + CA", len(c3.Certificate))
	}
	ip, err := ca.LoadOrCreateServerCert(t.TempDir(), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	if err := ip.Leaf.VerifyHostname("203.0.113.7"); err != nil {
		t.Fatal(err)
	}
}

// TestPinnedHandshake runs a real TLS server with the ingest config and checks that
// an agent pinned to the right CA connects, and that a wrong pin, a wrong host and a
// system-trusted-but-foreign certificate are refused.
func TestPinnedHandshake(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := ca.LoadOrCreateServerCert(dir, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) > 0 {
			id, _ := BoxIDFromCert(r.TLS.PeerCertificates[0])
			_, _ = io.WriteString(w, "box "+id)
			return
		}
		_, _ = io.WriteString(w, "anonymous")
	}))
	srv.TLS = IngestTLSConfig(ca, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &srvCert, nil })
	srv.TLS.Certificates = []tls.Certificate{srvCert} // httptest would otherwise add its own
	srv.StartTLS()
	defer srv.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))

	get := func(cfg *tls.Config) (string, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		resp, err := c.Get(srv.URL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}

	// before enrollment: pinned, no client cert
	if body, err := get(AgentTLSConfig(ca.Fingerprint(), host, nil)); err != nil || body != "anonymous" {
		t.Fatalf("pinned anonymous: %q, %v", body, err)
	}
	// after enrollment: client cert identifies the box
	key, _ := GenerateKey()
	csr, _ := CSRPEM(key, "hw")
	certPEM, _, err := ca.IssueBox(csr, "box_abcdefghjkmn", BoxCertValidity)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := KeyPEM(key)
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := get(AgentTLSConfig(ca.Fingerprint(), host, &clientCert)); err != nil || body != "box box_abcdefghjkmn" {
		t.Fatalf("pinned with client cert: %q, %v", body, err)
	}
	// wrong pin
	if _, err := get(AgentTLSConfig(strings.Repeat("0", 32), host, nil)); err == nil {
		t.Fatal("wrong CA fingerprint accepted")
	}
	// wrong host
	if _, err := get(AgentTLSConfig(ca.Fingerprint(), "ingest.example.test", nil)); err == nil {
		t.Fatal("wrong host accepted")
	}
	// a box certificate from a different CA is rejected by the server
	otherCA, _ := LoadOrCreateCA(t.TempDir())
	certPEM2, _, _ := otherCA.IssueBox(csr, "box_foreign000000", BoxCertValidity)
	foreign, _ := tls.X509KeyPair(certPEM2, keyPEM)
	if _, err := get(AgentTLSConfig(ca.Fingerprint(), host, &foreign)); err == nil {
		t.Fatal("client certificate from a foreign CA accepted")
	}
}

func TestEnrollmentKey(t *testing.T) {
	fp := strings.Repeat("ab", 16)
	k, err := NewEnrollmentKey("ingest.ex0.example", 443, fp)
	if err != nil {
		t.Fatal(err)
	}
	s := k.String()
	if !strings.HasPrefix(s, "EX0:1:ingest.ex0.example:443:"+fp+":") || len(k.Secret) != 32 {
		t.Fatalf("key = %s", s)
	}
	p, err := ParseEnrollmentKey("  " + s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if p != k {
		t.Fatalf("roundtrip: %+v vs %+v", p, k)
	}
	if p.Address() != "ingest.ex0.example:443" || len(p.SecretHash()) != 64 {
		t.Fatalf("address/hash: %s %s", p.Address(), p.SecretHash())
	}

	v6, _ := NewEnrollmentKey("2001:db8::1", 8443, fp)
	p6, err := ParseEnrollmentKey(v6.String())
	if err != nil || p6.Host != "2001:db8::1" || p6.Port != 8443 {
		t.Fatalf("ipv6: %s → %+v, %v", v6.String(), p6, err)
	}

	bad := []string{
		"", "EX0:2:h:443:" + fp + ":" + k.Secret, "EX0:1:h:443:" + fp,
		"EX0:1::443:" + fp + ":" + k.Secret, "EX0:1:h:0:" + fp + ":" + k.Secret,
		"EX0:1:h:443:xyz:" + k.Secret, "EX0:1:h:443:" + fp + ":short",
		"EX0:1:h:443:" + fp + ":" + strings.ToUpper(k.Secret),
	}
	for _, b := range bad {
		if _, err := ParseEnrollmentKey(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}
