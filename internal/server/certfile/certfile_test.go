package certfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePair puts a self-signed certificate for name into dir and returns the paths.
func writePair(t *testing.T, dir, name string, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "console.crt")
	keyPath := filepath.Join(dir, "console.key")
	must(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	must(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndReload(t *testing.T) {
	dir := t.TempDir()
	first := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	certPath, keyPath := writePair(t, dir, "konsole.example.test", first)

	now := time.Now()
	p, err := Load(certPath, keyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Now = func() time.Time { return now }
	if got := p.NotAfter(); !got.Equal(first) {
		t.Fatalf("not after %s, want %s", got, first)
	}

	// a renewal: new files, and the clock has moved past the check interval
	second := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	time.Sleep(10 * time.Millisecond) // so the modification time differs
	writePair(t, dir, "konsole.example.test", second)
	now = now.Add(checkEvery + time.Second)
	if _, err := p.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	if got := p.NotAfter(); !got.Equal(second) {
		t.Fatalf("the renewal should be in use: %s, want %s", got, second)
	}

	// half a pair must not take the console down: the certificate in use stays
	must(t, os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nhalf written"), 0o600))
	now = now.Add(checkEvery + time.Second)
	c, err := p.GetCertificate(nil)
	if err != nil || c == nil {
		t.Fatalf("a broken file must not end the handshake: %v", err)
	}
	if got := p.NotAfter(); !got.Equal(second) {
		t.Fatalf("the working certificate should still serve: %s", got)
	}
}

func TestLoadRefusesWhatItCannotServe(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load("", "", nil); err == nil {
		t.Fatal("a pair needs both files")
	}
	if _, err := Load(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"), nil); err == nil {
		t.Fatal("a missing file should be named at start, not at every handshake")
	}
	certPath, keyPath := writePair(t, dir, "x.example.test", time.Now().Add(time.Hour))
	must(t, os.WriteFile(keyPath, []byte("not a key"), 0o600))
	_, err := Load(certPath, keyPath, nil)
	if err == nil || !strings.Contains(err.Error(), "certfile") {
		t.Fatalf("an unusable pair should say so: %v", err)
	}
}
