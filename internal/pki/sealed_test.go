package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/excubra/excubra/internal/secretbox"
)

// With a secret key, the CA's private key file is sealed at rest; a plain one
// from before is sealed on first use; without the key a sealed file is refused.
func TestPrivateKeyFilesAreSealedAtRest(t *testing.T) {
	dir := t.TempDir()
	KeySeal, KeyOpen = nil, nil
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := os.ReadFile(filepath.Join(dir, CAKeyFile))
	if !strings.Contains(string(plain), "PRIVATE KEY") {
		t.Fatal("plain key expected before a key is configured")
	}
	box, _ := secretbox.FromBytes([]byte("test key material"))
	KeySeal, KeyOpen = box.SealBytes, box.OpenBytes
	t.Cleanup(func() { KeySeal, KeyOpen = nil, nil })
	again, err := LoadOrCreateCA(dir)
	if err != nil || again.Fingerprint() != ca.Fingerprint() {
		t.Fatalf("reload: %v", err)
	}
	sealed, _ := os.ReadFile(filepath.Join(dir, CAKeyFile))
	if !secretbox.Sealed(string(sealed)) || strings.Contains(string(sealed), "PRIVATE KEY") {
		t.Fatal("key file was not sealed on first use")
	}
	if _, err := again.LoadOrCreateServerCert(dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	srvKey, _ := os.ReadFile(filepath.Join(dir, ServerKeyFile))
	if !secretbox.Sealed(string(srvKey)) {
		t.Fatal("server key file not sealed")
	}
	if _, err := again.LoadOrCreateServerCert(dir, "127.0.0.1"); err != nil {
		t.Fatal("sealed server key not reusable:", err)
	}
	KeySeal, KeyOpen = nil, nil
	if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("sealed key without the secret key must be refused: %v", err)
	}
	other, _ := secretbox.FromBytes([]byte("wrong key"))
	KeySeal, KeyOpen = other.SealBytes, other.OpenBytes
	if _, err := LoadOrCreateCA(dir); err == nil {
		t.Fatal("wrong key opened the CA")
	}
}
