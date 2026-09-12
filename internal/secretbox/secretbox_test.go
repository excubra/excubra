package secretbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealAndOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("t6H8a3QxJk9mN2pR5sV7wY0zB4dF6gH8jK1lM3nP5qS=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	sealed := b.Seal("nbp_token_123")
	if !Sealed(sealed) || strings.Contains(sealed, "nbp_token") {
		t.Fatalf("sealed: %q", sealed)
	}
	if got, err := b.Open(sealed); err != nil || got != "nbp_token_123" {
		t.Fatalf("open: %q %v", got, err)
	}
	if got, err := b.Open("plain"); err != nil || got != "plain" {
		t.Fatalf("plain passes through: %q %v", got, err)
	}
	first, second := b.Seal("a"), b.Seal("a")
	if first == second {
		t.Fatal("two seals of the same value must differ (nonce)")
	}
	// tampering and a wrong key are refused
	if _, err := b.Open(sealed[:len(sealed)-4] + "AAAA"); err == nil {
		t.Fatal("tampered value opened")
	}
	other, _ := FromBytes([]byte("some other key material, not base64"))
	if _, err := other.Open(sealed); err == nil {
		t.Fatal("wrong key opened the value")
	}
	// no key: plain reads, sealed does not
	var none *Box
	if got, err := none.Open("plain"); err != nil || got != "plain" {
		t.Fatal("nil box must pass plain values")
	}
	if _, err := none.Open(sealed); !errors.Is(err, ErrNoKey) {
		t.Fatalf("nil box on sealed: %v", err)
	}
	if none.Seal("x") != "x" {
		t.Fatal("nil box must not seal")
	}
	pem := []byte("-----BEGIN EC PRIVATE KEY-----\nMHc...\n-----END EC PRIVATE KEY-----\n")
	back, was, err := b.OpenBytes(b.SealBytes(pem))
	if err != nil || !was || string(back) != string(pem) {
		t.Fatalf("bytes roundtrip: %v %v", was, err)
	}
	if _, was, _ := b.OpenBytes(pem); was {
		t.Fatal("plain bytes reported sealed")
	}
}
