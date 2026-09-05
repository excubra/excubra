package sig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
)

func sign(t *testing.T, key *ecdsa.PrivateKey, blob []byte) string {
	t.Helper()
	d := sha256.Sum256(blob)
	der, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func TestVerifyWith(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	blob := []byte("excubra binary bytes")
	s := sign(t, key, blob)
	if err := VerifyWith(&key.PublicKey, blob, s); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWith(&key.PublicKey, []byte("tampered"), s); err == nil {
		t.Fatal("tampered blob verified")
	}
	if err := VerifyWith(&key.PublicKey, blob, "not base64!"); err == nil {
		t.Fatal("garbage signature accepted")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifyWith(&other.PublicKey, blob, s); err == nil {
		t.Fatal("wrong key verified")
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pub, err := ParsePublicKeyPEM(p)
	if err != nil || !pub.Equal(&key.PublicKey) {
		t.Fatalf("parse: %v", err)
	}
	if _, err := ParsePublicKeyPEM([]byte("nope")); err == nil {
		t.Fatal("garbage parsed")
	}
}

func TestPlaceholderDisablesUpdates(t *testing.T) {
	if Enabled() {
		t.Skip("a real release key is embedded")
	}
	if err := Verify([]byte("x"), "AA=="); !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
}
