// Package sig verifies release signatures (ADR-0006) with the standard library
// only. The release pipeline signs each binary with `cosign sign-blob --key`, which
// is an ECDSA P-256 signature over the SHA-256 digest of the blob, base64 encoded.
// The matching public key is embedded at build time from release.pub.
package sig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

//go:embed release.pub
var releasePubPEM []byte

// ErrNoKey is returned when the build carries no release key (development builds).
var ErrNoKey = errors.New("sig: no release key embedded — updates disabled")

// ParsePublicKeyPEM parses a PEM "PUBLIC KEY" block holding an ECDSA P-256 key.
func ParsePublicKeyPEM(p []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(p)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("sig: no PUBLIC KEY block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sig: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("sig: release key is not ECDSA")
	}
	return pub, nil
}

// ReleaseKey returns the embedded release public key, or ErrNoKey.
func ReleaseKey() (*ecdsa.PublicKey, error) {
	if len(strings.TrimSpace(string(releasePubPEM))) == 0 || !strings.Contains(string(releasePubPEM), "BEGIN PUBLIC KEY") {
		return nil, ErrNoKey
	}
	return ParsePublicKeyPEM(releasePubPEM)
}

// Enabled reports whether this build can verify releases.
func Enabled() bool {
	_, err := ReleaseKey()
	return err == nil
}

// Verify checks a cosign blob signature (base64 DER ECDSA over sha256(blob))
// against the embedded release key.
func Verify(blob []byte, signatureB64 string) error {
	pub, err := ReleaseKey()
	if err != nil {
		return err
	}
	return VerifyWith(pub, blob, signatureB64)
}

// VerifyWith checks a cosign blob signature against a given key.
func VerifyWith(pub *ecdsa.PublicKey, blob []byte, signatureB64 string) error {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return fmt.Errorf("sig: signature is not base64: %w", err)
	}
	digest := sha256.Sum256(blob)
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		return errors.New("sig: signature does not verify")
	}
	return nil
}
