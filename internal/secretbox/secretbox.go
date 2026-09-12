// Package secretbox keeps secrets at rest unreadable without a key that lives
// outside the data directory and the backups (ADR-0009 amendment): the NetBird
// token, API keys, the private keys of the internal CA. AES-256-GCM with a key
// from a file the operator keeps a copy of in the password manager. A value
// that was never sealed reads back as it is, so switching the key on is safe on
// a running installation; the server seals what it finds in plain text once.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Prefix marks a sealed value.
const Prefix = "enc:v1:"

// ErrNoKey is returned when a sealed value is read without a key.
var ErrNoKey = errors.New("secretbox: sealed value but no key configured (EXCUBRA_SECRET_KEY_FILE)")

// Box seals and opens with one key.
type Box struct {
	aead cipher.AEAD
}

// Load reads the key file: 32 bytes of base64 as openssl rand -base64 32 writes
// them, or any other content hashed to 32 bytes.
func Load(path string) (*Box, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secretbox: %w", err)
	}
	return FromBytes(raw)
}

// FromBytes builds a box from key material.
func FromBytes(raw []byte) (*Box, error) {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil, errors.New("secretbox: empty key")
	}
	key, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil || len(key) != 32 {
		sum := sha256.Sum256(raw)
		key = sum[:]
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Sealed reports whether a value carries the prefix.
func Sealed(v string) bool { return strings.HasPrefix(v, Prefix) }

// Seal encrypts a value; a nil box returns it unchanged.
func (b *Box) Seal(plain string) string {
	if b == nil {
		return plain
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic("secretbox: " + err.Error())
	}
	ct := b.aead.Seal(nil, nonce, []byte(plain), nil)
	return Prefix + base64.StdEncoding.EncodeToString(append(nonce, ct...))
}

// Open decrypts a sealed value; an unsealed value comes back as it is. A sealed
// value on a nil box is ErrNoKey; a tampered one an error.
func (b *Box) Open(v string) (string, error) {
	if !Sealed(v) {
		return v, nil
	}
	if b == nil {
		return "", ErrNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, Prefix))
	if err != nil || len(raw) < b.aead.NonceSize() {
		return "", errors.New("secretbox: malformed sealed value")
	}
	n := b.aead.NonceSize()
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", errors.New("secretbox: cannot open the sealed value (wrong key?)")
	}
	return string(plain), nil
}

// SealBytes and OpenBytes are Seal and Open for file contents (private keys).
func (b *Box) SealBytes(plain []byte) []byte { return []byte(b.Seal(string(plain))) }

// OpenBytes opens file contents; the second result says whether they were sealed.
func (b *Box) OpenBytes(data []byte) ([]byte, bool, error) {
	if !Sealed(string(data)) {
		return data, false, nil
	}
	s, err := b.Open(strings.TrimSpace(string(data)))
	return []byte(s), true, err
}
