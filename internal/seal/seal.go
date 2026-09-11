// Package seal is how a secret reaches a box without the server ever seeing it:
// the browser seals it to the box's X25519 public key (ECDH, HKDF-SHA256,
// AES-256-GCM), the server relays the ciphertext, the box opens it. The Go side
// here mirrors web/src/lib/seal.ts byte for byte; both are tested against each
// other through fixtures.
//
// Blob layout (base64): ephemeral public key (32) || nonce (12) || ciphertext+tag.
// HKDF salt = ephemeral public || recipient public, info = Info; the same string
// is the GCM additional data.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Info binds ciphertexts to this construction; a future v2 changes it.
const Info = "excubra-seal-v1"

const (
	pubLen   = 32
	nonceLen = 12
	tagLen   = 16
)

// GenerateKey creates a recipient key pair.
func GenerateKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// ParsePrivate loads a private key from its raw 32 bytes.
func ParsePrivate(raw []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(raw)
}

// Public encodes a public key the way the wire carries it.
func Public(priv *ecdh.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
}

// Fingerprint is what a person compares: sha256 of the public key, first 16 hex
// characters in groups of four.
func Fingerprint(pubB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(raw) != pubLen {
		return ""
	}
	h := sha256.Sum256(raw)
	s := hex.EncodeToString(h[:8])
	return s[0:4] + " " + s[4:8] + " " + s[8:12] + " " + s[12:16]
}

// Seal encrypts msg for the recipient public key (base64). Used by tests and by
// the server CLI; the browser normally does this.
func Seal(recipientB64 string, msg []byte) (string, error) {
	recRaw, err := base64.StdEncoding.DecodeString(recipientB64)
	if err != nil || len(recRaw) != pubLen {
		return "", errors.New("seal: bad recipient key")
	}
	recipient, err := ecdh.X25519().NewPublicKey(recRaw)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	eph, err := GenerateKey()
	if err != nil {
		return "", err
	}
	key, err := derive(eph, recipient, eph.PublicKey().Bytes(), recRaw)
	if err != nil {
		return "", err
	}
	gcm, err := aead(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	blob := append([]byte{}, eph.PublicKey().Bytes()...)
	blob = append(blob, nonce...)
	blob = gcm.Seal(blob, nonce, msg, []byte(Info))
	return base64.StdEncoding.EncodeToString(blob), nil
}

// Open decrypts a blob sealed to priv.
func Open(priv *ecdh.PrivateKey, blobB64 string) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil || len(blob) < pubLen+nonceLen+tagLen {
		return nil, errors.New("seal: bad blob")
	}
	eph, err := ecdh.X25519().NewPublicKey(blob[:pubLen])
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	key, err := derive(priv, eph, blob[:pubLen], priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	msg, err := gcm.Open(nil, blob[pubLen:pubLen+nonceLen], blob[pubLen+nonceLen:], []byte(Info))
	if err != nil {
		return nil, errors.New("seal: cannot open (wrong box or damaged)")
	}
	return msg, nil
}

func derive(priv *ecdh.PrivateKey, pub *ecdh.PublicKey, ephPub, recPub []byte) ([]byte, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	salt := append(append([]byte{}, ephPub...), recPub...)
	return hkdf.Key(sha256.New, shared, salt, Info, 32)
}

func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
