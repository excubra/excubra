package pki

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/excubra/excubra/internal/id"
)

// EnrollmentKey is what a box carries when it leaves the workshop (ADR-0010):
//
//	EX0:1:<host>:<port>:<ca_fp>:<secret>
//
// It names the ingest, pins the CA and holds a one-time secret. It names no tenant.
type EnrollmentKey struct {
	Host          string
	Port          int
	CAFingerprint string
	Secret        string
}

// SecretBytes is the length of the random secret (20 bytes → 32 base32 chars).
const SecretBytes = 20

var (
	fpRe     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	secretRe = regexp.MustCompile(`^[0-9a-hjkmnp-tv-z]{32}$`)
)

// NewEnrollmentKey creates a key with a fresh secret for the given ingest and CA.
func NewEnrollmentKey(host string, port int, caFingerprint string) (EnrollmentKey, error) {
	k := EnrollmentKey{Host: host, Port: port, CAFingerprint: caFingerprint, Secret: id.Secret(SecretBytes)}
	if err := k.validate(); err != nil {
		return EnrollmentKey{}, err
	}
	return k, nil
}

// String renders the key in its printable form.
func (k EnrollmentKey) String() string {
	host := k.Host
	if strings.Contains(host, ":") { // IPv6
		host = "[" + host + "]"
	}
	return fmt.Sprintf("EX0:1:%s:%d:%s:%s", host, k.Port, k.CAFingerprint, k.Secret)
}

// Address returns host:port for dialling.
func (k EnrollmentKey) Address() string { return net.JoinHostPort(k.Host, strconv.Itoa(k.Port)) }

// SecretHash is what the server stores: hex SHA-256 of the secret.
func (k EnrollmentKey) SecretHash() string { return HashSecret(k.Secret) }

// HashSecret hashes an enrollment secret the way the server stores it.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ParseEnrollmentKey parses the printable form. Whitespace around it is ignored.
func ParseEnrollmentKey(s string) (EnrollmentKey, error) {
	s = strings.TrimSpace(s)
	const prefix = "EX0:1:"
	if !strings.HasPrefix(s, prefix) {
		return EnrollmentKey{}, errors.New("enrollment key: must start with EX0:1:")
	}
	rest := s[len(prefix):]
	var host string
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 || len(rest) <= end+1 || rest[end+1] != ':' {
			return EnrollmentKey{}, errors.New("enrollment key: malformed IPv6 host")
		}
		host, rest = rest[1:end], rest[end+2:]
	} else {
		i := strings.Index(rest, ":")
		if i < 0 {
			return EnrollmentKey{}, errors.New("enrollment key: missing port")
		}
		host, rest = rest[:i], rest[i+1:]
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 3 {
		return EnrollmentKey{}, errors.New("enrollment key: expected port, CA fingerprint and secret")
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil {
		return EnrollmentKey{}, errors.New("enrollment key: bad port")
	}
	k := EnrollmentKey{Host: host, Port: port, CAFingerprint: parts[1], Secret: parts[2]}
	if err := k.validate(); err != nil {
		return EnrollmentKey{}, err
	}
	return k, nil
}

func (k EnrollmentKey) validate() error {
	if k.Host == "" || strings.ContainsAny(k.Host, " /[]") {
		return errors.New("enrollment key: bad host")
	}
	if k.Port < 1 || k.Port > 65535 {
		return errors.New("enrollment key: port out of range")
	}
	if !fpRe.MatchString(k.CAFingerprint) {
		return errors.New("enrollment key: CA fingerprint must be 32 hex characters")
	}
	if !secretRe.MatchString(k.Secret) {
		return errors.New("enrollment key: secret must be 32 base32 characters")
	}
	return nil
}
