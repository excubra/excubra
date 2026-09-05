// Package id generates the prefixed identifiers used throughout excubra
// (ADR-0005): "box_k7m2x9q4t8r3" for entities, sortable "evt_…" for events.
package id

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Crockford base32 alphabet: no I, L, O, U — unambiguous when read from a sticker.
const alphabet = "0123456789abcdefghjkmnpqrstvwxyz"

// RandomLen is the number of base32 characters in a random identifier (60 bits).
const RandomLen = 12

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// New returns prefix + "_" + 12 random base32 characters, e.g. "box_k7m2x9q4t8r3".
func New(prefix string) string {
	var b [8]byte
	mustRead(b[:])
	return prefix + "_" + encode(b[:], RandomLen)
}

// NewSortable returns prefix + "_" + 26 base32 characters: 48 bits of millisecond
// time followed by 80 random bits (ULID layout). Lexicographic order is time order.
func NewSortable(prefix string, t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli()) //nolint:gosec // UnixMilli is non-negative for any realistic clock
	binary.BigEndian.PutUint64(b[0:8], ms<<16)
	// b[0:6] now holds the 48-bit time; b[6:16] gets the random part.
	mustRead(b[6:])
	return prefix + "_" + encode(b[:], 26)
}

// FromSlug returns prefix + "_" + slug when slug is a valid operator-chosen slug
// ([a-z0-9-], 1–40 chars, no leading dash), otherwise an error.
func FromSlug(prefix, slug string) (string, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !slugRe.MatchString(slug) {
		return "", fmt.Errorf("id: %q is not a valid slug (a-z, 0-9, dash, 1-40 chars)", slug)
	}
	return prefix + "_" + slug, nil
}

// Secret returns n random bytes encoded in base32 (Crockford, lower-case); used for
// enrollment secrets and tokens that a human may need to type.
func Secret(n int) string {
	b := make([]byte, n)
	mustRead(b)
	return encode(b, (n*8+4)/5)
}

// encode writes the first outLen base32 characters of b (5 bits per char, MSB first).
func encode(b []byte, outLen int) string {
	out := make([]byte, 0, outLen)
	var acc uint32
	var bits uint
	for _, c := range b {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 && len(out) < outLen {
			bits -= 5
			out = append(out, alphabet[(acc>>bits)&31])
		}
		if len(out) == outLen {
			break
		}
	}
	for len(out) < outLen && bits > 0 { // trailing partial group
		if bits < 5 {
			acc <<= 5 - bits
			bits = 5
		}
		bits -= 5
		out = append(out, alphabet[(acc>>bits)&31])
	}
	return string(out)
}

func mustRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("id: crypto/rand failed: " + err.Error())
	}
}
