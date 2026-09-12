package dnswatch

import (
	"encoding/binary"
	"errors"
	"strings"
)

// The few bytes of a DNS message the sensor needs: the header, the first
// question, and the response code. Everything else is forwarded untouched.

const (
	headerLen  = 12
	rcodeNX    = 3
	rcodeFail  = 2
	qtypeTXT   = 16
	qtypeNULL  = 10
	maxNameLen = 253
)

// question is the first question of a message.
type question struct {
	ID    uint16
	Name  string // lower-case, no trailing dot
	Type  uint16
	End   int // offset just past the question section
	Flags uint16
}

var errMalformed = errors.New("malformed dns message")

// parseQuestion reads the header and the first question.
func parseQuestion(m []byte) (question, error) {
	if len(m) < headerLen {
		return question{}, errMalformed
	}
	q := question{ID: binary.BigEndian.Uint16(m[0:2]), Flags: binary.BigEndian.Uint16(m[2:4])}
	if binary.BigEndian.Uint16(m[4:6]) < 1 {
		return question{}, errMalformed
	}
	var labels []string
	i := headerLen
	for {
		if i >= len(m) {
			return question{}, errMalformed
		}
		l := int(m[i]) //nolint:gosec // i < len(m) is checked above
		i++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || i+l > len(m) { // compression is not used in a question
			return question{}, errMalformed
		}
		labels = append(labels, strings.ToLower(string(m[i:i+l])))
		i += l
	}
	if i+4 > len(m) {
		return question{}, errMalformed
	}
	q.Name = strings.Join(labels, ".")
	if len(q.Name) > maxNameLen {
		return question{}, errMalformed
	}
	q.Type = binary.BigEndian.Uint16(m[i : i+2])
	q.End = i + 4
	return q, nil
}

// rcode reads the response code of a message.
func rcode(m []byte) int {
	if len(m) < headerLen {
		return -1
	}
	return int(m[3] & 0x0F)
}

// answer builds a response to a query with the given rcode and no records: the
// header with QR set, RD copied, RA set, and the question echoed. Additional
// records of the query (EDNS) are dropped.
func answer(query []byte, q question, code int) []byte {
	out := make([]byte, q.End)
	copy(out, query[:q.End])
	flags := uint16(0x8000) | (q.Flags & 0x0100) | 0x0080 | uint16(code&0x0F) // QR, RD as asked, RA, RCODE
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}
