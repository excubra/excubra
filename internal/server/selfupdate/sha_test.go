package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
