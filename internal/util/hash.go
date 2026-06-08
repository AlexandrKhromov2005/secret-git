// Package util holds tiny shared helpers with no domain logic.
package util

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hex returns the lowercase hex of SHA-256(b). This is the content-address
// scheme for blobs (pack_id = SHA256(pack_blob)) and the manifest hash.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
