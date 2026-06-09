// Package server is the Tier-4 HTTP server: a DUMB API authorizer that stores ONLY
// opaque ciphertext (packs/manifest/roster/keyfile as bytes) plus the minimum
// metadata for authorization and CAS. It never holds keys, never parses or validates
// blobs, and is NOT a security boundary (see docs/FORMAT-SPEC-TIER4.md, ЧАСТЬ A).
package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (ЧАСТЬ C). // SECURITY-REVIEW: m=19 MiB, t=2, p=1, 16-byte
// salt, 32-byte output — confirm before freeze.
const (
	argonMemoryKiB = 19456 // 19 MiB
	argonTime      = 2
	argonThreads   = 1
	argonSaltLen   = 16
	argonKeyLen    = 32
)

// tokenBytes is the entropy of every server token (256 bits). // SECURITY-REVIEW:
// bootstrap / invite / API tokens are CSPRNG 256-bit, base64url; only their SHA-256
// is ever stored.
const tokenBytes = 32

// argon2IDKey is the argon2id primitive, indirected through a var so a test can count
// invocations and prove the login anti-enumeration decoy actually runs argon2id in the
// unknown-user branch. Production never reassigns it.
var argon2IDKey = argon2.IDKey

// Anti-enumeration decoy: a syntactically valid salt+params+hash with the SAME argon2id
// cost, used to perform equivalent work when a login names an unknown username, so the
// response time does not reveal whether the username exists.
//
// INVARIANT (load-bearing): the decoy's cost MUST equal the cost of a real verify, or the
// timing diverges and enumeration reopens. Today argon2-params are process-global — every
// hashPassword uses the same constants — so the decoy mirrors them via formatParams() and
// the argonSaltLen/argonKeyLen constants. If params ever become per-account or versioned,
// the decoy MUST mirror the cost of the specific account being probed; the silent
// dependency is pinned by TestDecoyArgonParamsMatchProduction, which fails if hashPassword's
// emitted params/lengths ever drift from the decoy.
// SECURITY-REVIEW: decoy cost == production cost; argon2id runs in both login branches
// (real verify and decoy); see (*Storage).login.
var (
	decoyArgonSaltHex = strings.Repeat("ab", argonSaltLen)
	decoyArgonParams  = formatParams()
	decoyArgonHashHex = strings.Repeat("cd", argonKeyLen)
)

// newToken returns a fresh 256-bit token, base64url (no padding), from crypto/rand.
func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("server: read token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns the hex SHA-256 of a token — the ONLY form persisted.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// constantTimeEqualHex compares two hex strings in constant time.
func constantTimeEqualHex(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// hashPassword runs argon2id with the frozen parameters over a fresh 16-byte salt
// and returns (saltHex, paramsString, hashHex). The plaintext password is never
// stored. // SECURITY-REVIEW: argon2id only (golang.org/x/crypto/argon2), no custom KDF.
func hashPassword(password string) (saltHex, params, hashHex string, err error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", "", "", fmt.Errorf("server: read salt: %w", err)
	}
	sum := argon2IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return hex.EncodeToString(salt), formatParams(), hex.EncodeToString(sum), nil
}

// verifyPassword recomputes argon2id with the stored salt+params and compares in
// constant time.
func verifyPassword(password, saltHex, params, hashHex string) (bool, error) {
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false, fmt.Errorf("server: decode salt: %w", err)
	}
	mem, t, p, keyLen, err := parseParams(params)
	if err != nil {
		return false, err
	}
	sum := argon2IDKey([]byte(password), salt, t, mem, p, keyLen)
	want, err := hex.DecodeString(hashHex)
	if err != nil {
		return false, fmt.Errorf("server: decode hash: %w", err)
	}
	return subtle.ConstantTimeCompare(sum, want) == 1, nil
}

func formatParams() string {
	return fmt.Sprintf("argon2id,m=%d,t=%d,p=%d,k=%d", argonMemoryKiB, argonTime, argonThreads, argonKeyLen)
}

// parseParams reads an "argon2id,m=..,t=..,p=..,k=.." string. Stored per-account so
// the cost can evolve without breaking existing hashes.
func parseParams(s string) (mem uint32, time uint32, threads uint8, keyLen uint32, err error) {
	mem, time, threads, keyLen = argonMemoryKiB, argonTime, argonThreads, argonKeyLen
	for _, part := range strings.Split(s, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		var v uint64
		if _, e := fmt.Sscanf(kv[1], "%d", &v); e != nil {
			return 0, 0, 0, 0, fmt.Errorf("server: bad argon param %q", part)
		}
		switch kv[0] {
		case "m":
			mem = uint32(v)
		case "t":
			time = uint32(v)
		case "p":
			threads = uint8(v)
		case "k":
			keyLen = uint32(v)
		}
	}
	return mem, time, threads, keyLen, nil
}
