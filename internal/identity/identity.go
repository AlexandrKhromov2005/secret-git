// Package identity implements the repository-independent member identity (§2 of
// the frozen format): a 32-byte seed from which two INDEPENDENT key pairs are
// derived via HKDF-SHA256 — X25519 for receiving the repo key, Ed25519 for
// signing the manifest — plus the OOB fingerprint.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
	"golang.org/x/crypto/hkdf"

	"encgit/internal/agekey"
)

// ErrDegenerateSeed is returned by FromSeed when the seed is obviously non-random
// (all 32 bytes identical, e.g. an all-zero / uninitialized seed). This is a guard
// against a forgotten or zeroed seed; it does NOT and cannot measure the entropy of
// a non-constant seed — full entropy is the caller's responsibility (use NewSeed /
// crypto/rand). See §2 and FORMAT-NOTES.
var ErrDegenerateSeed = errors.New("identity: degenerate seed (all bytes identical); seed must come from a CSPRNG")

const (
	// SeedLen is the size of a member seed in bytes (§2: 32 bytes from CSPRNG).
	SeedLen = 32

	// SECURITY-REVIEW: exact HKDF domain-separation strings, and the fact that the
	// X25519 and Ed25519 key materials are derived under DISTINCT info labels so
	// there is no dual-use between encryption and signing (§2, §7.3).
	infoX25519  = "encgit/member-x25519/v1"
	infoEd25519 = "encgit/member-ed25519/v1"
)

// Identity is a member's full key material derived from a seed.
type Identity struct {
	seed    [32]byte
	scalarX [32]byte // X25519 private scalar
	pubX    [32]byte // X25519 public (raw 32 bytes)
	ageID   *age.X25519Identity
	edPriv  ed25519.PrivateKey
	edPub   ed25519.PublicKey
	fpr     [32]byte
}

// NewSeed returns a fresh 32-byte member seed from the CSPRNG.
func NewSeed() ([32]byte, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, fmt.Errorf("identity: read seed: %w", err)
	}
	return seed, nil
}

// hkdf32 runs HKDF-SHA256 with an empty salt and the given info, reading 32 bytes.
// SECURITY-REVIEW: salt="" — Go's HKDF expands an empty/nil salt to a hashLen block
// of zeros (the no-salt default), matching the frozen format's salt="".
func hkdf32(ikm []byte, info string) ([32]byte, error) {
	var out [32]byte
	r := hkdf.New(sha256.New, ikm, nil, []byte(info))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, fmt.Errorf("identity: hkdf %q: %w", info, err)
	}
	return out, nil
}

// isDegenerateSeed reports whether every byte of the seed is identical (covers the
// all-zero / uninitialized case and any constant-byte seed).
func isDegenerateSeed(seed [32]byte) bool {
	for _, b := range seed[1:] {
		if b != seed[0] {
			return false
		}
	}
	return true
}

// FromSeed deterministically derives the full identity from a seed. It rejects an
// obviously degenerate (constant-byte) seed; see ErrDegenerateSeed.
func FromSeed(seed [32]byte) (*Identity, error) {
	if isDegenerateSeed(seed) {
		return nil, ErrDegenerateSeed
	}
	id := &Identity{seed: seed}

	// X25519 (repo-key reception).
	scalarX, err := hkdf32(seed[:], infoX25519)
	if err != nil {
		return nil, err
	}
	id.scalarX = scalarX
	if id.ageID, err = agekey.IdentityFromScalar(scalarX); err != nil {
		return nil, err
	}
	if id.pubX, err = agekey.PublicFromScalar(scalarX); err != nil {
		return nil, err
	}

	// Ed25519 (manifest signing) — independent material from a different info label.
	seedEd, err := hkdf32(seed[:], infoEd25519)
	if err != nil {
		return nil, err
	}
	id.edPriv = ed25519.NewKeyFromSeed(seedEd[:])
	id.edPub = id.edPriv.Public().(ed25519.PublicKey)

	// fingerprint = SHA-256(pub_x25519_raw32 || pub_ed25519_raw32).
	h := sha256.New()
	h.Write(id.pubX[:])
	h.Write(id.edPub)
	copy(id.fpr[:], h.Sum(nil))

	return id, nil
}

// Seed returns the underlying seed.
func (id *Identity) Seed() [32]byte { return id.seed }

// AgeIdentity returns the X25519 age identity (used to unwrap the keyfile).
func (id *Identity) AgeIdentity() *age.X25519Identity { return id.ageID }

// AgeRecipient returns the X25519 age recipient (used as a keyfile recipient).
func (id *Identity) AgeRecipient() *age.X25519Recipient { return id.ageID.Recipient() }

// PublicX25519 returns the raw 32-byte X25519 public key.
func (id *Identity) PublicX25519() [32]byte { return id.pubX }

// SigningKey returns the Ed25519 private key for manifest signing.
func (id *Identity) SigningKey() ed25519.PrivateKey { return id.edPriv }

// VerifyKey returns the Ed25519 public key.
func (id *Identity) VerifyKey() ed25519.PublicKey { return id.edPub }

// Fingerprint returns the raw 32-byte fingerprint.
func (id *Identity) Fingerprint() [32]byte { return id.fpr }

// FingerprintHex returns the fingerprint as lowercase hex (the manifest
// pusher_key_id form, and the placeholder OOB rendering; richer rendering is Tier 3).
func (id *Identity) FingerprintHex() string { return hex.EncodeToString(id.fpr[:]) }
