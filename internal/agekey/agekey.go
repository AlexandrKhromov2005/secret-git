// Package agekey bridges raw 32-byte X25519 scalars (as produced by our HKDF
// derivations) to filippo.io/age identities and recipients.
//
// age has no public API to build an X25519 identity from raw key bytes, so we
// bech32-encode the scalar exactly as age's own (*X25519Identity).String() does
// and parse it back with age.ParseX25519Identity. This is purely an encoding
// adapter — no key material is invented here; the scalar is the input.
package agekey

import (
	"fmt"

	"filippo.io/age"
	"golang.org/x/crypto/curve25519"

	"encgit/internal/bech32"
)

// secretKeyHRP is age's human-readable prefix for X25519 secret keys. age computes
// the bech32 checksum over this exact (upper-case) HRP and then upper-cases the
// whole string; we reproduce that so age.ParseX25519Identity accepts the result.
const secretKeyHRP = "AGE-SECRET-KEY-"

// IdentityFromScalar builds an *age.X25519Identity from a raw 32-byte X25519 scalar.
func IdentityFromScalar(scalar [32]byte) (*age.X25519Identity, error) {
	// secretKeyHRP is upper-case, so Encode returns the fully upper-cased string
	// that age itself emits for a secret key — no further casing needed.
	s, err := bech32.Encode(secretKeyHRP, scalar[:])
	if err != nil {
		return nil, fmt.Errorf("agekey: bech32 encode: %w", err)
	}
	id, err := age.ParseX25519Identity(s)
	if err != nil {
		return nil, fmt.Errorf("agekey: parse identity: %w", err)
	}
	return id, nil
}

// RecipientFromPublic builds an *age.X25519Recipient from a raw 32-byte X25519
// public key (used to wrap the repo key to roster members). It bech32-encodes the
// key the way age's X25519Recipient.String() does and parses it back.
func RecipientFromPublic(pub [32]byte) (*age.X25519Recipient, error) {
	s, err := bech32.Encode("age", pub[:])
	if err != nil {
		return nil, fmt.Errorf("agekey: bech32 encode recipient: %w", err)
	}
	r, err := age.ParseX25519Recipient(s)
	if err != nil {
		return nil, fmt.Errorf("agekey: parse recipient: %w", err)
	}
	return r, nil
}

// PublicFromScalar returns the raw 32-byte X25519 public key for a scalar. This
// equals the public key age derives for the same scalar (curve25519 clamps the
// scalar internally), so it is consistent with IdentityFromScalar(...).Recipient().
func PublicFromScalar(scalar [32]byte) ([32]byte, error) {
	var pub [32]byte
	out, err := curve25519.X25519(scalar[:], curve25519.Basepoint)
	if err != nil {
		return pub, fmt.Errorf("agekey: x25519: %w", err)
	}
	copy(pub[:], out)
	return pub, nil
}
