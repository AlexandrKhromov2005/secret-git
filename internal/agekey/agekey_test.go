package agekey

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"

	"encgit/internal/bech32"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPublicKeyAgainstRFC7748KAT checks our X25519 public-key derivation against
// the implementation-independent known-answer vectors in RFC 7748 §6.1. A
// round-trip encrypt/decrypt cannot catch a "consistently wrong" clamping (where
// encrypt and decrypt agree on a wrong public key); an external KAT can.
//
// SECURITY-REVIEW (§7.1): confirms the age recipient we hand to age.Encrypt carries
// the RFC-correct X25519 public key for the scalar.
func TestPublicKeyAgainstRFC7748KAT(t *testing.T) {
	// RFC 7748, Section 6.1 (Curve25519 Diffie-Hellman example).
	cases := []struct{ scalarHex, pubHex string }{
		{
			"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
		},
		{
			"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
			"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
		},
	}

	for i, c := range cases {
		var scalar [32]byte
		copy(scalar[:], mustDecodeHex(t, c.scalarHex))
		wantPub := mustDecodeHex(t, c.pubHex)

		// (1) Our agekey path (x/crypto/curve25519) must match the RFC KAT.
		ours, err := PublicFromScalar(scalar)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !bytes.Equal(ours[:], wantPub) {
			t.Fatalf("case %d: PublicFromScalar does NOT match RFC 7748 KAT (STOP & report):\n got %x\nwant %x", i, ours[:], wantPub)
		}

		// (2) An independent implementation (stdlib crypto/ecdh) must agree too.
		sk, err := ecdh.X25519().NewPrivateKey(scalar[:])
		if err != nil {
			t.Fatalf("case %d: ecdh: %v", i, err)
		}
		if !bytes.Equal(sk.PublicKey().Bytes(), wantPub) {
			t.Fatalf("case %d: crypto/ecdh disagrees with RFC 7748 KAT", i)
		}

		// (3) The age recipient produced from this scalar must carry exactly this
		// public key: encode the KAT pubkey as an age recipient string and compare
		// to what age itself emits via IdentityFromScalar().Recipient().
		id, err := IdentityFromScalar(scalar)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		wantRecipient, err := bech32.Encode("age", wantPub)
		if err != nil {
			t.Fatal(err)
		}
		if got := id.Recipient().String(); got != wantRecipient {
			t.Fatalf("case %d: age recipient %s != KAT-derived recipient %s", i, got, wantRecipient)
		}
	}
}

// TestClampingExercised uses a scalar whose clamping bits are deliberately set, then
// checks our derivation equals a manual RFC 7748 clamp followed by an independent
// scalar-base-mult, ruling out a non-clamping or mis-clamping code path.
func TestClampingExercised(t *testing.T) {
	var scalar [32]byte
	for i := range scalar {
		scalar[i] = byte(i*7 + 1)
	}
	scalar[0] |= 0x07  // low 3 bits clamping must clear
	scalar[31] |= 0x80 // top bit clamping must clear
	scalar[31] &= 0xBF // bit 6 clamping must set (start it cleared to prove it gets set)

	ours, err := PublicFromScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}

	clamped := scalar
	clamped[0] &= 248
	clamped[31] &= 127
	clamped[31] |= 64
	manual, err := curve25519.X25519(clamped[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ours[:], manual) {
		t.Fatalf("public key does not match manual-clamp derivation:\n got %x\nwant %x", ours[:], manual)
	}

	// And the independent implementation agrees on the clamped result.
	sk, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sk.PublicKey().Bytes(), manual) {
		t.Fatal("crypto/ecdh disagrees with manual-clamp derivation")
	}
}
