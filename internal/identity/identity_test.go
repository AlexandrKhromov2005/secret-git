package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func hkdfTest(t *testing.T, ikm []byte, info string) [32]byte {
	t.Helper()
	var out [32]byte
	r := hkdf.New(sha256.New, ikm, nil, []byte(info))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestFrozenDerivation independently recomputes the §2 derivation and checks it
// against Identity, which both pins the frozen format and confirms the X25519 and
// Ed25519 key materials are independent (no dual-use).
func TestFrozenDerivation(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 3)
	}

	id1, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if id1.FingerprintHex() != id2.FingerprintHex() {
		t.Fatal("FromSeed is not deterministic")
	}

	// X25519 public key.
	scalarX := hkdfTest(t, seed[:], infoX25519)
	wantPubX, err := curve25519.X25519(scalarX[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	gotPubX := id1.PublicX25519()
	if !bytes.Equal(wantPubX, gotPubX[:]) {
		t.Fatalf("x25519 pub mismatch:\n got %x\nwant %x", gotPubX[:], wantPubX)
	}

	// Ed25519 public key.
	seedEd := hkdfTest(t, seed[:], infoEd25519)
	wantEd := ed25519.NewKeyFromSeed(seedEd[:]).Public().(ed25519.PublicKey)
	if !bytes.Equal(wantEd, id1.VerifyKey()) {
		t.Fatalf("ed25519 pub mismatch:\n got %x\nwant %x", id1.VerifyKey(), wantEd)
	}

	// fingerprint = SHA-256(pub_x25519_raw32 || pub_ed25519_raw32).
	h := sha256.New()
	h.Write(gotPubX[:])
	h.Write(id1.VerifyKey())
	if want := hex.EncodeToString(h.Sum(nil)); want != id1.FingerprintHex() {
		t.Fatalf("fingerprint mismatch:\n got %s\nwant %s", id1.FingerprintHex(), want)
	}

	// Independence: the two derivations must not yield identical material.
	if bytes.Equal(scalarX[:], seedEd[:]) {
		t.Fatal("dual-use: X25519 scalar equals Ed25519 seed")
	}
}

func TestNewSeedRandomness(t *testing.T) {
	a, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two NewSeed calls returned identical seeds")
	}
}
