package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// hkdfRFC5869 is an independent implementation of HKDF-SHA256 (RFC 5869:
// HMAC-Extract then HMAC-Expand), used to cross-check the production derivation
// without reusing golang.org/x/crypto/hkdf. An empty salt expands to a HashLen
// block of zeros for the extract step — exactly the frozen format's salt="".
func hkdfRFC5869(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)

	var okm, block []byte
	for i := 1; len(okm) < length; i++ {
		exp := hmac.New(sha256.New, prk)
		exp.Write(block)
		exp.Write(info)
		exp.Write([]byte{byte(i)})
		block = exp.Sum(nil)
		okm = append(okm, block...)
	}
	return okm[:length]
}

func readSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "FORMAT-SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestFrozenDerivation independently recomputes the §2 derivation using a from-
// scratch RFC 5869 HKDF and an external X25519, then checks it against Identity.
// This pins the frozen derivation (extract+expand HKDF, salt="", exact info labels)
// and confirms the X25519 and Ed25519 key materials are independent.
func TestFrozenDerivation(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i + 3)
	}

	id, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	// X25519 public key from an independent HKDF + X25519.
	scalarX := hkdfRFC5869(seed[:], nil, []byte(infoX25519), 32)
	wantPubX, err := curve25519.X25519(scalarX, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	gotPubX := id.PublicX25519()
	if !bytes.Equal(wantPubX, gotPubX[:]) {
		t.Fatalf("x25519 pub mismatch (STOP & report):\n got %x\nwant %x", gotPubX[:], wantPubX)
	}

	// Ed25519 public key from an independent HKDF.
	seedEd := hkdfRFC5869(seed[:], nil, []byte(infoEd25519), 32)
	wantEd := ed25519.NewKeyFromSeed(seedEd).Public().(ed25519.PublicKey)
	if !bytes.Equal(wantEd, id.VerifyKey()) {
		t.Fatalf("ed25519 pub mismatch (STOP & report):\n got %x\nwant %x", id.VerifyKey(), wantEd)
	}

	// fingerprint = SHA-256(pub_x25519_raw32 || pub_ed25519_raw32).
	h := sha256.New()
	h.Write(gotPubX[:])
	h.Write(id.VerifyKey())
	if want := hex.EncodeToString(h.Sum(nil)); want != id.FingerprintHex() {
		t.Fatalf("fingerprint mismatch:\n got %s\nwant %s", id.FingerprintHex(), want)
	}

	// Independence: the two derivations must not yield identical material.
	if bytes.Equal(scalarX, seedEd) {
		t.Fatal("dual-use: X25519 scalar equals Ed25519 seed")
	}
}

// TestInfoStringsMatchSpec checks that the HKDF domain-separation labels in the
// code are byte-for-byte identical to the strings written in the frozen spec.
func TestInfoStringsMatchSpec(t *testing.T) {
	if infoX25519 != "encgit/member-x25519/v1" {
		t.Errorf("infoX25519 = %q", infoX25519)
	}
	if infoEd25519 != "encgit/member-ed25519/v1" {
		t.Errorf("infoEd25519 = %q", infoEd25519)
	}
	spec := readSpec(t)
	for _, s := range []string{infoX25519, infoEd25519} {
		if !strings.Contains(spec, s) {
			t.Errorf("info string %q not found in docs/FORMAT-SPEC.md", s)
		}
	}
}

// TestDeterminismAndDistinctness covers the §7.3 determinism requirement (one seed
// -> one set of keys) and the no-dual-use requirement (the member's two keys differ),
// plus that different seeds yield different identities.
func TestDeterminismAndDistinctness(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i*5 + 1)
	}
	a, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	// Determinism.
	if a.FingerprintHex() != b.FingerprintHex() {
		t.Fatal("FromSeed is not deterministic (fingerprint)")
	}
	if a.PublicX25519() != b.PublicX25519() {
		t.Fatal("FromSeed is not deterministic (x25519)")
	}
	if !bytes.Equal(a.VerifyKey(), b.VerifyKey()) {
		t.Fatal("FromSeed is not deterministic (ed25519)")
	}

	// Distinctness of the member's two keys (no dual-use).
	ax := a.PublicX25519()
	if bytes.Equal(ax[:], a.VerifyKey()) {
		t.Fatal("X25519 public key equals Ed25519 public key (dual-use)")
	}

	// Different seed -> different identity.
	var seed2 [32]byte
	for i := range seed2 {
		seed2[i] = byte(i*5 + 2)
	}
	c, err := FromSeed(seed2)
	if err != nil {
		t.Fatal(err)
	}
	if a.FingerprintHex() == c.FingerprintHex() {
		t.Fatal("different seeds produced the same fingerprint")
	}
}

// TestRejectsDegenerateSeed exercises the §2 entropy guard.
func TestRejectsDegenerateSeed(t *testing.T) {
	var zero [32]byte
	if _, err := FromSeed(zero); !errors.Is(err, ErrDegenerateSeed) {
		t.Fatalf("all-zero seed: got err=%v, want ErrDegenerateSeed", err)
	}
	var ff [32]byte
	for i := range ff {
		ff[i] = 0xff
	}
	if _, err := FromSeed(ff); !errors.Is(err, ErrDegenerateSeed) {
		t.Fatalf("all-0xff seed: got err=%v, want ErrDegenerateSeed", err)
	}
	// A non-degenerate seed (not all-identical) is accepted.
	var ok [32]byte
	ok[0] = 1
	if _, err := FromSeed(ok); err != nil {
		t.Fatalf("non-degenerate seed rejected: %v", err)
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
