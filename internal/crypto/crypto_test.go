package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"encgit/internal/agekey"
)

func TestPackRoundTripAndTamper(t *testing.T) {
	repoKey := bytes.Repeat([]byte{0x07}, 32)
	repoID := []byte("sixteen-byte-rid") // 16 bytes

	pk, err := DerivePackKeys(repoKey, repoID)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("raw git pack bytes \x00\x01\x02 with NULs")
	blob, err := Encrypt(plain, pk.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(blob, pk.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: %q", got)
	}

	// Key derivation is deterministic: a fresh derivation decrypts the same blob.
	pk2, err := DerivePackKeys(repoKey, repoID)
	if err != nil {
		t.Fatal(err)
	}
	if got2, err := Decrypt(blob, pk2.Identity); err != nil || !bytes.Equal(got2, plain) {
		t.Fatalf("re-derived identity could not decrypt: err=%v", err)
	}

	// Tamper: flipping one ciphertext byte must be detected (age AEAD).
	bad := append([]byte(nil), blob...)
	bad[len(bad)/2] ^= 0xff
	if _, err := Decrypt(bad, pk.Identity); err == nil {
		t.Fatal("ciphertext tamper not detected")
	}

	// repo_id domain separation: a different repo_id yields keys that cannot decrypt.
	pkOther, err := DerivePackKeys(repoKey, []byte("DIFFERENT-rid-16"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(blob, pkOther.Identity); err == nil {
		t.Fatal("blob decrypted under a different repo_id")
	}
}

func TestKeyfileWrapUnwrap(t *testing.T) {
	// Distinct scalars across many bytes (a single low byte would be masked away
	// by X25519 clamping and could collide).
	var scalarA, scalarB [32]byte
	for i := range scalarA {
		scalarA[i] = byte(i + 1)
		scalarB[i] = byte(i + 100)
	}
	idA, err := agekey.IdentityFromScalar(scalarA)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := agekey.IdentityFromScalar(scalarB)
	if err != nil {
		t.Fatal(err)
	}

	repoKey := make([]byte, 32)
	if _, err := rand.Read(repoKey); err != nil {
		t.Fatal(err)
	}

	keyfile, err := WrapRepoKey(repoKey, idA.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapRepoKey(keyfile, idA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, repoKey) {
		t.Fatal("unwrapped repo key mismatch")
	}

	// A non-recipient member cannot unwrap.
	if _, err := UnwrapRepoKey(keyfile, idB); err == nil {
		t.Fatal("non-recipient unwrapped the keyfile")
	}
}
