// Package crypto wraps filippo.io/age for all bulk encryption in encgit: the
// keyfile (repo key wrapped to members, §3) and the pack/manifest payload
// encryption to the repo-key-derived recipient (§4, §5.3 encrypt half).
//
// SECURITY-REVIEW (§7.1, §7.3): the sole recipient for packs and the manifest is
// an ordinary X25519 recipient whose scalar is HKDF-derived from the repo key with
// info = "encgit/pack-recipient/v1" || raw repo_id bytes. No raw AEAD, nonce, or
// chunking is implemented here — age does all of that internally; we treat each
// age output as one opaque blob.
package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"filippo.io/age"
	"golang.org/x/crypto/hkdf"

	"encgit/internal/agekey"
)

// infoPackRecipient is the HKDF domain-separation label for the pack/manifest
// recipient. The raw repo_id bytes are appended to it (confirmed: raw bytes, not
// hex) before derivation. // SECURITY-REVIEW (§7.3)
const infoPackRecipient = "encgit/pack-recipient/v1"

// PackKeys holds the derived recipient (for encrypting) and identity (for
// decrypting) for packs and the manifest. Both come from the same scalar.
type PackKeys struct {
	Identity  *age.X25519Identity
	Recipient *age.X25519Recipient
}

// DerivePackKeys derives the pack/manifest age keypair from the repo key and the
// raw repo_id bytes (§4).
func DerivePackKeys(repoKey, repoIDRaw []byte) (*PackKeys, error) {
	// info = "encgit/pack-recipient/v1" || repo_id (raw bytes). // SECURITY-REVIEW (§7.3)
	info := make([]byte, 0, len(infoPackRecipient)+len(repoIDRaw))
	info = append(info, infoPackRecipient...)
	info = append(info, repoIDRaw...)

	var scalar [32]byte
	r := hkdf.New(sha256.New, repoKey, nil, info)
	if _, err := io.ReadFull(r, scalar[:]); err != nil {
		return nil, fmt.Errorf("crypto: hkdf pack recipient: %w", err)
	}
	id, err := agekey.IdentityFromScalar(scalar)
	if err != nil {
		return nil, err
	}
	return &PackKeys{Identity: id, Recipient: id.Recipient()}, nil
}

// Encrypt encrypts plaintext to the given age recipients and returns the opaque
// age blob.
func Encrypt(plaintext []byte, recipients ...age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, fmt.Errorf("crypto: age encrypt: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("crypto: age write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("crypto: age close: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts an age blob using the given identities.
func Decrypt(blob []byte, identities ...age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(blob), identities...)
	if err != nil {
		return nil, fmt.Errorf("crypto: age decrypt: %w", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("crypto: age read: %w", err)
	}
	return out, nil
}

// keyfilePayloadLen is the fixed keyfile-v2 plaintext length: 8-byte big-endian
// repo_key_generation followed by the 32-byte repo key.
const keyfilePayloadLen = 8 + 32

// WrapRepoKey produces the keyfile-v2 blob (§C): the payload is
// uint64-BE(generation) || repo_key_32, encrypted with age to the members.
// SECURITY-REVIEW (m2): the generation lives INSIDE the age-AEAD-protected payload,
// so the server cannot re-stamp it without breaking decryption. This is a fixed
// binary layout, not a hand-rolled AEAD — age provides the AEAD.
func WrapRepoKey(generation uint64, repoKey []byte, recipients ...age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("crypto: keyfile needs at least one recipient")
	}
	if len(repoKey) != 32 {
		return nil, fmt.Errorf("crypto: repo key must be 32 bytes, got %d", len(repoKey))
	}
	payload := make([]byte, keyfilePayloadLen)
	binary.BigEndian.PutUint64(payload[:8], generation)
	copy(payload[8:], repoKey)
	return Encrypt(payload, recipients...)
}

// UnwrapRepoKey recovers the generation and repo key from a keyfile-v2 blob using a
// member identity. An AEAD failure is fatal (returned as an error); a wrong payload
// length is rejected.
func UnwrapRepoKey(keyfile []byte, id age.Identity) (generation uint64, repoKey []byte, err error) {
	payload, err := Decrypt(keyfile, id)
	if err != nil {
		return 0, nil, err
	}
	if len(payload) != keyfilePayloadLen {
		return 0, nil, fmt.Errorf("crypto: keyfile payload must be %d bytes, got %d", keyfilePayloadLen, len(payload))
	}
	generation = binary.BigEndian.Uint64(payload[:8])
	repoKey = append([]byte(nil), payload[8:]...)
	return generation, repoKey, nil
}
