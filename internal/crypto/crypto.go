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

// WrapRepoKey produces the keyfile blob: age.Encrypt(repo_key, recipients) (§3).
func WrapRepoKey(repoKey []byte, recipients ...age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("crypto: keyfile needs at least one recipient")
	}
	return Encrypt(repoKey, recipients...)
}

// UnwrapRepoKey recovers the repo key from the keyfile using a member identity.
func UnwrapRepoKey(keyfile []byte, id age.Identity) ([]byte, error) {
	return Decrypt(keyfile, id)
}
