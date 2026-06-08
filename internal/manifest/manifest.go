// Package manifest implements the encgit manifest (§5): canonical JSON (JCS)
// serialization, Ed25519 sign-then-encrypt ordering, verification, and the
// plaintext hash used for the prev-hash chain and the local pin.
//
// Sign-then-encrypt and the fact that repo_id, version, and prev_manifest_hash are
// covered by the signature are SECURITY-REVIEW items (§7.2): they prevent splicing
// states across repos or substituting a fork.
package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"encgit/internal/util"
)

// ErrBadSignature is returned when manifest signature verification fails.
var ErrBadSignature = errors.New("manifest: bad signature")

// Manifest is the in-memory form of the manifest object (v2).
type Manifest struct {
	RepoID           string            // hex
	Version          uint64            // strictly increasing per successful push
	PrevManifestHash *string           // hex, or nil for the first manifest
	Refs             map[string]string // ref name -> git object sha (hex)
	Packs            []string          // ordered live pack ids (hex)
	PusherKeyID      string            // signer fingerprint (hex)
	RosterHash       string            // v2: hash of the roster this manifest was produced under
	Sig              string            // base64 Ed25519 signature
}

// wire is the exact JSON shape of the v2 manifest, used for parsing.
type wire struct {
	RepoID           string            `json:"repo_id"`
	Version          uint64            `json:"version"`
	PrevManifestHash *string           `json:"prev_manifest_hash"`
	Refs             map[string]string `json:"refs"`
	Packs            []string          `json:"packs"`
	PusherKeyID      string            `json:"pusher_key_id"`
	RosterHash       string            `json:"roster_hash"`
	Sig              string            `json:"sig"`
}

// fields builds the ordered field set as a generic map for the canonical encoder.
// When includeSig is false the sig field is omitted (the bytes that get signed).
func (m *Manifest) fields(includeSig bool) map[string]any {
	refs := m.Refs
	if refs == nil {
		refs = map[string]string{}
	}
	packs := m.Packs
	if packs == nil {
		packs = []string{}
	}
	obj := map[string]any{
		"repo_id":       m.RepoID,
		"version":       m.Version,
		"refs":          refs,
		"packs":         packs,
		"pusher_key_id": m.PusherKeyID,
		"roster_hash":   m.RosterHash, // v2: signed binding to the roster (m1)
	}
	if m.PrevManifestHash == nil {
		obj["prev_manifest_hash"] = nil
	} else {
		obj["prev_manifest_hash"] = *m.PrevManifestHash
	}
	if includeSig {
		obj["sig"] = m.Sig
	}
	return obj
}

// SigningBytes is JCS(manifest without sig) — the exact bytes that are signed (§5.3 step 1).
func (m *Manifest) SigningBytes() ([]byte, error) {
	return canonicalJSON(m.fields(false))
}

// CanonicalBytes is JCS(manifest with sig) — the exact bytes that get encrypted
// (§5.3 step 4) and whose SHA-256 is the manifest hash.
func (m *Manifest) CanonicalBytes() ([]byte, error) {
	return canonicalJSON(m.fields(true))
}

// Hash returns SHA-256(CanonicalBytes) as hex: the value used for a successor's
// prev_manifest_hash and for the local pin. The hash is over the plaintext
// INCLUDING sig (§5.4 step 3 references the plaintext manifest).
func (m *Manifest) Hash() (string, error) {
	b, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return util.SHA256Hex(b), nil
}

// Sign computes the Ed25519 signature over SigningBytes and stores it (§5.3 steps 1-3).
// SECURITY-REVIEW (§7.2): the signed bytes are JCS(manifest WITHOUT sig) and cover
// repo_id, version, and prev_manifest_hash; callers must encrypt only AFTER signing.
func (m *Manifest) Sign(priv ed25519.PrivateKey) error {
	signed, err := m.SigningBytes()
	if err != nil {
		return err
	}
	m.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signed))
	return nil
}

// Verify checks the signature against the given Ed25519 public key. The caller is
// responsible for confirming pub is the key named by PusherKeyID and that it is a
// known member (§5.3 verification).
func (m *Manifest) Verify(pub ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(m.Sig)
	if err != nil {
		return fmt.Errorf("manifest: decode sig: %w", err)
	}
	signed, err := m.SigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, signed, sig) {
		return ErrBadSignature
	}
	return nil
}

// Marshal returns the canonical plaintext bytes to be encrypted (with sig).
func (m *Manifest) Marshal() ([]byte, error) {
	return m.CanonicalBytes()
}

// Parse decodes a decrypted manifest plaintext into a Manifest.
func Parse(plaintext []byte) (*Manifest, error) {
	var w wire
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("manifest: parse: %w", err)
	}
	return &Manifest{
		RepoID:           w.RepoID,
		Version:          w.Version,
		PrevManifestHash: w.PrevManifestHash,
		Refs:             w.Refs,
		Packs:            w.Packs,
		PusherKeyID:      w.PusherKeyID,
		RosterHash:       w.RosterHash,
		Sig:              w.Sig,
	}, nil
}
