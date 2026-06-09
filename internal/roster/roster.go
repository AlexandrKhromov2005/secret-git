// Package roster implements the Tier-3 roster document (the cryptographic
// membership boundary): which Ed25519 keys may sign the manifest/roster and which
// X25519 keys the repo key is wrapped to. It is a second mutable, encrypted,
// CAS-guarded pointer parallel to the manifest, with the same JCS serialization,
// sign-then-encrypt, and prev-hash chaining.
//
// The canonical JSON encoder is REUSED from internal/manifest (externally validated
// against RFC 8785); this package never re-implements canonicalization.
package roster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"encgit/internal/manifest"
	"encgit/internal/util"
)

// ErrBadSignature is returned when roster signature verification fails.
var ErrBadSignature = errors.New("roster: bad signature")

// Member is one roster entry (§1.2). Public keys are lowercase hex of the raw 32
// bytes; the fingerprint is derived, never stored.
type Member struct {
	Name       string
	X25519Pub  string // hex raw32 — repo-key reception
	Ed25519Pub string // hex raw32 — manifest/roster signature verification
}

// XPubBytes returns the raw 32-byte X25519 public key.
func (m Member) XPubBytes() ([]byte, error) { return decodeRaw32(m.X25519Pub) }

// EdPubBytes returns the raw 32-byte Ed25519 public key.
func (m Member) EdPubBytes() ([]byte, error) { return decodeRaw32(m.Ed25519Pub) }

// EdPub returns the Ed25519 public key.
func (m Member) EdPub() (ed25519.PublicKey, error) {
	b, err := m.EdPubBytes()
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

// Fingerprint is SHA-256(x25519_pub_raw32 || ed25519_pub_raw32), hex — the same
// fingerprint definition as §2 of the frozen v1 identity.
func (m Member) Fingerprint() (string, error) {
	x, err := m.XPubBytes()
	if err != nil {
		return "", err
	}
	e, err := m.EdPubBytes()
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(x)
	h.Write(e)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func decodeRaw32(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("roster: bad hex key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("roster: key must be 32 bytes, got %d", len(b))
	}
	return b, nil
}

// Roster is the in-memory form of the §1.2 roster object.
type Roster struct {
	RepoID            string
	Version           uint64
	PrevRosterHash    *string // hex, or nil for genesis (v0)
	Members           []Member
	AuthorKeyID       string // fingerprint hex of the signer
	RepoKeyGeneration uint64 // v2: repo_key generation; 0 at genesis, +1 only on repo-key rotation
	Sig               string // base64 Ed25519
}

// sortedMembers returns the members ordered by fingerprint (§1.2 determinism).
func (r *Roster) sortedMembers() ([]Member, error) {
	type fpItem struct {
		m  Member
		fp string
	}
	items := make([]fpItem, len(r.Members))
	for i, m := range r.Members {
		fp, err := m.Fingerprint()
		if err != nil {
			return nil, err
		}
		items[i] = fpItem{m: m, fp: fp}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].fp < items[j].fp })
	out := make([]Member, len(items))
	for i := range items {
		out[i] = items[i].m
	}
	return out, nil
}

func (r *Roster) fields(includeSig bool) (map[string]any, error) {
	sorted, err := r.sortedMembers()
	if err != nil {
		return nil, err
	}
	members := make([]any, len(sorted))
	for i, m := range sorted {
		members[i] = map[string]string{
			"name":        m.Name,
			"x25519_pub":  m.X25519Pub,
			"ed25519_pub": m.Ed25519Pub,
		}
	}
	obj := map[string]any{
		"repo_id":             r.RepoID,
		"version":             r.Version,
		"members":             members,
		"author_key_id":       r.AuthorKeyID,
		"repo_key_generation": r.RepoKeyGeneration, // v2: signed generation (m2 binding)
	}
	if r.PrevRosterHash == nil {
		obj["prev_roster_hash"] = nil
	} else {
		obj["prev_roster_hash"] = *r.PrevRosterHash
	}
	if includeSig {
		obj["sig"] = r.Sig
	}
	return obj, nil
}

// SigningBytes is JCS(roster without sig) — the exact bytes that are signed (§1.3).
func (r *Roster) SigningBytes() ([]byte, error) {
	obj, err := r.fields(false)
	if err != nil {
		return nil, err
	}
	return manifest.CanonicalJSON(obj)
}

// CanonicalBytes is JCS(roster with sig) — the bytes that get encrypted, and whose
// SHA-256 is the roster hash used by prev_roster_hash and the local pin.
func (r *Roster) CanonicalBytes() ([]byte, error) {
	obj, err := r.fields(true)
	if err != nil {
		return nil, err
	}
	return manifest.CanonicalJSON(obj)
}

// Hash returns SHA-256(CanonicalBytes) as hex — the WITH-sig roster hash used by
// prev_roster_hash (the roster chain) and the local pin (frozen Tier-3 convention).
func (r *Roster) Hash() (string, error) {
	b, err := r.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return util.SHA256Hex(b), nil
}

// BindingHash returns SHA-256(SigningBytes) as hex — the hash over EXACTLY the
// JCS-canonical bytes the roster signature is computed over (the signed part, WITHOUT
// the sig field). This is the v2 manifest.roster_hash preimage (m1); it is
// deliberately distinct from Hash() (which includes sig and chains the roster).
// SECURITY-REVIEW (m1): roster_hash preimage = SHA-256(JCS(roster signed-part, no sig)).
func (r *Roster) BindingHash() (string, error) {
	b, err := r.SigningBytes()
	if err != nil {
		return "", err
	}
	return util.SHA256Hex(b), nil
}

// Sign signs the sig-less canonical bytes and stores the signature (§1.3).
// SECURITY-REVIEW (§7, sign-then-encrypt): the signed bytes cover repo_id, version,
// prev_roster_hash and the full member set; callers must encrypt only AFTER signing.
func (r *Roster) Sign(priv ed25519.PrivateKey) error {
	signed, err := r.SigningBytes()
	if err != nil {
		return err
	}
	r.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signed))
	return nil
}

// Verify checks the signature with the given Ed25519 public key. The caller decides
// whether pub belongs to a trusted author (§1.3: author ∈ roster v(n-1)).
func (r *Roster) Verify(pub ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(r.Sig)
	if err != nil {
		return fmt.Errorf("roster: decode sig: %w", err)
	}
	signed, err := r.SigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, signed, sig) {
		return ErrBadSignature
	}
	return nil
}

// Marshal returns the canonical plaintext (with sig) to encrypt.
func (r *Roster) Marshal() ([]byte, error) { return r.CanonicalBytes() }

// FindByFingerprint returns the member whose fingerprint matches fp.
func (r *Roster) FindByFingerprint(fp string) (Member, bool) {
	for _, m := range r.Members {
		if got, err := m.Fingerprint(); err == nil && got == fp {
			return m, true
		}
	}
	return Member{}, false
}

type wireRoster struct {
	RepoID         string  `json:"repo_id"`
	Version        uint64  `json:"version"`
	PrevRosterHash *string `json:"prev_roster_hash"`
	Members        []struct {
		Name       string `json:"name"`
		X25519Pub  string `json:"x25519_pub"`
		Ed25519Pub string `json:"ed25519_pub"`
	} `json:"members"`
	AuthorKeyID       string `json:"author_key_id"`
	RepoKeyGeneration uint64 `json:"repo_key_generation"`
	Sig               string `json:"sig"`
}

// Parse decodes a decrypted roster plaintext.
func Parse(plaintext []byte) (*Roster, error) {
	var w wireRoster
	dec := json.NewDecoder(bytes.NewReader(plaintext))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("roster: parse: %w", err)
	}
	r := &Roster{
		RepoID:            w.RepoID,
		Version:           w.Version,
		PrevRosterHash:    w.PrevRosterHash,
		AuthorKeyID:       w.AuthorKeyID,
		RepoKeyGeneration: w.RepoKeyGeneration,
		Sig:               w.Sig,
	}
	for _, m := range w.Members {
		r.Members = append(r.Members, Member{Name: m.Name, X25519Pub: m.X25519Pub, Ed25519Pub: m.Ed25519Pub})
	}
	return r, nil
}
