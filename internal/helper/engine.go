// Package helper is the Tier-1 push/fetch engine: it orchestrates git plumbing,
// the age crypto layer, the signed manifest, the store, and the local anti-rollback
// state to implement §5.4 (push), §5.5 (fetch), §5.6 (CAS + rebase-retry), and
// §5.7 (rollback/equivocation detection) of the frozen format.
//
// This is the engine the (Tier 4) git-remote-encgit / HTTP helper will sit on top
// of; here it runs directly against the local store stub.
package helper

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"encgit/internal/crypto"
	"encgit/internal/identity"
	"encgit/internal/localstate"
	"encgit/internal/manifest"
	"encgit/internal/store"
	"encgit/internal/util"
)

// RepoIDLen is the length in bytes of a repo_id (see FORMAT-NOTES).
const RepoIDLen = 16

// maxPushRetries bounds the CAS rebase-retry loop (§5.6).
const maxPushRetries = 16

// Init creates a fresh repository in the store: it generates repo_id and the repo
// key, wraps the repo key to the single founding member (the keyfile, §3), and
// stores it. It returns the new repo_id as hex (the caller persists it as repo
// coordinates; it is not part of the encrypted format). No manifest exists yet —
// the first push creates version 1.
func Init(st store.Store, member *identity.Identity) (repoIDHex string, err error) {
	repoID := make([]byte, RepoIDLen)
	if _, err := rand.Read(repoID); err != nil {
		return "", fmt.Errorf("helper: read repo_id: %w", err)
	}
	repoKey := make([]byte, 32)
	if _, err := rand.Read(repoKey); err != nil {
		return "", fmt.Errorf("helper: read repo key: %w", err)
	}
	keyfile, err := crypto.WrapRepoKey(repoKey, member.AgeRecipient())
	if err != nil {
		return "", err
	}
	if err := st.PutKeyfile(keyfile); err != nil {
		return "", err
	}
	return hex.EncodeToString(repoID), nil
}

// Engine binds a local git repo, a store, local state, and a member identity to a
// specific repo_id, with the pack/manifest keys derived from the unwrapped repo key.
type Engine struct {
	gitDir  string
	store   store.Store
	state   *localstate.Store
	member  *identity.Identity
	repoID  []byte // raw
	repoHex string
	pack    *crypto.PackKeys
}

// Open binds an Engine. It unwraps the repo key from the keyfile with the member's
// X25519 identity and derives the pack/manifest recipient from (repo key, repo_id).
func Open(gitDir string, st store.Store, state *localstate.Store, member *identity.Identity, repoIDHex string) (*Engine, error) {
	repoID, err := hex.DecodeString(repoIDHex)
	if err != nil {
		return nil, fmt.Errorf("helper: bad repo_id hex: %w", err)
	}
	keyfile, err := st.GetKeyfile()
	if err != nil {
		return nil, fmt.Errorf("helper: get keyfile: %w", err)
	}
	repoKey, err := crypto.UnwrapRepoKey(keyfile, member.AgeIdentity())
	if err != nil {
		return nil, fmt.Errorf("helper: unwrap repo key: %w", err)
	}
	pack, err := crypto.DerivePackKeys(repoKey, repoID)
	if err != nil {
		return nil, err
	}
	return &Engine{
		gitDir:  gitDir,
		store:   st,
		state:   state,
		member:  member,
		repoID:  repoID,
		repoHex: hex.EncodeToString(repoID),
		pack:    pack,
	}, nil
}

// verifyManifest checks the signature against a known member. In v1 the only known
// member is the local one (self); the full roster is Tier 3.
// SECURITY-REVIEW (§5.3): the signer named by pusher_key_id must be a known member
// (here: among the local member set) before its Ed25519 key is trusted to verify.
func (e *Engine) verifyManifest(m *manifest.Manifest) error {
	if m.PusherKeyID != e.member.FingerprintHex() {
		return fmt.Errorf("helper: manifest signed by unknown member %s", m.PusherKeyID)
	}
	return m.Verify(e.member.VerifyKey())
}

// current is a decrypted+verified snapshot of the live manifest (or empty).
type current struct {
	manifest *manifest.Manifest
	version  uint64 // store CAS version; 0 == no manifest yet
	hash     string // SHA-256 of the canonical plaintext (empty when none)
}

func (e *Engine) loadCurrent() (*current, error) {
	blob, version, err := e.store.GetManifest()
	if err != nil {
		return nil, err
	}
	if version == 0 {
		return &current{}, nil
	}
	plain, err := crypto.Decrypt(blob, e.pack.Identity)
	if err != nil {
		return nil, fmt.Errorf("helper: decrypt manifest: %w", err)
	}
	m, err := manifest.Parse(plain)
	if err != nil {
		return nil, err
	}
	if err := e.verifyManifest(m); err != nil {
		return nil, err
	}
	return &current{manifest: m, version: version, hash: util.SHA256Hex(plain)}, nil
}

// importPack downloads one pack blob, verifies SHA-256(blob)==pack_id (§5.5 step 3),
// decrypts it, and feeds the objects into the local git object store. It does not
// touch refs or local state; callers track which packs they have imported.
func (e *Engine) importPack(packID string) error {
	packBlob, err := e.store.GetBlob(packID)
	if err != nil {
		return fmt.Errorf("helper: get pack %s: %w", packID, err)
	}
	if got := util.SHA256Hex(packBlob); got != packID {
		// SECURITY-REVIEW (§5.5): the manifest binds state to pack_id = SHA-256 of
		// the ciphertext; a mismatch means the blob was substituted/tampered.
		return fmt.Errorf("helper: pack id mismatch: want %s got %s", packID, got)
	}
	rawPack, err := crypto.Decrypt(packBlob, e.pack.Identity)
	if err != nil {
		return fmt.Errorf("helper: decrypt pack %s: %w", packID, err)
	}
	if err := indexPack(e.gitDir, rawPack); err != nil {
		return fmt.Errorf("helper: index pack %s: %w", packID, err)
	}
	return nil
}

// ensureLocalObjects imports any of the current manifest's packs whose objects are
// not yet in the local repo (tracked via st.ImportedPacks). This is what makes the
// CAS rebase work: §5.6 says a conflicted pusher fetches the fresh state before
// rebuilding, so that the current refs are usable as git "have".
func (e *Engine) ensureLocalObjects(cur *current, st *localstate.State) error {
	for _, p := range curPacks(cur) {
		if st.HasPack(p) {
			continue
		}
		if err := e.importPack(p); err != nil {
			return err
		}
		st.AddPack(p)
	}
	return nil
}

// Push implements §5.4: gather new objects into one encrypted pack, build a signed
// encrypted manifest at version N+1, and CAS-swap it; on a version conflict it
// fetches the fresh manifest, rebases on it, and retries (§5.6).
//
// refs are the local ref names to publish (e.g. "refs/heads/main"); empty means all
// refs under refs/heads. Refs already in the manifest that are not pushed are kept.
func (e *Engine) Push(refs []string) error {
	if len(refs) == 0 {
		var err error
		if refs, err = listHeadRefs(e.gitDir); err != nil {
			return err
		}
		if len(refs) == 0 {
			return errors.New("helper: nothing to push (no refs/heads)")
		}
	}

	// Resolve the refs being pushed to their object ids once up front.
	wantRefs := make(map[string]string, len(refs))
	for _, ref := range refs {
		sha, err := revParse(e.gitDir, ref)
		if err != nil {
			return err
		}
		wantRefs[ref] = sha
	}

	st, _, err := e.state.Load()
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < maxPushRetries; attempt++ {
		cur, err := e.loadCurrent()
		if err != nil {
			return err
		}

		// Make sure the objects behind the current refs exist locally (needed as
		// git "have"), importing any packs from a competing push we lack.
		if err := e.ensureLocalObjects(cur, &st); err != nil {
			return err
		}

		// have = current manifest ref objects; want = pushed refs (kept refs merged).
		newRefs := map[string]string{}
		if cur.manifest != nil {
			for k, v := range cur.manifest.Refs {
				newRefs[k] = v
			}
		}
		for k, v := range wantRefs {
			newRefs[k] = v
		}
		have := uniqueValues(curRefsMap(cur))
		want := uniqueValues(wantRefs)

		pack, count, err := generatePack(e.gitDir, want, have)
		if err != nil {
			return err
		}

		newPacks := curPacks(cur)
		if count > 0 {
			// SECURITY-REVIEW (§7.1): pack encrypted via the repo-key-derived age
			// recipient; pack_id is the SHA-256 of the ciphertext blob.
			blob, err := crypto.Encrypt(pack, e.pack.Recipient)
			if err != nil {
				return err
			}
			packID := util.SHA256Hex(blob)
			if err := e.store.PutBlob(packID, blob); err != nil {
				return err
			}
			newPacks = append(newPacks, packID)
			st.AddPack(packID)
		}

		m := &manifest.Manifest{
			RepoID:           e.repoHex,
			Version:          cur.version + 1,
			PrevManifestHash: prevHashPtr(cur),
			Refs:             newRefs,
			Packs:            newPacks,
			PusherKeyID:      e.member.FingerprintHex(),
		}
		// SECURITY-REVIEW (§7.2): sign-then-encrypt — sign the sig-less canonical
		// bytes (which cover repo_id, version, prev_manifest_hash), then encrypt.
		if err := m.Sign(e.member.SigningKey()); err != nil {
			return err
		}
		plain, err := m.Marshal()
		if err != nil {
			return err
		}
		newHash := util.SHA256Hex(plain)
		manifestBlob, err := crypto.Encrypt(plain, e.pack.Recipient)
		if err != nil {
			return err
		}

		err = e.store.CASManifest(cur.version, manifestBlob, cur.version+1)
		if errors.Is(err, store.ErrVersionConflict) {
			lastErr = err
			_ = e.state.Save(st) // persist imported-pack progress before retrying
			continue             // rebase on the fresh manifest and retry (§5.6)
		}
		if err != nil {
			return err
		}

		// Success: advance the local pin to what we just pushed.
		st.Version = m.Version
		st.ManifestHash = newHash
		return e.state.Save(st)
	}
	return fmt.Errorf("helper: push gave up after %d version conflicts: %w", maxPushRetries, lastErr)
}

// Fetch implements §5.5: download+decrypt+verify the manifest, run the §5.7
// freshness/rollback checks against the local pin, import any missing packs
// (verifying SHA-256(blob)==pack_id), and update local refs from the manifest.
func (e *Engine) Fetch() error {
	blob, version, err := e.store.GetManifest()
	if err != nil {
		return err
	}
	if version == 0 {
		return nil // nothing published yet
	}
	plain, err := crypto.Decrypt(blob, e.pack.Identity)
	if err != nil {
		return fmt.Errorf("helper: decrypt manifest: %w", err)
	}
	m, err := manifest.Parse(plain)
	if err != nil {
		return err
	}
	// Verify the signature (and signer) BEFORE trusting any contents (§5.3).
	if err := e.verifyManifest(m); err != nil {
		return err
	}
	newHash := util.SHA256Hex(plain)

	// §5.7 rollback / equivocation detection.
	st, exists, err := e.state.Load()
	if err != nil {
		return err
	}
	if exists {
		if m.Version <= st.Version {
			return fmt.Errorf("helper: rollback detected: manifest version %d <= pinned %d", m.Version, st.Version)
		}
		if m.PrevManifestHash == nil || *m.PrevManifestHash != st.ManifestHash {
			return fmt.Errorf("helper: equivocation detected: prev_manifest_hash does not chain to pinned manifest")
		}
	}

	// Import missing packs (verifying ciphertext hash == pack_id inside importPack).
	for _, packID := range m.Packs {
		if st.HasPack(packID) {
			continue
		}
		if err := e.importPack(packID); err != nil {
			return err
		}
		st.AddPack(packID)
	}

	// Update local refs from the manifest (§5.5 step 4).
	for ref, sha := range m.Refs {
		if err := updateRef(e.gitDir, ref, sha); err != nil {
			return err
		}
	}

	st.Version = m.Version
	st.ManifestHash = newHash
	return e.state.Save(st)
}

// --- small helpers over the current snapshot ---

func curRefsMap(c *current) map[string]string {
	if c.manifest == nil {
		return nil
	}
	return c.manifest.Refs
}

func curPacks(c *current) []string {
	if c.manifest == nil {
		return nil
	}
	out := make([]string, len(c.manifest.Packs))
	copy(out, c.manifest.Packs)
	return out
}

func prevHashPtr(c *current) *string {
	if c.manifest == nil {
		return nil // first manifest: prev_manifest_hash = null
	}
	h := c.hash
	return &h
}

func uniqueValues(m map[string]string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range m {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	return out
}
