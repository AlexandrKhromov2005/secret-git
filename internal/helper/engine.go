// Package helper is the push/fetch engine. On top of the frozen v1 manifest flow
// (§5.4 push, §5.5 fetch, §5.6 CAS + rebase-retry, §5.7 rollback/equivocation) it
// adds the Tier-3 roster: manifest signers must be in the current trusted roster,
// the roster is a second CAS-guarded encrypted pointer with its own anti-rollback
// pin, and membership changes (add/remove/full-rekey) update the keyfile and, on
// removal, rotate the repo key.
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
	"encgit/internal/roster"
	"encgit/internal/store"
	"encgit/internal/util"
)

// RepoIDLen is the length in bytes of a repo_id (see FORMAT-NOTES).
const RepoIDLen = 16

// maxPushRetries bounds the CAS rebase-retry loop (§5.6).
const maxPushRetries = 16

// Init creates a fresh repository: it generates repo_id and the repo key, wraps the
// repo key to the founding member (the keyfile, §3), and publishes the genesis
// roster v0 = {founder} (§2). It returns the new repo_id as hex.
func Init(st store.Store, founder *identity.Identity, founderName string) (repoIDHex string, err error) {
	repoID := make([]byte, RepoIDLen)
	if _, err := rand.Read(repoID); err != nil {
		return "", fmt.Errorf("helper: read repo_id: %w", err)
	}
	repoKey := make([]byte, 32)
	if _, err := rand.Read(repoKey); err != nil {
		return "", fmt.Errorf("helper: read repo key: %w", err)
	}
	keyfile, err := crypto.WrapRepoKey(1, repoKey, founder.AgeRecipient()) // generation 1
	if err != nil {
		return "", err
	}
	if err := st.PutKeyfile(keyfile); err != nil {
		return "", err
	}

	pack, err := crypto.DerivePackKeys(repoKey, repoID)
	if err != nil {
		return "", err
	}
	repoHex := hex.EncodeToString(repoID)
	gen := &roster.Roster{
		RepoID:            repoHex,
		Version:           0, // genesis = v0 (§2)
		PrevRosterHash:    nil,
		Members:           []roster.Member{memberFromIdentity(founder, founderName)},
		AuthorKeyID:       founder.FingerprintHex(),
		RepoKeyGeneration: 1, // genesis generation = 1 (§B: 0 is never valid)
	}
	if err := gen.Sign(founder.SigningKey()); err != nil {
		return "", err
	}
	plain, err := gen.Marshal()
	if err != nil {
		return "", err
	}
	blob, err := crypto.Encrypt(plain, pack.Recipient)
	if err != nil {
		return "", err
	}
	if err := st.CASRoster(0, blob, 0); err != nil {
		return "", fmt.Errorf("helper: publish genesis roster: %w", err)
	}
	return repoHex, nil
}

// Engine binds a local git repo, a store, local state, and a member identity to a
// specific repo_id. The repo key and pack/manifest keys are refreshed from the
// keyfile on each operation so the engine follows repo-key rotations transparently.
type Engine struct {
	gitDir  string
	store   store.Store
	state   *localstate.Store
	member  *identity.Identity
	repoID  []byte // raw
	repoHex string

	repoKey      []byte                      // current repo key (refreshed from the keyfile)
	kfGeneration uint64                      // generation read from the keyfile (v2, checked against the roster)
	pack         *crypto.PackKeys            // current pack/manifest keys
	knownKeys    [][]byte                    // every repo key this client has held (current + historical)
	packCache    map[string]*crypto.PackKeys // derived pack keys per known repo key
}

// Open binds an Engine and derives the current pack/manifest keys from the keyfile.
func Open(gitDir string, st store.Store, state *localstate.Store, member *identity.Identity, repoIDHex string) (*Engine, error) {
	repoID, err := hex.DecodeString(repoIDHex)
	if err != nil {
		return nil, fmt.Errorf("helper: bad repo_id hex: %w", err)
	}
	e := &Engine{
		gitDir:  gitDir,
		store:   st,
		state:   state,
		member:  member,
		repoID:  repoID,
		repoHex: hex.EncodeToString(repoID),
	}
	if err := e.refreshPackKeys(); err != nil {
		return nil, err
	}
	return e, nil
}

// refreshPackKeys re-reads the keyfile, unwraps the current repo key with the
// member's X25519 identity, and re-derives the pack/manifest keys. Called at the
// start of each operation so a repo-key rotation by another member is picked up
// (and so a removed member's unwrap fails fast).
func (e *Engine) refreshPackKeys() error {
	keyfile, err := e.store.GetKeyfile()
	if err != nil {
		return fmt.Errorf("helper: get keyfile: %w", err)
	}
	generation, repoKey, err := crypto.UnwrapRepoKey(keyfile, e.member.AgeIdentity())
	if err != nil {
		return fmt.Errorf("helper: unwrap repo key (not a current member?): %w", err)
	}
	pack, err := crypto.DerivePackKeys(repoKey, e.repoID)
	if err != nil {
		return err
	}
	e.repoKey = repoKey
	e.kfGeneration = generation
	e.pack = pack

	// Accumulate this key in the member-local cache so pre-rotation packs stay
	// readable to a continuing member (see localstate.State.RepoKeys).
	st, _, err := e.state.Load()
	if err != nil {
		return err
	}
	if !st.HasKey(repoKey) {
		st.AddKey(repoKey)
		if err := e.state.Save(st); err != nil {
			return err
		}
	}
	e.knownKeys = st.RepoKeys
	e.packCache = map[string]*crypto.PackKeys{hex.EncodeToString(repoKey): pack}
	return nil
}

// packKeysFor returns (and caches) the pack/manifest keys for a known repo key.
func (e *Engine) packKeysFor(key []byte) (*crypto.PackKeys, error) {
	h := hex.EncodeToString(key)
	if pk, ok := e.packCache[h]; ok {
		return pk, nil
	}
	pk, err := crypto.DerivePackKeys(key, e.repoID)
	if err != nil {
		return nil, err
	}
	e.packCache[h] = pk
	return pk, nil
}

// decryptPack decrypts a pack blob, trying the current key first and then every
// historical key this client holds (packs may predate a repo-key rotation, §3.2).
func (e *Engine) decryptPack(blob []byte) ([]byte, error) {
	if out, err := crypto.Decrypt(blob, e.pack.Identity); err == nil {
		return out, nil
	}
	for _, k := range e.knownKeys {
		pk, err := e.packKeysFor(k)
		if err != nil {
			continue
		}
		if out, err := crypto.Decrypt(blob, pk.Identity); err == nil {
			return out, nil
		}
	}
	return nil, errors.New("helper: no known repo key decrypts this pack (pre-rotation history requires the old key; run a full rekey while you still hold it)")
}

// checkKeyfileGeneration enforces m2: the generation embedded in the keyfile (read
// in refreshPackKeys) MUST equal the current trusted roster's repo_key_generation,
// otherwise the keyfile is stale/forged (a downgrade) and is rejected.
// SECURITY-REVIEW (m2): binds the keyfile to the roster's repo_key generation.
func (e *Engine) checkKeyfileGeneration(trusted *roster.Roster) error {
	// SECURITY-REVIEW (m2): the genesis generation is 1, so 0 is never a valid
	// generation; reject it so a missing/zero field cannot masquerade as valid.
	if trusted.RepoKeyGeneration == 0 || e.kfGeneration == 0 {
		return fmt.Errorf("helper: invalid repo_key_generation 0 (genesis is 1; 0 is never valid)")
	}
	if e.kfGeneration != trusted.RepoKeyGeneration {
		return fmt.Errorf("helper: keyfile generation %d does not match roster generation %d (stale/forged keyfile)",
			e.kfGeneration, trusted.RepoKeyGeneration)
	}
	return nil
}

// verifyManifestWithRoster enforces §4 + m1: the manifest's roster_hash MUST equal
// the BINDING hash of the current trusted roster (SHA-256 over the roster's signed
// bytes, WITHOUT sig), the signer named by pusher_key_id MUST be a member of that
// roster, and the Ed25519 signature must verify under their key.
// SECURITY-REVIEW (m1): roster_hash binds the manifest to a specific roster, so a
// manifest produced under a different (e.g. older) roster — even one signed by a
// then-valid, since-removed member — is rejected (cross-roster splice closed).
// SECURITY-REVIEW (§4): roster membership is the signature gate; a removed member is
// rejected because they are no longer present.
func (e *Engine) verifyManifestWithRoster(m *manifest.Manifest, trusted *roster.Roster) error {
	binding, err := trusted.BindingHash()
	if err != nil {
		return err
	}
	if m.RosterHash != binding {
		return fmt.Errorf("helper: manifest roster_hash %s does not match current roster %s (cross-roster splice?)",
			m.RosterHash, binding)
	}
	signer, ok := trusted.FindByFingerprint(m.PusherKeyID)
	if !ok {
		return fmt.Errorf("helper: manifest signer %s is not in the current roster", m.PusherKeyID)
	}
	pub, err := signer.EdPub()
	if err != nil {
		return err
	}
	return m.Verify(pub)
}

// current is a decrypted+verified snapshot of the live manifest (or empty).
type current struct {
	manifest *manifest.Manifest
	version  uint64 // store CAS version; 0 == no manifest yet
	hash     string // SHA-256 of the canonical plaintext (empty when none)
}

func (e *Engine) loadCurrent(trusted *roster.Roster) (*current, error) {
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
	if err := e.verifyManifestWithRoster(m, trusted); err != nil {
		return nil, err
	}
	return &current{manifest: m, version: version, hash: util.SHA256Hex(plain)}, nil
}

// importPack downloads one pack blob, verifies SHA-256(blob)==pack_id (§5.5 step 3),
// decrypts it, and feeds the objects into the local git object store.
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
	rawPack, err := e.decryptPack(packBlob)
	if err != nil {
		return fmt.Errorf("helper: decrypt pack %s: %w", packID, err)
	}
	if err := indexPack(e.gitDir, rawPack); err != nil {
		return fmt.Errorf("helper: index pack %s: %w", packID, err)
	}
	return nil
}

// ensureLocalObjects imports any of the current manifest's packs whose objects are
// not yet in the local repo (tracked via st.ImportedPacks), so the current refs are
// usable as git "have" during a CAS rebase (§5.6).
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

// Push implements §5.4 with the Tier-3 acceptance rule: the pusher (self) must be in
// the current roster, and the manifest is signed by self. On a version conflict it
// fetches the fresh manifest, rebases, and retries (§5.6).
func (e *Engine) Push(refs []string) error {
	if err := e.refreshPackKeys(); err != nil {
		return err
	}
	trusted, _, err := e.loadTrustedRoster()
	if err != nil {
		return err
	}
	if err := e.checkKeyfileGeneration(trusted); err != nil {
		return err
	}
	if _, ok := trusted.FindByFingerprint(e.member.FingerprintHex()); !ok {
		return errors.New("helper: cannot push: you are not in the current roster")
	}
	// m1: bind every push to the current roster via the without-sig binding hash.
	rosterBinding, err := trusted.BindingHash()
	if err != nil {
		return err
	}

	if len(refs) == 0 {
		if refs, err = listHeadRefs(e.gitDir); err != nil {
			return err
		}
		if len(refs) == 0 {
			return errors.New("helper: nothing to push (no refs/heads)")
		}
	}

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
		cur, err := e.loadCurrent(trusted)
		if err != nil {
			return err
		}
		if err := e.ensureLocalObjects(cur, &st); err != nil {
			return err
		}

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
			RosterHash:       rosterBinding, // m1: bind this push to the current roster (without-sig hash)
		}
		// SECURITY-REVIEW (§7.2): sign-then-encrypt — sign the sig-less canonical
		// bytes (which cover repo_id, version, prev_manifest_hash, roster_hash), then encrypt.
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
			_ = e.state.Save(st)
			continue
		}
		if err != nil {
			return err
		}

		st.Version = m.Version
		st.ManifestHash = newHash
		return e.state.Save(st)
	}
	return fmt.Errorf("helper: push gave up after %d version conflicts: %w", maxPushRetries, lastErr)
}

// Fetch implements §5.5 with the Tier-3 acceptance rule (§4): advance the trusted
// roster, then require the manifest signer to be in it, run §5.7 freshness checks,
// import missing packs, and update refs.
func (e *Engine) Fetch() error {
	if err := e.refreshPackKeys(); err != nil {
		return err
	}
	trusted, _, err := e.loadTrustedRoster()
	if err != nil {
		return err
	}
	// m2: the keyfile's generation must match the current roster before its repo key
	// is used to decrypt anything.
	if err := e.checkKeyfileGeneration(trusted); err != nil {
		return err
	}

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
	// m1 + §4: roster_hash must bind to the current roster, signer must be a member,
	// and the signature must verify.
	if err := e.verifyManifestWithRoster(m, trusted); err != nil {
		return err
	}
	newHash := util.SHA256Hex(plain)

	st, _, err := e.state.Load()
	if err != nil {
		return err
	}
	if st.Version != 0 {
		if m.Version <= st.Version {
			return fmt.Errorf("helper: rollback detected: manifest version %d <= pinned %d", m.Version, st.Version)
		}
		if m.PrevManifestHash == nil || *m.PrevManifestHash != st.ManifestHash {
			return fmt.Errorf("helper: equivocation detected: prev_manifest_hash does not chain to pinned manifest")
		}
	}

	for _, packID := range m.Packs {
		if st.HasPack(packID) {
			continue
		}
		if err := e.importPack(packID); err != nil {
			return err
		}
		st.AddPack(packID)
	}
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
		return nil
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
