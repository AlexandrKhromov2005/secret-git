package helper_test

import (
	"path/filepath"
	"strings"
	"testing"

	"encgit/internal/crypto"
	"encgit/internal/helper"
	"encgit/internal/identity"
	"encgit/internal/manifest"
)

// curManifest decrypts the current manifest and returns it plus its hash.
func curManifest(t *testing.T, st interface {
	GetManifest() ([]byte, uint64, error)
}, pk *crypto.PackKeys) (*manifest.Manifest, string) {
	t.Helper()
	blob, ver, err := st.GetManifest()
	if err != nil || ver == 0 {
		t.Fatalf("no manifest: %v", err)
	}
	plain, err := crypto.Decrypt(blob, pk.Identity)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	h, err := m.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return m, h
}

// rewrapKeyfileGeneration re-wraps the current repo key to a single member under a
// chosen (possibly wrong) generation — an adversarial keyfile downgrade.
func rewrapKeyfileGeneration(t *testing.T, st interface {
	GetKeyfile() ([]byte, error)
	PutKeyfile([]byte) error
}, member *identity.Identity, generation uint64) {
	t.Helper()
	kf, err := st.GetKeyfile()
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := crypto.UnwrapRepoKey(kf, member.AgeIdentity())
	if err != nil {
		t.Fatal(err)
	}
	bad, err := crypto.WrapRepoKey(generation, key, member.AgeRecipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutKeyfile(bad); err != nil {
		t.Fatal(err)
	}
}

// Test 1 (m1 isolation): a manifest signed by a VALID current member but stamped
// with a wrong roster_hash is rejected by the roster_hash binding alone.
func TestManifestRosterHashMismatchRejected(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	alice := newMember(t)
	repoID, err := helper.Init(st, alice, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	sha := commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, alice, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	dstEng := engine(t, dst, st, alice, repoID)
	if err := dstEng.Fetch(); err != nil {
		t.Fatal(err)
	}

	pk := derivePackKeys(t, st, alice, repoID)
	curM, curHash := curManifest(t, st, pk)
	forged := &manifest.Manifest{
		RepoID:           repoID,
		Version:          curM.Version + 1,
		PrevManifestHash: &curHash,
		Refs:             map[string]string{"refs/heads/main": sha},
		Packs:            curM.Packs,
		PusherKeyID:      alice.FingerprintHex(),   // a valid current signer
		RosterHash:       strings.Repeat("00", 32), // ...but a wrong roster_hash
	}
	installSignedManifest(t, st, pk, alice, forged, nil)

	err = dstEng.Fetch()
	if err == nil || !strings.Contains(err.Error(), "roster_hash") {
		t.Fatalf("expected roster_hash-binding rejection, got %v", err)
	}
}

// Test 2 (cross-roster splice): a manifest signed by a member valid under the OLD
// roster but removed under the current one is rejected by a roster-synced client.
func TestCrossRosterSpliceBlocked(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	alice := newMember(t)
	repoID, err := helper.Init(st, alice, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	sha := commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, alice, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}

	// Add carol, then remove her (rotation -> generation 1).
	carol := newMember(t)
	xc, ec := memberPubs(carol)
	if err := engine(t, src, st, alice, repoID).AddMember("carol", xc, ec, carol.FingerprintHex()); err != nil {
		t.Fatal(err)
	}
	oldRosterHash := currentRosterHash(t, st, alice, repoID) // roster with carol (gen 0)
	if err := engine(t, src, st, alice, repoID).RemoveMember(carol.FingerprintHex()); err != nil {
		t.Fatal(err)
	}

	// Adversary forges a manifest signed by the removed carol, encrypted under the
	// CURRENT (gen-1) key, stamped with the OLD roster_hash.
	pkNew := derivePackKeys(t, st, alice, repoID)
	splice := &manifest.Manifest{
		RepoID:      repoID,
		Version:     50,
		Refs:        map[string]string{"refs/heads/main": sha},
		Packs:       []string{},
		PusherKeyID: carol.FingerprintHex(),
		RosterHash:  oldRosterHash,
	}
	installSignedManifest(t, st, pkNew, carol, splice, nil)

	// A roster-synced client (advances to the carol-less roster) rejects it.
	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	err = engine(t, dst, st, alice, repoID).Fetch()
	if err == nil || !strings.Contains(err.Error(), "roster") {
		t.Fatalf("expected cross-roster splice to be blocked, got %v", err)
	}
}

// Test 3 (m2): a keyfile whose embedded generation does not match the current
// roster's repo_key_generation is rejected.
func TestKeyfileGenerationMismatchRejected(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	alice := newMember(t)
	repoID, err := helper.Init(st, alice, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, alice, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}

	// Forge a keyfile with the same key but a wrong generation (roster is gen 0).
	rewrapKeyfileGeneration(t, st, alice, 42)

	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	err = engine(t, dst, st, alice, repoID).Fetch()
	if err == nil || !strings.Contains(err.Error(), "keyfile generation") {
		t.Fatalf("expected keyfile-generation rejection, got %v", err)
	}
}

// Test 4 (Q3b): the server serves an old keyfile (generation G) while the roster is
// at generation G+1. A client already synced to G+1 (key cached) rejects the keyfile
// at the generation check. The only residual path — a client FULLY frozen at G (old
// roster + old keyfile + old key, internally consistent) — is plain §5.7 equivocation,
// detectable but not preventable; m3 catches it only when the head is visible.
func TestQ3bKeyfileDowngradeRejected(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	alice := newMember(t)
	repoID, err := helper.Init(st, alice, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, alice, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}
	carol := newMember(t)
	xc, ec := memberPubs(carol)
	if err := engine(t, src, st, alice, repoID).AddMember("carol", xc, ec, carol.FingerprintHex()); err != nil {
		t.Fatal(err)
	}
	keyfileGenG, err := st.GetKeyfile() // generation 0 (pre-rotation)
	if err != nil {
		t.Fatal(err)
	}
	if err := engine(t, src, st, alice, repoID).RemoveMember(carol.FingerprintHex()); err != nil {
		t.Fatal(err) // rotation -> generation 1; src state now caches key1 and pins the gen-1 roster
	}

	// Server downgrades the keyfile back to generation G while the roster is G+1.
	if err := st.PutKeyfile(keyfileGenG); err != nil {
		t.Fatal(err)
	}

	// alice (a continuing member, key1 cached) reads the gen-1 roster but rejects the
	// stale keyfile at the m2 generation check.
	err = engine(t, src, st, alice, repoID).Fetch()
	if err == nil || !strings.Contains(err.Error(), "keyfile generation") {
		t.Fatalf("expected keyfile downgrade to be rejected at the generation check, got %v", err)
	}
}

// Test 5 (re-issue on add): adding a member re-issues the manifest with the new
// roster_hash, so a member who advanced the roster accepts the current manifest,
// while a manifest still carrying the pre-add roster_hash is rejected.
func TestManifestReissuedOnAdd(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	alice := newMember(t)
	repoID, err := helper.Init(st, alice, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, alice, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	dstEng := engine(t, dst, st, alice, repoID)
	if err := dstEng.Fetch(); err != nil { // pin genesis
		t.Fatal(err)
	}
	genesisHash := currentRosterHash(t, st, alice, repoID)

	carol := newMember(t)
	xc, ec := memberPubs(carol)
	if err := engine(t, src, st, alice, repoID).AddMember("carol", xc, ec, carol.FingerprintHex()); err != nil {
		t.Fatal(err)
	}

	// The member advances the roster to v1 and accepts the re-issued manifest
	// (its roster_hash matches the new roster).
	if err := dstEng.Fetch(); err != nil {
		t.Fatalf("re-issued manifest after add was not accepted: %v", err)
	}

	// A manifest still carrying the PRE-add (genesis) roster_hash is now rejected.
	pk := derivePackKeys(t, st, alice, repoID)
	curM, curHash := curManifest(t, st, pk)
	stale := &manifest.Manifest{
		RepoID:           repoID,
		Version:          curM.Version + 1,
		PrevManifestHash: &curHash,
		Refs:             curM.Refs,
		Packs:            curM.Packs,
		PusherKeyID:      alice.FingerprintHex(),
		RosterHash:       genesisHash, // stale roster_hash
	}
	installSignedManifest(t, st, pk, alice, stale, nil)
	if err := dstEng.Fetch(); err == nil || !strings.Contains(err.Error(), "roster_hash") {
		t.Fatalf("expected stale roster_hash to be rejected, got %v", err)
	}
}
