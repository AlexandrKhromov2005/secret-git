package helper_test

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"encgit/internal/crypto"
	"encgit/internal/helper"
	"encgit/internal/identity"
	"encgit/internal/localstate"
	"encgit/internal/manifest"
	"encgit/internal/roster"
	"encgit/internal/store"
)

// memberPubs returns an identity's raw X25519 and Ed25519 public keys.
func memberPubs(id *identity.Identity) (x [32]byte, ed [32]byte) {
	x = id.PublicX25519()
	copy(ed[:], id.VerifyKey())
	return
}

// memberOf builds a roster.Member from an identity.
func memberOf(id *identity.Identity, name string) roster.Member {
	x := id.PublicX25519()
	return roster.Member{
		Name:       name,
		X25519Pub:  hex.EncodeToString(x[:]),
		Ed25519Pub: hex.EncodeToString(id.VerifyKey()),
	}
}

// installForgedRoster CAS-installs a roster v1 authored by `attacker`, correctly
// chained to genesis, so the honest client rejects it at the author-membership check
// (the attacker is not in the trusted genesis roster).
func installForgedRoster(t *testing.T, st store.Store, pk *crypto.PackKeys, repoID string, attacker *identity.Identity) error {
	t.Helper()
	blob, _, err := st.GetRoster()
	if err != nil || blob == nil {
		t.Fatalf("no genesis roster: %v", err)
	}
	genPlain, err := crypto.Decrypt(blob, pk.Identity)
	if err != nil {
		t.Fatal(err)
	}
	gen, err := roster.Parse(genPlain)
	if err != nil {
		t.Fatal(err)
	}
	genHash, err := gen.Hash()
	if err != nil {
		t.Fatal(err)
	}
	forged := &roster.Roster{
		RepoID:         repoID,
		Version:        1,
		PrevRosterHash: &genHash,
		Members:        []roster.Member{memberOf(attacker, "mallory")},
		AuthorKeyID:    attacker.FingerprintHex(),
	}
	if err := forged.Sign(attacker.SigningKey()); err != nil {
		t.Fatal(err)
	}
	plain, err := forged.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rblob, err := crypto.Encrypt(plain, pk.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	return st.CASRoster(0, rblob, 1)
}

// manifestPacks decrypts the current manifest and returns its pack ids.
func manifestPacks(t *testing.T, st store.Store, member *identity.Identity, repoID string) []string {
	t.Helper()
	pk := derivePackKeys(t, st, member, repoID)
	blob, ver, err := st.GetManifest()
	if err != nil {
		t.Fatal(err)
	}
	if ver == 0 {
		return nil
	}
	plain, err := crypto.Decrypt(blob, pk.Identity)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	return m.Packs
}

// TestAddMemberThenNewMemberFetches: founder pushes history, adds a second member
// with an OOB-verified fingerprint, and the new member clones+fetches successfully.
func TestAddMemberThenNewMemberFetches(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	m0 := newMember(t)
	repoID, err := helper.Init(st, m0, "alice")
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	sha := commit(t, src, "a.txt", "shared history", "c1")
	if err := engine(t, src, st, m0, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}

	// Add a second member (OOB fingerprint supplied and correct).
	m1 := newMember(t)
	x1, ed1 := memberPubs(m1)
	if err := engine(t, src, st, m0, repoID).AddMember("bob", x1, ed1, m1.FingerprintHex()); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// The new member clones a fresh repo and fetches.
	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	if err := engine(t, dst, st, m1, repoID).Fetch(); err != nil {
		t.Fatalf("new member fetch: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != sha {
		t.Fatalf("new member ref = %s, want %s", got, sha)
	}
	if got := git(t, dst, "show", "main:a.txt"); got != "shared history" {
		t.Fatalf("new member content = %q", got)
	}
}

func TestAddRequiresOOBFingerprint(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	m0 := newMember(t)
	repoID, err := helper.Init(st, m0, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")

	m1 := newMember(t)
	x1, ed1 := memberPubs(m1)

	// No OOB fingerprint -> rejected.
	if err := engine(t, src, st, m0, repoID).AddMember("bob", x1, ed1, ""); err == nil {
		t.Fatal("add without OOB fingerprint was accepted")
	}
	// Wrong OOB fingerprint -> rejected.
	if err := engine(t, src, st, m0, repoID).AddMember("bob", x1, ed1, "00"+m1.FingerprintHex()[2:]); err == nil {
		t.Fatal("add with mismatched OOB fingerprint was accepted")
	}
	// Correct OOB fingerprint -> accepted.
	if err := engine(t, src, st, m0, repoID).AddMember("bob", x1, ed1, m1.FingerprintHex()); err != nil {
		t.Fatalf("add with correct OOB fingerprint failed: %v", err)
	}
}

// TestRemoveEnforcesBothGates: after removal, the removed member (1) cannot decrypt
// (repo key rotated) and (2) their manifest signature is rejected (not in roster).
func TestRemoveEnforcesBothGates(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	m0 := newMember(t)
	repoID, err := helper.Init(st, m0, "alice")
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, m0, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}

	// Add then remove m1.
	m1 := newMember(t)
	x1, ed1 := memberPubs(m1)
	if err := engine(t, src, st, m0, repoID).AddMember("bob", x1, ed1, m1.FingerprintHex()); err != nil {
		t.Fatal(err)
	}
	// m1 fetches once while still a member (so it holds the old objects/key).
	dst1 := filepath.Join(root, "dst1")
	initRepo(t, dst1, "main")
	if err := engine(t, dst1, st, m1, repoID).Fetch(); err != nil {
		t.Fatalf("m1 fetch while member: %v", err)
	}

	if err := engine(t, src, st, m0, repoID).RemoveMember(m1.FingerprintHex()); err != nil {
		t.Fatalf("remove: %v", err)
	}

	// Gate B (encryption): m1 can no longer unwrap the (rotated) repo key — this now
	// fails as early as Open, so test Open directly rather than via the t.Fatal-on-
	// error engine() helper.
	dst2 := filepath.Join(root, "dst2")
	initRepo(t, dst2, "main")
	state2 := localstate.NewStore(filepath.Join(dst2, ".encgit", "state.json"))
	if _, err := helper.Open(dst2, st, state2, m1, repoID); err == nil {
		t.Fatal("removed member could still unwrap the repo key (key not rotated?)")
	}

	// Continuing member m0 still works after the removal+rotation.
	commit(t, src, "b.txt", "v2", "c2")
	if err := engine(t, src, st, m0, repoID).Push(nil); err != nil {
		t.Fatalf("continuing member push after removal: %v", err)
	}

	// Gate A (roster): a manifest signed by m1, even encrypted under the NEW key,
	// is rejected because m1 is no longer in the roster. (Done last because it
	// CAS-overwrites the manifest pointer with a forgery honest clients reject.)
	pkNew := derivePackKeys(t, st, m0, repoID)
	forged := &manifest.Manifest{
		RepoID:      repoID,
		Version:     99,
		Refs:        map[string]string{"refs/heads/main": "deadbeef"},
		Packs:       []string{},
		PusherKeyID: m1.FingerprintHex(),
	}
	installSignedManifest(t, st, pkNew, m1, forged, nil)

	dst3 := filepath.Join(root, "dst3")
	initRepo(t, dst3, "main")
	err = engine(t, dst3, st, m0, repoID).Fetch()
	if err == nil || !strings.Contains(err.Error(), "not in the current roster") {
		t.Fatalf("expected roster rejection of removed signer, got %v", err)
	}
}

// TestRosterServerSwapDetected: a forged roster authored by a non-member is rejected
// by the author-chain / pin check.
func TestRosterServerSwapDetected(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	m0 := newMember(t)
	repoID, err := helper.Init(st, m0, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, m0, repoID).Push(nil); err != nil { // pins genesis roster
		t.Fatal(err)
	}

	// Attacker (not in the genesis roster) forges roster v1 adding themselves.
	attacker := newMember(t)
	pk := derivePackKeys(t, st, m0, repoID)
	if err := installForgedRoster(t, st, pk, repoID, attacker); err != nil {
		t.Fatalf("install forged roster: %v", err)
	}

	err = engine(t, src, st, m0, repoID).Fetch()
	if err == nil || !strings.Contains(err.Error(), "roster") {
		t.Fatalf("expected roster swap to be detected, got %v", err)
	}
}

// TestRosterAuthorizationChain: M0 -> adds M1 -> M1 adds M2, each author is in the
// prior roster, so the chain is accepted.
func TestRosterAuthorizationChain(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	m0 := newMember(t)
	repoID, err := helper.Init(st, m0, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, m0, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}

	m1 := newMember(t)
	x1, ed1 := memberPubs(m1)
	if err := engine(t, src, st, m0, repoID).AddMember("bob", x1, ed1, m1.FingerprintHex()); err != nil {
		t.Fatal(err)
	}

	// m1 joins (anchors current roster) then adds m2 as the authorized author.
	dstB := filepath.Join(root, "dstB")
	initRepo(t, dstB, "main")
	engB := engine(t, dstB, st, m1, repoID)
	if err := engB.Fetch(); err != nil {
		t.Fatal(err)
	}
	m2 := newMember(t)
	x2, ed2 := memberPubs(m2)
	if err := engB.AddMember("carol", x2, ed2, m2.FingerprintHex()); err != nil {
		t.Fatalf("m1 (authorized) failed to add m2: %v", err)
	}

	// m2 can now fetch (anchors roster v2 with three members).
	dstC := filepath.Join(root, "dstC")
	initRepo(t, dstC, "main")
	if err := engine(t, dstC, st, m2, repoID).Fetch(); err != nil {
		t.Fatalf("m2 fetch: %v", err)
	}
}

// TestRekeyAfterRemoveKeepsHistory: after a minimal-rotation removal, a continuing
// member (whose local key cache still holds the pre-rotation key) can full-rekey,
// after which a fresh clone reads the full history under the current key.
func TestRekeyAfterRemoveKeepsHistory(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	m0 := newMember(t)
	repoID, err := helper.Init(st, m0, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	sha := commit(t, src, "a.txt", "history", "c1")
	// One engine session for the founder, reused so its key cache persists in state.
	if err := engine(t, src, st, m0, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}

	m1 := newMember(t)
	x1, ed1 := memberPubs(m1)
	if err := engine(t, src, st, m0, repoID).AddMember("bob", x1, ed1, m1.FingerprintHex()); err != nil {
		t.Fatal(err)
	}
	if err := engine(t, src, st, m0, repoID).RemoveMember(m1.FingerprintHex()); err != nil {
		t.Fatal(err)
	}
	// Full rekey must succeed: the old packs are under the pre-rotation key, which
	// m0's local key cache still holds.
	if err := engine(t, src, st, m0, repoID).FullRekey(); err != nil {
		t.Fatalf("rekey after remove: %v", err)
	}

	// A fresh clone (empty state, only the current key) now reads the full history.
	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	if err := engine(t, dst, st, m0, repoID).Fetch(); err != nil {
		t.Fatalf("fresh clone fetch after rekey: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != sha {
		t.Fatalf("ref = %s, want %s", got, sha)
	}
	if got := git(t, dst, "show", "main:a.txt"); got != "history" {
		t.Fatalf("content = %q", got)
	}
}

// TestFullRekeyReencryptsHistory: a full rekey re-encrypts packs under a new key and
// deletes the old blobs; a continuing member still reads, and the old pack id is gone.
func TestFullRekeyReencryptsHistory(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	m0 := newMember(t)
	repoID, err := helper.Init(st, m0, "alice")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	sha := commit(t, src, "a.txt", "v1", "c1")
	if err := engine(t, src, st, m0, repoID).Push(nil); err != nil {
		t.Fatal(err)
	}

	// Capture the old pack id from the current manifest.
	oldPacks := manifestPacks(t, st, m0, repoID)
	if len(oldPacks) == 0 {
		t.Fatal("expected at least one pack")
	}

	if err := engine(t, src, st, m0, repoID).FullRekey(); err != nil {
		t.Fatalf("full rekey: %v", err)
	}

	// Old pack blobs must be gone.
	for _, id := range oldPacks {
		if ok, _ := st.HasBlob(id); ok {
			t.Fatalf("old pack %s still present after full rekey", id)
		}
	}

	// A continuing member with a fresh clone reads the re-encrypted history.
	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	if err := engine(t, dst, st, m0, repoID).Fetch(); err != nil {
		t.Fatalf("fetch after rekey: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != sha {
		t.Fatalf("ref after rekey = %s, want %s", got, sha)
	}
	if got := git(t, dst, "show", "main:a.txt"); got != "v1" {
		t.Fatalf("content after rekey = %q", got)
	}
}
