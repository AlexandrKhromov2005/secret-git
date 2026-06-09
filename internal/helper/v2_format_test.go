package helper_test

import (
	"path/filepath"
	"testing"

	"encgit/internal/crypto"
	"encgit/internal/helper"
	"encgit/internal/identity"
	"encgit/internal/roster"
	"encgit/internal/store"
)

// loadRoster decrypts and parses the current roster.
func loadRoster(t *testing.T, st store.Store, member *identity.Identity, repoID string) *roster.Roster {
	t.Helper()
	pk := derivePackKeys(t, st, member, repoID)
	blob, _, err := st.GetRoster()
	if err != nil || blob == nil {
		t.Fatalf("no roster: %v", err)
	}
	plain, err := crypto.Decrypt(blob, pk.Identity)
	if err != nil {
		t.Fatal(err)
	}
	r, err := roster.Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func keyfileGeneration(t *testing.T, st store.Store, member *identity.Identity) uint64 {
	t.Helper()
	kf, err := st.GetKeyfile()
	if err != nil {
		t.Fatal(err)
	}
	gen, _, err := crypto.UnwrapRepoKey(kf, member.AgeIdentity())
	if err != nil {
		t.Fatal(err)
	}
	return gen
}

// TestGenesisGenerationIsOne pins the v2 start value: genesis roster AND keyfile
// both carry repo_key_generation == 1 (never 0).
func TestGenesisGenerationIsOne(t *testing.T) {
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	alice := newMember(t)
	repoID, err := helper.Init(st, alice, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if g := loadRoster(t, st, alice, repoID).RepoKeyGeneration; g != 1 {
		t.Fatalf("genesis roster generation = %d, want 1", g)
	}
	if g := keyfileGeneration(t, st, alice); g != 1 {
		t.Fatalf("genesis keyfile generation = %d, want 1", g)
	}
}

// TestRemoveIncrementsGeneration: a removal bumps the generation (1 -> 2), an add
// leaves it unchanged.
func TestRemoveIncrementsGeneration(t *testing.T) {
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
	if g := loadRoster(t, st, alice, repoID).RepoKeyGeneration; g != 1 {
		t.Fatalf("after add, generation = %d, want 1 (add does not rotate)", g)
	}
	if err := engine(t, src, st, alice, repoID).RemoveMember(carol.FingerprintHex()); err != nil {
		t.Fatal(err)
	}
	if g := loadRoster(t, st, alice, repoID).RepoKeyGeneration; g != 2 {
		t.Fatalf("after remove, generation = %d, want 2", g)
	}
	if g := keyfileGeneration(t, st, alice); g != 2 {
		t.Fatalf("after remove, keyfile generation = %d, want 2", g)
	}
}

// TestManifestRosterHashUsesBindingPreimage pins m1's preimage: the published
// manifest's roster_hash equals the roster's BindingHash (without sig), NOT its
// with-sig Hash().
func TestManifestRosterHashUsesBindingPreimage(t *testing.T) {
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

	pk := derivePackKeys(t, st, alice, repoID)
	m, _ := curManifest(t, st, pk)
	r := loadRoster(t, st, alice, repoID)

	binding, err := r.BindingHash()
	if err != nil {
		t.Fatal(err)
	}
	withSig, err := r.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if m.RosterHash != binding {
		t.Fatalf("manifest.roster_hash = %s, want roster BindingHash %s", m.RosterHash, binding)
	}
	if m.RosterHash == withSig {
		t.Fatal("manifest.roster_hash must NOT be the with-sig roster Hash()")
	}
}
