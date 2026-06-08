package helper_test

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"encgit/internal/crypto"
	"encgit/internal/helper"
	"encgit/internal/identity"
	"encgit/internal/localstate"
	"encgit/internal/manifest"
	"encgit/internal/store"
	"encgit/internal/store/localfs"
	"encgit/internal/util"
)

// --- git + environment helpers ---

func isolateGit(t *testing.T) {
	t.Helper()
	// Detach from any global/system git config and provide a fixed identity, so
	// commits are reproducible and unaffected by the developer's environment.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_AUTHOR_NAME", "encgit-test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@encgit.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "encgit-test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@encgit.invalid")
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func mkdir(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func initRepo(t *testing.T, dir, branch string) {
	t.Helper()
	mkdir(t, dir)
	git(t, dir, "init", "-q", "-b", branch)
}

func commit(t *testing.T, dir, file, content, msg string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", msg)
	return git(t, dir, "rev-parse", "HEAD")
}

func newMember(t *testing.T) *identity.Identity {
	t.Helper()
	seed, err := identity.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func openStore(t *testing.T, dir string) *localfs.Store {
	t.Helper()
	st, err := localfs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func engine(t *testing.T, gitDir string, st store.Store, member *identity.Identity, repoID string) *helper.Engine {
	t.Helper()
	state := localstate.NewStore(filepath.Join(gitDir, ".encgit", "state.json"))
	eng, err := helper.Open(gitDir, st, state, member, repoID)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// derivePackKeys reconstructs the pack/manifest keys the way a member would, so
// adversarial tests can craft malicious manifest blobs.
func derivePackKeys(t *testing.T, st store.Store, member *identity.Identity, repoIDHex string) *crypto.PackKeys {
	t.Helper()
	keyfile, err := st.GetKeyfile()
	if err != nil {
		t.Fatal(err)
	}
	repoKey, err := crypto.UnwrapRepoKey(keyfile, member.AgeIdentity())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(repoIDHex)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := crypto.DerivePackKeys(repoKey, raw)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// installSignedManifest signs m with the given member, optionally corrupts it,
// encrypts it, and CAS-installs it at version m.Version — this is the adversarial
// server forcing a crafted manifest onto the client.
func installSignedManifest(t *testing.T, st store.Store, pk *crypto.PackKeys, member *identity.Identity, m *manifest.Manifest, corrupt func(*manifest.Manifest)) {
	t.Helper()
	if err := m.Sign(member.SigningKey()); err != nil {
		t.Fatal(err)
	}
	if corrupt != nil {
		corrupt(m)
	}
	plain, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.Encrypt(plain, pk.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	_, cur, err := st.GetManifest()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CASManifest(cur, blob, m.Version); err != nil {
		t.Fatal(err)
	}
}

// --- tests ---

func TestPushFetchEndToEnd(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	member := newMember(t)
	repoID, err := helper.Init(st, member, "founder")
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	shaA := commit(t, src, "a.txt", "hello A", "first")

	srcEng := engine(t, src, st, member, repoID)
	if err := srcEng.Push(nil); err != nil {
		t.Fatalf("first push: %v", err)
	}

	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	dstEng := engine(t, dst, st, member, repoID)
	if err := dstEng.Fetch(); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != shaA {
		t.Fatalf("ref mismatch after fetch: got %s want %s", got, shaA)
	}
	if got := git(t, dst, "show", "main:a.txt"); got != "hello A" {
		t.Fatalf("content mismatch: %q", got)
	}

	// Second push/fetch round.
	shaB := commit(t, src, "b.txt", "hello B", "second")
	if err := srcEng.Push(nil); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if err := dstEng.Fetch(); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != shaB {
		t.Fatalf("ref mismatch after second fetch: got %s want %s", got, shaB)
	}
	if got := git(t, dst, "show", "main:b.txt"); got != "hello B" {
		t.Fatalf("second content mismatch: %q", got)
	}
}

// conflictOnce wraps a store and, on the first CASManifest call, runs a competing
// push and then returns a version conflict — forcing the engine into a real rebase.
type conflictOnce struct {
	store.Store
	fired      bool
	competitor func() error
}

func (c *conflictOnce) CASManifest(expected uint64, blob []byte, newVersion uint64) error {
	if !c.fired {
		c.fired = true
		if err := c.competitor(); err != nil {
			return err
		}
		return store.ErrVersionConflict
	}
	return c.Store.CASManifest(expected, blob, newVersion)
}

func TestCASConflictRebaseRetry(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	member := newMember(t)
	repoID, err := helper.Init(st, member, "founder")
	if err != nil {
		t.Fatal(err)
	}

	// Client A pushes refs/heads/main; client B concurrently pushes refs/heads/other.
	srcA := filepath.Join(root, "srcA")
	initRepo(t, srcA, "main")
	shaA := commit(t, srcA, "a.txt", "A content", "a")

	srcB := filepath.Join(root, "srcB")
	initRepo(t, srcB, "other")
	shaB := commit(t, srcB, "b.txt", "B content", "b")

	engB := engine(t, srcB, st, member, repoID) // uses the raw store

	wrapped := &conflictOnce{Store: st, competitor: func() error { return engB.Push(nil) }}
	engA := engine(t, srcA, wrapped, member, repoID)
	if err := engA.Push(nil); err != nil {
		t.Fatalf("A push (with forced conflict): %v", err)
	}

	// The store must now be at version 2 and hold both refs.
	if _, v, _ := st.GetManifest(); v != 2 {
		t.Fatalf("store version = %d, want 2", v)
	}

	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	dstEng := engine(t, dst, st, member, repoID)
	if err := dstEng.Fetch(); err != nil {
		t.Fatalf("fetch after conflict: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != shaA {
		t.Fatalf("main = %s, want %s", got, shaA)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/other"); got != shaB {
		t.Fatalf("other = %s, want %s", got, shaB)
	}
	if got := git(t, dst, "show", "main:a.txt"); got != "A content" {
		t.Fatalf("a.txt = %q", got)
	}
	if got := git(t, dst, "show", "other:b.txt"); got != "B content" {
		t.Fatalf("b.txt = %q", got)
	}
}

func TestRollbackDetected(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	member := newMember(t)
	repoID, err := helper.Init(st, member, "founder")
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	commit(t, src, "a.txt", "v1", "c1")
	srcEng := engine(t, src, st, member, repoID)
	if err := srcEng.Push(nil); err != nil {
		t.Fatal(err)
	}
	blobV1, _, err := st.GetManifest() // capture the v1 manifest blob
	if err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	dstEng := engine(t, dst, st, member, repoID)
	if err := dstEng.Fetch(); err != nil { // pin v1
		t.Fatal(err)
	}

	// Advance to v2.
	commit(t, src, "b.txt", "v2", "c2")
	if err := srcEng.Push(nil); err != nil {
		t.Fatal(err)
	}
	if err := dstEng.Fetch(); err != nil { // pin v2
		t.Fatal(err)
	}

	// Adversarial server rolls the pointer back to the stale v1 blob+version.
	if err := st.CASManifest(2, blobV1, 1); err != nil {
		t.Fatal(err)
	}
	err = dstEng.Fetch()
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("expected rollback detection, got %v", err)
	}
}

func TestEquivocationDetected(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	member := newMember(t)
	repoID, err := helper.Init(st, member, "founder")
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	shaA := commit(t, src, "a.txt", "v1", "c1")
	srcEng := engine(t, src, st, member, repoID)
	if err := srcEng.Push(nil); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	dstEng := engine(t, dst, st, member, repoID)
	if err := dstEng.Fetch(); err != nil { // pin v1 (hash H1)
		t.Fatal(err)
	}

	// Read v1's pack list to reuse in the forged manifest.
	pk := derivePackKeys(t, st, member, repoID)
	v1blob, _, _ := st.GetManifest()
	v1plain, err := crypto.Decrypt(v1blob, pk.Identity)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := manifest.Parse(v1plain)
	if err != nil {
		t.Fatal(err)
	}

	// Forge a v2 whose prev_manifest_hash does NOT chain to the pinned v1.
	wrongPrev := strings.Repeat("00", 32)
	forged := &manifest.Manifest{
		RepoID:           repoID,
		Version:          2,
		PrevManifestHash: &wrongPrev,
		Refs:             map[string]string{"refs/heads/main": shaA},
		Packs:            v1.Packs,
		PusherKeyID:      member.FingerprintHex(),
	}
	installSignedManifest(t, st, pk, member, forged, nil)

	err = dstEng.Fetch()
	if err == nil || !strings.Contains(err.Error(), "equivocation") {
		t.Fatalf("expected equivocation detection, got %v", err)
	}
}

func TestBadSignatureRejected(t *testing.T) {
	isolateGit(t)
	root := t.TempDir()
	st := openStore(t, filepath.Join(root, "store"))
	member := newMember(t)
	repoID, err := helper.Init(st, member, "founder")
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	shaA := commit(t, src, "a.txt", "v1", "c1")
	srcEng := engine(t, src, st, member, repoID)
	if err := srcEng.Push(nil); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	dstEng := engine(t, dst, st, member, repoID)
	if err := dstEng.Fetch(); err != nil { // pin v1
		t.Fatal(err)
	}

	pk := derivePackKeys(t, st, member, repoID)
	v1blob, _, _ := st.GetManifest()
	v1plain, _ := crypto.Decrypt(v1blob, pk.Identity)
	v1, _ := manifest.Parse(v1plain)
	h1 := util.SHA256Hex(v1plain)

	// A properly-chained v2, but with a corrupted signature.
	forged := &manifest.Manifest{
		RepoID:           repoID,
		Version:          2,
		PrevManifestHash: &h1,
		Refs:             map[string]string{"refs/heads/main": shaA},
		Packs:            v1.Packs,
		PusherKeyID:      member.FingerprintHex(),
	}
	installSignedManifest(t, st, pk, member, forged, func(m *manifest.Manifest) {
		raw, err := base64.StdEncoding.DecodeString(m.Sig)
		if err != nil {
			t.Fatal(err)
		}
		raw[0] ^= 0xff
		m.Sig = base64.StdEncoding.EncodeToString(raw)
	})

	if err := dstEng.Fetch(); err == nil {
		t.Fatal("expected signature verification failure, got nil")
	}
}
