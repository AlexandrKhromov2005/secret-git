package httpstore_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"encgit/internal/helper"
	"encgit/internal/identity"
	"encgit/internal/localstate"
	"encgit/internal/server"
	"encgit/internal/store"
	"encgit/internal/store/httpstore"
	"encgit/internal/store/localfs"
)

// --- git + env helpers (mirrors the helper package's e2e harness) ---

func isolateGit(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_AUTHOR_NAME", "t")
	t.Setenv("GIT_AUTHOR_EMAIL", "t@e.x")
	t.Setenv("GIT_COMMITTER_NAME", "t")
	t.Setenv("GIT_COMMITTER_EMAIL", "t@e.x")
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

func initRepo(t *testing.T, dir, branch string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
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

// --- HTTP auth helpers ---

func postJSON(t *testing.T, url, token string, body map[string]string) (int, map[string]string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]string{}
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

// httpRepo bundles a running test server + a provisioned repo + a writer token.
type httpRepo struct {
	ts      *httptest.Server
	repoID  string
	founder *identity.Identity
	token   string // founder API token (writer)
}

func (h *httpRepo) store(t *testing.T) store.Store {
	t.Helper()
	s, err := httpstore.New(h.ts.URL, h.repoID, h.token, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// setupHTTPRepo: create genesis locally (helper.Init), stand up a server, run the full
// HTTP auth flow (bootstrap -> admin -> create repo -> writer invite -> register ->
// login), then upload the genesis (keyfile + roster) to the server.
func setupHTTPRepo(t *testing.T) *httpRepo {
	t.Helper()

	// 1. Genesis via the local stub.
	gendir := t.TempDir()
	genfs, err := localfs.Open(filepath.Join(gendir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	founder := newMember(t)
	repoID, err := helper.Init(genfs, founder, "founder")
	if err != nil {
		t.Fatal(err)
	}

	// 2. Server.
	sdir := t.TempDir()
	st, err := server.OpenStorage(filepath.Join(sdir, "meta.db"), filepath.Join(sdir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ts := httptest.NewServer(server.New(st, server.DefaultConfig()).Handler())
	t.Cleanup(ts.Close)

	// 3. Full HTTP auth flow.
	btok, err := st.EnsureBootstrap()
	if err != nil || btok == "" {
		t.Fatalf("ensure bootstrap: %v", err)
	}
	if code, _ := postJSON(t, ts.URL+"/auth/bootstrap", "", map[string]string{"token": btok, "username": "admin", "password": "pw"}); code != 201 {
		t.Fatalf("bootstrap exchange: %d", code)
	}
	_, al := postJSON(t, ts.URL+"/auth/login", "", map[string]string{"username": "admin", "password": "pw"})
	adminToken := al["token"]
	if adminToken == "" {
		t.Fatal("no admin token")
	}
	if code, _ := postJSON(t, ts.URL+"/repos", adminToken, map[string]string{"repo_id": repoID}); code != 201 {
		t.Fatalf("create repo: %d", code)
	}
	_, inv := postJSON(t, ts.URL+"/repos/"+repoID+"/invites", adminToken, map[string]string{"role": "writer"})
	inviteToken := inv["invite_token"]
	if inviteToken == "" {
		t.Fatal("no invite token")
	}
	if code, _ := postJSON(t, ts.URL+"/auth/register", "", map[string]string{"invite_token": inviteToken, "username": "founder", "password": "pw"}); code != 201 {
		t.Fatalf("register: %d", code)
	}
	_, fl := postJSON(t, ts.URL+"/auth/login", "", map[string]string{"username": "founder", "password": "pw"})
	founderToken := fl["token"]
	if founderToken == "" {
		t.Fatal("no founder token")
	}

	h := &httpRepo{ts: ts, repoID: repoID, founder: founder, token: founderToken}

	// 4. Upload the genesis keyfile + roster to the server (founder = writer).
	kf, err := genfs.GetKeyfile()
	if err != nil {
		t.Fatal(err)
	}
	rblob, _, err := genfs.GetRoster()
	if err != nil {
		t.Fatal(err)
	}
	hs := h.store(t)
	if err := hs.PutKeyfile(kf); err != nil {
		t.Fatalf("upload keyfile: %v", err)
	}
	if err := hs.CASRoster(0, rblob, 0); err != nil {
		t.Fatalf("upload genesis roster: %v", err)
	}
	return h
}

func openEngine(t *testing.T, h *httpRepo, gitDir string) *helper.Engine {
	t.Helper()
	state := localstate.NewStore(filepath.Join(gitDir, ".encgit", "state.json"))
	eng, err := helper.Open(gitDir, h.store(t), state, h.founder, h.repoID)
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// TestHTTPStoreEndToEnd: full push -> fetch on a real git repo through the HTTP store.
func TestHTTPStoreEndToEnd(t *testing.T) {
	isolateGit(t)
	h := setupHTTPRepo(t)
	root := t.TempDir()

	src := filepath.Join(root, "src")
	initRepo(t, src, "main")
	shaA := commit(t, src, "a.txt", "hello over http", "first")
	if err := openEngine(t, h, src).Push(nil); err != nil {
		t.Fatalf("push: %v", err)
	}

	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	if err := openEngine(t, h, dst).Fetch(); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != shaA {
		t.Fatalf("ref mismatch: got %s want %s", got, shaA)
	}
	if got := git(t, dst, "show", "main:a.txt"); got != "hello over http" {
		t.Fatalf("content mismatch: %q", got)
	}

	// Second round.
	shaB := commit(t, src, "b.txt", "more", "second")
	if err := openEngine(t, h, src).Push(nil); err != nil {
		t.Fatalf("second push: %v", err)
	}
	if err := openEngine(t, h, dst).Fetch(); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != shaB {
		t.Fatalf("second ref mismatch: got %s want %s", got, shaB)
	}
}

// conflictOnce triggers a competing push before the first CASManifest, so the real
// PUT /manifest hits a stale version -> server 412 -> store.ErrVersionConflict ->
// the helper's existing rebase-retry converges.
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
	}
	return c.Store.CASManifest(expected, blob, newVersion)
}

// TestHTTPStoreCASConflictRebaseRetry: concurrent PUT /manifest yields a real 412 that
// the helper resolves via rebase-retry (no new retry logic).
func TestHTTPStoreCASConflictRebaseRetry(t *testing.T) {
	isolateGit(t)
	h := setupHTTPRepo(t)
	root := t.TempDir()

	srcA := filepath.Join(root, "srcA")
	initRepo(t, srcA, "main")
	shaA := commit(t, srcA, "a.txt", "A", "a")

	srcB := filepath.Join(root, "srcB")
	initRepo(t, srcB, "other")
	shaB := commit(t, srcB, "b.txt", "B", "b")

	engB := openEngine(t, h, srcB) // pushes via the raw HTTP store

	// engine A pushes through a wrapper that makes B push first.
	stateA := localstate.NewStore(filepath.Join(srcA, ".encgit", "state.json"))
	wrapped := &conflictOnce{Store: h.store(t), competitor: func() error { return engB.Push(nil) }}
	engA, err := helper.Open(srcA, wrapped, stateA, h.founder, h.repoID)
	if err != nil {
		t.Fatal(err)
	}
	if err := engA.Push(nil); err != nil {
		t.Fatalf("A push with forced conflict: %v", err)
	}

	// A fresh clone sees both refs.
	dst := filepath.Join(root, "dst")
	initRepo(t, dst, "main")
	if err := openEngine(t, h, dst).Fetch(); err != nil {
		t.Fatalf("fetch after conflict: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != shaA {
		t.Fatalf("main = %s, want %s", got, shaA)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/other"); got != shaB {
		t.Fatalf("other = %s, want %s", got, shaB)
	}
}
