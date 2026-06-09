package main

import (
	"bytes"
	"encoding/hex"
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
	"encgit/internal/server"
	"encgit/internal/store/localfs"
)

// --- git + env helpers ---

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

// postJSON posts a JSON body to the server (optionally bearer-authenticated) and returns
// the status and decoded string map. Used only for the ADMIN/account API steps (which are
// server endpoints an admin drives, not encgit CLI commands).
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

func writeSeed(t *testing.T, path string) *identity.Identity {
	t.Helper()
	seed, err := identity.NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed[:])+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := identity.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestFullCLIFlowFromScratch is the proof that the founder-provisioning gap is closed: a
// server-backed repo is brought up and read back END TO END through the encgit commands —
// crucially, the genesis is published by `encgit publish-genesis` (its function), NOT by
// direct store.PutKeyfile/CASRoster calls in the test.
func TestFullCLIFlowFromScratch(t *testing.T) {
	isolateGit(t)

	// 1. Server + admin (bootstrap -> admin account -> admin token).
	sdir := t.TempDir()
	st, err := server.OpenStorage(filepath.Join(sdir, "meta.db"), filepath.Join(sdir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ts := httptest.NewServer(server.New(st, server.DefaultConfig()).Handler())
	t.Cleanup(ts.Close)

	btok, err := st.EnsureBootstrap()
	if err != nil || btok == "" {
		t.Fatalf("ensure bootstrap: %v", err)
	}
	if code, _ := postJSON(t, ts.URL+"/auth/bootstrap", "", map[string]string{"token": btok, "username": "admin", "password": "pw"}); code != 201 {
		t.Fatalf("bootstrap exchange: %d", code)
	}
	_, al := postJSON(t, ts.URL+"/auth/login", "", map[string]string{"username": "admin", "password": "pw"})
	adminTok := al["token"]
	if adminTok == "" {
		t.Fatal("no admin token")
	}

	// 2. Founder: identity (seed file) + LOCAL init -> repo_id (and fingerprint).
	seedDir := t.TempDir()
	seedPath := filepath.Join(seedDir, "founder.seed")
	founder := writeSeed(t, seedPath)
	initDir := filepath.Join(t.TempDir(), "initstore")
	localStore, err := localfs.Open(initDir)
	if err != nil {
		t.Fatal(err)
	}
	repoID, err := helper.Init(localStore, founder, "founder")
	if err != nil {
		t.Fatalf("init: %v", err)
	}

	// 3. Admin: create the repo with THIS repo_id, issue a writer invite, founder registers.
	if code, _ := postJSON(t, ts.URL+"/repos", adminTok, map[string]string{"repo_id": repoID}); code != 201 {
		t.Fatalf("create repo: %d", code)
	}
	_, inv := postJSON(t, ts.URL+"/repos/"+repoID+"/invites", adminTok, map[string]string{"role": "writer"})
	if inv["invite_token"] == "" {
		t.Fatal("no invite token")
	}
	if code, _ := postJSON(t, ts.URL+"/auth/register", "", map[string]string{"invite_token": inv["invite_token"], "username": "founder", "password": "pw"}); code != 201 {
		t.Fatalf("register founder: %d", code)
	}

	// 4. Founder: login (saves the API token next to the seed, like `encgit login`), then
	//    publish-genesis VIA THE COMMAND, then push the actual git repo.
	tok, err := serverLogin(ts.URL, "founder", "pw")
	if err != nil || tok == "" {
		t.Fatalf("founder login: %v", err)
	}
	if err := saveToken(seedPath, ts.URL, tok); err != nil {
		t.Fatal(err)
	}
	if err := cmdPublishGenesis([]string{"--store", ts.URL, "--repo-id", repoID, "--from", initDir, "--seed", seedPath}); err != nil {
		t.Fatalf("publish-genesis: %v", err)
	}

	src := filepath.Join(t.TempDir(), "src")
	initRepo(t, src, "main")
	sha := commit(t, src, "a.txt", "hello from scratch", "first")
	if err := cmdPush([]string{"--store", ts.URL, "--seed", seedPath, "--repo-id", repoID, "--git", src}); err != nil {
		t.Fatalf("push: %v", err)
	}

	// 5. Fresh clone (founder identity) fetches — proves the genesis really landed and is
	//    valid: keyfile decrypts, roster + manifest signatures verify, m1/m2 pass.
	dst := filepath.Join(t.TempDir(), "dst")
	initRepo(t, dst, "main")
	if err := cmdFetch([]string{"--store", ts.URL, "--seed", seedPath, "--repo-id", repoID, "--git", dst}); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got := git(t, dst, "rev-parse", "refs/heads/main"); got != sha {
		t.Fatalf("ref mismatch: got %s want %s", got, sha)
	}
	if got := git(t, dst, "show", "main:a.txt"); got != "hello from scratch" {
		t.Fatalf("content mismatch: %q", got)
	}

	// publish-genesis is idempotent: re-running is a safe no-op (does not clobber).
	if err := cmdPublishGenesis([]string{"--store", ts.URL, "--repo-id", repoID, "--from", initDir, "--seed", seedPath}); err != nil {
		t.Fatalf("publish-genesis (rerun) should be a no-op: %v", err)
	}
}
