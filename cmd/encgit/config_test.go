package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigGet checks `encgit config get KEY` prints the single resolved value and errors
// on an unknown key.
func TestConfigGet(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg"))
	repoDir := filepath.Join(root, "repo")
	if err := saveConfig(repoConfigPath(repoDir), repoConfig{Store: "https://s", RepoID: "abc", Seed: "/s", CACert: "/c"}); err != nil {
		t.Fatal(err)
	}
	get := func(key string) string {
		t.Helper()
		r, w, _ := os.Pipe()
		old := os.Stdout
		os.Stdout = w
		err := cmdConfig([]string{"get", "--git", repoDir, key})
		_ = w.Close()
		os.Stdout = old
		if err != nil {
			t.Fatalf("config get %s: %v", key, err)
		}
		b, _ := io.ReadAll(r)
		return strings.TrimSpace(string(b))
	}
	if v := get("store"); v != "https://s" {
		t.Errorf("store: got %q", v)
	}
	if v := get("repo_id"); v != "abc" {
		t.Errorf("repo_id: got %q", v)
	}
	if v := get("cacert"); v != "/c" {
		t.Errorf("cacert: got %q", v)
	}
	if err := cmdConfig([]string{"get", "--git", repoDir, "bogus"}); err == nil {
		t.Error("unknown key should error")
	}
}

// TestConfigMergePrecedence checks that loadConfig overlays the per-repo config on top of
// the user-global one (per-repo wins; missing fields inherit from global), that a missing
// file is not an error, and that saved config is 0600.
func TestConfigMergePrecedence(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg")) // hermetic global config

	gp, err := globalConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(gp, repoConfig{Store: "https://global", Seed: "/g/seed", CACert: "/g/ca"}); err != nil {
		t.Fatal(err)
	}
	repoDir := filepath.Join(root, "repo")
	if err := saveConfig(repoConfigPath(repoDir), repoConfig{Store: "https://repo", RepoID: "deadbeef"}); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Store != "https://repo" { // per-repo overrides global
		t.Errorf("store: got %q want https://repo", cfg.Store)
	}
	if cfg.RepoID != "deadbeef" { // only set per-repo
		t.Errorf("repo_id: got %q want deadbeef", cfg.RepoID)
	}
	if cfg.Seed != "/g/seed" || cfg.CACert != "/g/ca" { // inherited from global
		t.Errorf("seed/cacert not inherited from global: seed=%q cacert=%q", cfg.Seed, cfg.CACert)
	}

	gonly, err := loadConfig("") // global only
	if err != nil {
		t.Fatal(err)
	}
	if gonly.Store != "https://global" || gonly.RepoID != "" {
		t.Errorf("global-only load wrong: %+v", gonly)
	}

	if _, err := loadConfig(filepath.Join(root, "absent")); err != nil {
		t.Errorf("missing per-repo config must not error: %v", err)
	}

	info, err := os.Stat(repoConfigPath(repoDir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config perms: got %o want 600", info.Mode().Perm())
	}
}
