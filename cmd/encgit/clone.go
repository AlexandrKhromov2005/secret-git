package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"encgit/internal/helper"
	"encgit/internal/localstate"
)

// cmdClone bootstraps a fresh local repository from a server-backed encgit repo in one
// step: it creates the target dir, `git init`s it, fetches (download -> verify signatures
// + roster/keyfile bindings -> decrypt -> import), and checks out a branch. Run
// `encgit login` first so a token is available for an http(s) --store.
//
//	encgit clone --store URL --seed FILE --repo-id HEX [--cacert FILE] [--branch NAME] DIR
func cmdClone(args []string) error {
	fs := flag.NewFlagSet("clone", flag.ContinueOnError)
	store := fs.String("store", "", "server URL (http(s)://...) or localfs directory")
	seedPath := fs.String("seed", "", "path to the member seed file")
	repoID := fs.String("repo-id", "", "repo_id (hex)")
	caCert := fs.String("cacert", "", "PEM file pinning the server's TLS cert (or set "+caCertEnv+")")
	branch := fs.String("branch", "", "branch to check out (default: the only fetched head)")
	statePath := fs.String("state", "", "local pin/state file (default <dir>/.encgit/state.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := fs.Arg(0)
	if dir == "" || *store == "" || *seedPath == "" || *repoID == "" {
		return errors.New("usage: encgit clone --store URL --seed FILE --repo-id HEX [--cacert FILE] [--branch NAME] DIR")
	}
	if nonEmptyDir(dir) {
		return fmt.Errorf("clone: %s already exists and is not empty", dir)
	}

	id, err := loadSeed(*seedPath)
	if err != nil {
		return err
	}
	st, err := openStore(*store, *repoID, *seedPath, *caCert)
	if err != nil {
		return err
	}

	// If anything fails after we create the directory, remove it so the clone can be
	// retried into the same path (a half-initialized .git would otherwise block a retry).
	// We only ever remove a directory WE created — never a pre-existing one the user gave us.
	created := !dirExists(dir)
	cleanup := func(e error) error {
		if created {
			_ = os.RemoveAll(dir)
		}
		return e
	}

	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		return cleanup(fmt.Errorf("git init %s: %v: %s", dir, err, strings.TrimSpace(string(out))))
	}
	sp := *statePath
	if sp == "" {
		sp = filepath.Join(dir, ".encgit", "state.json")
	}
	eng, err := helper.Open(dir, st, localstate.NewStore(sp), id, *repoID)
	if err != nil {
		return cleanup(err)
	}
	if err := eng.Fetch(); err != nil {
		return cleanup(err)
	}
	b, err := pickBranch(dir, *branch)
	if err != nil {
		return cleanup(err)
	}
	if out, err := exec.Command("git", "-C", dir, "checkout", "-f", b).CombinedOutput(); err != nil {
		return cleanup(fmt.Errorf("git checkout %s: %v: %s", b, err, strings.TrimSpace(string(out))))
	}
	fmt.Printf("cloned into %s (branch %s)\n", dir, b)
	return nil
}

// dirExists reports whether path exists and is a directory.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// nonEmptyDir reports whether path exists and already contains entries (so clone never
// clobbers an existing repo/directory).
func nonEmptyDir(path string) bool {
	entries, err := os.ReadDir(path)
	return err == nil && len(entries) > 0
}

// pickBranch returns want if it is among the fetched heads, otherwise the sole fetched
// head, otherwise an error (zero heads, or several without an explicit --branch).
func pickBranch(dir, want string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "for-each-ref", "--format=%(refname:short)", "refs/heads").Output()
	if err != nil {
		return "", fmt.Errorf("clone: list heads: %w", err)
	}
	heads := strings.Fields(string(out))
	if want != "" {
		for _, h := range heads {
			if h == want {
				return want, nil
			}
		}
		return "", fmt.Errorf("clone: branch %q is not among the fetched heads %v", want, heads)
	}
	switch len(heads) {
	case 0:
		return "", errors.New("clone: nothing was fetched (no branches)")
	case 1:
		return heads[0], nil
	default:
		return "", fmt.Errorf("clone: multiple branches fetched %v; choose one with --branch", heads)
	}
}
