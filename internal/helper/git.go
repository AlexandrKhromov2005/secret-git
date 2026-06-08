package helper

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// runGit runs `git <args...>` with the given working directory and optional
// stdin, returning stdout. On failure the error includes git's stderr.
func runGit(dir string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// revParse resolves a ref to the hex object id it points at.
func revParse(dir, ref string) (string, error) {
	out, err := runGit(dir, nil, "rev-parse", "--verify", "--end-of-options", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// listHeadRefs returns all refs under refs/heads.
func listHeadRefs(dir string) ([]string, error) {
	out, err := runGit(dir, nil, "for-each-ref", "--format=%(refname)", "refs/heads")
	if err != nil {
		return nil, err
	}
	var refs []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			refs = append(refs, l)
		}
	}
	return refs, nil
}

// generatePack builds a (non-thin) packfile containing the objects reachable from
// want but not from have. It returns the raw pack bytes and the number of objects;
// count==0 (nil pack) means there is nothing new to send.
func generatePack(dir string, want, have []string) ([]byte, int, error) {
	args := []string{"rev-list", "--objects"}
	args = append(args, want...)
	if len(have) > 0 {
		args = append(args, "--not")
		args = append(args, have...)
	}
	objList, err := runGit(dir, nil, args...)
	if err != nil {
		return nil, 0, err
	}
	count := 0
	for _, l := range strings.Split(string(objList), "\n") {
		if strings.TrimSpace(l) != "" {
			count++
		}
	}
	if count == 0 {
		return nil, 0, nil
	}
	// Object-list mode: pack-objects reads object names (leading hex of each line)
	// from stdin. Default output is a complete (non-thin) pack.
	pack, err := runGit(dir, objList, "pack-objects", "--stdout", "-q")
	if err != nil {
		return nil, 0, err
	}
	return pack, count, nil
}

// indexPack feeds a raw packfile into the local object store.
func indexPack(dir string, pack []byte) error {
	_, err := runGit(dir, pack, "index-pack", "--stdin", "--fix-thin")
	return err
}

// updateRef points ref at sha in the local repo.
func updateRef(dir, ref, sha string) error {
	_, err := runGit(dir, nil, "update-ref", "--end-of-options", ref, sha)
	return err
}
