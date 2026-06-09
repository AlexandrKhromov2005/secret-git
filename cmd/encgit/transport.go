package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"encgit/internal/store"
	"encgit/internal/store/httpstore"
	"encgit/internal/store/localfs"
)

// isHTTPURL reports whether s parses with an http/https scheme. This is the ONLY rule
// for selecting the HTTP store; any other value is a localfs directory path. No
// heuristics beyond the scheme (confirmed convention).
func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

func tokenKey(rawURL string) string { return strings.TrimRight(rawURL, "/") }

// openStore selects the store implementation from the --store value's scheme.
func openStore(storeFlag, repoID, seedPath string) (store.Store, error) {
	if isHTTPURL(storeFlag) {
		token, err := loadToken(seedPath, storeFlag)
		if err != nil {
			return nil, err
		}
		if token == "" {
			return nil, fmt.Errorf("no API token for %s; run `encgit login --seed %s %s <username>` first",
				tokenKey(storeFlag), seedPath, tokenKey(storeFlag))
		}
		return httpstore.New(storeFlag, repoID, token, nil)
	}
	return localfs.Open(storeFlag)
}

// --- token persistence (a JSON map server-URL -> token, next to the seed, 0600) ---

func tokenStorePath(seedPath string) string {
	return filepath.Join(filepath.Dir(seedPath), "encgit-tokens.json")
}

func loadTokens(seedPath string) (map[string]string, error) {
	data, err := os.ReadFile(tokenStorePath(seedPath))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func loadToken(seedPath, rawURL string) (string, error) {
	m, err := loadTokens(seedPath)
	if err != nil {
		return "", err
	}
	return m[tokenKey(rawURL)], nil
}

func saveToken(seedPath, rawURL, token string) error {
	m, err := loadTokens(seedPath)
	if err != nil {
		return err
	}
	m[tokenKey(rawURL)] = token
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(tokenStorePath(seedPath), data, 0o600)
}

// serverLogin exchanges username+password for an API token (returned once).
func serverLogin(baseURL, username, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(tokenKey(baseURL)+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("login failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Token, nil
}

// readPassword reads a password without echo from a terminal, or as a plain line
// when stdin is not a terminal (piped, for automation/tests). Either way the
// password is not echoed by us.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "password: ")
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(pw), err
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// cmdPublishGenesis implements: encgit publish-genesis --store URL --repo-id HEX --from DIR --seed FILE
//
// It is the one-time bridge that uploads a locally-created genesis (keyfile + genesis
// roster, already produced by `encgit init` into the --from store) to a freshly-created
// server repo, over the SAME store.Store interface that push uses. It writes NO new crypto
// (the bytes are already signed/wrapped by helper.Init) and adds NO new store methods. Run
// it after the admin has created the repo with this repo_id and granted the founder writer,
// and before the first `git push`. helper.Init and push are untouched.
func cmdPublishGenesis(args []string) error {
	fs := flag.NewFlagSet("publish-genesis", flag.ContinueOnError)
	storeFlag := fs.String("store", "", "remote server URL (http(s)://...)")
	repoID := fs.String("repo-id", "", "repo_id (hex) from init")
	from := fs.String("from", "", "local init store directory holding the genesis (keyfile + roster)")
	seedPath := fs.String("seed", "", "member seed file (locates the API token for --store)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *storeFlag == "" || *repoID == "" || *from == "" || *seedPath == "" {
		return errors.New("publish-genesis: --store, --repo-id, --from and --seed are required")
	}
	if !isHTTPURL(*storeFlag) {
		return errors.New("publish-genesis: --store must be an http(s):// server URL")
	}
	local, err := localfs.Open(*from)
	if err != nil {
		return err
	}
	remote, err := openStore(*storeFlag, *repoID, *seedPath)
	if err != nil {
		return err
	}
	return publishGenesis(local, remote)
}

// publishGenesis copies the already-signed genesis (keyfile + genesis roster) from a local
// store to a remote store using ONLY the frozen store.Store interface. It is conservative
// and safe to re-run: it never blindly overwrites an existing remote genesis.
// SECURITY-REVIEW: idempotent / no-clobber — publishes only when absent, no-ops when the
// remote already holds the byte-identical genesis, and refuses (does not overwrite) a
// differing remote keyfile or any remote roster that is not the byte-identical genesis. The
// roster is published with the SAME CAS baseline as helper.Init / the e2e test:
// CASRoster(expected=0, blob, newVersion=0).
func publishGenesis(local, remote store.Store) error {
	kf, err := local.GetKeyfile()
	if err != nil {
		return fmt.Errorf("read local keyfile: %w", err)
	}
	rblob, _, err := local.GetRoster()
	if err != nil {
		return fmt.Errorf("read local roster: %w", err)
	}
	if rblob == nil {
		return errors.New("no local genesis roster in --from (run `encgit init` against it first)")
	}

	published := false

	// Keyfile: singleton, no CAS. Publish if absent; no-op if identical; refuse to clobber.
	switch existing, err := remote.GetKeyfile(); {
	case errors.Is(err, store.ErrNotFound):
		if err := remote.PutKeyfile(kf); err != nil {
			return fmt.Errorf("publish keyfile: %w", err)
		}
		published = true
	case err != nil:
		return fmt.Errorf("check remote keyfile: %w", err)
	case !bytes.Equal(existing, kf):
		return errors.New("remote already has a different keyfile; refusing to overwrite")
	}

	// Genesis roster: CAS at version 0. Publish if absent; no-op if the byte-identical
	// genesis is already there; refuse otherwise (a differing or advanced roster).
	switch existing, ver, err := remote.GetRoster(); {
	case err != nil:
		return fmt.Errorf("check remote roster: %w", err)
	case existing == nil:
		if err := remote.CASRoster(0, rblob, 0); err != nil {
			return fmt.Errorf("publish genesis roster: %w", err)
		}
		published = true
	case ver == 0 && bytes.Equal(existing, rblob):
		// identical genesis already present -> no-op
	default:
		return fmt.Errorf("remote already has a roster (version %d); refusing to overwrite genesis", ver)
	}

	if published {
		fmt.Println("published genesis (keyfile + roster) to the server")
	} else {
		fmt.Println("genesis already present on the server; nothing to do")
	}
	return nil
}

// cmdLogin implements: encgit login --seed FILE <url> <username>
func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	seedPath := fs.String("seed", "", "path to the member seed file (the API token is stored next to it)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 || *seedPath == "" {
		return errors.New("usage: encgit login --seed FILE <url> <username>")
	}
	serverURL, username := rest[0], rest[1]
	if !isHTTPURL(serverURL) {
		return fmt.Errorf("url must be http(s)://...")
	}
	pw, err := readPassword()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	token, err := serverLogin(serverURL, username, pw)
	if err != nil {
		return err
	}
	if err := saveToken(*seedPath, serverURL, token); err != nil {
		return err
	}
	fmt.Printf("login ok; API token saved for %s\n", tokenKey(serverURL))
	return nil
}
