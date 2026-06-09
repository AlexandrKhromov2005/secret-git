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
