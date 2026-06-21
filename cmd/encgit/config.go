package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// repoConfig holds the per-repo / per-user defaults that let push/fetch/clone run without
// repeating --store/--seed/--repo-id/--cacert. Every value is non-secret (a path, a URL, an
// id); the seed file these point to keeps its own 0600 protection.
type repoConfig struct {
	Store  string `json:"store,omitempty"`
	RepoID string `json:"repo_id,omitempty"`
	Seed   string `json:"seed,omitempty"`
	CACert string `json:"cacert,omitempty"`
}

// globalConfigPath is the user-global config (XDG-aware: ~/.config/encgit/config.json).
func globalConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "encgit", "config.json"), nil
}

// repoConfigPath is a repo-local config (<gitDir>/.encgit/config.json), a sibling of the
// existing state.json pin.
func repoConfigPath(gitDir string) string {
	return filepath.Join(gitDir, ".encgit", "config.json")
}

// readConfigFile loads one config file; a missing file is NOT an error (zero value).
func readConfigFile(path string) (repoConfig, error) {
	var c repoConfig
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("parse config %s: %w", path, err)
	}
	return c, nil
}

// loadConfig merges the user-global config (lowest precedence) with the per-repo config in
// gitDir (higher). An empty gitDir loads only the global config. Non-empty fields in the
// higher-precedence file win.
func loadConfig(gitDir string) (repoConfig, error) {
	var cfg repoConfig
	if p, err := globalConfigPath(); err == nil {
		g, err := readConfigFile(p)
		if err != nil {
			return cfg, err
		}
		overlay(&cfg, g)
	}
	if gitDir != "" {
		r, err := readConfigFile(repoConfigPath(gitDir))
		if err != nil {
			return cfg, err
		}
		overlay(&cfg, r)
	}
	return cfg, nil
}

// overlay copies the non-empty fields of src over dst (src wins).
func overlay(dst *repoConfig, src repoConfig) {
	if src.Store != "" {
		dst.Store = src.Store
	}
	if src.RepoID != "" {
		dst.RepoID = src.RepoID
	}
	if src.Seed != "" {
		dst.Seed = src.Seed
	}
	if src.CACert != "" {
		dst.CACert = src.CACert
	}
}

// saveConfig writes cfg to path (0600), creating the parent directory.
func saveConfig(path string, cfg repoConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// cmdConfig implements:
//
//	encgit config show [--git DIR]
//	encgit config set (--global | --git DIR) [--store URL] [--seed FILE] [--repo-id HEX] [--cacert FILE]
func cmdConfig(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: encgit config show [--git DIR] | encgit config set (--global|--git DIR) [--store URL] [--seed FILE] [--repo-id HEX] [--cacert FILE]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	global := fs.Bool("global", false, "operate on the user-global config (~/.config/encgit/config.json)")
	gitDir := fs.String("git", "", "operate on a repo-local config (<dir>/.encgit/config.json)")
	store := fs.String("store", "", "server URL or localfs dir")
	seed := fs.String("seed", "", "member seed file path")
	repoID := fs.String("repo-id", "", "repo_id (hex)")
	caCert := fs.String("cacert", "", "PEM file pinning the server's TLS cert")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	switch sub {
	case "show":
		cfg, err := loadConfig(*gitDir)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))
		return nil
	case "get":
		// `encgit config get [--git DIR] KEY` prints one resolved value (for scripting).
		cfg, err := loadConfig(*gitDir)
		if err != nil {
			return err
		}
		switch key := fs.Arg(0); key {
		case "store":
			fmt.Println(cfg.Store)
		case "repo_id", "repo-id":
			fmt.Println(cfg.RepoID)
		case "seed":
			fmt.Println(cfg.Seed)
		case "cacert":
			fmt.Println(cfg.CACert)
		case "":
			return errors.New("config get: KEY required (store|repo_id|seed|cacert)")
		default:
			return fmt.Errorf("config get: unknown key %q (want store|repo_id|seed|cacert)", key)
		}
		return nil
	case "set":
		var path string
		switch {
		case *global:
			p, err := globalConfigPath()
			if err != nil {
				return err
			}
			path = p
		case *gitDir != "":
			path = repoConfigPath(*gitDir)
		default:
			return errors.New("config set: specify --global or --git DIR")
		}
		cur, err := readConfigFile(path)
		if err != nil {
			return err
		}
		overlay(&cur, repoConfig{Store: *store, RepoID: *repoID, Seed: *seed, CACert: *caCert})
		if err := saveConfig(path, cur); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", path)
		return nil
	default:
		return fmt.Errorf("config: unknown subcommand %q (want show|get|set)", sub)
	}
}
