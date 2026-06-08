// Command encgit is the Tier-1 CLI front-end for the push/fetch engine. It runs
// against a local directory store (the Tier-4 HTTP server is out of scope here).
//
// Subcommands:
//
//	encgit identity new   --seed FILE
//	encgit identity show  --seed FILE
//	encgit init           --store DIR --seed FILE
//	encgit push           --store DIR --seed FILE --repo-id HEX [--git DIR] [--state FILE] [refs...]
//	encgit fetch          --store DIR --seed FILE --repo-id HEX [--git DIR] [--state FILE]
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"encgit/internal/helper"
	"encgit/internal/identity"
	"encgit/internal/localstate"
	"encgit/internal/store/localfs"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "identity":
		err = cmdIdentity(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "push":
		err = cmdPush(os.Args[2:])
	case "fetch":
		err = cmdFetch(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `encgit — end-to-end encrypted git remote (Tier 1)

usage:
  encgit identity new   --seed FILE
  encgit identity show  --seed FILE
  encgit init           --store DIR --seed FILE
  encgit push           --store DIR --seed FILE --repo-id HEX [--git DIR] [--state FILE] [refs...]
  encgit fetch          --store DIR --seed FILE --repo-id HEX [--git DIR] [--state FILE]
`)
}

// --- seed file I/O (64 hex chars, 0600) ---

func loadSeed(path string) (*identity.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read seed: %w", err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode seed hex: %w", err)
	}
	if len(raw) != identity.SeedLen {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", identity.SeedLen, len(raw))
	}
	var seed [32]byte
	copy(seed[:], raw)
	return identity.FromSeed(seed)
}

func cmdIdentity(args []string) error {
	if len(args) < 1 {
		return errors.New("identity: expected 'new' or 'show'")
	}
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	seedPath := fs.String("seed", "", "path to the member seed file")
	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *seedPath == "" {
		return errors.New("identity: --seed is required")
	}

	switch sub {
	case "new":
		if _, err := os.Stat(*seedPath); err == nil {
			return fmt.Errorf("identity new: %s already exists; refusing to overwrite", *seedPath)
		}
		seed, err := identity.NewSeed()
		if err != nil {
			return err
		}
		if err := os.WriteFile(*seedPath, []byte(hex.EncodeToString(seed[:])+"\n"), 0o600); err != nil {
			return fmt.Errorf("write seed: %w", err)
		}
		id, err := identity.FromSeed(seed)
		if err != nil {
			return err
		}
		fmt.Printf("wrote seed to %s\nfingerprint: %s\n", *seedPath, id.FingerprintHex())
		return nil
	case "show":
		id, err := loadSeed(*seedPath)
		if err != nil {
			return err
		}
		pubX := id.PublicX25519()
		fmt.Printf("fingerprint:  %s\n", id.FingerprintHex())
		fmt.Printf("x25519 pub:   %x\n", pubX[:])
		fmt.Printf("ed25519 pub:  %x\n", id.VerifyKey())
		fmt.Printf("age recipient: %s\n", id.AgeRecipient())
		return nil
	default:
		return fmt.Errorf("identity: unknown subcommand %q", sub)
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	storeDir := fs.String("store", "", "path to the (local stub) store directory")
	seedPath := fs.String("seed", "", "path to the member seed file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *storeDir == "" || *seedPath == "" {
		return errors.New("init: --store and --seed are required")
	}
	id, err := loadSeed(*seedPath)
	if err != nil {
		return err
	}
	st, err := localfs.Open(*storeDir)
	if err != nil {
		return err
	}
	repoID, err := helper.Init(st, id)
	if err != nil {
		return err
	}
	fmt.Printf("initialized repo\nrepo_id: %s\n", repoID)
	fmt.Println("(share repo_id and the keyfile with members out of band; pass --repo-id on push/fetch)")
	return nil
}

// engineFlags is the shared flag set for push/fetch.
type engineFlags struct {
	storeDir, seedPath, repoID, gitDir, statePath string
}

func bindEngineFlags(fs *flag.FlagSet) *engineFlags {
	f := &engineFlags{}
	fs.StringVar(&f.storeDir, "store", "", "path to the (local stub) store directory")
	fs.StringVar(&f.seedPath, "seed", "", "path to the member seed file")
	fs.StringVar(&f.repoID, "repo-id", "", "repo_id (hex) from init")
	fs.StringVar(&f.gitDir, "git", ".", "path to the local git repository")
	fs.StringVar(&f.statePath, "state", "", "path to the local pin/state file (default <git>/.encgit/state.json)")
	return f
}

func (f *engineFlags) open() (*helper.Engine, error) {
	if f.storeDir == "" || f.seedPath == "" || f.repoID == "" {
		return nil, errors.New("--store, --seed and --repo-id are required")
	}
	id, err := loadSeed(f.seedPath)
	if err != nil {
		return nil, err
	}
	st, err := localfs.Open(f.storeDir)
	if err != nil {
		return nil, err
	}
	statePath := f.statePath
	if statePath == "" {
		statePath = filepath.Join(f.gitDir, ".encgit", "state.json")
	}
	state := localstate.NewStore(statePath)
	return helper.Open(f.gitDir, st, state, id, f.repoID)
}

func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	f := bindEngineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	eng, err := f.open()
	if err != nil {
		return err
	}
	if err := eng.Push(fs.Args()); err != nil {
		return err
	}
	fmt.Println("push ok")
	return nil
}

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	f := bindEngineFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	eng, err := f.open()
	if err != nil {
		return err
	}
	if err := eng.Fetch(); err != nil {
		return err
	}
	fmt.Println("fetch ok")
	return nil
}
