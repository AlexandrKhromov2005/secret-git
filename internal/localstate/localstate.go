// Package localstate persists the client-side, per-remote state that the frozen
// format keeps locally: the §5.7 anti-rollback / anti-equivocation pin
// (last accepted version + manifest hash), plus a fetch optimization recording
// which pack ids are already in the local git object store.
//
// The (version, manifest_hash) pair is the security-relevant pin. imported_packs
// is NOT part of any security check — it only avoids re-downloading packs.
package localstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// State is the persisted per-remote client state.
type State struct {
	Version       uint64   `json:"version"`        // last accepted manifest version (0 = none)
	ManifestHash  string   `json:"manifest_hash"`  // last accepted manifest hash (hex)
	ImportedPacks []string `json:"imported_packs"` // pack ids already in the local object store

	// Tier 3 roster pin (§1.4 anti-rollback) plus the locally-trusted roster.
	// RosterPinned distinguishes "genesis roster v0 accepted" (version 0) from
	// "no roster seen yet", since the genesis version is 0.
	RosterPinned  bool   `json:"roster_pinned"`
	RosterVersion uint64 `json:"roster_version"`
	RosterHash    string `json:"roster_hash"`
	TrustedRoster []byte `json:"trusted_roster"` // canonical plaintext of the last accepted roster

	// RepoKeys is the member-local cache of every repo key this client has held.
	// The keyfile only ever wraps the CURRENT key; after a minimal-rotation removal
	// (§3.2) older packs remain under older keys, so a continuing member must retain
	// the old keys to read pre-rotation packs or to run a full rekey. Fresh clones
	// only ever learn the current key (the documented minimal-rotation limitation).
	RepoKeys [][]byte `json:"repo_keys"`
}

// HasKey reports whether k is already in the local key cache.
func (st *State) HasKey(k []byte) bool {
	for _, e := range st.RepoKeys {
		if bytes.Equal(e, k) {
			return true
		}
	}
	return false
}

// AddKey records a repo key in the local cache (idempotent).
func (st *State) AddKey(k []byte) {
	if !st.HasKey(k) {
		st.RepoKeys = append(st.RepoKeys, append([]byte(nil), k...))
	}
}

// Store loads and saves State at a file path.
type Store struct {
	path string
}

// NewStore returns a State store backed by the given file path.
func NewStore(path string) *Store { return &Store{path: path} }

// Load returns the state and whether it existed. A missing file yields a zero
// State and exists=false (first use).
func (s *Store) Load() (State, bool, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("localstate: read: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return State{}, false, fmt.Errorf("localstate: parse: %w", err)
	}
	return st, true, nil
}

// Save writes the state atomically.
func (s *Store) Save(st State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("localstate: mkdir: %w", err)
	}
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("localstate: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("localstate: write: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("localstate: rename: %w", err)
	}
	return nil
}

// HasPack reports whether id is recorded as imported.
func (st *State) HasPack(id string) bool {
	for _, p := range st.ImportedPacks {
		if p == id {
			return true
		}
	}
	return false
}

// AddPack records id as imported (idempotent).
func (st *State) AddPack(id string) {
	if !st.HasPack(id) {
		st.ImportedPacks = append(st.ImportedPacks, id)
	}
}
