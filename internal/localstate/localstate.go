// Package localstate persists the client-side, per-remote state that the frozen
// format keeps locally: the §5.7 anti-rollback / anti-equivocation pin
// (last accepted version + manifest hash), plus a fetch optimization recording
// which pack ids are already in the local git object store.
//
// The (version, manifest_hash) pair is the security-relevant pin. imported_packs
// is NOT part of any security check — it only avoids re-downloading packs.
package localstate

import (
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
