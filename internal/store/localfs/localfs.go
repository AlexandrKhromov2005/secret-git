// Package localfs is the Tier-1 local-directory implementation of store.Store.
// It is a stand-in for the (Tier 4) HTTP server: blobs are files named by their
// content hash, the manifest is a blob plus an integer version file, and the
// keyfile is a single blob. The manifest CAS swap is serialized with an OS file
// lock so concurrent pushers behave like they would against a real server.
package localfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"encgit/internal/store"
	"encgit/internal/util"
)

// Store is a directory-backed store.Store.
type Store struct {
	root string
}

var _ store.Store = (*Store)(nil)

// Open creates (if needed) and returns a localfs store rooted at dir.
func Open(dir string) (*Store, error) {
	for _, sub := range []string{"", "blobs", "manifest", "roster"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, fmt.Errorf("localfs: mkdir: %w", err)
		}
	}
	return &Store{root: dir}, nil
}

func (s *Store) blobPath(id string) string { return filepath.Join(s.root, "blobs", id) }

// writeAtomic writes data to path via a temp file + rename.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// PutBlob stores data under id, rejecting a mismatched content hash.
func (s *Store) PutBlob(id string, data []byte) error {
	if id == "" || strings.ContainsAny(id, "/\\") {
		return fmt.Errorf("localfs: invalid blob id %q", id)
	}
	if got := util.SHA256Hex(data); got != id {
		return fmt.Errorf("localfs: blob id mismatch: id=%s hash=%s", id, got)
	}
	path := s.blobPath(id)
	if _, err := os.Stat(path); err == nil {
		return nil // idempotent: already present
	}
	return writeAtomic(path, data)
}

// GetBlob returns the blob for id.
func (s *Store) GetBlob(id string) ([]byte, error) {
	data, err := os.ReadFile(s.blobPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("localfs: get blob: %w", err)
	}
	return data, nil
}

// HasBlob reports whether id is present.
func (s *Store) HasBlob(id string) (bool, error) {
	_, err := os.Stat(s.blobPath(id))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("localfs: has blob: %w", err)
}

func (s *Store) manifestBlobPath() string    { return filepath.Join(s.root, "manifest", "blob") }
func (s *Store) manifestVersionPath() string { return filepath.Join(s.root, "manifest", "version") }
func (s *Store) lockPath() string            { return filepath.Join(s.root, "manifest", "lock") }

func (s *Store) readVersion() (uint64, error) {
	data, err := os.ReadFile(s.manifestVersionPath())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("localfs: read version: %w", err)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("localfs: parse version: %w", err)
	}
	return v, nil
}

// GetManifest returns the current manifest blob and version, or (nil, 0, nil).
func (s *Store) GetManifest() ([]byte, uint64, error) {
	v, err := s.readVersion()
	if err != nil {
		return nil, 0, err
	}
	if v == 0 {
		return nil, 0, nil
	}
	blob, err := os.ReadFile(s.manifestBlobPath())
	if err != nil {
		return nil, 0, fmt.Errorf("localfs: read manifest: %w", err)
	}
	return blob, v, nil
}

// withLock runs fn while holding an exclusive OS lock on the manifest, so the CAS
// swap is serialized across processes (§5.6).
func (s *Store) withLock(fn func() error) error {
	f, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("localfs: open lock: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("localfs: flock: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

// CASManifest swaps the manifest only if the stored version equals expectedVersion.
func (s *Store) CASManifest(expectedVersion uint64, blob []byte, newVersion uint64) error {
	return s.withLock(func() error {
		cur, err := s.readVersion()
		if err != nil {
			return err
		}
		if cur != expectedVersion {
			return store.ErrVersionConflict
		}
		if err := writeAtomic(s.manifestBlobPath(), blob); err != nil {
			return fmt.Errorf("localfs: write manifest: %w", err)
		}
		if err := writeAtomic(s.manifestVersionPath(), []byte(strconv.FormatUint(newVersion, 10))); err != nil {
			return fmt.Errorf("localfs: write version: %w", err)
		}
		return nil
	})
}

// DeleteBlob removes a blob; absence is not an error.
func (s *Store) DeleteBlob(id string) error {
	if id == "" || strings.ContainsAny(id, "/\\") {
		return fmt.Errorf("localfs: invalid blob id %q", id)
	}
	err := os.Remove(s.blobPath(id))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("localfs: delete blob: %w", err)
	}
	return nil
}

func (s *Store) rosterBlobPath() string    { return filepath.Join(s.root, "roster", "blob") }
func (s *Store) rosterVersionPath() string { return filepath.Join(s.root, "roster", "version") }
func (s *Store) rosterLockPath() string    { return filepath.Join(s.root, "roster", "lock") }

func readVersionFile(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("localfs: parse version: %w", err)
	}
	return v, nil
}

// GetRoster returns the current roster blob and version. Unlike the manifest, the
// genesis roster has version 0, so "no roster" is detected by blob absence.
func (s *Store) GetRoster() ([]byte, uint64, error) {
	blob, err := os.ReadFile(s.rosterBlobPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil // no roster yet
	}
	if err != nil {
		return nil, 0, fmt.Errorf("localfs: read roster: %w", err)
	}
	v, err := readVersionFile(s.rosterVersionPath())
	if err != nil {
		return nil, 0, err
	}
	return blob, v, nil
}

// CASRoster swaps the roster only if the stored version equals expectedVersion.
// For genesis (no roster yet) the stored version reads as 0.
func (s *Store) CASRoster(expectedVersion uint64, blob []byte, newVersion uint64) error {
	f, err := os.OpenFile(s.rosterLockPath(), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("localfs: open roster lock: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("localfs: flock: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	// Current version: absent blob => no roster => 0.
	cur := uint64(0)
	if _, statErr := os.Stat(s.rosterBlobPath()); statErr == nil {
		if cur, err = readVersionFile(s.rosterVersionPath()); err != nil {
			return err
		}
	}
	if cur != expectedVersion {
		return store.ErrVersionConflict
	}
	if err := writeAtomic(s.rosterBlobPath(), blob); err != nil {
		return fmt.Errorf("localfs: write roster: %w", err)
	}
	if err := writeAtomic(s.rosterVersionPath(), []byte(strconv.FormatUint(newVersion, 10))); err != nil {
		return fmt.Errorf("localfs: write roster version: %w", err)
	}
	return nil
}

// PutKeyfile stores the keyfile blob.
func (s *Store) PutKeyfile(data []byte) error {
	return writeAtomic(filepath.Join(s.root, "keyfile"), data)
}

// GetKeyfile returns the keyfile blob.
func (s *Store) GetKeyfile() ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.root, "keyfile"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("localfs: get keyfile: %w", err)
	}
	return data, nil
}
