// Package store defines the server abstraction: an opaque, content-addressed blob
// store plus the single mutable manifest pointer with a CAS version, and the
// keyfile blob. It holds ONLY ciphertext and the integer CAS counter — never keys,
// ref names, repo_id, or any plaintext (§0, §1).
//
// In Tier 1 the only implementation is a local directory stub (subpackage
// localfs). Tier 4 adds an HTTP-backed implementation of this same interface
// without touching any format code.
package store

import "errors"

// ErrNotFound is returned when a requested blob or the keyfile is absent.
var ErrNotFound = errors.New("store: not found")

// ErrVersionConflict is returned by CASManifest when the stored version does not
// equal the caller's expected version (§5.6).
var ErrVersionConflict = errors.New("store: manifest version conflict")

// Store is the server interface. Implementations must be safe for the manifest
// swap to be serialized (§5.6); blob puts are additive and need no ordering.
type Store interface {
	// PutBlob stores data under its content address id (hex SHA-256 of data).
	// It is idempotent and must reject a mismatched id.
	PutBlob(id string, data []byte) error
	// GetBlob returns the blob for id, or ErrNotFound.
	GetBlob(id string) ([]byte, error)
	// HasBlob reports whether id is present.
	HasBlob(id string) (bool, error)

	// DeleteBlob removes a blob (used only by a full rekey, which drops the old
	// pack blobs). Deleting an absent blob is not an error.
	DeleteBlob(id string) error

	// GetManifest returns the current manifest blob and its CAS version. When no
	// manifest exists yet it returns (nil, 0, nil).
	GetManifest() (blob []byte, version uint64, err error)
	// CASManifest atomically swaps the manifest to (blob, newVersion) only if the
	// currently stored version equals expectedVersion, else ErrVersionConflict.
	CASManifest(expectedVersion uint64, blob []byte, newVersion uint64) error

	// GetRoster returns the current roster blob and its CAS version (Tier 3). When
	// no roster exists yet it returns (nil, 0, nil). Note: the genesis roster has
	// version 0, so "no roster" is signalled by a nil blob, not by version==0.
	GetRoster() (blob []byte, version uint64, err error)
	// CASRoster atomically swaps the roster to (blob, newVersion) only if the
	// currently stored version equals expectedVersion, else ErrVersionConflict.
	// Genesis creation uses expectedVersion==0 with no roster present.
	CASRoster(expectedVersion uint64, blob []byte, newVersion uint64) error

	// PutKeyfile stores the keyfile blob (repo key wrapped to members, §3).
	PutKeyfile(data []byte) error
	// GetKeyfile returns the keyfile blob, or ErrNotFound.
	GetKeyfile() ([]byte, error)
}
