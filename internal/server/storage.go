package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Role is a per-repo access role (deny-by-default; see the access matrix).
type Role string

const (
	RoleReader Role = "reader"
	RoleWriter Role = "writer"
)

// Server-side sentinel errors (mapped to HTTP status codes by the handlers).
var (
	errConflict      = errors.New("server: version conflict")   // -> 412
	errNotFound      = errors.New("server: not found")          // -> 404
	errBadHash       = errors.New("server: blob hash mismatch") // -> 400
	errUsedOrExpired = errors.New("server: token used or expired")
	errBadToken      = errors.New("server: bad token")
	errLastAdmin     = errors.New("server: cannot disable the last admin") // -> 409
)

// Storage bundles the SQLite metadata DB and the on-disk blob directory. Manifest
// and roster blobs live INLINE in SQLite so their CAS is a single atomic UPDATE;
// packs and the keyfile are files on disk per repo.
type Storage struct {
	db      *sql.DB
	blobDir string
}

// OpenStorage opens (and migrates) the SQLite DB at dbPath and roots blobs at blobDir.
func OpenStorage(dbPath, blobDir string) (*Storage, error) {
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		return nil, fmt.Errorf("server: mkdir blobdir: %w", err)
	}
	dsn := "file:" + dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("server: open db: %w", err)
	}
	// Serialize DB access: simplest correct behavior for CAS under concurrency.
	db.SetMaxOpenConns(1)
	s := &Storage{db: db, blobDir: blobDir}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the DB.
func (s *Storage) Close() error { return s.db.Close() }

func (s *Storage) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS accounts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  argon2_salt   TEXT NOT NULL,
  argon2_params TEXT NOT NULL,
  argon2_hash   TEXT NOT NULL,
  is_admin      INTEGER NOT NULL DEFAULT 0,
  disabled      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS repos (
  repo_id    TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS repo_access (
  account_id INTEGER NOT NULL,
  repo_id    TEXT NOT NULL,
  role       TEXT NOT NULL,
  PRIMARY KEY (account_id, repo_id)
);
CREATE TABLE IF NOT EXISTS invites (
  token_hash TEXT PRIMARY KEY,
  repo_id    TEXT NOT NULL,
  role       TEXT NOT NULL,
  expiry     INTEGER NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_tokens (
  token_hash TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL,
  expiry     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bootstrap (
  token_hash TEXT NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS manifest_state (
  repo_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  blob    BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS roster_state (
  repo_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  blob    BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS login_throttle (
  scope        TEXT NOT NULL,
  key          TEXT NOT NULL,
  fail_count   INTEGER NOT NULL,
  window_until INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (scope, key)
);`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("server: migrate: %w", err)
	}
	// Forward-migrate a DB created before account disabling existed: CREATE TABLE IF NOT
	// EXISTS never adds a column to a pre-existing table, so add it explicitly (idempotent).
	if err := s.addColumnIfMissing("accounts", "disabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	return nil
}

// addColumnIfMissing adds column (with the given SQL declaration) to table only when it
// is not already present, so existing databases migrate forward without data loss. table
// is a trusted compile-time constant (never user input).
func (s *Storage) addColumnIfMissing(table, column, decl string) error {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('` + table + `')`)
	if err != nil {
		return fmt.Errorf("server: inspect %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == column {
			return rows.Err() // already present
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, decl)); err != nil {
		return fmt.Errorf("server: add column %s.%s: %w", table, column, err)
	}
	return nil
}

// --- bootstrap ---

type account struct {
	id      int64
	isAdmin bool
}

// adminCount returns the number of admin accounts.
func (s *Storage) adminCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM accounts WHERE is_admin=1`).Scan(&n)
	return n, err
}

// EnsureBootstrap, if there are no admins and no unused bootstrap row, generates a
// one-time bootstrap token, stores ONLY its SHA-256, and returns the plaintext token
// (to be printed once). If a bootstrap already exists or an admin exists, returns "".
// SECURITY-REVIEW: bootstrap token is CSPRNG 256-bit; only its hash is stored; single-use.
func (s *Storage) EnsureBootstrap() (string, error) {
	admins, err := s.adminCount()
	if err != nil {
		return "", err
	}
	if admins > 0 {
		return "", nil
	}
	var existing int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM bootstrap WHERE used=0`).Scan(&existing); err != nil {
		return "", err
	}
	if existing > 0 {
		return "", nil // a live bootstrap token already exists
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`INSERT INTO bootstrap(token_hash, used) VALUES(?, 0)`, hashToken(token)); err != nil {
		return "", err
	}
	return token, nil
}

// consumeBootstrap verifies a bootstrap token and, on success, creates the first
// admin account and marks the token used — all in one transaction.
// SECURITY-REVIEW: atomic single-use bootstrap. The token is claimed by a guarded
// UPDATE (used=0) requiring exactly one affected row; a SELECT-then-UPDATE would let two
// concurrent exchanges of the same token both succeed (two admins). The claim precedes
// the account INSERT inside one transaction, so a failed INSERT rolls back the claim and
// the token is not burned.
func (s *Storage) consumeBootstrap(token, username, password string) error {
	salt, params, hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	th := hashToken(token)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`UPDATE bootstrap SET used=1 WHERE token_hash=? AND used=0`, th)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errBadToken // unknown or already-used token
	}
	if _, err := tx.Exec(`INSERT INTO accounts(username, argon2_salt, argon2_params, argon2_hash, is_admin) VALUES(?,?,?,?,1)`,
		username, salt, params, hash); err != nil {
		return err
	}
	return tx.Commit()
}

// --- accounts / login ---

func (s *Storage) accountByUsername(username string) (id int64, salt, params, hash string, isAdmin, disabled bool, err error) {
	var adm, dis int
	row := s.db.QueryRow(`SELECT id, argon2_salt, argon2_params, argon2_hash, is_admin, disabled FROM accounts WHERE username=?`, username)
	if err = row.Scan(&id, &salt, &params, &hash, &adm, &dis); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = errNotFound
		}
		return
	}
	return id, salt, params, hash, adm == 1, dis == 1, nil
}

// login verifies the password and issues an API token (returns the plaintext token
// once; stores only its hash). SECURITY-REVIEW: API token CSPRNG, hash-only, expiry.
func (s *Storage) login(username, password string, ttl time.Duration) (string, error) {
	id, salt, params, hash, _, disabled, err := s.accountByUsername(username)
	if err != nil {
		if errors.Is(err, errNotFound) {
			// SECURITY-REVIEW: anti-enumeration — run an equivalent-cost argon2id pass for
			// an unknown username so login timing is indistinguishable from a wrong password,
			// then return the same generic rejection (handler renders both as 401
			// "invalid credentials"). No early exit that would skip argon2id.
			_, _ = verifyPassword(password, decoyArgonSaltHex, decoyArgonParams, decoyArgonHashHex)
			return "", errBadToken
		}
		return "", err
	}
	ok, err := verifyPassword(password, salt, params, hash)
	if err != nil {
		return "", err
	}
	// SECURITY-REVIEW: a disabled account is rejected like a wrong password — the SAME
	// generic errBadToken (-> 401), AFTER the argon2id verify — so the disabled state is not
	// a timing/enumeration oracle. A disabled account also has no live tokens (disable
	// deletes them), so it cannot authenticate or mint a new one until re-enabled.
	if !ok || disabled {
		return "", errBadToken
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`INSERT INTO api_tokens(token_hash, account_id, expiry) VALUES(?,?,?)`,
		hashToken(token), id, time.Now().Add(ttl).Unix()); err != nil {
		return "", err
	}
	return token, nil
}

// authenticate resolves a bearer token to an account, enforcing expiry. The lookup
// is by SHA-256(token); the comparison is constant-time.
// SECURITY-REVIEW: API token lookup by hash, constant-time, expiry-checked.
func (s *Storage) authenticate(token string) (account, error) {
	th := hashToken(token)
	var (
		acc    account
		stored string
		exp    int64
	)
	row := s.db.QueryRow(`SELECT t.token_hash, t.account_id, t.expiry, a.is_admin, a.disabled
		FROM api_tokens t JOIN accounts a ON a.id=t.account_id WHERE t.token_hash=?`, th)
	var adm, dis int
	if err := row.Scan(&stored, &acc.id, &exp, &adm, &dis); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return account{}, errBadToken
		}
		return account{}, err
	}
	if !constantTimeEqualHex(stored, th) {
		return account{}, errBadToken
	}
	// SECURITY-REVIEW: a disabled account's tokens are invalid even before expiry — this is
	// the revocation check. disableAccount also deletes the rows, so this is defense in depth
	// against any token created in a race with the disable.
	if dis == 1 {
		return account{}, errBadToken
	}
	if time.Now().Unix() >= exp {
		return account{}, errUsedOrExpired
	}
	acc.isAdmin = adm == 1
	return acc, nil
}

// disableAccount disables an account AND deletes all of its API tokens, so every live
// token is revoked immediately and the account can neither authenticate nor log in until
// re-enabled. It refuses to disable the last enabled admin (which would lock out all admin
// operations). Unknown username -> errNotFound; disabling an already-disabled account is a
// no-op (and skips the last-admin guard, which only fires on an enabled admin).
// SECURITY-REVIEW: revocation = disabled flag + delete api_tokens, in one transaction.
func (s *Storage) disableAccount(username string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var (
		id            int64
		isAdmin, disV int
	)
	err = tx.QueryRow(`SELECT id, is_admin, disabled FROM accounts WHERE username=?`, username).Scan(&id, &isAdmin, &disV)
	if errors.Is(err, sql.ErrNoRows) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if isAdmin == 1 && disV == 0 {
		var otherAdmins int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM accounts WHERE is_admin=1 AND disabled=0 AND id<>?`, id).Scan(&otherAdmins); err != nil {
			return err
		}
		if otherAdmins == 0 {
			return errLastAdmin
		}
	}
	if _, err := tx.Exec(`UPDATE accounts SET disabled=1 WHERE id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM api_tokens WHERE account_id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// enableAccount clears the disabled flag. The user must log in again for a fresh token
// (disable deleted the old ones). Unknown username -> errNotFound.
func (s *Storage) enableAccount(username string) error {
	res, err := s.db.Exec(`UPDATE accounts SET disabled=0 WHERE username=?`, username)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotFound
	}
	return nil
}

// --- repos / access / invites ---

func (s *Storage) createRepo(repoID string) error {
	_, err := s.db.Exec(`INSERT INTO repos(repo_id, created_at) VALUES(?,?)`, repoID, time.Now().Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("server: repo already exists")
	}
	return err
}

func (s *Storage) repoExists(repoID string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM repos WHERE repo_id=?`, repoID).Scan(&n)
	return n > 0, err
}

func (s *Storage) grantAccess(accountID int64, repoID string, role Role) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO repo_access(account_id, repo_id, role) VALUES(?,?,?)`,
		accountID, repoID, string(role))
	return err
}

// roleFor returns the account's role for a repo, or ("", false) if none. Admin status
// does NOT imply data access (orthogonality): admins still need a repo-scoped role.
func (s *Storage) roleFor(accountID int64, repoID string) (Role, bool, error) {
	var r string
	err := s.db.QueryRow(`SELECT role FROM repo_access WHERE account_id=? AND repo_id=?`, accountID, repoID).Scan(&r)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return Role(r), true, nil
}

// createInvite issues a one-time, expiring invite bound to repo_id+role. Returns the
// plaintext token once; stores only its hash.
// SECURITY-REVIEW: invite single-use, expiry, bound to repo_id+role.
func (s *Storage) createInvite(repoID string, role Role, ttl time.Duration) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(`INSERT INTO invites(token_hash, repo_id, role, expiry, used) VALUES(?,?,?,?,0)`,
		hashToken(token), repoID, string(role), time.Now().Add(ttl).Unix()); err != nil {
		return "", err
	}
	return token, nil
}

// consumeInvite redeems an invite to create a new account bound to its repo_id+role,
// marking the invite used — all in one transaction.
// SECURITY-REVIEW: atomic single-use + expiry. The invite is claimed by a guarded UPDATE
// (used=0 AND not expired) requiring exactly one affected row; used/expired/unknown all
// collapse to the same RowsAffected==0 rejection (errBadToken — a single generic outcome,
// no oracle). A SELECT-then-UPDATE would let two concurrent redemptions of one invite both
// create an account. The (repo_id, role) binding is read from the now-claimed row inside
// the same transaction, so the redeemer cannot choose the repo or escalate the role; a
// failed account/binding INSERT rolls the claim back and the invite is not burned.
func (s *Storage) consumeInvite(token, username, password string) error {
	salt, params, hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	th := hashToken(token)
	now := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`UPDATE invites SET used=1 WHERE token_hash=? AND used=0 AND expiry > ?`, th, now)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errBadToken // unknown, already-used, or expired
	}
	var repoID, role string
	if err := tx.QueryRow(`SELECT repo_id, role FROM invites WHERE token_hash=?`, th).Scan(&repoID, &role); err != nil {
		return err
	}
	ins, err := tx.Exec(`INSERT INTO accounts(username, argon2_salt, argon2_params, argon2_hash, is_admin) VALUES(?,?,?,?,0)`,
		username, salt, params, hash)
	if err != nil {
		return err
	}
	accID, err := ins.LastInsertId()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO repo_access(account_id, repo_id, role) VALUES(?,?,?)`, accID, repoID, role); err != nil {
		return err
	}
	return tx.Commit()
}

// --- manifest / roster CAS (inline blobs, atomic) ---

// getManifest returns the manifest blob + version, or (nil,0) when none.
func (s *Storage) getManifest(repoID string) ([]byte, uint64, error) {
	var (
		blob []byte
		ver  int64
	)
	err := s.db.QueryRow(`SELECT version, blob FROM manifest_state WHERE repo_id=?`, repoID).Scan(&ver, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	return blob, uint64(ver), nil
}

// casManifest swaps the manifest iff the current version == expected, setting the new
// version to expected+1 (the first manifest is version 1). Returns the new version or
// errConflict. Single atomic transaction.
func (s *Storage) casManifest(repoID string, expected uint64, blob []byte) (uint64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cur int64
	err = tx.QueryRow(`SELECT version FROM manifest_state WHERE repo_id=?`, repoID).Scan(&cur)
	if errors.Is(err, sql.ErrNoRows) {
		cur = 0
	} else if err != nil {
		return 0, err
	}
	if uint64(cur) != expected {
		return 0, errConflict
	}
	newVer := expected + 1
	if _, err := tx.Exec(`INSERT INTO manifest_state(repo_id, version, blob) VALUES(?,?,?)
		ON CONFLICT(repo_id) DO UPDATE SET version=excluded.version, blob=excluded.blob`,
		repoID, int64(newVer), blob); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return newVer, nil
}

// getRoster returns the roster blob + version, or (nil,0) when none. NOTE: a row with
// version 0 is the EXISTING genesis roster; absence (no row) is "none".
func (s *Storage) getRoster(repoID string) ([]byte, uint64, bool, error) {
	var (
		blob []byte
		ver  int64
	)
	err := s.db.QueryRow(`SELECT version, blob FROM roster_state WHERE repo_id=?`, repoID).Scan(&ver, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	return blob, uint64(ver), true, nil
}

// casRoster mirrors localfs CASRoster exactly: a missing roster reads as version 0,
// so genesis is (expected=0, newVersion=0) and the first change is (expected=0,
// newVersion=1). The new version is supplied explicitly by the caller. errConflict on
// mismatch. Single atomic transaction.
func (s *Storage) casRoster(repoID string, expected, newVersion uint64, blob []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cur int64
	err = tx.QueryRow(`SELECT version FROM roster_state WHERE repo_id=?`, repoID).Scan(&cur)
	hasRow := true
	if errors.Is(err, sql.ErrNoRows) {
		cur, hasRow = 0, false
	} else if err != nil {
		return err
	}
	if uint64(cur) != expected {
		return errConflict
	}
	_ = hasRow
	if _, err := tx.Exec(`INSERT INTO roster_state(repo_id, version, blob) VALUES(?,?,?)
		ON CONFLICT(repo_id) DO UPDATE SET version=excluded.version, blob=excluded.blob`,
		repoID, int64(newVersion), blob); err != nil {
		return err
	}
	return tx.Commit()
}

// --- blobs / keyfile (files on disk per repo) ---

func (s *Storage) repoBlobDir(repoID string) string { return filepath.Join(s.blobDir, repoID) }

func safeName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "/\\.") && len(name) <= 128
}

// putBlob stores a content-addressed blob; it verifies the hash (content-addressing
// integrity — NOT content understanding) and is idempotent.
func (s *Storage) putBlob(repoID, hash string, data []byte) error {
	if !safeName(repoID) || !safeName(hash) {
		return errNotFound
	}
	if got := sha256Hex(data); got != hash {
		return errBadHash
	}
	dir := s.repoBlobDir(repoID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, hash)
	if _, err := os.Stat(path); err == nil {
		return nil // idempotent
	}
	return writeFileAtomic(path, data)
}

func (s *Storage) getBlob(repoID, hash string) ([]byte, error) {
	if !safeName(repoID) || !safeName(hash) {
		return nil, errNotFound
	}
	data, err := os.ReadFile(filepath.Join(s.repoBlobDir(repoID), hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNotFound
	}
	return data, err
}

func (s *Storage) hasBlob(repoID, hash string) (bool, error) {
	if !safeName(repoID) || !safeName(hash) {
		return false, nil
	}
	_, err := os.Stat(filepath.Join(s.repoBlobDir(repoID), hash))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// deleteBlob removes a content-addressed blob; absence is not an error.
func (s *Storage) deleteBlob(repoID, hash string) error {
	if !safeName(repoID) || !safeName(hash) {
		return nil
	}
	err := os.Remove(filepath.Join(s.repoBlobDir(repoID), hash))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Storage) keyfilePath(repoID string) string {
	return filepath.Join(s.repoBlobDir(repoID), "keyfile")
}

func (s *Storage) putKeyfile(repoID string, data []byte) error {
	if !safeName(repoID) {
		return errNotFound
	}
	if err := os.MkdirAll(s.repoBlobDir(repoID), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(s.keyfilePath(repoID), data)
}

func (s *Storage) getKeyfile(repoID string) ([]byte, error) {
	if !safeName(repoID) {
		return nil, errNotFound
	}
	data, err := os.ReadFile(s.keyfilePath(repoID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errNotFound
	}
	return data, err
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
