package server

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStorage(t *testing.T) *Storage {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenStorage(filepath.Join(dir, "meta.db"), filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestArgon2idRoundTrip(t *testing.T) {
	salt, params, hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if salt == "" || params == "" || hash == "" {
		t.Fatal("empty argon2 fields")
	}
	ok, err := verifyPassword("correct horse battery staple", salt, params, hash)
	if err != nil || !ok {
		t.Fatalf("correct password did not verify: ok=%v err=%v", ok, err)
	}
	bad, err := verifyPassword("wrong password", salt, params, hash)
	if err != nil {
		t.Fatal(err)
	}
	if bad {
		t.Fatal("wrong password verified")
	}
}

func TestBootstrapIsOneTimeAndHashed(t *testing.T) {
	st := openTestStorage(t)

	token, err := st.EnsureBootstrap()
	if err != nil || token == "" {
		t.Fatalf("ensure bootstrap: token=%q err=%v", token, err)
	}
	// Calling again before consumption must NOT mint a second token.
	again, err := st.EnsureBootstrap()
	if err != nil || again != "" {
		t.Fatalf("second EnsureBootstrap minted a token: %q", again)
	}
	// Only the hash is stored.
	var stored string
	if err := st.db.QueryRow(`SELECT token_hash FROM bootstrap`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Fatal("bootstrap token stored in plaintext")
	}
	if stored != hashToken(token) {
		t.Fatal("stored value is not SHA-256 of the token")
	}

	// First exchange succeeds.
	if err := st.consumeBootstrap(token, "admin", "pw"); err != nil {
		t.Fatalf("first bootstrap exchange failed: %v", err)
	}
	// Second exchange of the same token is rejected (single-use).
	if err := st.consumeBootstrap(token, "admin2", "pw"); !errors.Is(err, errBadToken) {
		t.Fatalf("second bootstrap exchange: want errBadToken, got %v", err)
	}
	// With an admin present, no new bootstrap token is minted.
	if tok, _ := st.EnsureBootstrap(); tok != "" {
		t.Fatal("bootstrap minted after admin exists")
	}
}

func TestInviteOneTimeExpiryAndBinding(t *testing.T) {
	st := openTestStorage(t)
	if err := st.createRepo("repoA"); err != nil {
		t.Fatal(err)
	}

	token, err := st.createInvite("repoA", RoleWriter, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.consumeInvite(token, "bob", "pw"); err != nil {
		t.Fatalf("redeem invite: %v", err)
	}
	// Account is bound to repoA with writer role.
	id, _, _, _, _, err := st.accountByUsername("bob")
	if err != nil {
		t.Fatal(err)
	}
	role, has, err := st.roleFor(id, "repoA")
	if err != nil || !has || role != RoleWriter {
		t.Fatalf("invite binding wrong: role=%v has=%v err=%v", role, has, err)
	}
	// One-time: the same invite cannot be redeemed again.
	if err := st.consumeInvite(token, "carol", "pw"); !errors.Is(err, errBadToken) {
		t.Fatalf("second redeem: want errBadToken, got %v", err)
	}

	// An expired invite is rejected.
	expired, err := st.createInvite("repoA", RoleReader, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.consumeInvite(expired, "dave", "pw"); !errors.Is(err, errUsedOrExpired) {
		t.Fatalf("expired invite: want errUsedOrExpired, got %v", err)
	}
}

func TestLoginAndTokenLifecycle(t *testing.T) {
	st := openTestStorage(t)
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "admin", "s3cret"); err != nil {
		t.Fatal(err)
	}

	apiToken, err := st.login("admin", "s3cret", time.Hour)
	if err != nil || apiToken == "" {
		t.Fatalf("login: %v", err)
	}
	acc, err := st.authenticate(apiToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !acc.isAdmin {
		t.Fatal("expected admin account")
	}
	// Wrong password does not log in.
	if _, err := st.login("admin", "wrong", time.Hour); !errors.Is(err, errBadToken) {
		t.Fatalf("wrong password login: want errBadToken, got %v", err)
	}
	// Unknown/garbage bearer token is rejected.
	if _, err := st.authenticate("not-a-real-token"); !errors.Is(err, errBadToken) {
		t.Fatalf("garbage token: want errBadToken, got %v", err)
	}
	// Expired token is rejected.
	expiredTok, err := st.login("admin", "s3cret", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.authenticate(expiredTok); !errors.Is(err, errUsedOrExpired) {
		t.Fatalf("expired token: want errUsedOrExpired, got %v", err)
	}
}
