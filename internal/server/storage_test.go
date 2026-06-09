package server

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
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

	// An expired invite is rejected. Used/expired/unknown collapse to one generic
	// rejection (errBadToken) — see consumeInvite (ЧАСТЬ A: единый ответ, no oracle).
	expired, err := st.createInvite("repoA", RoleReader, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.consumeInvite(expired, "dave", "pw"); !errors.Is(err, errBadToken) {
		t.Fatalf("expired invite: want errBadToken, got %v", err)
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

// countSuccesses returns how many of the errors are nil.
func countSuccesses(errs []error) int {
	n := 0
	for _, e := range errs {
		if e == nil {
			n++
		}
	}
	return n
}

// TestConcurrentBootstrapConsumeOneWinner models the check-and-mark race: many
// goroutines exchange the SAME bootstrap token at once. The atomic single-use claim
// must admit exactly one (one admin), the rest rejected. Distinct usernames isolate the
// token's single-use guarantee from any account UNIQUE collision.
func TestConcurrentBootstrapConsumeOneWinner(t *testing.T) {
	st := openTestStorage(t)
	tok, err := st.EnsureBootstrap()
	if err != nil || tok == "" {
		t.Fatalf("ensure bootstrap: token=%q err=%v", tok, err)
	}

	const n = 8
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = st.consumeBootstrap(tok, fmt.Sprintf("admin%d", i), "pw")
		}(i)
	}
	close(start)
	wg.Wait()

	if got := countSuccesses(errs); got != 1 {
		t.Fatalf("concurrent bootstrap consume: want exactly 1 success, got %d (%v)", got, errs)
	}
	admins, err := st.adminCount()
	if err != nil {
		t.Fatal(err)
	}
	if admins != 1 {
		t.Fatalf("want exactly 1 admin after the race, got %d", admins)
	}
}

// TestConcurrentInviteConsumeOneWinner is the invite analogue: many goroutines redeem
// the SAME invite at once; exactly one account is created.
func TestConcurrentInviteConsumeOneWinner(t *testing.T) {
	st := openTestStorage(t)
	if err := st.createRepo("repoA"); err != nil {
		t.Fatal(err)
	}
	tok, err := st.createInvite("repoA", RoleWriter, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	const n = 8
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = st.consumeInvite(tok, fmt.Sprintf("user%d", i), "pw")
		}(i)
	}
	close(start)
	wg.Wait()

	if got := countSuccesses(errs); got != 1 {
		t.Fatalf("concurrent invite consume: want exactly 1 success, got %d (%v)", got, errs)
	}
	var accounts int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&accounts); err != nil {
		t.Fatal(err)
	}
	if accounts != 1 {
		t.Fatalf("want exactly 1 account created after the race, got %d", accounts)
	}
}

// TestInviteBindingIsServerControlled: the (repo_id, role) binding comes from the invite
// row, not from the redeemer — a reader invite yields exactly reader on exactly its repo,
// and grants nothing on a different repo (cannot be retargeted or escalated).
func TestInviteBindingIsServerControlled(t *testing.T) {
	st := openTestStorage(t)
	if err := st.createRepo("repoA"); err != nil {
		t.Fatal(err)
	}
	if err := st.createRepo("repoB"); err != nil {
		t.Fatal(err)
	}
	tok, err := st.createInvite("repoA", RoleReader, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.consumeInvite(tok, "eve", "pw"); err != nil {
		t.Fatal(err)
	}
	id, _, _, _, _, err := st.accountByUsername("eve")
	if err != nil {
		t.Fatal(err)
	}
	role, has, err := st.roleFor(id, "repoA")
	if err != nil || !has || role != RoleReader {
		t.Fatalf("repoA binding: role=%v has=%v err=%v (want reader, no escalation)", role, has, err)
	}
	if _, has, err := st.roleFor(id, "repoB"); err != nil || has {
		t.Fatalf("repoB access leaked: has=%v err=%v (invite must not retarget)", has, err)
	}
}

// TestLoginNoUserEnumeration: an unknown username and a wrong password must both return
// the same generic rejection AND perform the same argon2id work (the decoy). argon2id is
// counted through the argon2IDKey seam — timing is never asserted (flaky).
func TestLoginNoUserEnumeration(t *testing.T) {
	st := openTestStorage(t)
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "alice", "correct"); err != nil {
		t.Fatal(err)
	}

	var calls int
	orig := argon2IDKey
	argon2IDKey = func(password, salt []byte, time, mem uint32, threads uint8, keyLen uint32) []byte {
		calls++
		return orig(password, salt, time, mem, threads, keyLen)
	}
	defer func() { argon2IDKey = orig }()

	calls = 0
	if _, err := st.login("alice", "wrong", time.Hour); !errors.Is(err, errBadToken) {
		t.Fatalf("wrong password: want errBadToken, got %v", err)
	}
	wrongPwCalls := calls

	calls = 0
	if _, err := st.login("ghost", "whatever", time.Hour); !errors.Is(err, errBadToken) {
		t.Fatalf("unknown user: want errBadToken, got %v", err)
	}
	unknownCalls := calls

	if wrongPwCalls == 0 || unknownCalls == 0 {
		t.Fatalf("argon2id must run in both branches: wrongPw=%d unknownUser=%d", wrongPwCalls, unknownCalls)
	}
	if wrongPwCalls != unknownCalls {
		t.Fatalf("argon2id work differs between branches (enumeration oracle): wrongPw=%d unknownUser=%d", wrongPwCalls, unknownCalls)
	}
}
