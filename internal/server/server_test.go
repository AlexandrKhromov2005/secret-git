package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func makeServer(t *testing.T) (*httptest.Server, *Storage) {
	t.Helper()
	return makeServerCfg(t, DefaultConfig())
}

func makeServerCfg(t *testing.T, cfg Config) (*httptest.Server, *Storage) {
	t.Helper()
	st := openTestStorage(t)
	ts := httptest.NewServer(New(st, cfg).Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

// proxyTrustCfg trusts the loopback test client as a reverse proxy, so X-Forwarded-For
// drives the per-IP throttle key (lets a test vary the client IP).
func proxyTrustCfg() Config {
	c := DefaultConfig()
	c.TrustedProxyCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	c.ClientIPHeader = "X-Forwarded-For"
	return c
}

// loginReq posts to /auth/login and returns the live response (caller closes Body).
func loginReq(t *testing.T, ts *httptest.Server, username, password string) *http.Response {
	t.Helper()
	return loginReqIP(t, ts, username, password, "")
}

// loginReqIP posts to /auth/login, optionally setting X-Forwarded-For to clientIP.
func loginReqIP(t *testing.T, ts *httptest.Server, username, password, clientIP string) *http.Response {
	t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"}`
	req, err := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if clientIP != "" {
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// makeAccount creates an account with the given repo role and returns a login token.
func makeAccount(t *testing.T, st *Storage, username, repoID string, role Role) string {
	t.Helper()
	salt, params, hash, err := hashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	res, err := st.db.Exec(`INSERT INTO accounts(username, argon2_salt, argon2_params, argon2_hash, is_admin) VALUES(?,?,?,?,0)`,
		username, salt, params, hash)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if role != "" {
		if err := st.grantAccess(id, repoID, role); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := st.login(username, "pw", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func do(t *testing.T, ts *httptest.Server, method, path, token, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestAuthorizationMatrix(t *testing.T) {
	ts, st := makeServer(t)
	if err := st.createRepo("r1"); err != nil {
		t.Fatal(err)
	}
	if err := st.createRepo("r2"); err != nil {
		t.Fatal(err)
	}
	reader := makeAccount(t, st, "reader", "r1", RoleReader)
	writer := makeAccount(t, st, "writer", "r1", RoleWriter)
	outsider := makeAccount(t, st, "outsider", "r2", RoleWriter) // writer on r2, nothing on r1

	// content-hash of "x" for a valid PUT.
	hash := sha256Hex([]byte("x"))
	blobPath := "/repos/r1/blobs/" + hash

	cases := []struct {
		name, method, path, token, body string
		want                            int
	}{
		{"unauth GET manifest -> 401", "GET", "/repos/r1/manifest", "", "", 401},
		{"unauth PUT blob -> 401", "PUT", blobPath, "", "x", 401},
		{"reader GET manifest (none) -> 404", "GET", "/repos/r1/manifest", reader, "", 404},
		{"reader GET roster (none) -> 404", "GET", "/repos/r1/roster", reader, "", 404},
		{"reader PUT blob -> 403", "PUT", blobPath, reader, "x", 403},
		{"reader DELETE blob -> 403", "DELETE", blobPath, reader, "", 403},
		{"writer PUT blob -> 204", "PUT", blobPath, writer, "x", 204},
		{"writer GET blob -> 200", "GET", blobPath, writer, "", 200},
		{"writer DELETE blob -> 204", "DELETE", blobPath, writer, "", 204},
		{"r2 token on r1 -> 403", "GET", "/repos/r1/manifest", outsider, "", 403},
		{"r2 writer PUT on r1 -> 403", "PUT", blobPath, outsider, "x", 403},
	}
	for _, c := range cases {
		if got := do(t, ts, c.method, c.path, c.token, c.body); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// TestExpiredTokenRejectedHTTP: a real, hash-matching bearer token that has expired is
// rejected with 401 at the HTTP layer (B3 — expiry enforced on every request).
func TestExpiredTokenRejectedHTTP(t *testing.T) {
	ts, st := makeServer(t)
	if err := st.createRepo("r1"); err != nil {
		t.Fatal(err)
	}
	salt, params, hash, err := hashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	res, err := st.db.Exec(`INSERT INTO accounts(username, argon2_salt, argon2_params, argon2_hash, is_admin) VALUES(?,?,?,?,0)`,
		"bob", salt, params, hash)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	if err := st.grantAccess(id, "r1", RoleReader); err != nil {
		t.Fatal(err)
	}
	// A genuine token for bob, but already expired.
	expired, err := st.login("bob", "pw", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := do(t, ts, "GET", "/repos/r1/manifest", expired, ""); got != 401 {
		t.Fatalf("expired token: got %d, want 401", got)
	}
}

// postLogin posts credentials to /auth/login and returns the status and the raw body.
func postLogin(t *testing.T, ts *httptest.Server, username, password string) (int, string) {
	t.Helper()
	body := `{"username":"` + username + `","password":"` + password + `"}`
	resp, err := http.Post(ts.URL+"/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestLoginResponseIdenticalForUnknownAndWrong: the unknown-username and wrong-password
// responses must be byte-identical (status + body), so a caller cannot enumerate users
// (B5). The equivalent argon2id work is asserted separately in TestLoginNoUserEnumeration.
func TestLoginResponseIdenticalForUnknownAndWrong(t *testing.T) {
	ts, st := makeServer(t)
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "alice", "correct"); err != nil {
		t.Fatal(err)
	}

	wrongStatus, wrongBody := postLogin(t, ts, "alice", "wrong")
	// Both probes share the test client IP, so the first failure opens a per-IP backoff
	// window; clear it so the second probe is a genuine first-attempt credential check
	// (the 429 throttle response is exercised separately in the throttle tests).
	if _, err := st.db.Exec(`DELETE FROM login_throttle`); err != nil {
		t.Fatal(err)
	}
	unknownStatus, unknownBody := postLogin(t, ts, "ghost", "wrong")

	if wrongStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized {
		t.Fatalf("status: wrongPw=%d unknownUser=%d, want both 401", wrongStatus, unknownStatus)
	}
	if wrongBody != unknownBody {
		t.Fatalf("responses differ (enumeration): wrongPw=%q unknownUser=%q", wrongBody, unknownBody)
	}
}

// TestLoginThrottle429WithoutArgon2: a failed login opens a backoff window; a retry inside
// the window is rejected 429 + Retry-After WITHOUT running argon2id (the load-bearing
// invariant). argon2id invocations are counted through the seam.
func TestLoginThrottle429WithoutArgon2(t *testing.T) {
	ts, st := makeServer(t)
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "alice", "correct"); err != nil {
		t.Fatal(err)
	}

	var calls int
	orig := argon2IDKey
	argon2IDKey = func(p, s []byte, tt, m uint32, th uint8, k uint32) []byte {
		calls++
		return orig(p, s, tt, m, th, k)
	}
	defer func() { argon2IDKey = orig }()

	// First attempt: runs argon2id, fails, opens a window.
	calls = 0
	if r := loginReq(t, ts, "alice", "wrong"); r.StatusCode != http.StatusUnauthorized {
		r.Body.Close()
		t.Fatalf("first wrong login: got %d, want 401", r.StatusCode)
	} else {
		r.Body.Close()
	}
	if calls == 0 {
		t.Fatal("first attempt should have run argon2id")
	}

	// Within the window: 429 + Retry-After, and NO argon2id.
	calls = 0
	r := loginReq(t, ts, "alice", "wrong")
	defer r.Body.Close()
	if r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("within window: got %d, want 429", r.StatusCode)
	}
	if r.Header.Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
	if calls != 0 {
		t.Fatalf("argon2id ran during a 429 reject (DoS not closed): %d calls", calls)
	}
}

// TestLoginThrottlePerUserSymmetric: an unknown username is throttled IDENTICALLY to a
// known one. The client IP is varied per request (trusted proxy header) so the block can
// only come from the per-user scope — proving symmetry that would otherwise be an oracle.
func TestLoginThrottlePerUserSymmetric(t *testing.T) {
	ts, st := makeServerCfg(t, proxyTrustCfg())
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "alice", "correct"); err != nil {
		t.Fatal(err)
	}

	// Each probe uses its OWN fresh pair of client IPs, so the per-IP scope never blocks
	// and the second-attempt 429 can only come from the per-user scope.
	probe := func(user, ipA, ipB string) (int, int) {
		r1 := loginReqIP(t, ts, user, "wrong", ipA)
		s1 := r1.StatusCode
		r1.Body.Close()
		r2 := loginReqIP(t, ts, user, "wrong", ipB)
		s2 := r2.StatusCode
		r2.Body.Close()
		return s1, s2
	}

	knownFirst, knownSecond := probe("alice", "198.51.100.1", "198.51.100.2") // existing user
	ghostFirst, ghostSecond := probe("ghost", "203.0.113.1", "203.0.113.2")   // non-existent user

	if knownFirst != http.StatusUnauthorized || ghostFirst != http.StatusUnauthorized {
		t.Fatalf("first attempts: known=%d ghost=%d, want 401", knownFirst, ghostFirst)
	}
	if knownSecond != http.StatusTooManyRequests || ghostSecond != http.StatusTooManyRequests {
		t.Fatalf("per-user throttle not symmetric over existence: known=%d ghost=%d, want both 429", knownSecond, ghostSecond)
	}
}

// TestLoginThrottle429SymmetricOverExistence: the third anti-enumeration facet. With an
// EQUAL attempt history, a known user and a ghost that land in a per-user backoff window
// get an IDENTICAL 429 response — same status, same body, same Retry-After (within a small
// clock tolerance). per-IP is isolated by varying the client IP per request, so the block
// can only come from the per-user scope. A long backoff base makes the window robust.
// SECURITY-REVIEW: 429-in-window response is symmetric over username existence.
func TestLoginThrottle429SymmetricOverExistence(t *testing.T) {
	cfg := proxyTrustCfg()
	cfg.LoginBackoffBase = 30 * time.Second // one failure -> ~30s window, robustly in-window
	cfg.LoginBackoffMax = 60 * time.Second
	ts, st := makeServerCfg(t, cfg)
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "alice", "correct"); err != nil {
		t.Fatal(err)
	}

	// One failure from IP-A opens the per-user window; probe from a FRESH IP-B so only the
	// per-user scope can block, and capture the 429.
	probe := func(user, ipA, ipB string) (int, string, int) {
		loginReqIP(t, ts, user, "wrong", ipA).Body.Close()
		r := loginReqIP(t, ts, user, "wrong", ipB)
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		ra, _ := strconv.Atoi(r.Header.Get("Retry-After"))
		return r.StatusCode, string(body), ra
	}
	kCode, kBody, kRA := probe("alice", "198.51.100.1", "198.51.100.2") // existing user
	gCode, gBody, gRA := probe("ghost", "203.0.113.1", "203.0.113.2")   // non-existent user

	if kCode != http.StatusTooManyRequests || gCode != http.StatusTooManyRequests {
		t.Fatalf("status: known=%d ghost=%d, want both 429", kCode, gCode)
	}
	if kBody != gBody {
		t.Fatalf("429 body differs over existence (enumeration): known=%q ghost=%q", kBody, gBody)
	}
	if d := kRA - gRA; d < -2 || d > 2 {
		t.Fatalf("Retry-After differs beyond tolerance (enumeration): known=%d ghost=%d", kRA, gRA)
	}
}

// TestLoginThrottlePerIPIsolationHTTP: distinct client IPs do not share a counter, and a
// blocked IP blocks even a fresh username.
func TestLoginThrottlePerIPIsolationHTTP(t *testing.T) {
	ts, st := makeServerCfg(t, proxyTrustCfg())
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "alice", "correct"); err != nil {
		t.Fatal(err)
	}

	// Open a window for IP-A via user u1.
	loginReqIP(t, ts, "u1", "wrong", "198.51.100.10").Body.Close()

	// A different IP with a different user is not throttled.
	rB := loginReqIP(t, ts, "u2", "wrong", "198.51.100.20")
	codeB := rB.StatusCode
	rB.Body.Close()
	if codeB != http.StatusUnauthorized {
		t.Fatalf("different IP+user should not be throttled: got %d, want 401", codeB)
	}

	// IP-A is still blocked even for a brand-new username (IP scope).
	rA := loginReqIP(t, ts, "u3-fresh", "wrong", "198.51.100.10")
	codeA := rA.StatusCode
	rA.Body.Close()
	if codeA != http.StatusTooManyRequests {
		t.Fatalf("blocked IP should reject a fresh user: got %d, want 429", codeA)
	}
}

// TestLoginSemaphore503WithoutArgon2: with one argon2id slot and a short acquire timeout, a
// second concurrent login (while the first is mid-argon2id, before it has recorded any
// failure) gets 503 WITHOUT running argon2id, and concurrent argon2id never exceeds the cap.
func TestLoginSemaphore503WithoutArgon2(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConcurrentArgon2 = 1
	cfg.Argon2AcquireTimeout = 50 * time.Millisecond
	ts, st := makeServerCfg(t, cfg)
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "alice", "correct"); err != nil { // uses real argon2 (mock not yet installed)
		t.Fatal(err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var cur, max int
	orig := argon2IDKey
	argon2IDKey = func(p, s []byte, tt, m uint32, th uint8, k uint32) []byte {
		mu.Lock()
		cur++
		if cur > max {
			max = cur
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		cur--
		mu.Unlock()
		return orig(p, s, tt, m, th, k)
	}
	defer func() { argon2IDKey = orig }()

	// Request 1 grabs the only slot and blocks inside argon2id.
	done1 := make(chan int, 1)
	go func() {
		r := loginReq(t, ts, "alice", "wrong")
		done1 <- r.StatusCode
		r.Body.Close()
	}()
	<-entered // request 1 is inside argon2id, holding the slot (no failure recorded yet)

	// Request 2 cannot acquire a slot within the timeout -> 503, WITHOUT argon2id.
	r2 := loginReq(t, ts, "alice", "wrong")
	code2 := r2.StatusCode
	r2.Body.Close()
	if code2 != http.StatusServiceUnavailable {
		t.Fatalf("saturated server: got %d, want 503", code2)
	}

	close(release) // let request 1 finish
	<-done1

	mu.Lock()
	gotMax := max
	mu.Unlock()
	if gotMax > 1 {
		t.Fatalf("concurrent argon2id exceeded the cap: max=%d, want <=1", gotMax)
	}
}

func TestAdminEndpointsRequireAdmin(t *testing.T) {
	ts, st := makeServer(t)
	if err := st.createRepo("r1"); err != nil {
		t.Fatal(err)
	}
	nonAdmin := makeAccount(t, st, "joe", "r1", RoleWriter)

	if got := do(t, ts, "POST", "/repos", "", `{"repo_id":"r9"}`); got != 401 {
		t.Errorf("unauth create repo: got %d, want 401", got)
	}
	if got := do(t, ts, "POST", "/repos", nonAdmin, `{"repo_id":"r9"}`); got != 403 {
		t.Errorf("non-admin create repo: got %d, want 403", got)
	}
	if got := do(t, ts, "POST", "/repos/r1/invites", nonAdmin, `{"role":"reader"}`); got != 403 {
		t.Errorf("non-admin create invite: got %d, want 403", got)
	}

	// A real admin can.
	tok, _ := st.EnsureBootstrap()
	if err := st.consumeBootstrap(tok, "admin", "pw"); err != nil {
		t.Fatal(err)
	}
	adminToken, err := st.login("admin", "pw", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := do(t, ts, "POST", "/repos", adminToken, `{"repo_id":"r9"}`); got != 201 {
		t.Errorf("admin create repo: got %d, want 201", got)
	}
}
