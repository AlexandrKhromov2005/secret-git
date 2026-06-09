package server

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestBackoffSecondsGrowsAndCaps(t *testing.T) {
	base, max := time.Second, 60*time.Second
	if got := backoffSeconds(0, base, max); got != 0 {
		t.Fatalf("n=0 must have no window, got %d", got)
	}
	want := map[int64]int64{1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 60, 8: 60, 50: 60}
	for n, w := range want {
		if got := backoffSeconds(n, base, max); got != w {
			t.Errorf("backoffSeconds(%d) = %d, want %d", n, got, w)
		}
	}
}

// TestThrottleBackoffGrowsAndPersists: repeated failures on one key grow the window
// exponentially and cap at MAX_BACKOFF; the state is read back from SQLite.
func TestThrottleBackoffGrowsAndPersists(t *testing.T) {
	st := openTestStorage(t)
	base, max := time.Second, 60*time.Second
	now := int64(1_000_000)

	if err := st.throttleFail(now, "1.2.3.4", "bob", base, max); err != nil {
		t.Fatal(err)
	}
	bu, err := st.throttleStatus(now, "1.2.3.4", "bob", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if bu != now+1 {
		t.Fatalf("after 1 failure: blockedUntil=%d, want %d", bu, now+1)
	}

	if err := st.throttleFail(now, "1.2.3.4", "bob", base, max); err != nil {
		t.Fatal(err)
	}
	if bu, _ = st.throttleStatus(now, "1.2.3.4", "bob", 3600); bu != now+2 {
		t.Fatalf("after 2 failures: blockedUntil=%d, want %d", bu, now+2)
	}

	for i := 0; i < 12; i++ {
		if err := st.throttleFail(now, "1.2.3.4", "bob", base, max); err != nil {
			t.Fatal(err)
		}
	}
	if bu, _ = st.throttleStatus(now, "1.2.3.4", "bob", 3600); bu != now+60 {
		t.Fatalf("capped window: blockedUntil=%d, want %d", bu, now+60)
	}
}

// TestThrottleNoLockout: the window is finite — once it passes, the attempt is allowed
// again (a hard lockout would be a DoS on the victim).
func TestThrottleNoLockout(t *testing.T) {
	st := openTestStorage(t)
	base, max := time.Second, 60*time.Second
	now := int64(2_000_000)
	for i := 0; i < 12; i++ {
		if err := st.throttleFail(now, "ip", "user", base, max); err != nil {
			t.Fatal(err)
		}
	}
	if bu, _ := st.throttleStatus(now, "ip", "user", 3600); bu != now+60 {
		t.Fatalf("blockedUntil=%d, want %d", bu, now+60)
	}
	later := now + 61
	if bu, _ := st.throttleStatus(later, "ip", "user", 3600); bu > later {
		t.Fatalf("still blocked after the window: blockedUntil=%d, now=%d", bu, later)
	}
}

// TestThrottlePerIPIsolation: per-IP and per-user counters are keyed independently —
// failures on one (IP,user) do not block a different IP+user.
func TestThrottlePerIPIsolation(t *testing.T) {
	st := openTestStorage(t)
	base, max := time.Second, 60*time.Second
	now := int64(3_000_000)
	for i := 0; i < 5; i++ {
		if err := st.throttleFail(now, "10.0.0.1", "alice", base, max); err != nil {
			t.Fatal(err)
		}
	}
	// IP-A is blocked even for a fresh username (the IP scope blocks).
	if bu, _ := st.throttleStatus(now, "10.0.0.1", "fresh-user", 3600); bu <= now {
		t.Fatal("IP-A should be blocked by its own counter")
	}
	// A different IP with a different user is unaffected (counters do not merge).
	if bu, _ := st.throttleStatus(now, "10.0.0.2", "bob", 3600); bu > now {
		t.Fatalf("IP-B/user-B should not be blocked: blockedUntil=%d, now=%d", bu, now)
	}
}

// TestThrottleResetOnSuccess: a success clears BOTH scopes.
func TestThrottleResetOnSuccess(t *testing.T) {
	st := openTestStorage(t)
	base, max := time.Second, 60*time.Second
	now := int64(4_000_000)
	for i := 0; i < 2; i++ {
		if err := st.throttleFail(now, "ip", "user", base, max); err != nil {
			t.Fatal(err)
		}
	}
	if bu, _ := st.throttleStatus(now, "ip", "user", 3600); bu <= now {
		t.Fatal("expected an active window before reset")
	}
	if err := st.throttleReset("ip", "user"); err != nil {
		t.Fatal(err)
	}
	if bu, _ := st.throttleStatus(now, "ip", "user", 3600); bu > now {
		t.Fatalf("reset should clear the window: blockedUntil=%d", bu)
	}
	var c int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM login_throttle`).Scan(&c); err != nil {
		t.Fatal(err)
	}
	if c != 0 {
		t.Fatalf("rows remain after reset: %d", c)
	}
}

// TestThrottlePrune: rows whose window expired more than PRUNE_GRACE ago are deleted, so
// junk usernames/IPs cannot grow the table without bound.
func TestThrottlePrune(t *testing.T) {
	st := openTestStorage(t)
	base, max := time.Second, 60*time.Second
	t0 := int64(5_000_000)
	if err := st.throttleFail(t0, "stale-ip", "stale-user", base, max); err != nil { // window = t0+1
		t.Fatal(err)
	}
	grace := int64(10)
	later := t0 + 1 + grace + 5 // window expired well over PRUNE_GRACE ago
	if _, err := st.throttleStatus(later, "other-ip", "other-user", grace); err != nil {
		t.Fatal(err)
	}
	var c int
	if err := st.db.QueryRow(`SELECT COUNT(*) FROM login_throttle WHERE key IN ('stale-ip','stale-user')`).Scan(&c); err != nil {
		t.Fatal(err)
	}
	if c != 0 {
		t.Fatalf("stale rows not pruned: %d remain", c)
	}
}

// TestClientIPExtraction covers the ЧАСТЬ C antispoof rules: trust the proxy header only
// from a trusted source CIDR, take the rightmost token, and fail closed to RemoteAddr.
func TestClientIPExtraction(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	withProxy := Config{TrustedProxyCIDRs: trusted, ClientIPHeader: "X-Forwarded-For"}

	newReq := func(remoteAddr, xff string) *http.Request {
		r := httptest.NewRequest("POST", "/auth/login", nil)
		r.RemoteAddr = remoteAddr
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct {
		name       string
		cfg        Config
		remoteAddr string
		xff        string
		want       string
	}{
		{"no proxy config -> RemoteAddr", Config{}, "203.0.113.5:1234", "198.51.100.7", "203.0.113.5"},
		{"trusted proxy -> header", withProxy, "10.0.0.1:9", "198.51.100.7", "198.51.100.7"},
		{"trusted proxy -> rightmost token (client spoof on the left ignored)", withProxy, "10.0.0.1:9", "1.1.1.1, 198.51.100.7", "198.51.100.7"},
		{"untrusted source -> RemoteAddr (header ignored)", withProxy, "203.0.113.9:9", "198.51.100.7", "203.0.113.9"},
		{"trusted source, garbage header -> RemoteAddr", withProxy, "10.0.0.1:9", "not-an-ip", "10.0.0.1"},
		{"header set but no trusted CIDRs -> RemoteAddr (fail closed)", Config{ClientIPHeader: "X-Forwarded-For"}, "10.0.0.1:9", "198.51.100.7", "10.0.0.1"},
	}
	for _, c := range cases {
		if got := clientIP(newReq(c.remoteAddr, c.xff), c.cfg); got != c.want {
			t.Errorf("%s: clientIP = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestDecoyArgonParamsMatchProduction pins the load-bearing anti-enumeration invariant
// (ЧАСТЬ E): the login decoy's argon2id cost must equal what hashPassword actually emits.
// If production params/lengths ever drift from the decoy, timing diverges and enumeration
// reopens — this test fails first.
func TestDecoyArgonParamsMatchProduction(t *testing.T) {
	prodSalt, prodParams, prodHash, err := hashPassword("x")
	if err != nil {
		t.Fatal(err)
	}
	if decoyArgonParams != prodParams {
		t.Fatalf("decoy argon params %q != production %q (timing would diverge -> enumeration)", decoyArgonParams, prodParams)
	}
	decoySalt, err := hex.DecodeString(decoyArgonSaltHex)
	if err != nil {
		t.Fatal(err)
	}
	prodSaltB, err := hex.DecodeString(prodSalt)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoySalt) != len(prodSaltB) || len(decoySalt) != argonSaltLen {
		t.Fatalf("decoy salt len %d != production %d / argonSaltLen %d", len(decoySalt), len(prodSaltB), argonSaltLen)
	}
	decoyHash, err := hex.DecodeString(decoyArgonHashHex)
	if err != nil {
		t.Fatal(err)
	}
	prodHashB, err := hex.DecodeString(prodHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoyHash) != len(prodHashB) || len(decoyHash) != argonKeyLen {
		t.Fatalf("decoy hash len %d != production %d / argonKeyLen %d", len(decoyHash), len(prodHashB), argonKeyLen)
	}
}
