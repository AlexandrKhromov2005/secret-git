package server

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// This file adds the /auth/login rate-limiting layer: a persistent per-IP + per-username
// exponential backoff (against brute force and flooding) and an in-process limiter on
// concurrent argon2id executions (a direct cap on peak login memory). Both sit IN FRONT of
// argon2id; the cheap rejections (429 inside a window, 503 when saturated) must happen
// BEFORE any argon2id work — that is the load-bearing invariant. Neither relaxes the
// frozen anti-enumeration behavior: the per-username counter is kept for ANY presented
// username, existing or not, and the argon2id semaphore wraps both the real verify and the
// decoy. See docs/FORMAT-SPEC-TIER4.md.

// backoffSeconds returns the backoff window (whole seconds) for the n-th consecutive
// failure on a key: min(MAX_BACKOFF, BASE * 2^(n-1)) for n>=1, and 0 for n<=0 (a fresh key,
// or one just reset by success, has no window). The window is always FINITE and capped, so
// this is a backoff, never a hard lockout — a lockout by attacker-controlled username would
// itself be a DoS on the victim.
// SECURITY-REVIEW: exponential backoff with a finite ceiling (no hard lockout).
func backoffSeconds(n int64, base, max time.Duration) int64 {
	if n < 1 {
		return 0
	}
	b := base
	for i := int64(1); i < n; i++ {
		b *= 2
		if b >= max { // early exit also prevents overflow for large n
			b = max
			break
		}
	}
	if b > max {
		b = max
	}
	return int64(b / time.Second)
}

// clientIP returns the IP used as the per-IP throttle key. It trusts cfg.ClientIPHeader
// ONLY when the connection's own source address (host of r.RemoteAddr) is inside one of
// cfg.TrustedProxyCIDRs — trust is bound to the unspoofable connection address, NOT to a
// flag. When trusted, it takes the RIGHTMOST header token (the value the trusted proxy
// itself appended; left tokens of X-Forwarded-For are client-controlled). Otherwise, or on
// any parse failure / missing config, it falls back to r.RemoteAddr's host (fail-closed).
// SECURITY-REVIEW: client IP from a trusted proxy header; antispoof (CIDR-gated, rightmost,
// silent fallback to RemoteAddr).
func clientIP(r *http.Request, cfg Config) string {
	remote := remoteHost(r.RemoteAddr)
	if cfg.ClientIPHeader == "" || len(cfg.TrustedProxyCIDRs) == 0 {
		return remote
	}
	ra, err := netip.ParseAddr(remote)
	if err != nil || !addrInAny(ra, cfg.TrustedProxyCIDRs) {
		return remote // connection is not from a trusted proxy
	}
	hv := r.Header.Get(cfg.ClientIPHeader)
	if hv == "" {
		return remote
	}
	parts := strings.Split(hv, ",")
	cand := strings.TrimSpace(parts[len(parts)-1]) // rightmost = trusted proxy's value
	if ip, ok := parseIPLoose(cand); ok {
		return ip
	}
	return remote // invalid header content -> fail closed, never crash
}

// remoteHost strips the port from a host:port (or returns the input if there is no port).
func remoteHost(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// parseIPLoose accepts a bare IP or an ip:port and returns the canonical IP string.
func parseIPLoose(s string) (string, bool) {
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap().String(), true
	}
	if h := remoteHost(s); h != s {
		if ip, err := netip.ParseAddr(h); err == nil {
			return ip.Unmap().String(), true
		}
	}
	return "", false
}

func addrInAny(a netip.Addr, cidrs []netip.Prefix) bool {
	a = a.Unmap()
	for _, c := range cidrs {
		if c.Contains(a) {
			return true
		}
	}
	return false
}

// --- persistent backoff state (SQLite) ---

const (
	throttleScopeIP   = "ip"
	throttleScopeUser = "user"
)

// throttleStatus prunes long-expired rows, then returns the latest active window across the
// ('ip', ipKey) and ('user', userKey) rows. If the result is > now the caller must reject
// cheaply (429 + Retry-After) WITHOUT running argon2id. Pruning here keeps the table from
// growing unbounded from junk usernames/IPs.
// SECURITY-REVIEW: self-pruning throttle table (disk-DoS guard).
func (s *Storage) throttleStatus(now int64, ipKey, userKey string, pruneGraceSec int64) (int64, error) {
	if _, err := s.db.Exec(`DELETE FROM login_throttle WHERE window_until < ?`, now-pruneGraceSec); err != nil {
		return 0, err
	}
	rows, err := s.db.Query(
		`SELECT window_until FROM login_throttle WHERE (scope=? AND key=?) OR (scope=? AND key=?)`,
		throttleScopeIP, ipKey, throttleScopeUser, userKey)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var blockedUntil int64
	for rows.Next() {
		var wu int64
		if err := rows.Scan(&wu); err != nil {
			return 0, err
		}
		if wu > blockedUntil {
			blockedUntil = wu
		}
	}
	return blockedUntil, rows.Err()
}

// throttleFail records a failed attempt for BOTH scopes, incrementing fail_count and setting
// window_until = now + backoff(fail_count). The per-user counter is bumped for ANY presented
// username — existing or not — so throttling cannot become an account-existence oracle.
// SECURITY-REVIEW: throttle symmetric over username existence (no "unknown user -> skip").
func (s *Storage) throttleFail(now int64, ipKey, userKey string, base, max time.Duration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range []struct{ scope, key string }{
		{throttleScopeIP, ipKey},
		{throttleScopeUser, userKey},
	} {
		var fc int64
		err := tx.QueryRow(`SELECT fail_count FROM login_throttle WHERE scope=? AND key=?`, e.scope, e.key).Scan(&fc)
		if errors.Is(err, sql.ErrNoRows) {
			fc = 0
		} else if err != nil {
			return err
		}
		fc++
		wu := now + backoffSeconds(fc, base, max)
		if _, err := tx.Exec(
			`INSERT INTO login_throttle(scope, key, fail_count, window_until, updated_at) VALUES(?,?,?,?,?)
			 ON CONFLICT(scope, key) DO UPDATE SET fail_count=excluded.fail_count, window_until=excluded.window_until, updated_at=excluded.updated_at`,
			e.scope, e.key, fc, wu, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// throttleReset clears BOTH scopes after a successful login.
func (s *Storage) throttleReset(ipKey, userKey string) error {
	_, err := s.db.Exec(
		`DELETE FROM login_throttle WHERE (scope=? AND key=?) OR (scope=? AND key=?)`,
		throttleScopeIP, ipKey, throttleScopeUser, userKey)
	return err
}

// --- in-process argon2id concurrency limiter (peak-memory ceiling) ---

// acquireArgon2 reserves one of the MaxConcurrentArgon2 argon2id slots, waiting at most
// Argon2AcquireTimeout. It returns a release func and true on success; false means the
// server is saturated and the caller MUST reject cheaply (503) WITHOUT running argon2id —
// otherwise a flood would pile up waiting goroutines (another DoS). This is an in-process
// resource bond, deliberately NOT persisted in SQLite (that is the separate, persistent
// backoff mechanism). It wraps BOTH the real verify and the decoy so the anti-enumeration
// equal-work property is preserved.
// SECURITY-REVIEW: in-process ceiling on concurrent argon2id => bounds peak login memory.
func (s *Server) acquireArgon2() (func(), bool) {
	timer := time.NewTimer(s.cfg.Argon2AcquireTimeout)
	defer timer.Stop()
	select {
	case s.argon2Sem <- struct{}{}:
		return func() { <-s.argon2Sem }, true
	case <-timer.C:
		return nil, false
	}
}
