package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Config tunes the server's token/invite lifetimes, request limits, and the /auth/login
// rate-limiting layer.
type Config struct {
	TokenTTL   time.Duration // API session token lifetime
	InviteTTL  time.Duration // invite token lifetime
	MaxBodyLen int64         // memory-safety bound on a single request body (NOT a quota)

	// /auth/login rate limiting (see throttle.go).
	LoginBackoffBase     time.Duration // BASE: first backoff window
	LoginBackoffMax      time.Duration // MAX_BACKOFF: finite ceiling (no hard lockout)
	ThrottlePruneGrace   time.Duration // rows whose window expired this long ago are pruned
	MaxConcurrentArgon2  int           // ceiling on simultaneous argon2id (peak-memory bond)
	Argon2AcquireTimeout time.Duration // max wait for a slot before a cheap 503

	// Client-IP extraction behind the mandatory reverse proxy (ЧАСТЬ C). Fail-closed: with
	// no trusted proxy CIDRs and/or no header name, the per-IP key is r.RemoteAddr's host.
	// The proxy header is trusted ONLY for connections whose source address is in
	// TrustedProxyCIDRs, and only its rightmost token is used.
	TrustedProxyCIDRs []netip.Prefix // source addresses whose ClientIPHeader is trusted
	ClientIPHeader    string         // e.g. "X-Forwarded-For"; "" => never trust a header
}

// DefaultConfig returns sensible defaults. Client-IP extraction is fail-closed (no proxy
// header trusted) until an operator configures TrustedProxyCIDRs + ClientIPHeader.
func DefaultConfig() Config {
	return Config{
		TokenTTL:             24 * time.Hour,
		InviteTTL:            72 * time.Hour,
		MaxBodyLen:           1 << 31,
		LoginBackoffBase:     time.Second,      // SECURITY-REVIEW: BASE = 1s
		LoginBackoffMax:      60 * time.Second, // SECURITY-REVIEW: MAX_BACKOFF = 60s (finite)
		ThrottlePruneGrace:   time.Hour,
		MaxConcurrentArgon2:  4,               // SECURITY-REVIEW: ~4×19MiB peak argon2id
		Argon2AcquireTimeout: 2 * time.Second, // SECURITY-REVIEW: cheap 503 past this
	}
}

// Server is the Tier-4 HTTP authorizer over a Storage. It never inspects blob/manifest
// content (ЧАСТЬ A): bodies are opaque bytes.
type Server struct {
	*Storage
	cfg       Config
	argon2Sem chan struct{} // in-process argon2id concurrency limiter (capacity = MaxConcurrentArgon2)
}

// New builds a Server.
func New(st *Storage, cfg Config) *Server {
	n := cfg.MaxConcurrentArgon2
	if n < 1 {
		n = 1
	}
	return &Server{Storage: st, cfg: cfg, argon2Sem: make(chan struct{}, n)}
}

// Handler returns the HTTP handler with all routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Auth (unauthenticated entry points).
	mux.HandleFunc("POST /auth/bootstrap", s.handleBootstrap)
	mux.HandleFunc("POST /auth/register", s.handleRegister)
	mux.HandleFunc("POST /auth/login", s.handleLogin)
	// Admin (instance-level).
	mux.HandleFunc("POST /repos", s.handleCreateRepo)
	mux.HandleFunc("POST /repos/{repo_id}/invites", s.handleCreateInvite)
	// Data (repo-scoped roles; bytes are opaque).
	mux.HandleFunc("GET /repos/{repo_id}/blobs/{hash}", s.handleGetBlob)
	mux.HandleFunc("HEAD /repos/{repo_id}/blobs/{hash}", s.handleHeadBlob)
	mux.HandleFunc("PUT /repos/{repo_id}/blobs/{hash}", s.handlePutBlob)
	mux.HandleFunc("DELETE /repos/{repo_id}/blobs/{hash}", s.handleDeleteBlob)
	mux.HandleFunc("GET /repos/{repo_id}/manifest", s.handleGetManifest)
	mux.HandleFunc("PUT /repos/{repo_id}/manifest", s.handlePutManifest)
	mux.HandleFunc("GET /repos/{repo_id}/roster", s.handleGetRoster)
	mux.HandleFunc("PUT /repos/{repo_id}/roster", s.handlePutRoster)
	mux.HandleFunc("GET /repos/{repo_id}/keyfile", s.handleGetKeyfile)
	mux.HandleFunc("PUT /repos/{repo_id}/keyfile", s.handlePutKeyfile)
	return mux
}

// --- helpers ---

func (s *Server) body(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyLen)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return nil, false
	}
	return data, true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// bearer extracts the token from an Authorization: Bearer header.
func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if !strings.HasPrefix(h, p) {
		return "", false
	}
	return strings.TrimSpace(h[len(p):]), true
}

// authRepo authenticates the bearer token and enforces the repo-scoped role.
// 401 if unauthenticated; 403 if authenticated but lacking the required role
// (deny-by-default). // SECURITY-REVIEW: deny-by-default; admin status grants NO data access.
func (s *Server) authRepo(w http.ResponseWriter, r *http.Request, repoID string, needWrite bool) (account, bool) {
	token, ok := bearer(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return account{}, false
	}
	acc, err := s.authenticate(token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return account{}, false
	}
	role, has, err := s.roleFor(acc.id, repoID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return account{}, false
	}
	if !has {
		http.Error(w, "forbidden", http.StatusForbidden)
		return account{}, false
	}
	if needWrite && role != RoleWriter {
		http.Error(w, "forbidden", http.StatusForbidden)
		return account{}, false
	}
	return acc, true
}

// authAdmin authenticates and requires instance-level admin.
func (s *Server) authAdmin(w http.ResponseWriter, r *http.Request) (account, bool) {
	token, ok := bearer(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return account{}, false
	}
	acc, err := s.authenticate(token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return account{}, false
	}
	if !acc.isAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return account{}, false
	}
	return acc, true
}

func parseETagVersion(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"`)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func etag(v uint64) string { return fmt.Sprintf(`"%d"`, v) }

// --- auth endpoints ---

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	var req struct{ Token, Username, Password string }
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	if err := s.consumeBootstrap(req.Token, req.Username, req.Password); err != nil {
		if errors.Is(err, errBadToken) {
			http.Error(w, "invalid bootstrap token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "bootstrap failed", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InviteToken string `json:"invite_token"`
		Username    string
		Password    string
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == "" || req.Password == "" {
		http.Error(w, "username and password required", http.StatusBadRequest)
		return
	}
	if err := s.consumeInvite(req.InviteToken, req.Username, req.Password); err != nil {
		if errors.Is(err, errBadToken) || errors.Is(err, errUsedOrExpired) {
			http.Error(w, "invalid or expired invite", http.StatusUnauthorized)
			return
		}
		http.Error(w, "registration failed", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if !decodeJSON(w, r, &req) {
		return
	}
	now := time.Now().Unix()
	ipKey := clientIP(r, s.cfg)
	userKey := req.Username // the presented username, verbatim — see throttle symmetry note

	// Step 1: cheap reject inside an active backoff window, BEFORE any argon2id. The
	// per-IP and per-user windows are checked identically for existing and unknown users.
	graceSec := int64(s.cfg.ThrottlePruneGrace / time.Second)
	blockedUntil, err := s.throttleStatus(now, ipKey, userKey, graceSec)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if blockedUntil > now {
		// SECURITY-REVIEW: load-bearing — 429 returned WITHOUT reaching argon2id, and the
		// response (status, body, Retry-After) is computed only from the window, identically
		// for existing and unknown usernames, so it is not an existence oracle.
		w.Header().Set("Retry-After", strconv.FormatInt(blockedUntil-now, 10))
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	// Step 2: bound peak argon2id memory — a cheap 503 if saturated, BEFORE argon2id. The
	// slot covers s.login's single argon2id in BOTH the real-verify and decoy branches.
	release, ok := s.acquireArgon2()
	if !ok {
		// SECURITY-REVIEW: load-bearing — 503 returned WITHOUT reaching argon2id.
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}
	token, loginErr := s.login(req.Username, req.Password, s.cfg.TokenTTL)
	release()

	if loginErr != nil {
		if errors.Is(loginErr, errBadToken) {
			// Credential failure (incl. unknown username): bump backoff for BOTH scopes,
			// then the same generic 401 (no user enumeration).
			if err := s.throttleFail(now, ipKey, userKey, s.cfg.LoginBackoffBase, s.cfg.LoginBackoffMax); err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		// Infrastructure error (not a credential signal): do not bump the throttle.
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	// Success: clear BOTH scopes.
	if err := s.throttleReset(ipKey, userKey); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// --- admin endpoints ---

func (s *Server) handleCreateRepo(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authAdmin(w, r); !ok {
		return
	}
	var req struct {
		RepoID          string `json:"repo_id"`
		FounderUsername string `json:"founder_username"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !safeName(req.RepoID) {
		http.Error(w, "bad repo_id", http.StatusBadRequest)
		return
	}
	if err := s.createRepo(req.RepoID); err != nil {
		http.Error(w, "create repo failed (exists?)", http.StatusConflict)
		return
	}
	// Optionally assign a founder writer at creation time if the account exists.
	if req.FounderUsername != "" {
		id, _, _, _, _, err := s.accountByUsername(req.FounderUsername)
		if err != nil {
			http.Error(w, "founder account not found", http.StatusBadRequest)
			return
		}
		if err := s.grantAccess(id, req.RepoID, RoleWriter); err != nil {
			http.Error(w, "grant failed", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authAdmin(w, r); !ok {
		return
	}
	repoID := r.PathValue("repo_id")
	exists, err := s.repoExists(repoID)
	if err != nil || !exists {
		http.Error(w, "unknown repo", http.StatusNotFound)
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	role := Role(req.Role)
	if role != RoleReader && role != RoleWriter {
		http.Error(w, "role must be reader or writer", http.StatusBadRequest)
		return
	}
	token, err := s.createInvite(repoID, role, s.cfg.InviteTTL)
	if err != nil {
		http.Error(w, "invite failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"invite_token": token})
}

// --- blob endpoints ---

func (s *Server) handleGetBlob(w http.ResponseWriter, r *http.Request) {
	repoID, hash := r.PathValue("repo_id"), r.PathValue("hash")
	if _, ok := s.authRepo(w, r, repoID, false); !ok {
		return
	}
	data, err := s.getBlob(repoID, hash)
	if errors.Is(err, errNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *Server) handleHeadBlob(w http.ResponseWriter, r *http.Request) {
	repoID, hash := r.PathValue("repo_id"), r.PathValue("hash")
	if _, ok := s.authRepo(w, r, repoID, false); !ok {
		return
	}
	ok, err := s.hasBlob(repoID, hash)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePutBlob(w http.ResponseWriter, r *http.Request) {
	repoID, hash := r.PathValue("repo_id"), r.PathValue("hash")
	if _, ok := s.authRepo(w, r, repoID, true); !ok {
		return
	}
	data, ok := s.body(w, r)
	if !ok {
		return
	}
	if err := s.putBlob(repoID, hash, data); err != nil {
		if errors.Is(err, errBadHash) {
			http.Error(w, "blob hash mismatch", http.StatusBadRequest)
			return
		}
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteBlob(w http.ResponseWriter, r *http.Request) {
	repoID, hash := r.PathValue("repo_id"), r.PathValue("hash")
	// SECURITY-REVIEW: blob deletion requires writer (deny-by-default; reader -> 403).
	// This is the accepted compromised-account DoS risk (ЧАСТЬ A), not a confidentiality
	// or integrity break.
	if _, ok := s.authRepo(w, r, repoID, true); !ok {
		return
	}
	if err := s.deleteBlob(repoID, hash); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- manifest endpoints (CAS via If-Match; server sets version+1) ---

func (s *Server) handleGetManifest(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	if _, ok := s.authRepo(w, r, repoID, false); !ok {
		return
	}
	blob, ver, err := s.getManifest(repoID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if blob == nil {
		http.Error(w, "no manifest", http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", etag(ver))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(blob)
}

func (s *Server) handlePutManifest(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	if _, ok := s.authRepo(w, r, repoID, true); !ok {
		return
	}
	expected, ok := parseETagVersion(r.Header.Get("If-Match"))
	if !ok {
		http.Error(w, "If-Match required", http.StatusPreconditionRequired)
		return
	}
	blob, ok := s.body(w, r)
	if !ok {
		return
	}
	newVer, err := s.casManifest(repoID, expected, blob)
	if errors.Is(err, errConflict) {
		http.Error(w, "version conflict", http.StatusPreconditionFailed)
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", etag(newVer))
	w.WriteHeader(http.StatusNoContent)
}

// --- roster endpoints (CAS via If-Match + explicit new version; mirrors localfs) ---

func (s *Server) handleGetRoster(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	if _, ok := s.authRepo(w, r, repoID, false); !ok {
		return
	}
	blob, ver, exists, err := s.getRoster(repoID)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "no roster", http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", etag(ver))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(blob)
}

// rosterNewVersionHeader carries the explicit target version for a roster CAS, since
// the roster's genesis is 0->0 (not expected+1), unlike the manifest.
const rosterNewVersionHeader = "Encgit-New-Version"

func (s *Server) handlePutRoster(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	if _, ok := s.authRepo(w, r, repoID, true); !ok {
		return
	}
	expected, ok := parseETagVersion(r.Header.Get("If-Match"))
	if !ok {
		http.Error(w, "If-Match required", http.StatusPreconditionRequired)
		return
	}
	newVer, ok := parseETagVersion(r.Header.Get(rosterNewVersionHeader))
	if !ok {
		http.Error(w, rosterNewVersionHeader+" required", http.StatusBadRequest)
		return
	}
	blob, ok := s.body(w, r)
	if !ok {
		return
	}
	if err := s.casRoster(repoID, expected, newVer, blob); errors.Is(err, errConflict) {
		http.Error(w, "version conflict", http.StatusPreconditionFailed)
		return
	} else if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("ETag", etag(newVer))
	w.WriteHeader(http.StatusNoContent)
}

// --- keyfile endpoints (singleton, no CAS) ---

func (s *Server) handleGetKeyfile(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	if _, ok := s.authRepo(w, r, repoID, false); !ok {
		return
	}
	data, err := s.getKeyfile(repoID)
	if errors.Is(err, errNotFound) {
		http.Error(w, "no keyfile", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func (s *Server) handlePutKeyfile(w http.ResponseWriter, r *http.Request) {
	repoID := r.PathValue("repo_id")
	if _, ok := s.authRepo(w, r, repoID, true); !ok {
		return
	}
	data, ok := s.body(w, r)
	if !ok {
		return
	}
	if err := s.putKeyfile(repoID, data); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
