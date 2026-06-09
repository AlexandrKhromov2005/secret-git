package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func makeServer(t *testing.T) (*httptest.Server, *Storage) {
	t.Helper()
	st := openTestStorage(t)
	srv := New(st, DefaultConfig())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
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
	unknownStatus, unknownBody := postLogin(t, ts, "ghost", "wrong")

	if wrongStatus != http.StatusUnauthorized || unknownStatus != http.StatusUnauthorized {
		t.Fatalf("status: wrongPw=%d unknownUser=%d, want both 401", wrongStatus, unknownStatus)
	}
	if wrongBody != unknownBody {
		t.Fatalf("responses differ (enumeration): wrongPw=%q unknownUser=%q", wrongBody, unknownBody)
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
