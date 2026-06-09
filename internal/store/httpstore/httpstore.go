// Package httpstore is the Tier-4 HTTP-backed implementation of store.Store. It is a
// drop-in for the localfs stub: the helper engine, manifest, crypto, and roster code
// are untouched. All bodies are opaque ciphertext; the server never parses them. A
// 412 (Precondition Failed) on a manifest/roster CAS is mapped to
// store.ErrVersionConflict so the helper's EXISTING rebase-retry logic is reused.
package httpstore

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"encgit/internal/store"
)

// rosterNewVersionHeader carries the explicit roster CAS target version (genesis is
// 0->0, not expected+1). Must match the server's header name.
const rosterNewVersionHeader = "Encgit-New-Version"

// Store talks to a Tier-4 server for one repo, authenticating with a bearer token.
type Store struct {
	client *http.Client
	base   string // e.g. "https://host" (no trailing slash)
	repoID string
	token  string
}

var _ store.Store = (*Store)(nil)

// New returns an HTTP-backed store for repoID at baseURL, authenticating with token.
func New(baseURL, repoID, token string, client *http.Client) (*Store, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		return nil, fmt.Errorf("httpstore: empty base URL")
	}
	return &Store{client: client, base: strings.TrimRight(baseURL, "/"), repoID: repoID, token: token}, nil
}

func (s *Store) url(suffix string) string {
	return s.base + "/repos/" + s.repoID + suffix
}

// do issues a request with the bearer token and optional headers/body.
func (s *Store) do(method, url string, body []byte, headers map[string]string) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, fmt.Errorf("httpstore: new request: %w", err)
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpstore: %s %s: %w", method, url, err)
	}
	return resp, nil
}

func drain(resp *http.Response) { io.Copy(io.Discard, resp.Body); resp.Body.Close() }

func statusErr(method, url string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	resp.Body.Close()
	return fmt.Errorf("httpstore: %s %s: HTTP %d: %s", method, url, resp.StatusCode, strings.TrimSpace(string(body)))
}

// --- blobs ---

func (s *Store) PutBlob(id string, data []byte) error {
	url := s.url("/blobs/" + id)
	resp, err := s.do(http.MethodPut, url, data, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return statusErr(http.MethodPut, url, resp)
	}
	drain(resp)
	return nil
}

func (s *Store) GetBlob(id string) ([]byte, error) {
	url := s.url("/blobs/" + id)
	resp, err := s.do(http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drain(resp)
		return nil, store.ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		return nil, statusErr(http.MethodGet, url, resp)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (s *Store) HasBlob(id string) (bool, error) {
	url := s.url("/blobs/" + id)
	resp, err := s.do(http.MethodHead, url, nil, nil)
	if err != nil {
		return false, err
	}
	drain(resp)
	switch {
	case resp.StatusCode == http.StatusOK:
		return true, nil
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("httpstore: HEAD %s: HTTP %d", url, resp.StatusCode)
	}
}

func (s *Store) DeleteBlob(id string) error {
	url := s.url("/blobs/" + id)
	resp, err := s.do(http.MethodDelete, url, nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return statusErr(http.MethodDelete, url, resp)
	}
	drain(resp)
	return nil
}

// --- manifest (CAS via If-Match; server sets version+1) ---

func (s *Store) GetManifest() ([]byte, uint64, error) {
	return s.getPointer(s.url("/manifest"))
}

func (s *Store) CASManifest(expectedVersion uint64, blob []byte, newVersion uint64) error {
	url := s.url("/manifest")
	headers := map[string]string{"If-Match": etag(expectedVersion)}
	return s.casPointer(http.MethodPut, url, blob, headers)
}

// --- roster (CAS via If-Match + explicit new version) ---

func (s *Store) GetRoster() ([]byte, uint64, error) {
	return s.getPointer(s.url("/roster"))
}

func (s *Store) CASRoster(expectedVersion uint64, blob []byte, newVersion uint64) error {
	url := s.url("/roster")
	headers := map[string]string{
		"If-Match":             etag(expectedVersion),
		rosterNewVersionHeader: strconv.FormatUint(newVersion, 10),
	}
	return s.casPointer(http.MethodPut, url, blob, headers)
}

// getPointer GETs a CAS pointer (manifest/roster): 404 -> (nil,0,nil); 200 -> blob+ETag.
func (s *Store) getPointer(url string) ([]byte, uint64, error) {
	resp, err := s.do(http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drain(resp)
		return nil, 0, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, 0, statusErr(http.MethodGet, url, resp)
	}
	defer resp.Body.Close()
	blob, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	ver, ok := parseETag(resp.Header.Get("ETag"))
	if !ok {
		return nil, 0, fmt.Errorf("httpstore: GET %s: missing/invalid ETag", url)
	}
	return blob, ver, nil
}

// casPointer PUTs a CAS pointer; 412 -> store.ErrVersionConflict (reuses helper retry).
func (s *Store) casPointer(method, url string, blob []byte, headers map[string]string) error {
	resp, err := s.do(method, url, blob, headers)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusPreconditionFailed {
		drain(resp)
		return store.ErrVersionConflict
	}
	if resp.StatusCode/100 != 2 {
		return statusErr(method, url, resp)
	}
	drain(resp)
	return nil
}

// --- keyfile (singleton, no CAS) ---

func (s *Store) PutKeyfile(data []byte) error {
	url := s.url("/keyfile")
	resp, err := s.do(http.MethodPut, url, data, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return statusErr(http.MethodPut, url, resp)
	}
	drain(resp)
	return nil
}

func (s *Store) GetKeyfile() ([]byte, error) {
	url := s.url("/keyfile")
	resp, err := s.do(http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drain(resp)
		return nil, store.ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		return nil, statusErr(http.MethodGet, url, resp)
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func etag(v uint64) string { return `"` + strconv.FormatUint(v, 10) + `"` }

func parseETag(s string) (uint64, bool) {
	s = strings.Trim(strings.TrimSpace(s), `"`)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
