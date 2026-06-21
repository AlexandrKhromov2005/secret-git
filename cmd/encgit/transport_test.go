package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestHTTPClientForCACert proves the --cacert path: the default client rejects a
// self-signed TLS server, while a client built from the pinned cert trusts it. It
// also covers the empty/missing/non-PEM input cases.
func TestHTTPClientForCACert(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	// Empty path -> nil client (caller falls back to default system trust).
	if c, err := httpClientForCACert(""); err != nil || c != nil {
		t.Fatalf("empty cacert: want (nil,nil), got (%v,%v)", c, err)
	}
	// Missing file -> error.
	if _, err := httpClientForCACert(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Fatal("missing cacert file: want error, got nil")
	}
	// A file with no PEM certificate -> error.
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := httpClientForCACert(junk); err == nil {
		t.Fatal("non-PEM cacert: want error, got nil")
	}

	// The default client must REJECT the self-signed server (cert not in system pool).
	if _, err := http.Get(ts.URL); err == nil {
		t.Fatal("default client unexpectedly trusted a self-signed server")
	}

	// Pin the server's own cert -> the built client must trust exactly it.
	certPath := filepath.Join(t.TempDir(), "server.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(certPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := httpClientForCACert(certPath)
	if err != nil {
		t.Fatalf("build pinned client: %v", err)
	}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("pinned client should trust the server cert: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

// TestResolveCACertEnvFallback checks the ENCGIT_CACERT fallback: the explicit flag
// wins, otherwise the env var is used, otherwise empty.
func TestResolveCACertEnvFallback(t *testing.T) {
	t.Setenv(caCertEnv, "/from/env.pem")
	if got := resolveCACert("/from/flag.pem"); got != "/from/flag.pem" {
		t.Fatalf("flag should win, got %q", got)
	}
	if got := resolveCACert(""); got != "/from/env.pem" {
		t.Fatalf("env fallback expected, got %q", got)
	}
	t.Setenv(caCertEnv, "")
	if got := resolveCACert(""); got != "" {
		t.Fatalf("no flag, no env -> empty, got %q", got)
	}
}
