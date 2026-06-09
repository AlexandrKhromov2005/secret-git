// Command encgit-server is the Tier-4 HTTP authorizer. It stores ONLY opaque
// ciphertext plus auth/CAS metadata; it holds no keys and never parses blobs.
//
// DEPLOYMENT REQUIREMENT (hard): this server speaks plain HTTP and MUST run behind a
// TLS-terminating reverse proxy. Bearer tokens and passwords MUST NEVER travel in
// plaintext. The application intentionally does not terminate TLS itself.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"encgit/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (plain HTTP; put a TLS proxy in front)")
	dbPath := flag.String("db", "encgit-server.db", "SQLite metadata database path")
	blobDir := flag.String("blobs", "encgit-blobs", "directory for per-repo blob storage")
	clientIPHeader := flag.String("client-ip-header", "",
		"header carrying the real client IP behind a trusted proxy (e.g. X-Forwarded-For); empty = trust none")
	trustedProxyCIDRs := flag.String("trusted-proxy-cidrs", "",
		"comma-separated CIDRs of trusted reverse proxies; -client-ip-header is honored ONLY for connections from these")
	flag.Parse()

	cfg := server.DefaultConfig()
	cfg.ClientIPHeader = *clientIPHeader
	if cidrs, err := parseCIDRs(*trustedProxyCIDRs); err != nil {
		log.Fatalf("trusted-proxy-cidrs: %v", err)
	} else {
		cfg.TrustedProxyCIDRs = cidrs
	}
	if cfg.ClientIPHeader != "" && len(cfg.TrustedProxyCIDRs) == 0 {
		// Fail-closed warning: a header without a trusted-proxy allowlist is never trusted,
		// so per-IP throttling collapses to the proxy's address (degradation, not a hole).
		fmt.Fprintln(os.Stderr, "warning: -client-ip-header set but -trusted-proxy-cidrs empty; "+
			"the header is NOT trusted and per-IP login throttling will key on the proxy address")
	}

	st, err := server.OpenStorage(*dbPath, *blobDir)
	if err != nil {
		log.Fatalf("open storage: %v", err)
	}
	defer st.Close()

	// One-time bootstrap: if there is no admin yet, mint a single-use bootstrap token
	// and print it to the console (only its SHA-256 is stored).
	token, err := st.EnsureBootstrap()
	if err != nil {
		log.Fatalf("bootstrap: %v", err)
	}
	if token != "" {
		fmt.Fprintf(os.Stderr, "\n=== encgit-server bootstrap ===\n"+
			"No admin exists yet. Exchange this ONE-TIME token for the first admin via\n"+
			"  POST /auth/bootstrap {\"token\":\"...\",\"username\":\"...\",\"password\":\"...\"}\n"+
			"bootstrap token: %s\n"+
			"(only its SHA-256 is stored; it cannot be recovered)\n\n", token)
	}

	srv := server.New(st, cfg)
	fmt.Fprintf(os.Stderr, "encgit-server listening on %s (plain HTTP — front with a TLS proxy)\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}

// parseCIDRs parses a comma-separated list of CIDR prefixes (empty -> nil).
func parseCIDRs(s string) ([]netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
		}
		out = append(out, p)
	}
	return out, nil
}
