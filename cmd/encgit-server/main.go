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
	"os"

	"encgit/internal/server"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address (plain HTTP; put a TLS proxy in front)")
	dbPath := flag.String("db", "encgit-server.db", "SQLite metadata database path")
	blobDir := flag.String("blobs", "encgit-blobs", "directory for per-repo blob storage")
	flag.Parse()

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

	srv := server.New(st, server.DefaultConfig())
	fmt.Fprintf(os.Stderr, "encgit-server listening on %s (plain HTTP — front with a TLS proxy)\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
