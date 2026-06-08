package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleManifest() *Manifest {
	prev := "abc123"
	return &Manifest{
		RepoID:           "deadbeef",
		Version:          2,
		PrevManifestHash: &prev,
		Refs:             map[string]string{"refs/heads/main": "aaa", "refs/heads/feature": "bbb"},
		Packs:            []string{"p1", "p2"},
		PusherKeyID:      "ffff",
		Sig:              "U0lH",
	}
}

func readSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "FORMAT-SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestManifestSchemaFieldsMatchSpec pins the §5.2 manifest field names against the
// frozen spec document (not against a self-authored canonical golden — the JCS
// encoding rules themselves are validated externally in jcs_rfc8785_test.go). It
// also confirms which fields are covered by the signature vs the full plaintext.
func TestManifestSchemaFieldsMatchSpec(t *testing.T) {
	spec := readSpec(t)
	m := sampleManifest()
	canon, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	sign, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}

	fields := []string{"repo_id", "version", "prev_manifest_hash", "refs", "packs", "pusher_key_id", "sig"}
	for _, f := range fields {
		if !strings.Contains(spec, `"`+f+`"`) {
			t.Errorf("field %q is not documented in docs/FORMAT-SPEC.md", f)
		}
		if !bytes.Contains(canon, []byte(`"`+f+`":`)) {
			t.Errorf("field %q missing from canonical plaintext", f)
		}
	}

	// sig is the only field excluded from the signed bytes; all others are present.
	if bytes.Contains(sign, []byte(`"sig":`)) {
		t.Error("sig must not appear in signing bytes")
	}
	for _, f := range fields {
		if f == "sig" {
			continue
		}
		if !bytes.Contains(sign, []byte(`"`+f+`":`)) {
			t.Errorf("field %q missing from signing bytes", f)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := sampleManifest()
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	plain, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	// Re-canonicalizing the parsed manifest reproduces the exact bytes.
	reCanon, err := got.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reCanon, plain) {
		t.Fatalf("re-canonicalization differs:\n got %s\nwant %s", reCanon, plain)
	}
	if err := got.Verify(pub); err != nil {
		t.Fatalf("parsed manifest failed to verify: %v", err)
	}
}
