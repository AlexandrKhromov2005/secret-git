package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

func TestCanonicalGolden(t *testing.T) {
	m := sampleManifest()

	gotCanon, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	wantCanon := `{"packs":["p1","p2"],"prev_manifest_hash":"abc123","pusher_key_id":"ffff","refs":{"refs/heads/feature":"bbb","refs/heads/main":"aaa"},"repo_id":"deadbeef","sig":"U0lH","version":2}`
	if string(gotCanon) != wantCanon {
		t.Fatalf("canonical mismatch:\n got %s\nwant %s", gotCanon, wantCanon)
	}

	// Signing bytes are the same object WITHOUT the sig field.
	gotSign, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	wantSign := `{"packs":["p1","p2"],"prev_manifest_hash":"abc123","pusher_key_id":"ffff","refs":{"refs/heads/feature":"bbb","refs/heads/main":"aaa"},"repo_id":"deadbeef","version":2}`
	if string(gotSign) != wantSign {
		t.Fatalf("signing-bytes mismatch:\n got %s\nwant %s", gotSign, wantSign)
	}

	// Determinism: repeated encodings are byte-identical.
	for range 50 {
		again, err := m.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, gotCanon) {
			t.Fatal("canonical encoding is not deterministic")
		}
	}

	// null prev_manifest_hash renders as JSON null.
	m.PrevManifestHash = nil
	nullCanon, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(nullCanon, []byte(`"prev_manifest_hash":null`)) {
		t.Fatalf("null prev not rendered: %s", nullCanon)
	}
}

func TestEncodeStringEscaping(t *testing.T) {
	// Expected values are built from a literal backslash so no \u / \x escape text
	// appears in the test source itself.
	bs := "\\"
	cases := []struct {
		in, want string
	}{
		{`a"b`, `"a` + bs + `"b"`},                                      // " -> \"
		{`a\b`, `"a` + bs + bs + `b"`},                                  // \ -> \\
		{"tab\tnl\ncr\r", `"tab` + bs + `tnl` + bs + `ncr` + bs + `r"`}, // \t \n \r
		{string(rune(0x01)) + string(rune(0x1f)), `"` + bs + `u0001` + bs + `u001f"`},
		{"unicode-Ω-é", `"unicode-Ω-é"`}, // non-ASCII emitted literally as UTF-8
	}
	for _, c := range cases {
		var buf bytes.Buffer
		encodeString(&buf, c.in)
		if buf.String() != c.want {
			t.Errorf("encodeString(%q) = %s, want %s", c.in, buf.String(), c.want)
		}
	}
}

func TestSignVerifyAndTamper(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := sampleManifest()
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify(pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// Tampering with a signed field invalidates the signature.
	m.Refs["refs/heads/main"] = "tampered"
	if err := m.Verify(pub); err == nil {
		t.Fatal("tampered manifest verified")
	}

	// A corrupted signature is rejected.
	m2 := sampleManifest()
	if err := m2.Sign(priv); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(m2.Sig)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	m2.Sig = base64.StdEncoding.EncodeToString(raw)
	if err := m2.Verify(pub); err == nil {
		t.Fatal("corrupted signature verified")
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
