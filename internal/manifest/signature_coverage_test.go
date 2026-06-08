package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// cloneManifest deep-copies a manifest so a mutation cannot disturb the baseline.
func cloneManifest(m *Manifest) *Manifest {
	c := *m
	c.Refs = make(map[string]string, len(m.Refs))
	for k, v := range m.Refs {
		c.Refs[k] = v
	}
	c.Packs = append([]string(nil), m.Packs...)
	if m.PrevManifestHash != nil {
		p := *m.PrevManifestHash
		c.PrevManifestHash = &p
	}
	return &c
}

// TestSignedFieldsCoverage proves that EVERY signed field is covered by the
// signature (§7.2): each individual mutation, applied while keeping the original
// signature, must make verification fail. This includes the refs key, the refs
// value, and a packs entry separately.
func TestSignedFieldsCoverage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	base := sampleManifest()
	if err := base.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := base.Verify(pub); err != nil {
		t.Fatalf("baseline signature must verify: %v", err)
	}

	mutations := []struct {
		name string
		mut  func(*Manifest)
	}{
		{"repo_id", func(m *Manifest) { m.RepoID += "00" }},
		{"version", func(m *Manifest) { m.Version++ }},
		{"prev_manifest_hash value", func(m *Manifest) { s := "ffff"; m.PrevManifestHash = &s }},
		{"prev_manifest_hash to null", func(m *Manifest) { m.PrevManifestHash = nil }},
		{"refs value", func(m *Manifest) { m.Refs["refs/heads/main"] = "deadbeef" }},
		{"refs key", func(m *Manifest) { delete(m.Refs, "refs/heads/main"); m.Refs["refs/heads/dev"] = "aaa" }},
		{"packs entry", func(m *Manifest) { m.Packs[0] = "pX" }},
		{"packs append", func(m *Manifest) { m.Packs = append(m.Packs, "pZ") }},
		{"pusher_key_id", func(m *Manifest) { m.PusherKeyID = "0000" }},
		{"roster_hash", func(m *Manifest) { m.RosterHash = "beef" }},
	}
	for _, mc := range mutations {
		m := cloneManifest(base)
		m.Sig = base.Sig // keep the original signature; only the field changes
		mc.mut(m)
		if err := m.Verify(pub); err == nil {
			t.Errorf("%s: mutation was NOT detected by signature verification", mc.name)
		}
	}
}

// TestSigExcludedFromSigningIncludedInPlaintext confirms the sign-then-encrypt
// boundary (§5.3 / §7.2): sig is excluded from the signed bytes but included in the
// canonical plaintext that is encrypted and hashed.
func TestSigExcludedFromSigningIncludedInPlaintext(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := sampleManifest()
	if err := m.Sign(priv); err != nil {
		t.Fatal(err)
	}
	sign1, _ := m.SigningBytes()
	canon1, _ := m.CanonicalBytes()
	hash1, _ := m.Hash()

	if bytes.Contains(sign1, []byte(`"sig"`)) {
		t.Error("sig key present in signing bytes (must be excluded)")
	}
	if !bytes.Contains(canon1, []byte(`"sig":"`+m.Sig+`"`)) {
		t.Error("sig not present in canonical plaintext (must be included)")
	}

	// Changing only sig must leave the signed bytes unchanged but change the
	// canonical plaintext and the manifest hash (the hash is taken over the
	// plaintext WITH sig).
	m.Sig = "QUJD" // different, still valid base64
	sign2, _ := m.SigningBytes()
	canon2, _ := m.CanonicalBytes()
	hash2, _ := m.Hash()

	if !bytes.Equal(sign1, sign2) {
		t.Error("signing bytes changed when only sig changed")
	}
	if bytes.Equal(canon1, canon2) {
		t.Error("canonical plaintext unchanged when sig changed")
	}
	if hash1 == hash2 {
		t.Error("manifest hash unchanged when sig changed (hash must cover sig)")
	}
}
