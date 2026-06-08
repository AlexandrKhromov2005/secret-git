package roster

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"testing"
)

// makeMember builds a member with a real Ed25519 key and an arbitrary 32-byte
// X25519 public value; it returns the member and its Ed25519 private key.
func makeMember(t *testing.T, name string, xseed byte) (Member, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var x [32]byte
	for i := range x {
		x[i] = xseed + byte(i)
	}
	return Member{
		Name:       name,
		X25519Pub:  hex.EncodeToString(x[:]),
		Ed25519Pub: hex.EncodeToString(pub),
	}, priv
}

func TestMemberFingerprint(t *testing.T) {
	m, _ := makeMember(t, "a", 1)
	x, _ := m.XPubBytes()
	e, _ := m.EdPubBytes()
	h := sha256.New()
	h.Write(x)
	h.Write(e)
	want := hex.EncodeToString(h.Sum(nil))
	got, err := m.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
}

func TestRosterSignVerifyAndTamper(t *testing.T) {
	m0, priv0 := makeMember(t, "alice", 1)
	m1, _ := makeMember(t, "bob", 50)
	fp0, _ := m0.Fingerprint()

	r := &Roster{
		RepoID:      "deadbeef",
		Version:     0,
		Members:     []Member{m0, m1},
		AuthorKeyID: fp0,
	}
	if err := r.Sign(priv0); err != nil {
		t.Fatal(err)
	}
	pub0, _ := m0.EdPub()
	if err := r.Verify(pub0); err != nil {
		t.Fatalf("valid roster signature rejected: %v", err)
	}

	// Tampering with a member invalidates the signature.
	r2 := *r
	r2.Members = []Member{{Name: "mallory", X25519Pub: m1.X25519Pub, Ed25519Pub: m1.Ed25519Pub}, m0}
	if err := r2.Verify(pub0); err == nil {
		t.Fatal("tampered roster verified")
	}

	// Tampering with the version invalidates the signature.
	r3 := *r
	r3.Version = 5
	if err := r3.Verify(pub0); err == nil {
		t.Fatal("version change not detected")
	}
}

func TestRosterMembersSortedDeterministically(t *testing.T) {
	m0, _ := makeMember(t, "a", 1)
	m1, _ := makeMember(t, "b", 80)
	m2, _ := makeMember(t, "c", 160)

	r1 := &Roster{RepoID: "r", Version: 1, Members: []Member{m0, m1, m2}, AuthorKeyID: "x"}
	r2 := &Roster{RepoID: "r", Version: 1, Members: []Member{m2, m0, m1}, AuthorKeyID: "x"}

	b1, err := r1.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	b2, err := r2.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Input order must not affect the canonical bytes (members are sorted by
	// fingerprint, §1.2).
	if !bytes.Equal(b1, b2) {
		t.Fatalf("member input order affected canonical bytes:\n%s\n%s", b1, b2)
	}

	// The members must appear in ascending fingerprint order in the output.
	type nf struct {
		name string
		fp   string
	}
	all := []nf{}
	for _, m := range []Member{m0, m1, m2} {
		fp, _ := m.Fingerprint()
		all = append(all, nf{m.Name, fp})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].fp < all[j].fp })
	prevIdx := -1
	for _, x := range all {
		idx := bytes.Index(b1, []byte(`"`+x.name+`"`))
		if idx <= prevIdx {
			t.Fatalf("members not in ascending fingerprint order; %q at %d", x.name, idx)
		}
		prevIdx = idx
	}
}

func TestRosterParseRoundTrip(t *testing.T) {
	m0, priv0 := makeMember(t, "alice", 1)
	m1, _ := makeMember(t, "bob", 50)
	fp0, _ := m0.Fingerprint()
	prev := "00ff"

	r := &Roster{
		RepoID:         "deadbeef",
		Version:        3,
		PrevRosterHash: &prev,
		Members:        []Member{m0, m1},
		AuthorKeyID:    fp0,
	}
	if err := r.Sign(priv0); err != nil {
		t.Fatal(err)
	}
	plain, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(plain)
	if err != nil {
		t.Fatal(err)
	}
	reCanon, err := got.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reCanon, plain) {
		t.Fatalf("re-canonicalization differs:\n got %s\nwant %s", reCanon, plain)
	}
	pub0, _ := m0.EdPub()
	if err := got.Verify(pub0); err != nil {
		t.Fatalf("parsed roster failed to verify: %v", err)
	}
}

func TestRosterRepoKeyGenerationSigned(t *testing.T) {
	m0, priv0 := makeMember(t, "alice", 1)
	fp0, _ := m0.Fingerprint()
	r := &Roster{RepoID: "r", Version: 2, Members: []Member{m0}, AuthorKeyID: fp0, RepoKeyGeneration: 3}
	if err := r.Sign(priv0); err != nil {
		t.Fatal(err)
	}
	canon, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canon, []byte(`"repo_key_generation":3`)) {
		t.Fatalf("repo_key_generation not in canonical bytes: %s", canon)
	}
	pub0, _ := m0.EdPub()
	// Tampering with the generation invalidates the signature.
	r2 := *r
	r2.RepoKeyGeneration = 4
	if err := r2.Verify(pub0); err == nil {
		t.Fatal("repo_key_generation change was not detected by the signature")
	}
}

func TestRosterGenesisPrevNull(t *testing.T) {
	m0, priv0 := makeMember(t, "alice", 1)
	fp0, _ := m0.Fingerprint()
	r := &Roster{RepoID: "r", Version: 0, PrevRosterHash: nil, Members: []Member{m0}, AuthorKeyID: fp0}
	if err := r.Sign(priv0); err != nil {
		t.Fatal(err)
	}
	canon, err := r.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(canon, []byte(`"prev_roster_hash":null`)) {
		t.Fatalf("genesis prev_roster_hash not null: %s", canon)
	}
}
