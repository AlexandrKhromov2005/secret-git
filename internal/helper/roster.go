package helper

import (
	"encoding/hex"
	"errors"
	"fmt"

	"filippo.io/age"

	"encgit/internal/agekey"
	"encgit/internal/identity"
	"encgit/internal/localstate"
	"encgit/internal/roster"
	"encgit/internal/util"
)

// memberFromIdentity builds a roster.Member from a local identity.
func memberFromIdentity(id *identity.Identity, name string) roster.Member {
	x := id.PublicX25519()
	return roster.Member{
		Name:       name,
		X25519Pub:  hex.EncodeToString(x[:]),
		Ed25519Pub: hex.EncodeToString(id.VerifyKey()),
	}
}

// rosterRecipients converts roster members to age recipients (for wrapping the repo
// key into the keyfile).
func rosterRecipients(members []roster.Member) ([]age.Recipient, error) {
	out := make([]age.Recipient, 0, len(members))
	for _, m := range members {
		xb, err := m.XPubBytes()
		if err != nil {
			return nil, err
		}
		var x [32]byte
		copy(x[:], xb)
		r, err := agekey.RecipientFromPublic(x)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// verifyRosterSelfConsistent verifies a roster's own signature when its author is
// among its members (the genesis / single-member case). For a mid-chain roster
// anchored fresh (TOFU), the author may be in a PRIOR roster we do not hold, so the
// signature cannot be self-checked here — the §2 OOB hash comparison is the anchor.
func verifyRosterSelfConsistent(r *roster.Roster) error {
	author, ok := r.FindByFingerprint(r.AuthorKeyID)
	if !ok {
		return nil // author not in this roster's members; rely on OOB anchoring
	}
	pub, err := author.EdPub()
	if err != nil {
		return err
	}
	return r.Verify(pub)
}

// loadTrustedRoster reads the server's roster, advances the locally-trusted roster
// if it is a valid direct successor of the pin (§1.3 author ∈ pinned roster, §1.4
// chain + anti-rollback), persists the advance, and returns the trusted roster and
// its hash. The first roster seen is trust-on-first-use (the §2 anchoring reduction;
// in a real join the human OOB-verifies roster_hash).
//
// SECURITY-REVIEW (§2, §7.2): no member key is accepted from the server without an
// OOB-anchored chain — TOFU stands in for the human's OOB hash check, and every
// later version is bound to the pinned roster by prev_roster_hash + author membership.
//
// m3 (hygiene, NOT a cryptographic barrier): this always reads the server's current
// roster pointer (its revealed head) and advances to it when it is a valid successor,
// so the client never operates on a roster older than the latest the server's valid
// chain proves. It does NOT defend against a server that simply withholds the head
// (serves a fully-consistent stale snapshot) — that residual is detectable only via
// §5.7 pin or out-of-band comparison, never preventable against a storage adversary.
func (e *Engine) loadTrustedRoster() (*roster.Roster, string, error) {
	blob, _, err := e.store.GetRoster()
	if err != nil {
		return nil, "", err
	}
	if blob == nil {
		return nil, "", errors.New("helper: repository has no roster")
	}
	// Decrypt via the multi-key helper: a downgraded keyfile must not be able to hide
	// the real (current-generation) roster from a client that holds the current key.
	plain, err := e.decryptPack(blob)
	if err != nil {
		return nil, "", fmt.Errorf("helper: decrypt roster: %w", err)
	}
	r, err := roster.Parse(plain)
	if err != nil {
		return nil, "", err
	}
	hash := util.SHA256Hex(plain)

	st, _, err := e.state.Load()
	if err != nil {
		return nil, "", err
	}

	if !st.RosterPinned {
		if err := verifyRosterSelfConsistent(r); err != nil {
			return nil, "", err
		}
		return r, hash, e.pinRoster(&st, r, plain, hash)
	}

	trusted, err := roster.Parse(st.TrustedRoster)
	if err != nil {
		return nil, "", err
	}

	switch {
	case r.Version == st.RosterVersion:
		if hash != st.RosterHash {
			return nil, "", errors.New("helper: roster equivocation: differing roster at the same version")
		}
		return trusted, st.RosterHash, nil
	case r.Version < st.RosterVersion:
		return nil, "", fmt.Errorf("helper: roster rollback: version %d < pinned %d", r.Version, st.RosterVersion)
	default: // r.Version > pinned: must be the direct, authorized successor
		if r.PrevRosterHash == nil || *r.PrevRosterHash != st.RosterHash {
			return nil, "", errors.New("helper: roster chain break / equivocation (prev_roster_hash)")
		}
		author, ok := trusted.FindByFingerprint(r.AuthorKeyID)
		if !ok {
			return nil, "", fmt.Errorf("helper: roster author %s is not in the previously trusted roster", r.AuthorKeyID)
		}
		pub, err := author.EdPub()
		if err != nil {
			return nil, "", err
		}
		if err := r.Verify(pub); err != nil {
			return nil, "", err
		}
		return r, hash, e.pinRoster(&st, r, plain, hash)
	}
}

// pinRoster records r as the new locally-trusted roster.
func (e *Engine) pinRoster(st *localstate.State, r *roster.Roster, plain []byte, hash string) error {
	st.RosterPinned = true
	st.RosterVersion = r.Version
	st.RosterHash = hash
	st.TrustedRoster = plain
	return e.state.Save(*st)
}
