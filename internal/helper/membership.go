package helper

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"encgit/internal/crypto"
	"encgit/internal/localstate"
	"encgit/internal/manifest"
	"encgit/internal/roster"
	"encgit/internal/util"
)

// ErrOOBFingerprintRequired is returned when AddMember is called without an explicit
// out-of-band-verified fingerprint for the new member (§3.1 step 1 / §7.5).
var ErrOOBFingerprintRequired = errors.New("helper: add requires an OOB-verified fingerprint")

func copyMembers(in []roster.Member) []roster.Member {
	out := make([]roster.Member, len(in))
	copy(out, in)
	return out
}

func membersExcept(in []roster.Member, fingerprint string) []roster.Member {
	out := make([]roster.Member, 0, len(in))
	for _, m := range in {
		if fp, err := m.Fingerprint(); err == nil && fp == fingerprint {
			continue
		}
		out = append(out, m)
	}
	return out
}

func random32() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("helper: read random: %w", err)
	}
	return b, nil
}

func (e *Engine) selfIsMember(r *roster.Roster) bool {
	_, ok := r.FindByFingerprint(e.member.FingerprintHex())
	return ok
}

// AddMember adds B to the roster (§3.1). It REQUIRES an explicit OOB-verified
// fingerprint that must match B's keys before the repo key is wrapped to B; this is
// the §7.5 gate against an honest member wrapping the repo key to a server-supplied
// key. Add does not rotate the repo key (B is meant to read history).
func (e *Engine) AddMember(name string, xpub, edpub [32]byte, oobFingerprint string) error {
	if err := e.refreshPackKeys(); err != nil {
		return err
	}
	trusted, curHash, err := e.loadTrustedRoster()
	if err != nil {
		return err
	}
	if !e.selfIsMember(trusted) {
		return errors.New("helper: only a current member can change the roster")
	}

	newMember := roster.Member{
		Name:       name,
		X25519Pub:  hex.EncodeToString(xpub[:]),
		Ed25519Pub: hex.EncodeToString(edpub[:]),
	}
	fp, err := newMember.Fingerprint()
	if err != nil {
		return err
	}
	// SECURITY-REVIEW (§7.5): the OOB-verified fingerprint MUST be supplied and MUST
	// match the keys we are about to trust, BEFORE wrapping the repo key to them.
	if oobFingerprint == "" {
		return ErrOOBFingerprintRequired
	}
	if oobFingerprint != fp {
		return fmt.Errorf("helper: OOB fingerprint mismatch: provided %s, keys hash to %s", oobFingerprint, fp)
	}
	if _, exists := trusted.FindByFingerprint(fp); exists {
		return errors.New("helper: member already in roster")
	}

	newMembers := append(copyMembers(trusted.Members), newMember)
	newR := &roster.Roster{
		RepoID:         e.repoHex,
		Version:        trusted.Version + 1,
		PrevRosterHash: &curHash,
		Members:        newMembers,
		AuthorKeyID:    e.member.FingerprintHex(),
	}
	if err := newR.Sign(e.member.SigningKey()); err != nil {
		return err
	}
	plain, err := newR.Marshal()
	if err != nil {
		return err
	}
	blob, err := crypto.Encrypt(plain, e.pack.Recipient) // same key — no rotation on add
	if err != nil {
		return err
	}
	if err := e.store.CASRoster(trusted.Version, blob, newR.Version); err != nil {
		return fmt.Errorf("helper: publish roster: %w", err)
	}

	// Rebuild the keyfile so the new member can unwrap the (unchanged) repo key.
	recips, err := rosterRecipients(newMembers)
	if err != nil {
		return err
	}
	keyfile, err := crypto.WrapRepoKey(e.repoKey, recips...)
	if err != nil {
		return err
	}
	if err := e.store.PutKeyfile(keyfile); err != nil {
		return err
	}

	st, _, err := e.state.Load()
	if err != nil {
		return err
	}
	return e.pinRoster(&st, newR, plain, util.SHA256Hex(plain))
}

// RemoveMember removes C and performs the default minimal rotation (§3.2): a new
// roster without C, a fresh repo key wrapped only to the remaining members, and a
// re-publish of the current manifest under the new key so it stays readable.
//
// SECURITY-REVIEW (§7.3): removal enforcement is TWO independent gates — C is no
// longer in the roster (signatures rejected) AND the repo key is rotated (C cannot
// decrypt new manifests/packs). Both must hold; neither alone is sufficient.
func (e *Engine) RemoveMember(targetFingerprint string) error {
	if err := e.refreshPackKeys(); err != nil {
		return err
	}
	trusted, curHash, err := e.loadTrustedRoster()
	if err != nil {
		return err
	}
	if !e.selfIsMember(trusted) {
		return errors.New("helper: only a current member can change the roster")
	}
	if targetFingerprint == e.member.FingerprintHex() {
		return errors.New("helper: refusing to remove yourself")
	}
	if _, ok := trusted.FindByFingerprint(targetFingerprint); !ok {
		return errors.New("helper: target is not a current member")
	}
	remaining := membersExcept(trusted.Members, targetFingerprint)
	if len(remaining) == 0 {
		return errors.New("helper: cannot remove the last member")
	}

	// Rotate the repo key.
	newRepoKey, err := random32()
	if err != nil {
		return err
	}
	newPack, err := crypto.DerivePackKeys(newRepoKey, e.repoID)
	if err != nil {
		return err
	}

	// New roster without C, encrypted to the NEW pack key (C cannot read it).
	newR := &roster.Roster{
		RepoID:         e.repoHex,
		Version:        trusted.Version + 1,
		PrevRosterHash: &curHash,
		Members:        remaining,
		AuthorKeyID:    e.member.FingerprintHex(),
	}
	if err := newR.Sign(e.member.SigningKey()); err != nil {
		return err
	}
	rplain, err := newR.Marshal()
	if err != nil {
		return err
	}
	rblob, err := crypto.Encrypt(rplain, newPack.Recipient)
	if err != nil {
		return err
	}
	if err := e.store.CASRoster(trusted.Version, rblob, newR.Version); err != nil {
		return fmt.Errorf("helper: publish roster: %w", err)
	}

	// New keyfile: wrap the NEW repo key only to the remaining members.
	recips, err := rosterRecipients(remaining)
	if err != nil {
		return err
	}
	keyfile, err := crypto.WrapRepoKey(newRepoKey, recips...)
	if err != nil {
		return err
	}
	if err := e.store.PutKeyfile(keyfile); err != nil {
		return err
	}

	st, _, err := e.state.Load()
	if err != nil {
		return err
	}

	// Re-publish the current manifest (same refs/packs) under the new key so members
	// who now hold only the new key can still read it.
	if err := e.republishManifest(trusted, newPack, &st); err != nil {
		return err
	}

	e.repoKey = newRepoKey
	e.pack = newPack
	st.AddKey(newRepoKey)
	return e.pinRoster(&st, newR, rplain, util.SHA256Hex(rplain))
}

// republishManifest re-encrypts the current manifest (unchanged refs/packs) under
// newPack at the next version, updating the manifest pin in st. No-op if there is no
// manifest yet.
func (e *Engine) republishManifest(trusted *roster.Roster, newPack *crypto.PackKeys, st *localstate.State) error {
	cur, err := e.loadCurrent(trusted) // decrypts with the current (old) key
	if err != nil {
		return err
	}
	if cur.manifest == nil {
		return nil
	}
	m := &manifest.Manifest{
		RepoID:           e.repoHex,
		Version:          cur.version + 1,
		PrevManifestHash: &cur.hash,
		Refs:             cur.manifest.Refs,
		Packs:            cur.manifest.Packs,
		PusherKeyID:      e.member.FingerprintHex(),
	}
	if err := m.Sign(e.member.SigningKey()); err != nil {
		return err
	}
	plain, err := m.Marshal()
	if err != nil {
		return err
	}
	blob, err := crypto.Encrypt(plain, newPack.Recipient)
	if err != nil {
		return err
	}
	if err := e.store.CASManifest(cur.version, blob, cur.version+1); err != nil {
		return fmt.Errorf("helper: re-publish manifest: %w", err)
	}
	st.Version = m.Version
	st.ManifestHash = util.SHA256Hex(plain)
	return nil
}

// FullRekey re-encrypts every live pack under a fresh repo key, publishes a new
// manifest listing the new pack ids, deletes the old pack blobs, rewraps the keyfile,
// and re-publishes the roster under the new key (§3.3). This is the heavy operation
// that cuts a removed member's residual access to history; it is never automatic.
func (e *Engine) FullRekey() error {
	if err := e.refreshPackKeys(); err != nil {
		return err
	}
	trusted, curRosterHash, err := e.loadTrustedRoster()
	if err != nil {
		return err
	}
	if !e.selfIsMember(trusted) {
		return errors.New("helper: only a current member can rekey")
	}
	cur, err := e.loadCurrent(trusted)
	if err != nil {
		return err
	}

	newRepoKey, err := random32()
	if err != nil {
		return err
	}
	newPack, err := crypto.DerivePackKeys(newRepoKey, e.repoID)
	if err != nil {
		return err
	}

	st, _, err := e.state.Load()
	if err != nil {
		return err
	}

	var oldPacks []string
	if cur.manifest != nil {
		oldPacks = cur.manifest.Packs
		newPacks := make([]string, 0, len(oldPacks))
		for _, oldID := range oldPacks {
			blob, err := e.store.GetBlob(oldID)
			if err != nil {
				return fmt.Errorf("helper: rekey get pack %s: %w", oldID, err)
			}
			if util.SHA256Hex(blob) != oldID {
				return fmt.Errorf("helper: rekey pack id mismatch for %s", oldID)
			}
			raw, err := e.decryptPack(blob) // tries current + historical keys
			if err != nil {
				return fmt.Errorf("helper: rekey decrypt pack %s: %w", oldID, err)
			}
			nblob, err := crypto.Encrypt(raw, newPack.Recipient) // new key
			if err != nil {
				return err
			}
			nID := util.SHA256Hex(nblob)
			if err := e.store.PutBlob(nID, nblob); err != nil {
				return err
			}
			newPacks = append(newPacks, nID)
			st.AddPack(nID) // objects are already local
		}

		m := &manifest.Manifest{
			RepoID:           e.repoHex,
			Version:          cur.version + 1,
			PrevManifestHash: &cur.hash,
			Refs:             cur.manifest.Refs,
			Packs:            newPacks,
			PusherKeyID:      e.member.FingerprintHex(),
		}
		if err := m.Sign(e.member.SigningKey()); err != nil {
			return err
		}
		mplain, err := m.Marshal()
		if err != nil {
			return err
		}
		mblob, err := crypto.Encrypt(mplain, newPack.Recipient)
		if err != nil {
			return err
		}
		if err := e.store.CASManifest(cur.version, mblob, cur.version+1); err != nil {
			return fmt.Errorf("helper: rekey publish manifest: %w", err)
		}
		st.Version = m.Version
		st.ManifestHash = util.SHA256Hex(mplain)
	}

	// Rewrap the keyfile under the new key to the current members.
	recips, err := rosterRecipients(trusted.Members)
	if err != nil {
		return err
	}
	keyfile, err := crypto.WrapRepoKey(newRepoKey, recips...)
	if err != nil {
		return err
	}
	if err := e.store.PutKeyfile(keyfile); err != nil {
		return err
	}

	// Re-publish the roster (same members) under the new key.
	newR := &roster.Roster{
		RepoID:         e.repoHex,
		Version:        trusted.Version + 1,
		PrevRosterHash: &curRosterHash,
		Members:        trusted.Members,
		AuthorKeyID:    e.member.FingerprintHex(),
	}
	if err := newR.Sign(e.member.SigningKey()); err != nil {
		return err
	}
	rplain, err := newR.Marshal()
	if err != nil {
		return err
	}
	rblob, err := crypto.Encrypt(rplain, newPack.Recipient)
	if err != nil {
		return err
	}
	if err := e.store.CASRoster(trusted.Version, rblob, newR.Version); err != nil {
		return fmt.Errorf("helper: rekey publish roster: %w", err)
	}

	// Delete the old pack blobs now that the new ones are referenced.
	for _, oldID := range oldPacks {
		if err := e.store.DeleteBlob(oldID); err != nil {
			return err
		}
	}

	e.repoKey = newRepoKey
	e.pack = newPack
	st.AddKey(newRepoKey)
	st.RosterPinned = true
	st.RosterVersion = newR.Version
	st.RosterHash = util.SHA256Hex(rplain)
	st.TrustedRoster = rplain
	return e.state.Save(st)
}
