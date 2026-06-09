# encgit — FROZEN FORMAT Tier 3 (roster, OOB-anchoring, membership)

> Canonical, frozen Tier-3 contract, reproduced from the project brief. It extends the
> frozen v1 format ([`FORMAT-SPEC.md`](FORMAT-SPEC.md)) **without changing the v1 manifest
> format (§5.2)**. Three soundness items (below, §7) remain open for external review BEFORE
> final freeze; implementation follows the contract and marks them `// SECURITY-REVIEW`.
> Implementation-level decisions are in [`../FORMAT-NOTES.md`](../FORMAT-NOTES.md).

## v2 — closes the cross-roster splice (manifest v1→v2, roster/keyfile v2)

A red-team review found a real High-severity attack: **cross-roster splice** — reanimating a
removed member's manifest against a lagging client by mixing the three independent server-held
pointers (roster, keyfile, manifest). v2 binds them. **There is no backward compatibility**:
pre-v2 repositories are re-initialized.

- **Manifest v2 — new signed field `"roster_hash"`** (hex): `SHA-256( JCS( roster's SIGNED part ) )`,
  i.e. SHA-256 over EXACTLY the JCS bytes the roster signature is computed over (the signed part,
  WITHOUT the roster's own `sig` field). This is DELIBERATELY a different preimage from
  `prev_roster_hash` / the roster pin (which stay "SHA-256 of canonical PLAINTEXT *with* sig",
  unchanged) — so the roster has two hashes: the with-sig one chains/pins it, the without-sig
  "binding" one binds the manifest to it. roster_hash is part of the signed JCS bytes (alongside all
  fields except `sig`); the canonical-key order places it between `repo_id` and `sig`. sign-then-encrypt
  and JCS are unchanged. // SECURITY-REVIEW (m1): preimage = SHA-256(JCS(roster signed-part, no sig)).
- **Roster v2 — new signed field `"repo_key_generation"`** (`uint64`): the generation of the repo
  key. **Genesis (roster v0) = 1** (not 0 — so a missing/zero field can never pass as a valid
  generation); incremented **only** on a repo-key rotation (remove with minimal rotation; full rekey).
  It does **not** change on add or on ordinary pushes. (The roster `version` is its own
  membership-change counter, separate from `repo_key_generation`.) // SECURITY-REVIEW (m2): start = 1.
- **Keyfile v2 — generation inside the AEAD payload**: the keyfile plaintext is now
  `uint64-BE(repo_key_generation) ‖ repo_key_32` (40 bytes), then `age.Encrypt(...)`. The age-AEAD
  protects the generation so the server cannot re-stamp it. This is a fixed binary layout, not a
  hand-rolled AEAD.

### Manifest acceptance v2 (rule D — order matters), on fetch
1. **Advance + pin the roster**: read the roster pointer, validate the chain (author ∈ previous
   roster, `prev_roster_hash`, version increases), update the local pin → the CURRENT trusted roster.
2. **Unwrap the keyfile and read its generation.** `// SECURITY-REVIEW (m2)`: the keyfile generation
   MUST equal `repo_key_generation` in the current trusted roster, else the keyfile is stale/forged
   (downgrade) → REJECT. Only on a match is the unwrapped repo key used as current.
3. **Decrypt the manifest** under the current repo key and verify the signature with the member whose
   fingerprint == `pusher_key_id`. `// SECURITY-REVIEW (m1)`: the manifest's `roster_hash` MUST equal
   the BINDING hash of the current trusted roster (step 1) — SHA-256 over the roster's signed bytes,
   WITHOUT sig — AND the signer MUST be a member of it, else REJECT. Then check the
   `version`/`prev_manifest_hash` chain (§5.7 v1).

### Consequence E — re-issue the manifest on every roster change
Because the manifest is bound to the CURRENT roster, any membership change MUST re-issue the current
manifest with the new `roster_hash`:
- **add**: same repo key → re-issue (new version, chained) with the new roster's hash, under the same key.
- **remove / full rekey**: new repo key → re-issue under the new key AND with the new roster's hash.
- No manifest yet (fresh repo before the first push) → skip; the first push carries the current `roster_hash`.

### m3 — recommended hygiene (NOT a security barrier)
On each operation the client best-effort reads the server's roster head and refuses to operate on a
roster older than the latest a valid server chain proves. This shrinks the equivocation window
against a lagging client but does NOT eliminate it (the server may simply never publish the head).
It is explicitly not a cryptographic barrier.

### Residual risk (stated plainly)
m1 + m2 reduce the splice to pure §5.7-style **equivocation** against a *fully frozen* lagging
participant (old roster + old keyfile + old key, all at generation G, internally consistent). That is
unpreventable against an adversary that owns storage — only **detectable** on synchronization and via
out-of-band comparison; m3 catches it only when the roster head is visible.

## 0. Two layers and threat model
- **Roster = cryptographic membership**: whose manifest signatures are accepted (members'
  Ed25519 keys) and to whom the repo key is wrapped (members' X25519 keys). This is the security
  boundary.
- **Tier 4 accounts** (invites, passwords, tokens) = operational layer: who may hit the API. NOT
  membership. Creating an account ≠ joining the roster. Adding to the roster is always a
  client-side, OOB-verified, member-signed operation; the server must not perform it.
- Adversary = the server (root). **Model assumption: members are honest.** The server can swap the
  *roster document* but cannot forge a member's signature and cannot wrap the repo key (it has no
  member Ed25519 private key and not the repo key). Two and only two strike points, both defended
  by OOB anchoring (§2): (1) an honest member, when adding someone, wraps the repo key to a
  server-substituted key; (2) a verifier trusting a server-supplied roster accepts a forged manifest.

## 1. Roster document (FROZEN)
A separate mutable, **encrypted** pointer parallel to the manifest: own version, own CAS, own
hash chain. Encrypted like the manifest (age to `pub_pack`, sign-then-encrypt) so the server does
not see member names or the membership graph.

### 1.1 Canonical serialization
The same canonical JSON (RFC 8785 JCS) as the manifest — **reuse the externally-validated encoder**
from `internal/manifest`. The signature is over the exact JCS bytes.

### 1.2 Fields
```jsonc
{
  "repo_id":           "<hex>",        // same repo_id as the repository (binds against cross-repo splice)
  "version":           <uint64>,       // strictly increases on each membership change
  "prev_roster_hash":  "<hex|null>",   // SHA-256 of the canonical PLAINTEXT of the previous roster; null for v0
  "members": [                         // ordered by fingerprint (determinism)
    {
      "name":        "<string>",       // human-readable label
      "x25519_pub":  "<hex raw32>",    // repo-key reception (keyfile wrapping)
      "ed25519_pub": "<hex raw32>"     // manifest & roster signature verification
      // fingerprint is NOT stored — derived: SHA-256(x25519_pub_raw32 || ed25519_pub_raw32) (§2 v1)
    }
  ],
  "author_key_id":     "<fingerprint-hex>",  // who signed THIS version; for v(n>0) MUST be a member of roster v(n-1)
  "sig":               "<base64 Ed25519>"    // author's signature; see 1.3
}
```

### 1.3 Signature (sign-then-encrypt, like the manifest)
1. Roster object WITHOUT `sig`, JCS-encoded → signed_bytes.
2. `sig = Ed25519_sign(author_ed25519_priv, signed_bytes)` (author = the member making the change).
3. Put `sig` back; `roster_blob = age.Encrypt(JCS(roster_with_sig), recipients=[pub_pack])`.
Verify: decrypt → drop sig → JCS the remainder → verify with `author_key_id`'s key. For v(n>0) that
key MUST be present in the (trusted) **roster v(n-1)** — the authorization chain back to genesis.

### 1.4 Roster pointer anti-rollback
Same as the manifest in §5.7 v1: the server stores an integer version next to `roster_blob`; the
client keeps a local pin of the last accepted `(roster_version, roster_hash)` and on read requires
`new.version > pinned.version` ∧ `new.prev_roster_hash == pinned.roster_hash`. Rollback or
equivocation is detected (not preventable — the server owns storage).

## 2. Genesis & OOB anchoring (FROZEN) — the crux
`roster v0`: founder M0 creates `members=[M0]`, `prev_roster_hash=null`, `author_key_id=M0`, signs
with their Ed25519. Authority comes NOT from a prior signature but from the **OOB hash comparison
when the next member joins**. For a single-member repo, anchoring is trivial (M0 trusts itself — a
generalization of the Tier-1 TOFU reduction).

OOB events when A adds B — both are a comparison of ONE short string, not n²:
- (a) **A verifies B's fingerprint** before wrapping the repo key: B generates keys and conveys the
  fingerprint out of band; B's public keys may travel any channel, but A checks the fingerprint OOB,
  so a server key-substitution is caught.
- (b) **B anchors the roster**: after receiving the repo key (via the keyfile), B decrypts the
  current roster and OOB-compares its `roster_hash` with A — anchoring the whole accepted-signer set
  at once. Thereafter B accepts roster updates by chain.

**Invariant (review):** no code path may accept a member's public key (to wrap the repo key or to
verify a signature) from server data WITHOUT an OOB-anchored chain. Genesis is the single
irreducible trusted off-server event.

## 3. Membership operations (FROZEN)
### 3.1 Add (A adds B)
1. A OOB-verifies B's fingerprint (§2a). Without a recorded OOB check the operation is REJECTED (§7).
2. A builds `roster v(n+1)` = current + B, `author_key_id=A`, `prev_roster_hash=SHA-256(JCS(current
   plaintext roster))`, signs, encrypts, publishes via CAS.
3. A rebuilds the keyfile: decrypt `repo_key`, re-encrypt (age) to the X25519 of all current members + B.
4. **No new repo key** — B is meant to read history (that is what the shared repo key is for). B then
   pulls the keyfile, unwraps the repo key, and does (§2b) — OOB-anchors the roster_hash.

### 3.2 Remove (A removes C) — minimal rotation (default)
1. A builds `roster v(n+1)` without C, `author_key_id=A`, chained, signed, encrypted, published.
2. A **rotates the repo key**: new `repo_key'` (32 CSPRNG bytes). `pub_pack'` is derived by the same
   §4 v1 rule (HKDF with `repo_id`) but differs because `repo_key` differs. Future packs/manifests
   encrypt to `pub_pack'`. The new keyfile wraps `repo_key'` to the remaining members (not C).
3. **Enforcement = two independent gates:** after rotation C cannot decrypt new manifests/packs (wrong
   repo key), AND C's signatures are rejected (no longer in the roster). Neither gate alone suffices.
- **Residual access (documented honestly):** C keeps whatever it already cloned/decrypted and can pull
  OLD packs from the server (still under the old repo key, which C had) until a full rekey re-encrypts
  them. Minimal rotation does NOT re-encrypt history.

### 3.3 Full rekey (optional, heavy, SEPARATE command)
Re-encrypt all live packs under `repo_key'`, delete the old pack blobs, new manifest listing the new
`pack_id`s. Cuts residual access to history. The server sees all blobs change at once (accepted).
Not the default.

## 4. Manifest acceptance with a roster (FROZEN rule; manifest format UNCHANGED)
A manifest is accepted ⟺: it decrypted under the current `repo_key`; the Ed25519 signature verifies
with the key of the member whose fingerprint == `pusher_key_id`; that member ∈ the **current trusted
roster**; and the `version`/`prev_hash` chain converges (§5.7 v1, unchanged).

### Fork 3 — DECISION (awaiting external soundness review)
`roster_hash` is **NOT** added to the manifest's signed fields. The §5.2 v1 format is unchanged.
Rationale: the key properties are already carried by (a) repo-key rotation = encryption gate on
removal, (b) roster membership = signature gate, (c) version/prev_hash chain = freshness. Binding
`roster_hash` would be defense-in-depth. **Residual threat for review:** roster-downgrade /
cross-roster splice — can the server show a client with a stale roster a manifest signed by a member
valid under the old roster but removed under the current one? Current defense: (i) the removed member
is not in the verifier's current roster → signature rejected; (ii) after rotation they cannot even
produce a decryptable manifest; (iii) the roster pointer is itself under the anti-rollback pin (§1.4),
so a "stale roster" is detected as equivocation. If a concrete attack is found, introduce it as
manifest v2 with a `roster_hash` binding.

## 5. What the server stores now (all ciphertext + integer CAS)
pack blobs, keyfile blob, encrypted manifest + manifest version (CAS), **encrypted roster + roster
version (CAS)**. The server still sees only sizes/timings/which account + two integer counters.

## 6. Locked forks
- **Fork 1:** the roster is changed by ANY single current member with a valid signature. A ≥k threshold
  is a future option (hook point: require k signatures per roster version).
- **Fork 2:** removal = minimal rotation by default; full rekey is a separate heavy command; residual
  access is documented.
- **Fork 3:** manifest format UNCHANGED (no `roster_hash` binding) — awaiting external soundness review.

## 7. SECURITY-CRITICAL — review, not tests (// SECURITY-REVIEW in code)
Carries over the two open §7 v1 items (age-recipient equivalence; sign-then-encrypt). Plus Tier 3:
1. **Fork 3 soundness** — confirm no roster-downgrade / cross-roster splice under rotation + multiple
   signers + chain + roster pin. (External reviewer.)
2. **OOB is the single genesis trust input.** No code path accepts a member key (to wrap or verify)
   from server data without an OOB-anchored chain.
3. **Removal enforcement = repo-key rotation AND roster exclusion.** Both must hold; cover both by test.
4. **Roster pointer under the same anti-rollback pin as the manifest** (version + prev_roster_hash + pin).
5. **"Members are honest" assumption.** Add MUST require/record an explicit OOB fingerprint check of the
   new member BEFORE wrapping the repo key; otherwise a careless member could wrap it to a server key.

## 9. Freeze boundary
- **Frozen (pending §7 soundness items):** roster format (§1), genesis anchoring (§2), add/remove/rotation
  semantics (§3), manifest acceptance rule (§4), roster pointer anti-rollback (§1.4).
- **Manifest format v1 (§5.2) UNCHANGED.**
- **Design next (do not implement):** Tier 4 — HTTP server, bootstrap token/admin, invites (user sets
  their own password), argon2id, sessions/tokens, blob CRUD + CAS endpoints. **An invite grants only API
  access, never roster membership.**
