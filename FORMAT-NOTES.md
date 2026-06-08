# FORMAT-NOTES — implementation decisions within the freedom of FROZEN FORMAT v1

The frozen contract lives in [`docs/FORMAT-SPEC.md`](docs/FORMAT-SPEC.md) (PART 1, verbatim).
This file records the concrete decisions taken where the spec left freedom, so future tiers
stay consistent. Nothing here overrides the frozen format; it pins the gaps.

## Confirmed with the spec owner (would otherwise be ambiguous)

- **`repo_id` bytes inside the pack-recipient HKDF `info`.** §4 says
  `info = "encgit/pack-recipient/v1" || repo_id`. The `|| repo_id` appends the **raw random
  `repo_id` bytes** (16 bytes), NOT its ASCII-hex rendering. The hex form only ever appears as
  the JSON `repo_id` field; key derivation uses the raw bytes.
  → `info = []byte("encgit/pack-recipient/v1") ++ repoIDRaw` (see `internal/crypto`).

- **Tier-1 "helper" scope.** Implemented as a push/fetch **engine + `encgit` CLI subcommands**
  against the local store stub. The `git-remote-encgit` stdin/stdout wire protocol is the
  HTTP-talking remote helper, which §6 assigns to Tier 4, so it is intentionally not built here.

## Sizes / encodings

- **seed** = 32 bytes (CSPRNG); stored locally as 64 lowercase hex chars in a `0600` file.
- **repo key** = 32 bytes (CSPRNG).
- **repo_id** = 16 bytes (128-bit) random, fixed at `init`; serialized as lowercase hex in the
  manifest `repo_id` field. Length was unspecified by §5.2 ("случайный"); 16 bytes chosen.
- **fingerprint** = `SHA-256(pub_x25519_raw32 || pub_ed25519_raw32)` → 32 bytes, rendered as
  lowercase hex for the manifest `pusher_key_id` field and for the (placeholder) OOB output.
  The richer human-readable fingerprint *rendering* is Tier 3; here it is plain hex.
- **manifest `sig`** = standard base64 (`base64.StdEncoding`) of the 64-byte Ed25519 signature.
- **content hash / blob id** = lowercase hex of `SHA-256(blob_ciphertext)`. `pack_id` and the
  store's content addresses are exactly this.

## HKDF (golang.org/x/crypto/hkdf, SHA-256)

- The derivations use **full HKDF (RFC 5869): extract + expand**, via `hkdf.New(sha256.New, ikm,
  salt, info)` — not expand-only. The `extract` step runs `HMAC-SHA256(salt, ikm)` to produce the
  PRK, then `expand` produces the output keying material.
- `salt=""` is implemented as an empty/nil salt, which Go's HKDF (per RFC 5869) substitutes with a
  block of `hashLen` zero bytes for the extract HMAC key — the HKDF-with-no-salt default.
  // SECURITY-REVIEW lives at each call site.
- Exact `info` strings, byte-for-byte (also asserted equal to `docs/FORMAT-SPEC.md` by tests):
  - member X25519: `encgit/member-x25519/v1`
  - member Ed25519: `encgit/member-ed25519/v1` (then `ed25519.NewKeyFromSeed`)
  - pack/manifest recipient: `encgit/pack-recipient/v1` ++ raw `repo_id` bytes
- `seed -> X25519` and `seed -> Ed25519` use distinct `info` labels, so the two key materials
  are independent (no dual-use).
- **Cross-checked externally:** `internal/identity` re-derives the member keys with an independent
  from-scratch RFC 5869 HKDF (HMAC-extract + HMAC-expand) and confirms the result matches — proving
  the extract+expand semantics and the `salt=""` zero-key behavior, not just self-consistency.

## Entropy invariant (§2)

- Member-key uniqueness rests entirely on the seed being **full-entropy 32 bytes from
  `crypto/rand`** (`identity.NewSeed`). Distinct members ⇒ distinct seeds ⇒ distinct keys is only
  guaranteed because the seed space (2^256) makes collisions negligible; there is no other
  uniqueness mechanism.
- `identity.FromSeed` rejects an obviously **degenerate seed** (all 32 bytes identical — covers the
  all-zero / uninitialized case) with `ErrDegenerateSeed`. This is a guard against a forgotten or
  zeroed seed; it deliberately does **not** attempt to measure the entropy of a non-constant seed
  (impossible in general) — supplying a high-entropy seed remains the caller's responsibility.

## age usage

- All bulk encryption (packs, manifest) and the keyfile wrap go through `filippo.io/age` only.
  No hand-rolled AEAD, nonce, or chunking anywhere. age performs its own salt/HKDF/STREAM
  chunking/tags/nonces internally; we treat the whole age output as one opaque blob.
- **age has no public constructor from raw key bytes**, so derived 32-byte X25519 scalars are
  turned into `*age.X25519Identity` by bech32-encoding them exactly the way age's own
  `X25519Identity.String()` does — `bech32.Encode("AGE-SECRET-KEY-", scalar)` then upper-cased —
  and feeding that to `age.ParseX25519Identity`. Because the produced string is byte-identical
  to what age would emit for the same scalar, age round-trips it. See `internal/bech32` (a
  minimal BIP-173 encoder; no decode needed) and `internal/agekey`.
- The age recipient for a scalar is `identity.Recipient()`. Raw X25519 public bytes (needed for
  the fingerprint and as the keyfile recipient) are computed with
  `curve25519.X25519(scalar, curve25519.Basepoint)`, which equals age's own recipient public key.
- **Cross-checked externally (§7.1):** `internal/agekey` confirms the derived public key against the
  implementation-independent **RFC 7748 §6.1 known-answer vectors** and against `crypto/ecdh` (a
  different X25519 implementation), and confirms the age recipient string carries exactly that
  public key. This rules out a "consistently wrong" clamping that a round-trip alone would miss.

## Canonical JSON (RFC 8785 JCS)

- **Self-implemented** canonical encoder (`internal/manifest`, marked // SECURITY-REVIEW for
  determinism), not a third-party library. This is safe here because the manifest value space is
  restricted to: strings, `uint64`, `null`, string→string maps, and string arrays — so the hard
  part of JCS (ECMAScript number canonicalization for floats) never arises ("только строки и
  целые (без float)" per §5.1).
- Object member names are sorted by **UTF-16 code-unit** sequence (JCS requirement), implemented
  via `utf16.Encode([]rune(key))`. For the all-ASCII keys used here this coincides with byte
  order, but the UTF-16 rule is honored for arbitrary ref names too.
- String escaping follows RFC 8785 §3.2.2.2: `"`, `\`, and `\b \t \n \f \r` use short escapes;
  other control chars `< U+0020` use lowercase `\u00xx`; every other code point is emitted
  literally as UTF-8. Arrays preserve order (JCS does not sort arrays); integers via
  `strconv.FormatUint`.
- **Validated against external vectors, not self-tuned expectations:** the encoder is checked
  byte-for-byte against the RFC 8785 reference test vectors from the `json-canonicalization`
  project (`internal/manifest/testdata/jcs/`, Apache-2.0) and the RFC 8785 §3.2.2.2 escape table —
  covering UTF-16 code-unit key sorting including a surrogate-pair (astral) key, the short escapes
  vs `\u00xx`, and literal non-ASCII. Out-of-domain inputs (floats, booleans, signed ints,
  heterogeneous arrays) must make the encoder **fail explicitly** rather than emit wrong bytes;
  this is tested too. If any external vector ever fails to match, the format is non-conformant —
  the response is to STOP and report, never to change the encoder.

## Manifest hashing & the prev/pin chain

- `manifest_hash` (used for `prev_manifest_hash` and for the local pin) = `SHA-256` of the
  **canonical plaintext including the `sig` field** — i.e. exactly the bytes that get encrypted
  in §5.3 step 4 (`JCS(manifest_with_sig)`). Signing bytes (§5.3 step 1) are `JCS(manifest)`
  *without* `sig`; the hash is over *with* `sig`. These two are deliberately different.
- Versions start at **1** for the first successful push; the store reports version **0** when no
  manifest exists yet, which is also the `expected_version` of the first push.

## Signature verification & the member set

- §5.3 says the verifier checks the signature with the key named by `pusher_key_id` and that this
  key "must be among the keyfile recipients". The fingerprint is a hash, so the verifier needs the
  actual member public keys to match it against. In v1 there is a single participant, so the
  known-member set is the **local member (self)**: fetch computes the local member's fingerprint,
  requires it to equal `pusher_key_id`, then verifies with that member's Ed25519 public key.
  Distributing/managing a multi-member roster is Tier 3.

## Local state, rollback / equivocation (§5.7)

- A per-remote local state file (JSON) holds `{version, manifest_hash, imported_packs}`.
  `version` + `manifest_hash` are the §5.7 pin; `imported_packs` is a pure fetch optimization
  (which pack ids are already in the local object store) and is not part of the security check.
- First fetch with no pin is trust-on-first-use; it accepts the manifest and records the pin.
  Subsequent fetches require `new.version > pin.version` AND
  `new.prev_manifest_hash == pin.manifest_hash`, else they reject (rollback/fork detected).
- After a successful push the pusher updates its own pin to the just-pushed state.

## Store interface (`internal/store`)

- The server is modeled as an interface holding only opaque content-addressed blobs, the single
  mutable manifest pointer (blob + integer CAS version), and the keyfile blob — never keys,
  `repo_id`, ref names, or anything plaintext. The local stub (`internal/store/localfs`) is a
  directory; CAS is serialized with an OS file lock. Tier 4 swaps in an HTTP-backed implementation
  of the same interface without touching format code.
- `repo_id` is **not** stored by the interface: it is repo "coordinates" handed to a member out of
  band (in Tier 4 it is the server-side repo identifier / URL). The CLI keeps it in a small local
  config file next to the git repo.

## git plumbing

- Push builds the new-objects pack with
  `git rev-list --objects <want> --not <have> | git pack-objects --stdout`, where `have` = the ref
  SHAs from the current manifest. Packs are **non-thin** (pack-objects default), so each pack is
  self-contained and can be indexed independently. If a push introduces no new objects, no pack is
  added (the manifest still advances refs/version).
- Fetch verifies `SHA-256(blob) == pack_id`, decrypts, then `git index-pack --stdin --fix-thin`
  into the local object store, in manifest `packs` order, then `git update-ref` for each manifest
  ref.
