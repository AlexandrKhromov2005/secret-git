# encgit — Tier 4 (HTTP server + authorization)

> Tier 4 is the **operational** layer. It does NOT change the on-disk/on-wire format (v2) or the
> `store.Store` interface — both are FROZEN (see `FORMAT-SPEC.md`, `FORMAT-SPEC-TIER3.md`). The HTTP
> server is a new implementation of the same store behind HTTP. This document is the interop contract.

## A. Bearing principle (frozen)
- The server is a **dumb API authorizer, NOT a security boundary.** It stores ONLY ciphertext (packs,
  manifest, roster, keyfile — opaque bytes) plus the minimum metadata for authorization and CAS. **There
  are no keys on the server, ever.** It has no git awareness; it does not parse, validate JCS, or check
  signatures (it cannot — it has no keys).
- **Accounts and the roster are orthogonal.** The roster (cryptographic membership) is an opaque blob to
  the server. Having an account NEVER means roster membership. Authorization answers only "does account X
  have access to repo R, and with what role" — nothing more.
- **Threat consequence:** a compromised account = DoS / junk-pack upload / blob deletion / impersonation
  ON THE WIRE — NEVER decryption or forgery. A junk pack is rejected by the fetching client at manifest
  signature verification; a stale/foreign manifest fails the client's m1 (`roster_hash`) and m2
  (`repo_key_generation`) checks. Tier 4 introduces NO place where the client trusts the server for
  confidentiality or integrity.

## B. Deployment requirement (HARD)
TLS is mandatory in deployment: bearer tokens and passwords MUST NEVER travel in plaintext. The
application intentionally does NOT terminate TLS — run it behind a TLS-terminating reverse proxy. The
server listens on plain HTTP only.

**Client-IP extraction behind the proxy (HARD, for the per-IP login throttle).** Because a reverse proxy
is mandatory, `r.RemoteAddr` is the proxy's address, not the client's — so by default the per-IP login
throttle (§H) keys on the proxy and collapses to a single global counter. To make per-IP throttling
effective the operator MUST configure trusted client-IP extraction: set `-trusted-proxy-cidrs` to the
proxy's source CIDR(s) and `-client-ip-header` to the header the proxy sets (e.g. `X-Forwarded-For`). The
proxy MUST **overwrite/append** that header itself (the rightmost token is trusted) and MUST NOT forward a
client-supplied value as-is. The server trusts the header ONLY for connections whose source address is in
the configured CIDRs (trust bound to the connection, not a flag); otherwise, or on any parse failure, it
fails closed to `RemoteAddr`. Leaving this unconfigured is safe (no spoofable trust) but degrades per-IP
throttling to the proxy address — it is a degradation, not a hole.

## C. HTTP API
`repo_id` is in the path; all blob/manifest/roster/keyfile bodies are opaque `application/octet-stream`.
Authentication: `Authorization: Bearer {token}` on every data and admin endpoint.

### Auth (unauthenticated entry points)
| Method/Path | Body | Result |
|---|---|---|
| `POST /auth/bootstrap` | `{token, username, password}` | 201 create first admin; 401 bad/used token |
| `POST /auth/register`  | `{invite_token, username, password}` | 201 create account; 401 bad/expired invite |
| `POST /auth/login`     | `{username, password}` | 200 `{token}` (returned once); 401 bad credentials |

### Admin (instance-level; requires an admin token)
| Method/Path | Body | Result |
|---|---|---|
| `POST /repos` | `{repo_id, founder_username?}` | 201; assigns founder writer if given; 409 if exists |
| `POST /repos/{repo_id}/invites` | `{role}` (`reader`/`writer`) | 201 `{invite_token}` (once) |

### Data (repo-scoped roles; opaque bytes)
| Method/Path | Role | Result / semantics |
|---|---|---|
| `GET /repos/{id}/blobs/{hash}`  | reader | 200 body; 404 |
| `HEAD /repos/{id}/blobs/{hash}` | reader | 200 / 404 |
| `PUT /repos/{id}/blobs/{hash}`  | writer | 204; 400 if `SHA-256(body) != hash`; idempotent |
| `DELETE /repos/{id}/blobs/{hash}` | writer | 204 (absent is not an error) |
| `GET /repos/{id}/manifest` | reader | 200 body + `ETag: "{version}"`; **404 = no manifest** |
| `PUT /repos/{id}/manifest` | writer | CAS: requires `If-Match: "{version}"`; on match writes & sets version+1 (204 + new `ETag`); **412** on mismatch |
| `GET /repos/{id}/roster`   | reader | 200 body + `ETag: "{version}"`; **404 = no roster** (a `version 0` row is the EXISTING genesis) |
| `PUT /repos/{id}/roster`   | writer | CAS: requires `If-Match: "{version}"` AND `Encgit-New-Version: "{n}"`; sets version=n (204 + `ETag`); **412** on mismatch |
| `GET /repos/{id}/keyfile`  | reader | 200 body; 404 (singleton, no version) |
| `PUT /repos/{id}/keyfile`  | writer | 204 (singleton, overwrite, **no CAS**) |

- **CAS mapping:** a `412 Precondition Failed` on `PUT /manifest` or `PUT /roster` is mapped by the
  HTTP store to the same version-conflict error the localfs stub returns, so the helper's EXISTING
  rebase-retry logic is reused unchanged.
- **Why the roster needs an explicit new version:** the manifest's first version is `1` (server can do
  `version+1`), but the roster's genesis is `0→0` (not `expected+1`) — genesis-create and the first
  change both have `If-Match: "0"`. So the roster PUT carries the target version in `Encgit-New-Version`,
  mirroring `store.CASRoster(expected, blob, newVersion)` exactly. A missing roster reads as version 0
  (the genesis insert path), identical to localfs.
- **401 vs 403:** unauthenticated → 401; authenticated but lacking the required role for `repo_id` → 403
  (deny-by-default). A token for one repo is rejected (403) on another repo_id.

## D. Authorization model
- **Bootstrap (one-time):** on first start with no admin, the server mints a CSPRNG 256-bit base64url
  bootstrap token, prints it to the console, and stores ONLY its SHA-256. It is exchanged once for the
  first admin account, then marked used. // SECURITY-REVIEW.
- **Invites (one-time, expiring, repo+role bound):** an admin issues an invite (`repo_id`+role); the
  server stores SHA-256(token)+repo_id+role+expiry+used. A user redeems it by setting their own password,
  creating an account bound to that repo_id with that role. // SECURITY-REVIEW.
- **Passwords:** argon2id (`golang.org/x/crypto/argon2`), m=19 MiB, t=2, p=1, 16-byte salt, 32-byte
  output; the DB stores salt+params+hash, never the plaintext. // SECURITY-REVIEW (confirm params).
- **Sessions:** `POST /auth/login` verifies argon2id ONCE and issues a CSPRNG 256-bit API token (returned
  once); the DB stores SHA-256(token)+account_id+expiry. Each later request carries the bearer token;
  lookup is by hash, constant-time, expiry-checked — so argon2id is not recomputed per request.
  // SECURITY-REVIEW.
- **Role matrix (deny-by-default; every data endpoint checks the role for `repo_id`):**
  - `reader` → GET/HEAD on blobs, manifest, roster, keyfile.
  - `writer` → reader + PUT blobs/manifest/roster/keyfile + DELETE blobs.
  - `admin` → instance-level only (create repo, create invites). **Admin grants NO automatic data
    access**: an admin still needs a repo-scoped role to touch repo data (orthogonality at the API layer
    too).
- **Atomic single-use (consume race).** Bootstrap and invite redemption claim the token with a single
  guarded `UPDATE ... SET used=1 WHERE token_hash=? AND used=0 [AND expiry>?]` and require exactly one
  affected row, inside the same transaction that creates the account. Two concurrent redemptions of one
  token therefore yield exactly one account (no two-admins / invite-reuse race), independent of the DB
  connection-pool size. Used / expired / unknown collapse to one generic rejection (no oracle).
  // SECURITY-REVIEW.
- **No login user-enumeration.** `POST /auth/login` returns an identical `401 invalid credentials` for an
  unknown username and a wrong password, and runs an equivalent-cost argon2id pass in BOTH branches (a
  decoy hash when the username is unknown) so response timing does not reveal account existence.
  // SECURITY-REVIEW.
- **Known limitation (v1): no token revocation.** A leaked/compromised API token stays valid until its
  expiry — there is no deny-list or rotation, and no way to disable an account and invalidate its live
  tokens. Account disablement + token revocation are deferred to the "account management" increment. This
  is an acknowledged availability/abuse gap, NOT a confidentiality break: a token never yields decryption
  or forgery (ЧАСТЬ A); mitigate operationally with short `TokenTTL`.

## E. Server storage
- Metadata: SQLite via the pure-Go `modernc.org/sqlite` (no cgo). Tables: `accounts`, `repos`,
  `repo_access`, `invites`, `api_tokens`, `bootstrap`, `manifest_state`, `roster_state`, `login_throttle`
  (per-IP / per-username login backoff state; see §H).
- Packs/blobs and the keyfile are files on disk under a per-repo directory (blobs by content hash).
- Manifest and roster blobs live INLINE in their `*_state` rows so the CAS is a single atomic SQL
  transaction (`UPDATE ... SET version=?, blob=? WHERE repo_id=? AND version=?`; 0 rows affected → 412).

## F. Out of scope (next increment; ЧАСТЬ F)
GC of orphaned packs; quotas; account management beyond creation (including account disablement and
API-token revocation — see the "no token revocation" limitation in ЧАСТЬ D); in-app TLS termination;
CAPTCHA; defense against a fully distributed (many-IP × many-username) login attack beyond §H.
(`/auth/login` rate-limiting itself is now implemented — see §H.)
Still out of scope (a deliberate choice, forced by the frozen `helper.Init`, which self-generates
`repo_id` and writes the genesis locally): a *one-shot* `encgit init --store URL` that both creates and
provisions a server repo. Bringing up a server-backed repo is instead a short sequence with a dedicated
`encgit publish-genesis` step — see §I.

## G. Client
- The store is selected by the `--store` value's scheme: an `http://`/`https://` URL → the HTTP store;
  any other value → a localfs directory (no heuristics beyond the scheme).
- `encgit login --seed FILE URL USERNAME` prompts for the password (no echo), `POST /auth/login`, and
  saves the API token in a `0600` JSON file (`URL → token`) next to the seed. `push`/`fetch` then send it
  as `Authorization: Bearer`.

## H. /auth/login rate limiting
Unbounded `/auth/login` is a memory-amplification DoS (argon2id is 19 MiB per attempt) and a
password-guessing surface. Two complementary mechanisms sit IN FRONT of argon2id; the cheap rejections
(429, 503) MUST happen BEFORE any argon2id — that is the load-bearing invariant.

**1. Persistent per-IP + per-username exponential backoff (SQLite `login_throttle`).** Two independent
failure counters: per-IP (coarse source throttle) and per-username (protects a specific account from
guessing). On each attempt, in strict order: (a) prune rows whose window expired more than a grace ago
(self-cleaning, so junk usernames cannot grow the table); (b) read the `('ip',ip)` and `('user',user)`
rows — if EITHER `window_until > now`, reject **429** with `Retry-After`, **without** argon2id; (c)
otherwise run the verify; (d) on credential failure bump BOTH counters (`fail_count++`,
`window_until = now + backoff(fail_count)`); on success reset BOTH. Backoff is
`min(MAX_BACKOFF, BASE·2^(n-1))` — **always finite and capped (defaults BASE=1s, MAX_BACKOFF=60s)**, never
a hard lockout (a lockout keyed by an attacker-chosen username would itself be a DoS on the victim). The
per-username counter is kept for ANY presented username — existing or not — and applied identically, so
throttling never becomes an account-existence oracle. `// SECURITY-REVIEW`.

**2. In-process limiter on concurrent argon2id (peak-memory ceiling).** A counting semaphore bounds
simultaneous argon2id to `MAX_CONCURRENT_ARGON2` (default 4 ≈ 4×19 MiB). Acquisition is a try-with-timeout
(`ACQUIRE_TIMEOUT`, default 2s); on timeout the request gets **503** cheaply, **without** argon2id (so a
flood cannot pile up waiting goroutines). The slot wraps BOTH the real verify and the anti-enumeration
decoy, preserving equal-work symmetry. This is an in-process resource bond, deliberately NOT in SQLite
(that is the separate persistent-count mechanism). `// SECURITY-REVIEW`.

**Client-IP key:** see §B — the per-IP key uses the trusted proxy header only from a trusted source CIDR
(rightmost token), else `RemoteAddr` (fail closed).

**Anti-enumeration decoy invariant (now explicit).** The decoy defeats timing-based enumeration only if its
argon2id cost equals a real verify's. argon2-params are process-global today (every `hashPassword` uses the
same constants), and the decoy mirrors them. A guard test (`TestDecoyArgonParamsMatchProduction`) fails if
the params/lengths `hashPassword` emits ever drift from the decoy. **If params ever become per-account or
versioned, the login decoy MUST mirror the probed account's cost**, or timing diverges and enumeration
reopens. `// SECURITY-REVIEW`.

**Residual risk (acknowledged MVP floor, not fixed here).** The FIRST attempt on a *fresh* key pays one
argon2id (no window yet); rotating keys yields one "free" argon2id per new key. Peak memory is still bounded
by the semaphore, and guessing a specific account is still bounded by the per-username backoff. A fully
distributed attack (many IPs × many usernames) can therefore cause argon2id work, but not unbounded memory
and not fast guessing of any one account. CAPTCHA / global-rate / proof-of-work defenses against that are
out of scope (§F).

## I. Founder genesis provisioning (flow)
Bringing up a server-backed repo from scratch is a short sequence, not one command:

1. **Founder, locally:** `encgit init --store <dir> --seed FILE` → generates `repo_id`, the repo key, the
   genesis roster (v0) and the keyfile, writing them to the local `<dir>` store. It prints `repo_id` and
   the founder `fingerprint`.
2. **Founder → admin, out of band:** hand over `repo_id` (and the `fingerprint`, for the same roster
   fingerprint-verification members already do at add time).
3. **Admin, on the server:** `POST /repos {repo_id}` with that exact `repo_id` (the server stores the id it
   is given; it does not generate one), then grant the founder writer. **Recommended — the invite path:**
   issue a writer invite and have the founder redeem it at `POST /auth/register`, which atomically creates
   the account bound to this `repo_id`+writer (an atomic single-use+binding, validated in the hardening
   pass). **Alternative — grant by username:** `POST /repos {repo_id, founder_username}`, but the founder's
   account MUST already exist before this grant — otherwise the server returns an error, because the username
   grant binds an existing account and cannot create one. (This ordering pitfall is why the invite path is
   recommended.)
4. **Founder:** `encgit login --seed FILE URL founder` (saves the API token next to the seed), then
   **`encgit publish-genesis --store URL --repo-id HEX --from <dir> --seed FILE`** — this uploads the
   already-signed genesis (keyfile + genesis roster) from the local `<dir>` to the server over the same
   `store.Store` interface push uses (no new crypto, no new store methods). Then `encgit push` publishes
   the first manifest + packs.
5. **Further members:** added by the Tier-3 membership flow (`member-add` → keyfile re-wrap) and given API
   accounts by Tier-4 invites — two ORTHOGONAL mechanisms.

**Why a sequence, not a one-shot `init --store URL`.** `helper.Init` is frozen: it self-generates `repo_id`
and writes the genesis into a *local* store. But the HTTP store needs `repo_id` to route, and the admin
creates the repo (with access control) and grants writer *before* the founder may write — so a single
command cannot both invent `repo_id` and land the genesis in a pre-authorized server repo. `publish-genesis`
is the explicit bridge: a separate, after-the-fact transfer of finished bytes. `git push` is deliberately
left untouched (it publishes only manifest + packs).

**Why `publish-genesis` is safe to re-run.** The keyfile is a singleton and the roster is published with
the genesis CAS baseline `CASRoster(expected=0, blob, newVersion=0)` (exactly as `helper.Init`). The command
first reads the remote: it publishes only what is absent, no-ops when the remote already holds the
byte-identical genesis, and refuses (never overwrites) a differing remote keyfile or any remote roster that
is not the byte-identical genesis (e.g. one already advanced past v0). // SECURITY-REVIEW.

**Orthogonality (account ↔ roster).** Creating an account or redeeming an invite grants only API access
(`accounts`/`repo_access`); it confers NO cryptographic membership. Being added to the roster grants
cryptographic membership; it confers NO API access. A compromised server/account can withhold or junk
ciphertext (DoS) but can never decrypt or forge — provisioning does not change that. // SECURITY-REVIEW.
