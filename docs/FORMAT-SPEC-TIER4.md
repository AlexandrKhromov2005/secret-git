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

## E. Server storage
- Metadata: SQLite via the pure-Go `modernc.org/sqlite` (no cgo). Tables: `accounts`, `repos`,
  `repo_access`, `invites`, `api_tokens`, `bootstrap`, `manifest_state`, `roster_state`.
- Packs/blobs and the keyfile are files on disk under a per-repo directory (blobs by content hash).
- Manifest and roster blobs live INLINE in their `*_state` rows so the CAS is a single atomic SQL
  transaction (`UPDATE ... SET version=?, blob=? WHERE repo_id=? AND version=?`; 0 rows affected → 412).

## F. Out of scope (next increment; ЧАСТЬ F)
GC of orphaned packs; quotas; rate-limiting; account management beyond creation; in-app TLS termination.
Also out of scope (forced by the frozen `helper.Init`, which self-generates `repo_id`, and the
minimal-client constraint): a one-shot CLI command for a founder to provision a repo's genesis over HTTP.
The genesis flow is: founder runs `encgit init` locally → reports `repo_id` to an admin → admin
`POST /repos {repo_id, founder_username}` + a writer invite → founder logs in and uploads the genesis
keyfile+roster. The e2e test performs this upload directly; a dedicated provisioning command is deferred.

## G. Client
- The store is selected by the `--store` value's scheme: an `http://`/`https://` URL → the HTTP store;
  any other value → a localfs directory (no heuristics beyond the scheme).
- `encgit login --seed FILE URL USERNAME` prompts for the password (no echo), `POST /auth/login`, and
  saves the API token in a `0600` JSON file (`URL → token`) next to the seed. `push`/`fetch` then send it
  as `Authorization: Bearer`.
