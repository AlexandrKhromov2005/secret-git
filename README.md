# encgit

End-to-end encrypted git remote: an untrusted server stores **only ciphertext**, and all encryption,
signing, and verification happen on the client. The single security boundary is the client — the server,
even with root, holds no keys and never sees your code, file names, or history.

- `encgit` — the client CLI (identity, init, push/fetch, membership, server login).
- `encgit-server` — the Tier-4 HTTP authorizer. It stores only ciphertext plus auth/CAS metadata and holds
  no keys. It speaks plain HTTP and does **not** terminate TLS itself — see [Deployment requirements](#deployment-requirements-hard).

Read the **[Security model](#security-model)** below — what is and is not protected, in precise terms —
before trusting encgit with anything that matters.

## Security model

encgit is built so an untrusted server — including its operator with root — cannot read or forge your
repository. Be precise about what that does and does not buy you.

### What is protected

- **Confidentiality and integrity of repository content against a root-level server.** The server stores
  only ciphertext (packs, manifest, roster, keyfile); there are no keys on the server, ever. On every fetch
  the client verifies the manifest's Ed25519 signature (the signer must be a current roster member), the
  `roster_hash` binding (m1), the `repo_key_generation` match (m2), and the `version` / `prev_*_hash` chain
  against a local pin. A compromised server or account therefore **cannot decrypt** your content and
  **cannot forge, splice, or roll back** a manifest that a syncing client will accept — such tampering is
  rejected with an error, never silently taken.

### What is NOT protected (stated plainly)

- **Metadata visible to the server.** The server sees the number and sizes of encrypted blobs, the timing
  and frequency of pushes, which account pushed, the `repo_id` (an opaque random identifier, but visible —
  it routes requests), and the monotonic manifest/roster version counters (it needs them as CAS tokens). It
  does **not** see your code, file names, directory structure, commit messages, the history graph, or any
  keys — but the metadata just listed does leak.
- **Availability against a malicious or compromised writer.** A writer — or a server wielding a writer's
  token — can upload junk packs, delete blobs, or otherwise disrupt the team. This is within the model (the
  server is not a security boundary), but it is a real operational risk for a team. Storage quotas and
  garbage collection are **not implemented yet** (a known limitation).
- **Token revocation is account-scoped and admin-driven.** An admin can disable an account
  (`POST /accounts/{username}/disable`), which **immediately revokes all of that account's live API tokens**
  and blocks new logins until `POST /accounts/{username}/enable`. This closes the earlier "no revocation" gap.
  The residual limitation: revocation acts per account, not per individual token, and requires an admin — so a
  leaked token whose account is *not* disabled still lives until its TTL. Keep `TokenTTL` short as defense in
  depth. (A token never yields decryption or forgery regardless; this is an availability/abuse surface, not a
  confidentiality break.)
- **An irreducible floor — a fully frozen, never-syncing participant.** A server that owns storage can
  always withhold updates and show a victim a *self-consistent but stale* snapshot (old roster + keyfile +
  manifest, mutually consistent by generation and `roster_hash`). The m1/m2 bindings do **not** prevent
  this — it is equivocation, which is unpreventable against a storage owner. It is, however, **detectable**:
  the moment the victim synchronizes with any honest peer (or compares state out of band) the divergence
  surfaces.

### The irreducible trust anchor: out-of-band fingerprint verification

Membership security rests on **out-of-band fingerprint verification**. When you add a member you MUST
confirm their fingerprint (from `encgit identity show`) over a trusted channel *before* wrapping the repo
key to their keys; a new member likewise anchors the roster by OOB-comparing its hash. This is the single
trusted off-server event in the whole system. **If you skip the OOB check, a malicious server can substitute
keys and the MITM protection is gone.** It is a requirement on you, the user — the tool cannot do it for you.

### Maturity

encgit has had internal design and implementation review, but it has **not undergone an independent
external security audit**. Get one before trusting it with production secrets. This note is part of being
honest about the tool's maturity — it is stated deliberately, not buried.

## Deployment requirements (HARD)

- **TLS is mandatory.** `encgit-server` speaks plain HTTP and deliberately does **not** terminate TLS. You
  **MUST** run it behind a TLS-terminating reverse proxy: bearer tokens and passwords **MUST NEVER** travel
  in plaintext. (Client encryption protects repository *content* regardless, but the API auth layer is only
  as private as its transport.)
- **Client-IP extraction behind the proxy.** Because a proxy is mandatory, the server sees the proxy's
  address, not the client's. To make per-IP login throttling effective you **MUST** configure trusted
  client-IP extraction: set `-trusted-proxy-cidrs` to your proxy's source CIDR(s) and `-client-ip-header`
  (e.g. `X-Forwarded-For`), and the proxy MUST overwrite that header rather than forward a client-supplied
  value. Left unconfigured the per-IP throttle collapses onto the proxy address (a degradation, not a hole).
  See `docs/FORMAT-SPEC-TIER4.md` §B and §H.

## Build

```
go build ./...
```

## Bring up a server-backed repo from scratch

This is a short sequence, not one command — see `docs/FORMAT-SPEC-TIER4.md` §I ("Founder genesis
provisioning") for the full rationale and security model. In brief:

**Operator (runs the server):**

```
encgit-server --addr 127.0.0.1:8080 --db ./encgit.db --blobs ./blobs \
  [-trusted-proxy-cidrs <proxy CIDR> -client-ip-header X-Forwarded-For]
```

On first start it prints a one-time bootstrap token; exchange it once for the first admin via
`POST /auth/bootstrap`. You **MUST** front it with a TLS-terminating proxy and configure the trusted-proxy
flags — see [Deployment requirements](#deployment-requirements-hard).

**Founder (creates the repo) + admin:**

```
# 1. founder, locally — prints repo_id and fingerprint:
encgit identity new --seed founder.seed          # if you don't have a seed yet
encgit init --store ./initstore --seed founder.seed

# 2. founder -> admin, OUT OF BAND: hand over repo_id (and fingerprint).

# 3. admin, on the server: create the repo with THAT repo_id, then grant the founder writer.
#    RECOMMENDED (invite path): POST /repos {repo_id}, then issue a writer invite; the founder
#    redeems it at POST /auth/register, which atomically creates the account bound to repo_id+writer.
#    ALTERNATIVE (grant by username): POST /repos {repo_id, founder_username} -- but the founder's
#    account MUST already exist before this grant, or it fails.

# 4. founder: log in, publish the genesis, then push:
encgit login --seed founder.seed https://server.example founder
encgit publish-genesis --store https://server.example --repo-id <REPO_ID> \
  --from ./initstore --seed founder.seed
encgit push --store https://server.example --seed founder.seed --repo-id <REPO_ID> --git .
```

`encgit init` writes the genesis (keyfile + roster) to the **local** `--from` store; `publish-genesis`
uploads those already-signed bytes to the freshly-created server repo (it is idempotent and never overwrites
an existing genesis); `push` then publishes the encrypted manifest + packs. Other members are added with
`encgit member-add` (cryptographic membership) and given API accounts via Tier-4 invites — two orthogonal
mechanisms.

### Onboarding another machine

Once a repo exists, a member sets up a new machine for an *existing* identity with one command — it builds the
client, pins the server cert (verified against an out-of-band fingerprint), writes the config, logs in, and
optionally clones:

```
scripts/onboard.sh --server https://HOST --fingerprint <sha256 from a trusted channel> \
  --seed /path/to/your.seed --user USERNAME [--repo-id HEX --dir DIR]
```

Transfer your existing seed to the machine first (it is your identity / master secret); the script never
creates or moves it. Get the fingerprint with
`openssl x509 -in server.crt -noout -fingerprint -sha256` on a machine you trust. After onboarding,
`encgit push` / `encgit fetch` run with no flags (defaults come from `~/.config/encgit/config.json` and the
per-repo `<git>/.encgit/config.json` that `encgit clone` writes; see `encgit config`).

### Updating the server

Roll the server to a new revision in place:

```
scripts/server-update.sh --host root@HOST [--server-url https://HOST --cacert FILE]
```

It runs `go test` as a gate, backs up the DB and tags the running image as `encgit-server:prev`,
syncs the source, rebuilds (the old container keeps serving during the build), recreates the
container, and health-checks (the account count must be unchanged and a login probe must return
401). It prints rollback steps (restore the DB backup + retag the previous image). Updates are
safe because the format is frozen, the API is additive, schema changes use idempotent migrations,
and data lives in the `/var/lib/encgit` host volume that survives container recreation — so
existing clients and data keep working. Most client-only changes need no server update at all.

## Documentation

- `docs/FORMAT-SPEC.md` — frozen on-disk/on-wire format (v1/v2).
- `docs/FORMAT-SPEC-TIER3.md` — roster / membership.
- `docs/FORMAT-SPEC-TIER4.md` — HTTP server, authorization, rate limiting, and the provisioning flow (§I).
- `FORMAT-NOTES.md` — implementation decisions and rationale.
