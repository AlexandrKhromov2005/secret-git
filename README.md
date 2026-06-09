# encgit

End-to-end encrypted git remote. The server stores **only ciphertext** (encrypted packs, manifest, roster,
keyfile) plus the minimum metadata for authorization and CAS — it holds no keys and never sees plaintext, ref
names, or `repo_id` content. A compromised server or account can withhold or junk ciphertext (a DoS) but can
never decrypt or forge.

- `encgit` — the client CLI (identity, init, push/fetch, membership, server login).
- `encgit-server` — the Tier-4 HTTP authorizer. Plain HTTP; **must** run behind a TLS-terminating reverse
  proxy (see `docs/FORMAT-SPEC-TIER4.md` §B).

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
`POST /auth/bootstrap`. Put a TLS proxy in front; behind a proxy, set the trusted-proxy flags so per-IP login
throttling keys on the real client (see §B/§H).

**Founder (creates the repo) + admin:**

```
# 1. founder, locally — prints repo_id and fingerprint:
encgit identity new --seed founder.seed          # if you don't have a seed yet
encgit init --store ./initstore --seed founder.seed

# 2. founder -> admin, OUT OF BAND: hand over repo_id (and fingerprint).

# 3. admin, on the server: create the repo with THAT repo_id and grant the founder writer
#    (POST /repos {repo_id} then a writer invite the founder redeems at POST /auth/register,
#    or POST /repos {repo_id, founder_username} if the account already exists).

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

## Documentation

- `docs/FORMAT-SPEC.md` — frozen on-disk/on-wire format (v1/v2).
- `docs/FORMAT-SPEC-TIER3.md` — roster / membership.
- `docs/FORMAT-SPEC-TIER4.md` — HTTP server, authorization, rate limiting, and the provisioning flow (§I).
- `FORMAT-NOTES.md` — implementation decisions and rationale.
