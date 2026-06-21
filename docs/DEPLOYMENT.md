# Deploying encgit-server

The canonical guide to standing up the server. `encgit-server` speaks plain HTTP and is **not**
a security boundary — it stores only ciphertext + auth/CAS metadata (see the README security
model). It therefore **must** sit behind a TLS-terminating reverse proxy. This guide deploys it
as two containers: **Caddy** (TLS) in front of **encgit-server**.

For the Dockerfile build targets (`devtest`, `ci-test`, `prod`) and developer/test workflows,
see [`Docker.md`](Docker.md). For the API/auth details, see
[`FORMAT-SPEC-TIER4.md`](FORMAT-SPEC-TIER4.md).

## Prerequisites

- A host with Docker Engine + the Compose plugin.
- TLS: either a **domain** pointed at the host (→ automatic Let's Encrypt), or a **bare IP**
  (→ a self-signed cert that clients pin out of band).
- The committed templates [`deploy/docker-compose.yml`](../deploy/docker-compose.yml) and
  [`deploy/Caddyfile`](../deploy/Caddyfile).

## Layout on the deploy host

Put the deploy config in one directory (the examples use `/opt/encgit`):

```
/opt/encgit/
  docker-compose.yml      # from deploy/docker-compose.yml
  Caddyfile               # from deploy/Caddyfile
  certs/                  # server.crt + server.key  (bare-IP / self-signed only)
  src/                    # the encgit source tree (git archive or git clone)
```

Data (the SQLite DB + blob storage) is persisted in the host path `/var/lib/encgit`, which
survives container recreation.

## 1. Source

```
mkdir -p /opt/encgit/src
# from a checkout on your machine:
git archive --format=tar HEAD | ssh root@HOST 'tar -x -C /opt/encgit/src'
# or, on the host:  git clone https://github.com/AlexandrKhromov2005/secret-git /opt/encgit/src
```

## 2. TLS certificate

**Bare IP (self-signed):** generate a cert with the host IP in the SAN, then have clients pin it.

```
mkdir -p /opt/encgit/certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
  -keyout /opt/encgit/certs/server.key -out /opt/encgit/certs/server.crt \
  -subj "/CN=encgit-server" -addext "subjectAltName=IP:<HOST_IP>"
chmod 600 /opt/encgit/certs/server.key
# fingerprint to hand to clients out of band (they verify it during onboarding):
openssl x509 -in /opt/encgit/certs/server.crt -noout -fingerprint -sha256
```

**Domain (Let's Encrypt):** skip the cert — switch `Caddyfile` to the domain block (see the
comment in `deploy/Caddyfile`); Caddy obtains and renews the cert automatically.

## 3. Data directory

```
mkdir -p /var/lib/encgit/blobs
chown -R 65532:65532 /var/lib/encgit   # the distroless nonroot uid the container runs as
```

## 4. Build and run

```
cd /opt/encgit
DOCKER_BUILDKIT=1 docker compose build   # builds encgit-server:prod from src/Docker/Dockerfile
docker compose up -d
docker compose ps
```

8080 is intentionally not published — only Caddy reaches it, on the internal network.

## 5. Bootstrap the first admin

On first start (empty DB) the server prints a one-time bootstrap token:

```
docker compose logs encgit-server | grep 'bootstrap token'
```

Exchange it once for the first admin (over TLS — pin the cert with `--cacert` for a bare IP):

```
curl --http1.1 --cacert certs/server.crt -X POST https://<HOST>/auth/bootstrap \
  -H 'Content-Type: application/json' -d '{"token":"<TOKEN>","username":"admin","password":"<PW>"}'
```

Then provision repos and members per the README ("Bring up a server-backed repo from scratch"
and `scripts/add-member.sh`).

## 6. Firewall (hardening)

```
ufw allow 22/tcp && ufw allow 443/tcp && ufw --force enable
```

The provider edge may answer SYN on all ports (a port scan can look "open" everywhere); only
443 has a real service, and 8080 is never bound on the host. The trusted-proxy + client-IP
flags are already set in the compose file (the `172.28.0.0/16` edge subnet is Caddy's network).

## Updating

Roll the server to a new revision with a test gate, DB backup, and rollback safety:

```
scripts/server-update.sh --host root@HOST --server-url https://HOST --cacert /path/to/server.crt
```

See the README ("Updating the server") for why updates are safe (frozen format, additive API,
idempotent migrations, persistent data volume).
