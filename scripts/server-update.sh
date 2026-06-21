#!/usr/bin/env bash
# encgit server update — roll the server to a new code revision, safely:
#   pre-flight `go test` -> back up the DB + tag the running image -> sync source ->
#   rebuild -> recreate (the /var/lib/encgit data volume persists; the schema migrates
#   forward via idempotent migrations) -> health check. Prints rollback steps on the way out.
#
# Safe-by-design: the on-disk/on-wire format is frozen, the HTTP API is additive, schema
# changes go through idempotent migrations, and data lives in a host volume that survives
# container recreation — so existing clients and data keep working across an update.
#
# Usage:
#   scripts/server-update.sh --host root@HOST [--remote-dir /opt/encgit] [--ref HEAD] \
#       [--server-url https://HOST --cacert FILE]   # adds an external login probe
#       [--skip-tests] [--yes]
set -euo pipefail

HOST="" REMOTE_DIR="/opt/encgit" REF="HEAD" SERVER_URL="" CACERT="" SKIP_TESTS=0 YES=0
usage() { sed -n '2,16p' "$0"; }
while [ $# -gt 0 ]; do
	case "$1" in
	--host) HOST="$2"; shift 2 ;;
	--remote-dir) REMOTE_DIR="$2"; shift 2 ;;
	--ref) REF="$2"; shift 2 ;;
	--server-url) SERVER_URL="$2"; shift 2 ;;
	--cacert) CACERT="$2"; shift 2 ;;
	--skip-tests) SKIP_TESTS=1; shift ;;
	--yes) YES=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) echo "server-update: unknown argument: $1" >&2; usage; exit 2 ;;
	esac
done
[ -n "$HOST" ] || { echo "server-update: --host root@HOST is required" >&2; usage; exit 2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
SHA="$(git rev-parse --short "$REF")"
echo "server-update: deploying $REF ($SHA) to $HOST:$REMOTE_DIR"
if ! git diff --quiet HEAD 2>/dev/null; then
	echo "  note: working tree has uncommitted changes — only the committed $REF tree is deployed"
fi

# account count via a read-only SQLite query on the host (heredoc -> ssh stdin -> python3).
count_accounts() {
	ssh "$HOST" python3 - <<'PY' 2>/dev/null || echo '?'
import sqlite3
try:
    c = sqlite3.connect('file:/var/lib/encgit/encgit.db?mode=ro', uri=True)
    print(c.execute('select count(*) from accounts').fetchone()[0])
except Exception:
    print('?')
PY
}

if [ "$SKIP_TESTS" -eq 0 ]; then
	echo "[1/6] go test ./..."
	go test ./... >/dev/null
	echo "  tests pass"
else
	echo "[1/6] skipping tests (--skip-tests)"
fi

if [ "$YES" -ne 1 ]; then
	printf "proceed with updating %s to %s? [y/N] " "$HOST" "$SHA"
	read -r ans </dev/tty
	case "$ans" in y | Y | yes | YES) ;; *) echo "aborted"; exit 1 ;; esac
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo backup)"
echo "[2/6] backing up DB + tagging the running image (encgit-server:prev)"
REMOTE_DIR="$REMOTE_DIR" STAMP="$STAMP" ssh "$HOST" "bash -s" <<REMOTE
set -e
mkdir -p "$REMOTE_DIR/backups/$STAMP"
for f in encgit.db encgit.db-wal encgit.db-shm; do
	[ -f "/var/lib/encgit/\$f" ] && cp -a "/var/lib/encgit/\$f" "$REMOTE_DIR/backups/$STAMP/" || true
done
docker image inspect encgit-server:prod >/dev/null 2>&1 && docker tag encgit-server:prod encgit-server:prev || true
echo "  backup -> $REMOTE_DIR/backups/$STAMP"
REMOTE

before="$(count_accounts)"
echo "  accounts before: $before"

echo "[3/6] syncing source ($SHA)"
git archive --format=tar "$REF" | ssh "$HOST" "rm -rf '$REMOTE_DIR/src' && mkdir -p '$REMOTE_DIR/src' && tar -x -C '$REMOTE_DIR/src'"

echo "[4/6] build (old container keeps serving during the build)"
ssh "$HOST" "cd '$REMOTE_DIR' && DOCKER_BUILDKIT=1 docker compose build encgit-server >/dev/null && echo '  built'"

echo "[5/6] recreate"
ssh "$HOST" "cd '$REMOTE_DIR' && docker compose up -d >/dev/null && docker compose ps --format '{{.Name}} {{.Status}}'"

echo "[6/6] health check"
sleep 4
after="$(count_accounts)"
echo "  accounts after: $after (was $before)"
if [ "$before" != "$after" ]; then
	echo "  ⚠️ account count changed ($before -> $after) — investigate before trusting the update!" >&2
fi
if [ -n "$SERVER_URL" ]; then
	ca=()
	[ -n "$CACERT" ] && ca=(--cacert "$CACERT")
	code="$(curl --http1.1 "${ca[@]}" -sS -o /dev/null -w '%{http_code}' --max-time 15 \
		-X POST "$SERVER_URL/auth/login" -H 'Content-Type: application/json' \
		-d '{"username":"_probe_","password":"x"}' 2>/dev/null || echo 000)"
	echo "  external /auth/login -> HTTP $code (expect 401)"
	[ "$code" = "401" ] || echo "  ⚠️ unexpected probe status $code — check the server" >&2
fi

cat <<EOF

server-update: done — $SHA deployed.
Roll back on $HOST if anything is wrong:
  cd $REMOTE_DIR && docker compose down
  cp -a backups/$STAMP/encgit.db* /var/lib/encgit/        # restore the DB
  docker tag encgit-server:prev encgit-server:prod        # restore the previous image
  docker compose up -d
EOF
