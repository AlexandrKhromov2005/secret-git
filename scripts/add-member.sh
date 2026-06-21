#!/usr/bin/env bash
# encgit add-member — add a NEW member to a repo you already belong to, in one step:
#   1. cryptographic membership: `encgit member-add` wraps the repo key to them
#      (you MUST have verified their fingerprint OUT OF BAND first — this is the trust anchor)
#   2. API access: issue a writer/reader invite (admin) which they redeem to register an account
#
# The new member first runs `encgit identity new` then `encgit identity show` on their machine
# and sends you their x25519 pub, ed25519 pub, and fingerprint over a trusted channel; verify
# the fingerprint before running this. You must be a current member of the repo (logged in:
# `encgit login`) and able to authenticate as an admin.
#
# Usage:
#   scripts/add-member.sh --name NAME --x25519 HEX --ed25519 HEX --fingerprint HEX \
#     [--role writer|reader] [--git DIR] [--admin-user admin]
set -euo pipefail

NAME="" X="" ED="" FP="" ROLE="writer" GIT="." ADMIN_USER="admin"
usage() { sed -n '2,17p' "$0"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--name) NAME="$2"; shift 2 ;;
	--x25519) X="$2"; shift 2 ;;
	--ed25519) ED="$2"; shift 2 ;;
	--fingerprint) FP="$2"; shift 2 ;;
	--role) ROLE="$2"; shift 2 ;;
	--git) GIT="$2"; shift 2 ;;
	--admin-user) ADMIN_USER="$2"; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	*) echo "add-member: unknown argument: $1" >&2; usage; exit 2 ;;
	esac
done
if [ -z "$NAME" ] || [ -z "$X" ] || [ -z "$ED" ] || [ -z "$FP" ]; then
	echo "add-member: --name, --x25519, --ed25519 and --fingerprint are required" >&2
	usage
	exit 2
fi
if [ "$ROLE" != writer ] && [ "$ROLE" != reader ]; then
	echo "add-member: --role must be 'writer' or 'reader'" >&2
	exit 2
fi

# Locate the encgit client.
EG="${ENCGIT:-$(command -v encgit || true)}"
if [ -z "$EG" ]; then
	for c in "$HOME/.encgit/bin/encgit" "$HOME/encgit-prod/bin/encgit"; do
		[ -x "$c" ] && EG="$c" && break
	done
fi
[ -n "$EG" ] || { echo "add-member: encgit binary not found (set \$ENCGIT or add it to PATH)" >&2; exit 1; }

# Resolve the repo coordinates from config (set up by clone / `encgit config`).
STORE="$("$EG" config get --git "$GIT" store)"
REPO_ID="$("$EG" config get --git "$GIT" repo_id)"
CACERT="$("$EG" config get --git "$GIT" cacert)"
if [ -z "$STORE" ] || [ -z "$REPO_ID" ]; then
	echo "add-member: no store/repo_id configured for $GIT — run from a configured repo or pass --git DIR" >&2
	exit 1
fi

echo "[1/2] cryptographic membership: member-add '$NAME' (fingerprint $FP)"
"$EG" member-add --git "$GIT" --name "$NAME" --x25519 "$X" --ed25519 "$ED" --fingerprint "$FP"

case "$STORE" in
http://* | https://*) ;;
*)
	echo "[2/2] store is local ($STORE) — no API invite to issue; crypto membership done."
	exit 0
	;;
esac

for c in curl openssl python3; do
	command -v "$c" >/dev/null 2>&1 || { echo "add-member: missing required tool: $c" >&2; exit 1; }
done
CA_ARGS=()
[ -n "$CACERT" ] && CA_ARGS=(--cacert "$CACERT")

echo "[2/2] issuing a $ROLE invite (admin '$ADMIN_USER')"
read -rsp "admin password for $ADMIN_USER: " ADMIN_PW </dev/tty
echo
ADMIN_TOKEN="$(printf '{"username":"%s","password":"%s"}' "$ADMIN_USER" "$ADMIN_PW" |
	curl --http1.1 "${CA_ARGS[@]}" -sS -X POST "$STORE/auth/login" -H 'Content-Type: application/json' --data @- |
	python3 -c 'import sys,json;print(json.load(sys.stdin).get("token",""))')"
[ -n "$ADMIN_TOKEN" ] || { echo "add-member: admin login failed (wrong password?)" >&2; exit 1; }

INVITE="$(curl --http1.1 "${CA_ARGS[@]}" -sS -X POST "$STORE/repos/$REPO_ID/invites" \
	-H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d "{\"role\":\"$ROLE\"}" |
	python3 -c 'import sys,json;print(json.load(sys.stdin).get("invite_token",""))')"
[ -n "$INVITE" ] || { echo "add-member: invite creation failed" >&2; exit 1; }

FP_CERT=""
[ -n "$CACERT" ] && [ -f "$CACERT" ] && FP_CERT="$(openssl x509 -in "$CACERT" -noout -fingerprint -sha256 | sed 's/.*=//')"

cat <<EOF

done: '$NAME' is in the roster and a $ROLE invite was issued.

Hand this to the new member over a trusted channel (the invite is single-use and expires):
  server:           $STORE
  cert fingerprint: ${FP_CERT:-<read it from a machine you trust>}
  repo_id:          $REPO_ID
  invite token:     $INVITE

They register their account, then onboard their machine (after 'encgit identity new'):
  curl --http1.1 --cacert server.crt -X POST "$STORE/auth/register" -H 'Content-Type: application/json' \\
    -d '{"invite_token":"$INVITE","username":"THEIR_NAME","password":"THEIR_PASSWORD"}'
  ./scripts/onboard.sh --server "$STORE" --fingerprint "${FP_CERT:-<fingerprint>}" \\
    --seed ~/their.seed --user THEIR_NAME --repo-id "$REPO_ID" --dir ~/checkout
EOF
