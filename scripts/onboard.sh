#!/usr/bin/env bash
#
# encgit machine onboarding — get a fresh machine ready to use an existing identity:
#   1. build the encgit client from this repo
#   2. fetch the server's TLS cert and VERIFY it against an out-of-band fingerprint
#   3. write the global config (so day-to-day commands need no flags)
#   4. log in (prompts for the password)
#   5. optionally clone a repo
#
# It does NOT create your identity — transfer your existing `me.seed` to this machine
# first (a brand-new user runs `encgit identity new` instead). The seed is the only
# secret; everything else here is non-secret (URL, paths, an id, a public cert).
#
# Usage:
#   scripts/onboard.sh \
#     --server https://HOST \
#     --fingerprint <sha256 of the server cert, from a trusted channel> \
#     --seed /path/to/me.seed \
#     --user USERNAME \
#     [--repo-id HEX --dir DIR]   # clone now
#     [--prefix DIR]              # where to install (default ~/.encgit)
set -euo pipefail

SERVER="" FINGERPRINT="" SEED="" USER_NAME="" REPO_ID="" DIR="" PREFIX="$HOME/.encgit"

usage() { sed -n '2,26p' "$0"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--server) SERVER="$2"; shift 2 ;;
	--fingerprint) FINGERPRINT="$2"; shift 2 ;;
	--seed) SEED="$2"; shift 2 ;;
	--user) USER_NAME="$2"; shift 2 ;;
	--repo-id) REPO_ID="$2"; shift 2 ;;
	--dir) DIR="$2"; shift 2 ;;
	--prefix) PREFIX="$2"; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	*) echo "onboard: unknown argument: $1" >&2; usage; exit 2 ;;
	esac
done

if [ -z "$SERVER" ] || [ -z "$FINGERPRINT" ] || [ -z "$SEED" ] || [ -z "$USER_NAME" ]; then
	echo "onboard: --server, --fingerprint, --seed and --user are required" >&2
	usage
	exit 2
fi
if [ ! -f "$SEED" ]; then
	echo "onboard: seed file not found: $SEED" >&2
	echo "  transfer your existing me.seed here first (it is your identity / master secret)." >&2
	exit 1
fi
for c in git go openssl; do
	command -v "$c" >/dev/null 2>&1 || { echo "onboard: missing required tool: $c" >&2; exit 1; }
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EG="$PREFIX/bin/encgit"
CERT="$PREFIX/server.crt"

# normalize a fingerprint for comparison: drop colons/whitespace, uppercase.
norm() { printf '%s' "$1" | tr -d ': \t\r\n' | tr 'a-f' 'A-F'; }

echo "[1/5] building encgit -> $EG"
mkdir -p "$PREFIX/bin"
( cd "$REPO_ROOT" && go build -o "$EG" ./cmd/encgit )

echo "[2/5] fetching + verifying the server TLS cert"
hostport="${SERVER#*://}"; hostport="${hostport%%/*}"
case "$hostport" in
*:*) connect="$hostport" ;;
*) connect="${hostport}:443" ;;
esac
openssl s_client -connect "$connect" </dev/null 2>/dev/null | openssl x509 >"$CERT"
got="$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | sed 's/.*=//')"
if [ "$(norm "$got")" != "$(norm "$FINGERPRINT")" ]; then
	echo "onboard: CERT FINGERPRINT MISMATCH — aborting (possible MITM)" >&2
	echo "  expected: $FINGERPRINT" >&2
	echo "  got:      $got" >&2
	rm -f "$CERT"
	exit 1
fi
echo "  cert fingerprint verified"

echo "[3/5] writing global config (~/.config/encgit/config.json)"
"$EG" config set --global --store "$SERVER" --seed "$SEED" --cacert "$CERT"

echo "[4/5] logging in as $USER_NAME"
"$EG" login --seed "$SEED" "$SERVER" "$USER_NAME"

if [ -n "$REPO_ID" ] && [ -n "$DIR" ]; then
	echo "[5/5] cloning $REPO_ID -> $DIR"
	"$EG" clone --repo-id "$REPO_ID" "$DIR"
else
	echo "[5/5] skipping clone (pass --repo-id and --dir to clone now)"
fi

echo
echo "onboard: done. client at $EG"
echo "  add it to PATH:   export PATH=\"$PREFIX/bin:\$PATH\""
echo "  then day-to-day:  cd <repo> && encgit fetch   # no flags needed"
