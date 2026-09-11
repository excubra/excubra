#!/bin/sh
# One-time key ceremony for the release signature (ADR-0006). Run it once, on the
# maintainer's machine, by hand — it creates the root of trust every box verifies
# updates against:
#
#   sh scripts/release-key.sh excubra/excubra
#
# It writes the private key to ~/.config/excubra/release-key.pem (0600), puts the
# public half into internal/sig/release.pub (commit that), stores the private key as
# the GitHub Actions secret RELEASE_KEY_PEM of the repository, and prints the
# fingerprint. Afterwards: copy the private key into the password manager; losing it
# means re-keying every box by hand.
set -eu
REPO="${1:?usage: scripts/release-key.sh <owner/repo>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$HOME/.config/excubra"
KEY="$DIR/release-key.pem"
PUB="$ROOT/internal/sig/release.pub"

command -v openssl >/dev/null || { echo "openssl missing" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh (GitHub CLI) missing" >&2; exit 1; }

umask 077
mkdir -p "$DIR"
if [ -f "$KEY" ]; then
  echo "== keeping the existing key $KEY"
else
  echo "== generating ECDSA P-256 key $KEY"
  openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$KEY"
fi
chmod 600 "$KEY"

echo "== public key → $PUB"
openssl pkey -in "$KEY" -pubout -out "$PUB"
chmod 644 "$PUB"

echo "== GitHub secret RELEASE_KEY_PEM on $REPO"
gh secret set RELEASE_KEY_PEM --repo "$REPO" < "$KEY"

echo "== fingerprint (sha256 of the DER public key)"
openssl pkey -pubin -in "$PUB" -outform DER | openssl dgst -sha256 | sed 's/^.*= //'

cat <<MSG

done. Next:
  1. put $KEY into the password manager (it never goes anywhere else)
  2. git add internal/sig/release.pub && git commit -m "release: public key" && git push
  3. git tag v0.2.0 && git push origin v0.2.0   — the workflow signs and publishes
MSG
