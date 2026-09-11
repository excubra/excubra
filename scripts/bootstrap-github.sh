#!/bin/sh
# Puts the project on GitHub and arms the release pipeline, once, by hand:
#
#   sh scripts/bootstrap-github.sh excubra/excubra [v0.2.0]
#
# 1. creates the repository (private) if it does not exist and pushes main
# 2. runs the key ceremony (scripts/release-key.sh): key on this machine, public key
#    committed, private key as the Actions secret
# 3. tags the release and pushes the tag — the workflow builds, signs, publishes;
#    every EX0 server imports it from the catalog within the hour
set -eu
REPO="${1:?usage: scripts/bootstrap-github.sh <owner/repo> [tag]}"
TAG="${2:-v0.2.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v gh >/dev/null || { echo "gh (GitHub CLI) missing" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh is not logged in: gh auth login" >&2; exit 1; }

echo "== repository $REPO"
if gh repo view "$REPO" >/dev/null 2>&1; then
  echo "   exists"
else
  gh repo create "$REPO" --private --description "EX0 — open-source monitoring, prevention and device management for small infrastructures"
fi
if ! git remote get-url origin >/dev/null 2>&1; then
  git remote add origin "https://github.com/$REPO.git"
fi
git push -u origin main

echo "== key ceremony"
sh scripts/release-key.sh "$REPO"
git add internal/sig/release.pub
git commit -q -m "release: public key of the signing key

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" || true
git push origin main

echo "== tag $TAG"
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "   tag exists, not moving it"
else
  git tag -a "$TAG" -m "$TAG"
fi
git push origin "$TAG"

cat <<MSG

done. Watch the pipeline:  gh run watch --repo $REPO
Then in the console: Updates → „Katalog jetzt prüfen“ → Kanal setzen → „Update holen“.
Remember: ~/.config/excubra/release-key.pem belongs in the password manager.
MSG
