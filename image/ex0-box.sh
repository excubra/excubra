#!/bin/bash
# Turns THIS machine (fresh Debian, as root) into an EX0 box with nothing but an
# enrollment key: downloads the signed release, verifies it against the release
# public key, and runs provision-box.sh. The console prints the one-liner:
#
#   curl -fsSL https://raw.githubusercontent.com/excubra/excubra/<tag>/image/ex0-box.sh \
#     | bash -s -- --enroll-key 'EX0:1:…' [--hostname ex0-kunde-standort] [--version 0.2.8]
#       [--ssh-lan] [--no-operator-peer] [--operator-lan-mode nat|macvlan]
#
# Everything after the key is passed to provision-box.sh unchanged. The box then
# enrolls, assigns itself to the key's site, joins the operator stack and reports
# its LAN — nobody touches it again (ADR-0017).
set -euo pipefail
REPO="${EX0_REPO:-excubra/excubra}"
VERSION=""
ENROLL_KEY=""
ENROLL_KEY_FILE=""
HOSTNAME_WANT=""
PASS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --enroll-key) ENROLL_KEY="$2"; shift 2 ;;
    --enroll-key-file) ENROLL_KEY_FILE="$2"; shift 2 ;;
    --hostname) HOSTNAME_WANT="$2"; PASS+=("--hostname" "$2"); shift 2 ;;
    --netbird-version|--netbird-setup-key|--netbird-url|--operator-lan-mode) PASS+=("$1" "$2"); shift 2 ;;
    --ssh-lan|--no-operator-peer|--operator-peer|--guest) PASS+=("$1"); shift ;;
    *) echo "ex0-box: unknown flag $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "ex0-box: run as root" >&2; exit 1; }
if [ -n "$ENROLL_KEY_FILE" ]; then ENROLL_KEY="$(head -c 512 "$ENROLL_KEY_FILE" | tr -d '[:space:]')"; rm -f "$ENROLL_KEY_FILE"; fi
if [ -z "$ENROLL_KEY" ] && [ ! -s /var/lib/excubra-agent/box.json ] && [ ! -f /var/lib/excubra-agent/enroll ]; then
  echo "ex0-box: --enroll-key 'EX0:1:…' required (from the console: Neue Box)" >&2; exit 2
fi
export DEBIAN_FRONTEND=noninteractive
command -v curl >/dev/null && command -v openssl >/dev/null && command -v gpg >/dev/null || { apt-get -qq update && apt-get -y -qq install curl ca-certificates openssl gnupg >/dev/null; }

case "$(dpkg --print-architecture)" in
  amd64) ARCH=amd64 ;;
  arm64) ARCH=arm64 ;;
  *) echo "ex0-box: unsupported architecture $(dpkg --print-architecture)" >&2; exit 1 ;;
esac
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || { echo "ex0-box: could not find the latest release of $REPO" >&2; exit 1; }
fi
TAG="v$VERSION"
REL="https://github.com/$REPO/releases/download/$TAG"
RAW="https://raw.githubusercontent.com/$REPO/$TAG"
W="$(mktemp -d /root/ex0-box.XXXXXX)"
trap 'rm -rf "$W"' EXIT
echo "== EX0 box $TAG for $ARCH"
cd "$W"
for f in "excubra_linux_$ARCH" SHA256SUMS SHA256SUMS.sig; do curl -fsSL -o "$f" "$REL/$f"; done
curl -fsSL -o release.pub "$RAW/internal/sig/release.pub"
for f in provision-box.sh netbird-operator-netns.sh netbird-operator-netns.service netbird-operator.service netbird-operator-ssh.service; do curl -fsSL -o "$f" "$RAW/image/$f"; done
curl -fsSL -o excubra-agent.service "$RAW/deploy/systemd/excubra-agent.service"

echo "== verifying the release signature"
base64 -d SHA256SUMS.sig > SHA256SUMS.der
openssl dgst -sha256 -verify release.pub -signature SHA256SUMS.der SHA256SUMS >/dev/null
grep " excubra_linux_$ARCH\$" SHA256SUMS | sha256sum -c --quiet -
chmod +x "excubra_linux_$ARCH" provision-box.sh
"./excubra_linux_$ARCH" version

ARGS=(--binary "$W/excubra_linux_$ARCH" --netbird-version 0.78.1)
[ -n "$ENROLL_KEY" ] && ARGS+=(--enroll-key "$ENROLL_KEY")
./provision-box.sh "${ARGS[@]}" "${PASS[@]}"
