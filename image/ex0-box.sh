#!/bin/bash
# Turns THIS machine (fresh Debian, as root) into an EX0 box with nothing but an
# enrollment key: downloads the signed release, verifies it against the release
# public key, and runs provision-box.sh. The console and the MCP server print the
# command:
#
#   curl -fsSL https://raw.githubusercontent.com/excubra/excubra/<tag>/image/ex0-box.sh -o /tmp/ex0-box.sh \
#     && bash /tmp/ex0-box.sh --enroll-key 'EX0:1:…' [--hostname ex0-kunde-standort] [--version 0.20.0]
#       [--ssh-key 'ssh-ed25519 AAAA… name']… [--ssh-lan] [--no-operator-peer] [--operator-lan-mode nat|macvlan]
#
# Never on a hypervisor or on a server that does something else: a box is a
# machine of its own or a container (on a Proxmox host use ex0-box-pct.sh).
#
# Everything after the key is passed to provision-box.sh unchanged. The box then
# enrolls, assigns itself to the key's site, joins the operator stack and reports
# its LAN — nobody touches it again (ADR-0017). The last line says what happened:
#
#   EX0-RESULT: ok box=box_… version=…      or      EX0-RESULT: failed — and why
#
# Everything is inside main, called on the last line: a download that broke off
# half-way runs nothing.
set -Eeuo pipefail

main() {
  umask 022   # the modes of what gets installed are ours, not the caller's
  REPO="${EX0_REPO:-excubra/excubra}"
  VERSION=""
  ENROLL_KEY=""
  ENROLL_KEY_FILE=""
  PASS=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) VERSION="$2"; shift 2 ;;
      --enroll-key) ENROLL_KEY="$2"; shift 2 ;;
      --enroll-key-file) ENROLL_KEY_FILE="$2"; shift 2 ;;
      --hostname|--netbird-version|--netbird-setup-key|--netbird-url|--operator-lan-mode|--ssh-key) PASS+=("$1" "$2"); shift 2 ;;
      --ssh-lan|--no-operator-peer|--operator-peer|--guest) PASS+=("$1"); shift ;;
      *) echo "ex0-box: unknown flag $1" >&2; exit 2 ;;
    esac
  done
  trap 'failed "line $LINENO: $BASH_COMMAND"' ERR
  [ "$(id -u)" = 0 ] || failed "run as root"
  if command -v pct >/dev/null 2>&1 && command -v pveam >/dev/null 2>&1; then
    failed "this is a Proxmox host — a box never lives on a hypervisor. Use ex0-box-pct.sh here: it makes a container for the box"
  fi
  if [ -n "$ENROLL_KEY_FILE" ] && [ -f "$ENROLL_KEY_FILE" ]; then
    ENROLL_KEY="$(head -c 512 "$ENROLL_KEY_FILE" | tr -d '[:space:]')"
    rm -f "$ENROLL_KEY_FILE"
  fi
  if [ -z "$ENROLL_KEY" ] && [ ! -s /var/lib/excubra-agent/box.id ] && [ ! -f /var/lib/excubra-agent/enroll ]; then
    failed "--enroll-key 'EX0:1:…' required (console: Neue Box, or ex0_new_box)"
  fi
  export DEBIAN_FRONTEND=noninteractive
  if ! { command -v curl >/dev/null && command -v openssl >/dev/null && command -v gpg >/dev/null; }; then
    apt-get -qq update
    apt-get -y -qq install curl ca-certificates openssl gnupg >/dev/null
  fi

  case "$(dpkg --print-architecture)" in
    amd64) ARCH=amd64 ;;
    arm64) ARCH=arm64 ;;
    *) failed "unsupported architecture $(dpkg --print-architecture)" ;;
  esac
  if [ -z "$VERSION" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)" || true
    [ -n "$VERSION" ] || failed "could not find the latest release of $REPO (no internet from this machine?)"
  fi
  TAG="v$VERSION"
  REL="https://github.com/$REPO/releases/download/$TAG"
  # EX0_RAW_BASE: a mirror, or a checkout served locally to try a change before
  # it is released. The binary below still has to verify against the public key.
  RAW="${EX0_RAW_BASE:-https://raw.githubusercontent.com/$REPO/$TAG}"
  W="$(mktemp -d /root/ex0-box.XXXXXX)"
  trap 'rm -rf "$W"' EXIT
  echo "== EX0 box $TAG for $ARCH"
  cd "$W"
  for f in "excubra_linux_$ARCH" SHA256SUMS SHA256SUMS.sig; do
    curl -fsSL -o "$f" "$REL/$f" || failed "could not download $f of release $TAG"
  done
  curl -fsSL -o release.pub "$RAW/internal/sig/release.pub" || failed "could not download the release public key"
  for f in provision-box.sh netbird-operator-netns.sh netbird-operator-netns.service netbird-operator.service netbird-operator-ssh.service excubra-agent-unit.sh excubra-agent-unit.path excubra-agent-unit.service; do
    curl -fsSL -o "$f" "$RAW/image/$f" || failed "could not download image/$f of $TAG"
  done
  curl -fsSL -o excubra-agent.service "$RAW/deploy/systemd/excubra-agent.service" || failed "could not download the agent unit of $TAG"

  echo "== verifying the release signature"
  base64 -d SHA256SUMS.sig > SHA256SUMS.der
  openssl dgst -sha256 -verify release.pub -signature SHA256SUMS.der SHA256SUMS >/dev/null || failed "the release signature does not verify — nothing was installed"
  grep " excubra_linux_$ARCH\$" SHA256SUMS > SHA256SUMS.one || failed "release $TAG lists no binary for $ARCH"
  sha256sum -c --quiet SHA256SUMS.one || failed "the downloaded binary does not match the signed checksum — nothing was installed"
  chmod +x "excubra_linux_$ARCH" provision-box.sh
  "./excubra_linux_$ARCH" version

  ARGS=(--binary "$W/excubra_linux_$ARCH" --netbird-version 0.78.1)
  [ -n "$ENROLL_KEY" ] && ARGS+=(--enroll-key "$ENROLL_KEY")
  trap - ERR
  # provision-box.sh ends with its own EX0-RESULT line and exit status
  ./provision-box.sh "${ARGS[@]}" ${PASS[@]+"${PASS[@]}"}
}

failed() {
  trap - ERR
  echo >&2
  echo "EX0-RESULT: failed — ex0-box: $*" >&2
  exit 1
}

main "$@"
