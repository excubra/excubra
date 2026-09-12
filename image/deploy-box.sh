#!/bin/bash
# Builds the agent binary for the box's architecture and provisions the box over SSH.
# From the repository root:
#
#   image/deploy-box.sh root@ex0-box-buero --enroll-key 'EX0:1:…' --hostname ex0-box-buero --ssh-lan
#
# EXCUBRA_ARCH=arm64 for a Raspberry Pi (default amd64 for a mini PC).
set -euo pipefail
TARGET="${1:?usage: image/deploy-box.sh <root@box> [provision flags]}"
shift
ARCH="${EXCUBRA_ARCH:-amd64}"
VERSION="$(sh "$(git rev-parse --show-toplevel)/scripts/version.sh" 2>/dev/null || echo 0.0.0-dev)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MODULE=github.com/excubra/excubra
echo "== building console"
sh "$(git rev-parse --show-toplevel)/scripts/web-build.sh"

echo "== building $VERSION for linux/$ARCH"
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -mod=readonly \
  -ldflags "-s -w -X $MODULE/internal/version.Version=$VERSION -X $MODULE/internal/version.Commit=$COMMIT -X $MODULE/internal/version.Date=$DATE" \
  -o "dist/excubra_linux_$ARCH" ./cmd/excubra
echo "== copying to $TARGET"
R=/root/excubra-box
ssh -o BatchMode=yes "$TARGET" "rm -rf $R && mkdir -p $R"
scp -q "dist/excubra_linux_$ARCH" "$TARGET:$R/excubra"
scp -q image/provision-box.sh image/netbird-operator-netns.sh image/netbird-operator.service deploy/systemd/excubra-agent.service "$TARGET:$R/"
echo "== provisioning"
ssh -o BatchMode=yes "$TARGET" "chmod +x $R/provision-box.sh && $R/provision-box.sh --binary $R/excubra $*"
ssh -o BatchMode=yes "$TARGET" "rm -rf $R"
