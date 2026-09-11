#!/bin/bash
# Builds the Linux binary from the current commit and provisions a host with it.
# Run from the repository root:
#
#   deploy/deploy.sh root@49.12.65.47 --ingest-host ingest.ex0.viico-cloud.de --hostname ex0
#
# Everything after the target is passed to provision-server.sh.
set -euo pipefail
TARGET="${1:?usage: deploy/deploy.sh <user@host> [provision flags]}"
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
REMOTE_DIR="/root/excubra-provision"
ssh -o BatchMode=yes "$TARGET" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR/systemd"
scp -q "dist/excubra_linux_$ARCH" "$TARGET:$REMOTE_DIR/excubra"
scp -q deploy/provision-server.sh deploy/restore-test.sh "$TARGET:$REMOTE_DIR/"
scp -q deploy/systemd/* "$TARGET:$REMOTE_DIR/systemd/"

echo "== provisioning"
ssh -o BatchMode=yes "$TARGET" "chmod +x $REMOTE_DIR/provision-server.sh && $REMOTE_DIR/provision-server.sh --binary $REMOTE_DIR/excubra $*"
ssh -o BatchMode=yes "$TARGET" "rm -rf $REMOTE_DIR"
