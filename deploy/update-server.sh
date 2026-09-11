#!/bin/bash
# Updates a running EX0 server to the current commit: builds the console and the Linux
# binary, copies the binary next to the installed one, swaps it atomically, restarts the
# service and checks /healthz on the overlay listener. Run from the repository root:
#
#   deploy/update-server.sh root@100.64.0.10
#
# The binary and the server unit change. Configuration, timers and data stay as they
# are; for those, run deploy/deploy.sh (idempotent) instead. Boxes and, from 0.3 on,
# the server itself update through the portal; this script is for the server until
# it runs a build that can.
set -euo pipefail
TARGET="${1:?usage: deploy/update-server.sh <user@host>}"

ARCH="${EXCUBRA_ARCH:-amd64}"
ROOT="$(git rev-parse --show-toplevel)"
VERSION="$(sh "$ROOT/scripts/version.sh" 2>/dev/null || echo 0.0.0-dev)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MODULE=github.com/excubra/excubra

echo "== building console"
sh "$ROOT/scripts/web-build.sh"

echo "== building $VERSION for linux/$ARCH"
mkdir -p "$ROOT/dist"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -mod=readonly \
  -ldflags "-s -w -X $MODULE/internal/version.Version=$VERSION -X $MODULE/internal/version.Commit=$COMMIT -X $MODULE/internal/version.Date=$DATE" \
  -o "$ROOT/dist/excubra_linux_$ARCH" "$ROOT/cmd/excubra"

echo "== installing on $TARGET"
scp -q -o BatchMode=yes "$ROOT/dist/excubra_linux_$ARCH" "$TARGET:/root/excubra.new"
scp -q -o BatchMode=yes "$ROOT/deploy/systemd/excubra-server.service" "$TARGET:/root/excubra-server.service"
ssh -o BatchMode=yes "$TARGET" 'set -eu
  install -d -m 0755 -o excubra -g excubra /opt/excubra/bin
  install -m 0755 -o excubra -g excubra /root/excubra.new /opt/excubra/bin/excubra.new
  rm -f /root/excubra.new
  echo "   was:  $(/usr/local/bin/excubra version 2>/dev/null || echo none)"
  echo "   new:  $(/opt/excubra/bin/excubra.new version)"
  mv /opt/excubra/bin/excubra.new /opt/excubra/bin/excubra   # atomic: never a half-written binary
  if [ ! -L /usr/local/bin/excubra ]; then rm -f /usr/local/bin/excubra; fi
  ln -sfn /opt/excubra/bin/excubra /usr/local/bin/excubra
  if ! cmp -s /root/excubra-server.service /etc/systemd/system/excubra-server.service; then
    install -m 0644 /root/excubra-server.service /etc/systemd/system/excubra-server.service
    systemctl daemon-reload
    echo "   unit updated"
  fi
  rm -f /root/excubra-server.service
  systemctl restart excubra-server
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    systemctl is-active --quiet excubra-server && break
  done
  OVERLAY="$(sed -n "s/^EXCUBRA_OVERLAY_LISTEN=//p" /etc/excubra/server.env)"
  SCHEME=http
  [ "$(sed -n "s/^EXCUBRA_OVERLAY_TLS=//p" /etc/excubra/server.env)" = "internal" ] && SCHEME=https
  if out="$(curl -fsk -m 5 "$SCHEME://$OVERLAY/healthz")"; then
    echo "   healthz: $out"
  else
    echo "   healthz failed — last log lines:" >&2
    journalctl -u excubra-server -n 20 --no-pager -o cat >&2
    exit 1
  fi'
echo "== done: $VERSION is running"
