#!/bin/bash
# Provisions an EX0 box that is an LXC container on a Proxmox host — without SSH access to
# the container itself. Files go in with `pct push`, the provisioning runs with `pct exec`.
# From the repository root:
#
#   image/deploy-box-pct.sh <ssh-host-of-proxmox> <ctid> --enroll-key 'EX0:1:…' --hostname kft-box
#
# The Proxmox host is reached over SSH as root (an ~/.ssh/config alias works). Everything
# after the ctid is passed to provision-box.sh unchanged. EXCUBRA_ARCH=arm64 for ARM hosts.
set -euo pipefail
PVE="${1:?usage: image/deploy-box-pct.sh <root@proxmox> <ctid> [provision flags]}"
CTID="${2:?usage: image/deploy-box-pct.sh <root@proxmox> <ctid> [provision flags]}"
shift 2
ARCH="${EXCUBRA_ARCH:-amd64}"
VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
MODULE=github.com/excubra/excubra
echo "== building $VERSION for linux/$ARCH"
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -mod=readonly \
  -ldflags "-s -w -X $MODULE/internal/version.Version=$VERSION -X $MODULE/internal/version.Commit=$COMMIT -X $MODULE/internal/version.Date=$DATE" \
  -o "dist/excubra_linux_$ARCH" ./cmd/excubra
R=/root/excubra-box
echo "== copying to $PVE, then into container $CTID"
ssh -o BatchMode=yes "$PVE" "rm -rf $R && mkdir -p $R"
scp -q "dist/excubra_linux_$ARCH" "$PVE:$R/excubra"
scp -q image/provision-box.sh deploy/systemd/excubra-agent.service "$PVE:$R/"
ssh -o BatchMode=yes "$PVE" "pct exec $CTID -- mkdir -p $R && for f in excubra provision-box.sh excubra-agent.service; do pct push $CTID $R/\$f $R/\$f; done"
echo "== provisioning"
# shellcheck disable=SC2145  # the flags are re-quoted for the remote shell on purpose
ssh -o BatchMode=yes "$PVE" "pct exec $CTID -- bash -c 'chmod +x $R/provision-box.sh && $R/provision-box.sh --binary $R/excubra $(printf "%q " "$@")'"
ssh -o BatchMode=yes "$PVE" "pct exec $CTID -- rm -rf $R; rm -rf $R"
