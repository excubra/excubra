#!/bin/sh
# Builds the single-page console (web/) into internal/server/console/webdist, which
# `go build` embeds. Installs node_modules from the lockfile when missing or stale.
#
#   sh scripts/web-build.sh          build
#   sh scripts/web-build.sh --check  type-check and lint only, no build
#
# Needs Node 22 with npm. Without it `go build` still works: the binary then serves the
# committed placeholder (webdist/unbuilt.html) under /app/.
set -eu
cd "$(dirname "$0")/../web"
if ! command -v npm >/dev/null 2>&1; then
  echo "web-build: npm not found; Node 22 is needed to build the console (docs/adr/0013-console-spa.md)" >&2
  exit 1
fi
if [ ! -d node_modules ] || [ package-lock.json -nt node_modules/.package-lock.json ]; then
  npm ci --no-audit --no-fund
fi
if [ "${1:-}" = "--check" ]; then
  npx tsc -b
  npm run --silent lint
  exit 0
fi
npm run --silent build
