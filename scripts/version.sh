#!/bin/sh
# Single source of truth for the build version string.
#
# internal/version.Parse requires MAJOR.MINOR.PATCH (a leading "v" and any
# "-suffix"/"+suffix" are trimmed). A bare "git describe" on a tagless tree
# returns a commit hash like "9297b25", which is NOT parseable — the agent then
# sends it in its version header and the ingest server rejects every heartbeat
# with 400 "bad agent version header". So derive a version that always parses:
#
#   - a v-prefixed tag at/behind HEAD  -> the tag (v0.1.0, or v0.1.0-3-gabc123-dirty)
#   - no such tag                      -> 0.1.0-dev+g<commit>[.dirty]
#
# Override at build time with VERSION=... in the environment.
set -eu
if [ -n "${VERSION:-}" ]; then
  printf '%s\n' "$VERSION"
elif v="$(git describe --tags --match 'v[0-9]*' --dirty 2>/dev/null)"; then
  printf '%s\n' "$v"
else
  c="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  d=""
  git diff --quiet 2>/dev/null || d=".dirty"
  printf '0.1.0-dev+g%s%s\n' "$c" "$d"
fi
