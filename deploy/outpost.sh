#!/bin/bash
# Sets up the outpost on THIS host (the EX0 server, or any Debian machine with a
# public address that customers' firewalls do not trust). Run as root:
#
#   deploy/outpost.sh --enroll-key 'EX0:1:…' [--binary /opt/excubra/bin/excubra]
#
# Then in the console: Boxen → the new box → make it an outpost (or
# `excubra server box role <box_id> outpost`). From then on it scans every site
# with the scan switched on, hourly, from outside.
set -euo pipefail
KEY=""
BINARY=/opt/excubra/bin/excubra
while [ $# -gt 0 ]; do
  case "$1" in
    --enroll-key) KEY="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    *) echo "outpost: unknown flag $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "outpost: run as root" >&2; exit 1; }
[ -x "$BINARY" ] || { echo "outpost: binary $BINARY not found" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE=/var/lib/excubra-outpost
BIN=/opt/excubra-outpost/bin
echo "== user and directories"
id excubra-outpost >/dev/null 2>&1 || useradd --system --home "$STATE" --shell /usr/sbin/nologin excubra-outpost
install -d -m 0700 -o excubra-outpost -g excubra-outpost "$STATE"
install -d -m 0755 /opt/excubra-outpost
install -d -m 0755 -o excubra-outpost -g excubra-outpost "$BIN"
echo "== binary (its own copy; it updates itself)"
install -m 0755 -o excubra-outpost -g excubra-outpost "$BINARY" "$BIN/excubra.new"
mv "$BIN/excubra.new" "$BIN/excubra"
"$BIN/excubra" version
if [ -n "$KEY" ] && [ ! -s "$STATE/box.json" ]; then
  echo "== enrollment key"
  install -m 0600 -o excubra-outpost -g excubra-outpost /dev/null "$STATE/enroll"
  printf '%s\n' "$KEY" > "$STATE/enroll"
fi
echo "== unit"
UNIT="$HERE/systemd/excubra-outpost.service"
[ -f "$UNIT" ] || UNIT="$HERE/excubra-outpost.service"
install -m 0644 "$UNIT" /etc/systemd/system/excubra-outpost.service
systemctl daemon-reload
systemctl enable excubra-outpost >/dev/null
systemctl restart excubra-outpost
sleep 5
systemctl --no-pager --lines=0 status excubra-outpost | sed -n '1,3p'
journalctl -u excubra-outpost --no-pager -n 5 -o cat
echo "outpost: running. Make it an outpost: excubra server box role <box_id> outpost"
