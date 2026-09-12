#!/bin/sh
# EX0: applies the capabilities the agent asks for (ADR-0006 amendment 2026-09-12).
#
# The agent runs without root and cannot change its own systemd unit, so a new
# release that needs a capability (port 53 for the DNS sensor, the decoy ports
# below 1024) would be stuck with the rights of the day the box was installed.
# The agent writes what it needs into its state directory; this script, run as
# root by excubra-agent-unit.path whenever that file changes, turns it into a
# drop-in. Only capabilities from the allowlist below can be asked for: nothing
# else of the unit can be changed this way, so a compromised agent gains at most
# the right to bind low ports.
set -eu
REQ=/var/lib/excubra-agent/unit.request
DROP_DIR=/etc/systemd/system/excubra-agent.service.d
DROP="$DROP_DIR/50-agent-request.conf"
ALLOWED="CAP_NET_RAW CAP_NET_BIND_SERVICE"

[ -s "$REQ" ] || exit 0
caps=""
for c in $(head -c 512 "$REQ" | tr -s ' \t\n' '   '); do
  case " $ALLOWED " in
    *" $c "*) caps="$caps $c" ;;
    *) echo "excubra-agent-unit: refusing $c (not in the allowlist)" >&2 ;;
  esac
done
caps="$(echo $caps)"
[ -n "$caps" ] || exit 0
new="$(printf '[Service]\nCapabilityBoundingSet=%s\nAmbientCapabilities=%s\n' "$caps" "$caps")"
if [ -f "$DROP" ] && [ "$(cat "$DROP")" = "$new" ]; then
  exit 0
fi
mkdir -p "$DROP_DIR"
printf '%s\n' "$new" > "$DROP"
echo "excubra-agent-unit: agent may use $caps; restarting the agent"
systemctl daemon-reload
systemctl restart excubra-agent
