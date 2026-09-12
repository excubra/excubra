#!/bin/sh
# The operator peer (EX0 remote access, ADR-0016) in its own network namespace.
#
# Two NetBird daemons in one namespace share one nftables table and the second wipes
# the first's routing rules (learned the hard way, 12.09.2026). So the second daemon
# gets a namespace of its own: a macvlan interface on the LAN with its own address
# from DHCP, its own WireGuard, its own firewall. From the LAN it looks like one more
# host; the customer daemon in the root namespace never notices it.
#
#   netbird-operator-netns.sh up     create namespace + macvlan, get an address, DNS
#   netbird-operator-netns.sh down   remove it all
#
# Used by netbird-operator.service (ExecStartPre/ExecStopPost). Needs the macvlan
# kernel module on the host and a LAN with DHCP.
set -eu
NS=operator
LINK="${OPERATOR_LAN_IF:-$(ip -o route show default | awk '{print $5; exit}')}"
IFACE=mvop

up() {
  [ -n "$LINK" ] || { echo "no LAN interface found" >&2; exit 1; }
  ip netns list | grep -qx "$NS" || ip netns add "$NS"
  if ! ip netns exec "$NS" ip link show "$IFACE" >/dev/null 2>&1; then
    ip link add "$IFACE" link "$LINK" type macvlan mode bridge
    ip link set "$IFACE" netns "$NS"
  fi
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip link set "$IFACE" up
  mkdir -p "/etc/netns/$NS"
  [ -f "/etc/netns/$NS/resolv.conf" ] || printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > "/etc/netns/$NS/resolv.conf"
  if command -v dhclient >/dev/null; then
    ip netns exec "$NS" dhclient -1 -q -pf "/run/dhclient-$NS.pid" "$IFACE" || echo "dhclient: no lease yet" >&2
  elif command -v udhcpc >/dev/null; then
    ip netns exec "$NS" udhcpc -i "$IFACE" -q -n -p "/run/udhcpc-$NS.pid" || echo "udhcpc: no lease yet" >&2
  else
    echo "no DHCP client (dhclient/udhcpc) installed" >&2; exit 1
  fi
  ip netns exec "$NS" ip -4 -o addr show "$IFACE" | awk '{print "operator peer address: "$4}'
}

down() {
  [ -f "/run/dhclient-$NS.pid" ] && kill "$(cat "/run/dhclient-$NS.pid")" 2>/dev/null || true
  [ -f "/run/udhcpc-$NS.pid" ] && kill "$(cat "/run/udhcpc-$NS.pid")" 2>/dev/null || true
  ip netns exec "$NS" ip link del "$IFACE" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
