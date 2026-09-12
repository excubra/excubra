#!/bin/sh
# The operator peer (EX0 remote access, ADR-0016) lives in its own network namespace.
#
# Two NetBird daemons in one namespace share one nftables table, and the second wipes
# the first's routing rules (learned the hard way, 12.09.2026). So the operator's
# daemon gets a namespace of its own: its own WireGuard interface, its own firewall
# table, its own routes. The customer's daemon in the root namespace never sees it.
#
# The way out of the namespace is chosen in /etc/default/netbird-operator:
#
#   OPERATOR_LAN_MODE=nat      (default) a veth pair to the root namespace, which
#                              forwards and masquerades for it. Nothing new appears on
#                              the LAN — no second MAC, no DHCP lease — so it works on a
#                              bridge, in an LXC container and behind port security.
#   OPERATOR_LAN_MODE=macvlan  a macvlan interface on the LAN with its own address from
#                              DHCP; the peer looks like one more host on the LAN. Needs
#                              DHCP and a NIC that accepts a second MAC (OPERATOR_LAN_IF
#                              picks the interface, default: the one with the default route).
#
# In both modes the veth pair also carries the box's own sshd: 169.254.222.1 is the
# root namespace, 169.254.222.2 the operator's. netbird-operator-ssh.service relays
# port 22 from the box's overlay address to the root namespace, so a technician reaches
# the box at its operator-overlay address like any other peer.
#
#   netbird-operator-netns.sh up      create the namespace and its way out
#   netbird-operator-netns.sh down    remove it all
#   netbird-operator-netns.sh status  what is there
#
# Used by netbird-operator-netns.service. In the root namespace it adds one veth
# interface, ip_forward=1 and (nat mode) one nftables table "ex0op" with a single
# masquerade rule for 169.254.222.0/30 — nothing that touches another daemon's rules.
set -eu
NS=operator
MODE="${OPERATOR_LAN_MODE:-nat}"
VETH_ROOT=veth-op
VETH_NS=op0
LL_ROOT=169.254.222.1
LL_NS=169.254.222.2
LL_NET=169.254.222.0/30
IFACE=mvop
NFT_TABLE=ex0op
RESOLV="/etc/netns/$NS/resolv.conf"

in_ns() { ip netns exec "$NS" "$@"; }

veth_up() {
  if ! ip link show "$VETH_ROOT" >/dev/null 2>&1; then
    ip link add "$VETH_ROOT" type veth peer name "$VETH_NS"
    ip link set "$VETH_NS" netns "$NS"
  fi
  ip addr replace "$LL_ROOT/30" dev "$VETH_ROOT"
  ip link set "$VETH_ROOT" up
  in_ns ip addr replace "$LL_NS/30" dev "$VETH_NS"
  in_ns ip link set "$VETH_NS" up
}

# nat mode: the root namespace routes for the operator namespace and hides it behind
# its own address. Idempotent: the table is (re)created as a whole.
nat_up() {
  in_ns ip route replace default via "$LL_ROOT" dev "$VETH_NS"
  sysctl -q -w net.ipv4.ip_forward=1 || echo "ip_forward could not be set (container?); forwarding must already be on" >&2
  nft -f - <<NFT
table inet $NFT_TABLE
delete table inet $NFT_TABLE
table inet $NFT_TABLE {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr $LL_NET oifname != "$VETH_ROOT" masquerade
  }
}
NFT
}

macvlan_up() {
  link="${OPERATOR_LAN_IF:-$(ip -o route show default | awk '{print $5; exit}')}"
  [ -n "$link" ] || { echo "no LAN interface found (OPERATOR_LAN_IF)" >&2; exit 1; }
  if ! in_ns ip link show "$IFACE" >/dev/null 2>&1; then
    ip link add "$IFACE" link "$link" type macvlan mode bridge
    ip link set "$IFACE" netns "$NS"
  fi
  in_ns ip link set "$IFACE" up
  if command -v dhclient >/dev/null; then
    in_ns dhclient -1 -q -pf "/run/dhclient-$NS.pid" "$IFACE" || echo "dhclient: no lease yet" >&2
  elif command -v udhcpc >/dev/null; then
    in_ns udhcpc -i "$IFACE" -q -n -p "/run/udhcpc-$NS.pid" || echo "udhcpc: no lease yet" >&2
  else
    echo "no DHCP client (dhclient/udhcpc) installed" >&2; exit 1
  fi
}

# The namespace cannot use a resolver that listens only in the root namespace
# (systemd-resolved's 127.0.0.53); take the upstream servers it knows, else public ones.
dns_up() {
  mkdir -p "/etc/netns/$NS"
  if [ "$MODE" = nat ] || [ ! -s "$RESOLV" ]; then
    servers=""
    [ -f /run/systemd/resolve/resolv.conf ] && servers="$(grep -E '^nameserver' /run/systemd/resolve/resolv.conf | grep -v ' 127\.' | head -3 || true)"
    [ -n "$servers" ] || servers="$(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | grep -v ' 127\.0\.0\.' | head -3 || true)"
    [ -n "$servers" ] || servers="$(printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9')"
    printf '%s\n' "$servers" > "$RESOLV"
  fi
}

up() {
  case "$MODE" in nat|macvlan) ;; *) echo "OPERATOR_LAN_MODE must be nat or macvlan, not '$MODE'" >&2; exit 2 ;; esac
  # "ip netns list" prints "operator (id: 0)" once the namespace has an id: match the name only
  ip netns list | awk '{print $1}' | grep -qx "$NS" || ip netns add "$NS"
  in_ns ip link set lo up
  veth_up
  dns_up
  if [ "$MODE" = nat ]; then nat_up; else macvlan_up; fi
  status
}

down() {
  [ -f "/run/dhclient-$NS.pid" ] && kill "$(cat "/run/dhclient-$NS.pid")" 2>/dev/null || true
  [ -f "/run/udhcpc-$NS.pid" ] && kill "$(cat "/run/udhcpc-$NS.pid")" 2>/dev/null || true
  nft delete table inet "$NFT_TABLE" 2>/dev/null || true
  ip link del "$VETH_ROOT" 2>/dev/null || true
  in_ns ip link del "$IFACE" 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
}

status() {
  if ! ip netns list | awk '{print $1}' | grep -qx "$NS"; then echo "operator namespace: not present"; return 0; fi
  echo "operator namespace: $MODE mode"
  in_ns ip -4 -o addr show 2>/dev/null | awk '$2 != "lo" {print "   " $2 " " $4}'
  in_ns ip -o route show default 2>/dev/null | awk '{print "   default via " $3 " dev " $5}'
  nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && echo "   nftables table $NFT_TABLE present in the root namespace" || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
