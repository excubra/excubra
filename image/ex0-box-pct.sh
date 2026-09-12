#!/bin/bash
# Makes an EX0 box as an LXC container on THIS Proxmox host, with nothing but an
# enrollment key. The console prints the one-liner:
#
#   curl -fsSL https://raw.githubusercontent.com/excubra/excubra/<tag>/image/ex0-box-pct.sh \
#     | bash -s -- --enroll-key 'EX0:1:…' [--hostname ex0-kunde-standort] [--version 0.2.8]
#       [--ctid 200] [--bridge vmbr0] [--ip dhcp | --ip 192.168.10.60/24 --gw 192.168.10.1]
#       [--storage local-lvm] [--disk 8] [--memory 1024]
#
# What it does: downloads the Debian 13 template if missing, creates an unprivileged
# container with nesting (for the operator namespace) and /dev/net/tun (for
# NetBird), starts it, and runs ex0-box.sh inside. The container then enrolls,
# assigns itself to the key's site, joins the operator stack and reports its LAN.
set -euo pipefail
REPO="${EX0_REPO:-excubra/excubra}"
VERSION=""
ENROLL_KEY=""
HOSTNAME_WANT="ex0-box"
CTID=""
BRIDGE="vmbr0"
IP="dhcp"
GW=""
STORAGE=""
DISK=8
MEMORY=1024
PASS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --enroll-key) ENROLL_KEY="$2"; shift 2 ;;
    --hostname) HOSTNAME_WANT="$2"; shift 2 ;;
    --ctid) CTID="$2"; shift 2 ;;
    --bridge) BRIDGE="$2"; shift 2 ;;
    --ip) IP="$2"; shift 2 ;;
    --gw) GW="$2"; shift 2 ;;
    --storage) STORAGE="$2"; shift 2 ;;
    --disk) DISK="$2"; shift 2 ;;
    --memory) MEMORY="$2"; shift 2 ;;
    --netbird-version|--operator-lan-mode) PASS+=("$1" "$2"); shift 2 ;;
    --no-operator-peer|--ssh-lan) PASS+=("$1"); shift ;;
    *) echo "ex0-box-pct: unknown flag $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "ex0-box-pct: run as root on the Proxmox host" >&2; exit 1; }
command -v pct >/dev/null && command -v pveam >/dev/null || { echo "ex0-box-pct: this is not a Proxmox host (pct/pveam missing)" >&2; exit 1; }
[ -n "$ENROLL_KEY" ] || { echo "ex0-box-pct: --enroll-key 'EX0:1:…' required (from the console: Neue Box)" >&2; exit 2; }
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$VERSION" ] || { echo "ex0-box-pct: could not find the latest release of $REPO" >&2; exit 1; }
fi
RAW="https://raw.githubusercontent.com/$REPO/v$VERSION/image"

echo "== storage"
TPL_STORE="$(pvesm status --content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
[ -n "$TPL_STORE" ] || TPL_STORE=local
if [ -z "$STORAGE" ]; then
  STORAGE="$(pvesm status --content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1}' | grep -E '^(local-lvm|local-zfs)$' | head -1)"
  [ -n "$STORAGE" ] || STORAGE="$(pvesm status --content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
  [ -n "$STORAGE" ] || { echo "ex0-box-pct: no storage for container disks found (--storage)" >&2; exit 1; }
fi
echo "   templates on $TPL_STORE, container disk on $STORAGE"

echo "== Debian 13 template"
pveam update >/dev/null 2>&1 || true
TPL="$(pveam available --section system 2>/dev/null | awk '{print $2}' | grep -E '^debian-13-standard_.*_amd64\.tar\.(zst|xz|gz)$' | sort -V | tail -1)"
[ -n "$TPL" ] || { echo "ex0-box-pct: no debian-13-standard template offered by pveam" >&2; exit 1; }
pveam list "$TPL_STORE" 2>/dev/null | grep -q "$TPL" || pveam download "$TPL_STORE" "$TPL"

[ -n "$CTID" ] || CTID="$(pvesh get /cluster/nextid)"
NET="name=eth0,bridge=$BRIDGE,ip=$IP"
[ "$IP" != dhcp ] && [ -n "$GW" ] && NET="$NET,gw=$GW"
echo "== container $CTID ($HOSTNAME_WANT), $NET"
pct create "$CTID" "$TPL_STORE:vztmpl/$TPL" --hostname "$HOSTNAME_WANT" --unprivileged 1 --features nesting=1 --ostype debian \
  --net0 "$NET" --rootfs "$STORAGE:$DISK" --memory "$MEMORY" --swap 256 --cores 2 --onboot 1 --start 0 \
  --description "EX0 box (ex0-box-pct.sh v$VERSION). Agent + operator peer + prepared customer peer. Managed from the EX0 console." >/dev/null
pct set "$CTID" --dev0 path=/dev/net/tun >/dev/null 2>&1 || {
  # older Proxmox: the raw lxc way
  printf 'lxc.cgroup2.devices.allow: c 10:200 rwm\nlxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file\n' >> "/etc/pve/lxc/$CTID.conf"
}
pct start "$CTID"
echo "== waiting for the network in the container"
for i in $(seq 1 60); do pct exec "$CTID" -- sh -c 'getent hosts deb.debian.org >/dev/null 2>&1' && break; sleep 2; done
pct exec "$CTID" -- sh -c 'getent hosts deb.debian.org >/dev/null 2>&1' || { echo "ex0-box-pct: the container has no network after two minutes (bridge $BRIDGE, ip $IP)" >&2; exit 1; }

echo "== EX0 inside the container"
umask 077
KEYFILE="$(mktemp /tmp/ex0-enroll.XXXXXX)"
printf '%s\n' "$ENROLL_KEY" > "$KEYFILE"
pct push "$CTID" "$KEYFILE" /root/ex0-enroll --perms 0600
rm -f "$KEYFILE"
pct exec "$CTID" -- bash -c "export DEBIAN_FRONTEND=noninteractive; apt-get -qq update >/dev/null && apt-get -y -qq install curl ca-certificates >/dev/null; curl -fsSL '$RAW/ex0-box.sh' | bash -s -- --enroll-key-file /root/ex0-enroll --hostname '$HOSTNAME_WANT' --version '$VERSION' $(printf "%q " "${PASS[@]}")"
echo
echo "ex0-box-pct: container $CTID is an EX0 box. It shows up in the console within a minute, assigned to its site."
