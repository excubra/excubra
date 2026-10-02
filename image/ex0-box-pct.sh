#!/bin/bash
# Makes an EX0 box as an LXC container on THIS Proxmox host, with nothing but an
# enrollment key. The console and the MCP server print the command:
#
#   curl -fsSL https://raw.githubusercontent.com/excubra/excubra/<tag>/image/ex0-box-pct.sh -o /tmp/ex0-box-pct.sh \
#     && bash /tmp/ex0-box-pct.sh --enroll-key 'EX0:1:…' [--hostname ex0-kunde-standort] [--version 0.20.0]
#       [--ctid 200] [--bridge vmbr0] [--ip dhcp | --ip 192.168.10.60/24 --gw 192.168.10.1]
#       [--storage local-lvm] [--disk 8] [--memory 1024] [--ssh-key 'ssh-ed25519 AAAA… name']…
#
# What it does: downloads the Debian 13 template if missing, creates an unprivileged
# container with nesting (for the operator namespace) and /dev/net/tun (for
# NetBird), starts it, and runs ex0-box.sh inside. The container then enrolls,
# assigns itself to the key's site, joins the operator stack and reports its LAN.
#
# It says what happened, in one line a person and a program can both read:
#
#   EX0-RESULT: ok ctid=200 hostname=… box=box_…
#   EX0-RESULT: failed step=… — and why
#
# and its exit status says the same. Run it again after a failure: it finds its
# own container by hostname and carries on in it instead of making a second one.
#
# Everything is inside main, called on the last line: a download that broke off
# half-way runs nothing.
set -Eeuo pipefail

main() {
  REPO="${EX0_REPO:-excubra/excubra}"
  VERSION=""
  ENROLL_KEY=""
  HOSTNAME_WANT="ex0-box"
  CTID=""
  BRIDGE=""
  IP="dhcp"
  GW=""
  STORAGE=""
  DISK=8
  MEMORY=1024
  PASS=()
  STEP="arguments"
  MADE=0

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
      --netbird-version|--operator-lan-mode|--ssh-key) PASS+=("$1" "$2"); shift 2 ;;
      --no-operator-peer|--ssh-lan) PASS+=("$1"); shift ;;
      *) echo "ex0-box-pct: unknown flag $1" >&2; exit 2 ;;
    esac
  done

  trap 'failed "line $LINENO: $BASH_COMMAND"' ERR

  [ "$(id -u)" = 0 ] || die "run as root on the Proxmox host"
  command -v pct >/dev/null && command -v pveam >/dev/null && command -v pvesm >/dev/null || die "this is not a Proxmox host (pct/pveam/pvesm missing) — on a machine of its own use ex0-box.sh"
  [ -n "$ENROLL_KEY" ] || die "--enroll-key 'EX0:1:…' required (console: Neue Box, or ex0_new_box)"
  case "$ENROLL_KEY" in EX0:1:*) ;; *) die "that is not an enrollment key (EX0:1:…)" ;; esac
  case "$HOSTNAME_WANT" in *[!a-z0-9-]*|-*|"") die "--hostname: lower-case letters, digits and dashes only" ;; esac
  case "$DISK$MEMORY${CTID:-1}" in *[!0-9]*) die "--ctid, --disk and --memory are numbers" ;; esac
  if [ "$IP" != dhcp ]; then
    case "$IP" in */*) ;; *) die "--ip needs the prefix length, e.g. 192.168.10.60/24 (or dhcp)" ;; esac
    [ -n "$GW" ] || die "a fixed --ip needs --gw (the gateway of that network)"
  fi

  STEP="release"
  if [ -z "$VERSION" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)" || true
    [ -n "$VERSION" ] || die "could not find the latest release of $REPO (no internet from this host?)"
  fi
  # EX0_RAW_BASE: where the release's files are read from instead of GitHub — a
  # mirror, or a checkout served locally to try a change before it is released.
  # The binary still has to verify against the release public key.
  RAW="${EX0_RAW_BASE:-https://raw.githubusercontent.com/$REPO/v$VERSION}/image"

  STEP="bridge"
  if [ -z "$BRIDGE" ]; then
    BRIDGE=vmbr0
    if [ ! -d /sys/class/net/vmbr0/bridge ]; then
      # no vmbr0: take the bridge the host's own default route leaves through
      dev="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}')" || true
      dev="${dev%%$'\n'*}"
      if [ -n "$dev" ] && [ -d "/sys/class/net/$dev/bridge" ]; then BRIDGE="$dev"; fi
    fi
  fi
  [ -d "/sys/class/net/$BRIDGE/bridge" ] || die "bridge $BRIDGE does not exist on this host (bridges here: $(bridges)) — name the LAN's bridge with --bridge"

  STEP="storage"
  echo "== storage"
  # whole answers first, picking second: no pipe that ends early under pipefail
  TPL_STORES="$(pvesm status --content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1}')" || true
  TPL_STORE="${TPL_STORES%%$'\n'*}"
  [ -n "$TPL_STORE" ] || TPL_STORE=local
  DISK_STORES="$(pvesm status --content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1}')" || true
  if [ -z "$STORAGE" ]; then
    for s in local-lvm local-zfs; do
      if grep -qx "$s" <<<"$DISK_STORES"; then STORAGE="$s"; break; fi
    done
    [ -n "$STORAGE" ] || STORAGE="${DISK_STORES%%$'\n'*}"
    [ -n "$STORAGE" ] || die "no storage for container disks found — name one with --storage"
  else
    grep -qx "$STORAGE" <<<"$DISK_STORES" \
      || die "storage $STORAGE does not exist here or takes no container disks (these do: $(tr '\n' ' ' <<<"$DISK_STORES"))"
  fi
  echo "   templates on $TPL_STORE, container disk on $STORAGE"

  STEP="container"
  # Ours already? A second run must continue in the first run's container, not
  # leave a half-made one behind and build another next to it.
  if [ -z "$CTID" ]; then
    SAME_NAME="$(pct list 2>/dev/null | awk -v h="$HOSTNAME_WANT" 'NR>1 && $NF==h{print $1}')" || true
    for id in $SAME_NAME; do
      if is_ours "$id"; then CTID="$id"; break; fi
    done
  fi
  if [ -n "$CTID" ] && pct status "$CTID" >/dev/null 2>&1; then
    is_ours "$CTID" || die "container $CTID exists and is not an EX0 box — choose another --ctid"
    echo "== container $CTID exists and is an EX0 box: continuing in it"
  else
    if [ "$IP" != dhcp ]; then
      addr="${IP%/*}"
      if ping -c 1 -W 1 "$addr" >/dev/null 2>&1; then
        die "$addr already answers on the network — it is taken; choose a free address for --ip"
      fi
    fi
    echo "== Debian 13 template"
    pveam update >/dev/null 2>&1 || true
    TPL="$(pveam available --section system 2>/dev/null | awk '{print $2}' | grep -E '^debian-13-standard_.*_amd64\.tar\.(zst|xz|gz)$' | sort -V | tail -1)" || true
    [ -n "$TPL" ] || die "no debian-13-standard template offered by pveam (no internet from this host?)"
    HAVE="$(pveam list "$TPL_STORE" 2>/dev/null)" || true
    case "$HAVE" in *"$TPL"*) ;; *) pveam download "$TPL_STORE" "$TPL" ;; esac

    [ -n "$CTID" ] || CTID="$(pvesh get /cluster/nextid)"
    NET="name=eth0,bridge=$BRIDGE,ip=$IP"
    [ "$IP" != dhcp ] && NET="$NET,gw=$GW"
    echo "== container $CTID ($HOSTNAME_WANT), $NET"
    pct create "$CTID" "$TPL_STORE:vztmpl/$TPL" --hostname "$HOSTNAME_WANT" --unprivileged 1 --features nesting=1 --ostype debian \
      --net0 "$NET" --rootfs "$STORAGE:$DISK" --memory "$MEMORY" --swap 256 --cores 2 --onboot 1 --start 0 \
      --description "EX0 box (ex0-box-pct.sh v$VERSION). Agent + operator peer + prepared customer peer. Managed from the EX0 console." >/dev/null
    MADE=1
    pct set "$CTID" --dev0 path=/dev/net/tun >/dev/null 2>&1 || {
      # older Proxmox: the raw lxc way
      printf 'lxc.cgroup2.devices.allow: c 10:200 rwm\nlxc.mount.entry: /dev/net/tun dev/net/tun none bind,create=file\n' >> "/etc/pve/lxc/$CTID.conf"
    }
  fi
  [ "$(pct status "$CTID" 2>/dev/null)" = "status: running" ] || pct start "$CTID"

  STEP="network in the container"
  echo "== waiting for the network in the container"
  ok=0
  for _ in $(seq 1 60); do
    if pct exec "$CTID" -- sh -c 'getent hosts deb.debian.org >/dev/null 2>&1'; then ok=1; break; fi
    sleep 2
  done
  if [ "$ok" != 1 ]; then
    echo "   what the container has:" >&2
    pct exec "$CTID" -- sh -c 'ip -4 -br addr; ip -4 route; cat /etc/resolv.conf' >&2 || true
    die "the container has no working network after two minutes (bridge $BRIDGE, ip $IP${GW:+, gw $GW}) — wrong bridge, address or gateway, or no DHCP on that network"
  fi

  STEP="installer"
  echo "== EX0 inside the container"
  W="$(mktemp -d /tmp/ex0-box-pct.XXXXXX)"   # 0700: the key file below is nobody else's
  # first the file, then the run: a download that fails is a failure, not an
  # empty script that ends quietly (29.09.2026: "is an EX0 box" over nothing)
  curl -fsSL -o "$W/ex0-box.sh" "$RAW/ex0-box.sh" || die "could not download ex0-box.sh v$VERSION from $RAW"
  [ "$(head -c 11 "$W/ex0-box.sh")" = '#!/bin/bash' ] || die "what came from $RAW/ex0-box.sh is not the installer"
  printf '%s\n' "$ENROLL_KEY" > "$W/enroll"
  pct push "$CTID" "$W/ex0-box.sh" /root/ex0-box.sh --perms 0700
  pct push "$CTID" "$W/enroll" /root/ex0-enroll --perms 0600
  rm -rf "$W"
  pct exec "$CTID" -- bash -c 'export DEBIAN_FRONTEND=noninteractive; command -v curl >/dev/null || { apt-get -qq update && apt-get -y -qq install curl ca-certificates >/dev/null; }' \
    || die "apt in the container failed (no way out to the Debian mirrors?)"
  # the key file is spent by the first run that enrolls; a later run finds the box
  # enrolled and needs none
  if pct exec "$CTID" -- env EX0_REPO="$REPO" EX0_RAW_BASE="${EX0_RAW_BASE:-}" bash /root/ex0-box.sh --enroll-key-file /root/ex0-enroll --hostname "$HOSTNAME_WANT" --version "$VERSION" ${PASS[@]+"${PASS[@]}"}; then
    :
  else
    die "the installer inside container $CTID failed — its last lines above say why"
  fi

  STEP="verification"
  pct exec "$CTID" -- systemctl is-active --quiet excubra-agent || die "the agent is not running in container $CTID"
  BOX="$(pct exec "$CTID" -- sh -c 'cat /var/lib/excubra-agent/box.id 2>/dev/null' | tr -d '[:space:]')" || true
  [ -n "$BOX" ] || die "the agent runs but has no identity: it did not enroll"
  ADDR="$(pct exec "$CTID" -- sh -c "ip -4 -o addr show dev eth0 2>/dev/null | awk '{print \$4}' | head -1")" || true

  trap - ERR
  echo
  echo "════════════════════════════════════════════════════════════════"
  echo "EX0-RESULT: ok ctid=$CTID hostname=$HOSTNAME_WANT box=$BOX"
  echo "  container $CTID on $BRIDGE, ${ADDR:-address unknown}$([ "$IP" = dhcp ] && echo ' (DHCP — reserve it in the router, or it may change)'), disk on $STORAGE"
  echo "  the box is enrolled and shows up at its site within a minute"
  echo "════════════════════════════════════════════════════════════════"
}

# bridges lists the host's bridges, without the firewall's own (fwbr…).
bridges() {
  local b n
  for b in /sys/class/net/*/bridge; do
    [ -d "$b" ] || continue
    n="$(basename "$(dirname "$b")")"
    case "$n" in fwbr*) ;; *) printf '%s ' "$n" ;; esac
  done
}

# is_ours: the container was made by this script (its description says so).
is_ours() {
  grep -qs '^#.*EX0 box' "/etc/pve/lxc/$1.conf" && return 0
  local c
  c="$(pct config "$1" 2>/dev/null)" || return 1
  case "$c" in *"description: EX0 box"*) return 0 ;; esac
  return 1
}

die() { failed "$*"; }

failed() {
  trap - ERR
  {
    echo
    echo "════════════════════════════════════════════════════════════════"
    echo "EX0-RESULT: failed step=${STEP// /-} — $*"
    if [ "${MADE:-0}" = 1 ] || { [ -n "${CTID:-}" ] && pct status "$CTID" >/dev/null 2>&1; }; then
      echo "  container ${CTID} stays as it is. Run the same command again to carry on in it"
      echo "  (same --hostname or --ctid ${CTID}), or remove it: pct stop ${CTID}; pct destroy ${CTID}"
    else
      echo "  nothing was created on this host"
    fi
    echo "════════════════════════════════════════════════════════════════"
  } >&2
  exit 1
}

main "$@"
