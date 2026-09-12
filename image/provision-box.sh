#!/bin/bash
# Turns a fresh Debian (a mini PC, Raspberry Pi OS Lite, an LXC container on a Proxmox)
# into an EX0 box. A box is ONE package, always with the same content:
#
#   1. the EX0 agent (excubra-agent.service): enrolls, monitors, updates itself
#   2. the operator peer (netbird-operator*.service): a NetBird client in the operator's
#      own overlay, in its own network namespace. EX0 hands it its key once the box is
#      assigned to a site; technicians then reach box and LAN from their one tunnel
#      (ADR-0016). Always on; --no-operator-peer removes it.
#   3. the customer peer (netbird.service): a NetBird client for the customer's own VPN,
#      installed and idle. It joins when a key is put in through the console — the
#      opt-in for customers who get an overlay of their own.
#
# Idempotent; run again for a binary update or to change an option. Run ON the box as root:
#
#   provision-box.sh --binary ./excubra_linux_amd64 --enroll-key 'EX0:1:…' \
#                    [--hostname ex0-box-buero] [--netbird-version 0.78.1] [--ssh-lan]
#                    [--no-operator-peer] [--operator-lan-mode nat|macvlan]
#                    [--netbird-url https://kunde.vpn.example.test --netbird-setup-key KEY]
#
# A machine that already ran NetBird before its first provisioning (a hand-built routing
# peer) is somebody else's network device: no firewall, no package upgrades, its NetBird
# is not touched ("guest"). Decided once, kept in /etc/excubra/provision.env.
set -euo pipefail

# best-effort steps: in an LXC container some of these are read-only or absent
try() { "$@" 2>/dev/null || echo "   (übersprungen: $* — in Containern normal)"; }

BINARY=""
ENROLL_KEY=""
HOSTNAME_WANT=""
NETBIRD_VERSION=0.78.1
NETBIRD_SETUP_KEY=""
NETBIRD_URL=""
OPERATOR_PEER=1
OPERATOR_LAN_MODE=nat
SSH_LAN=0
FORCE_GUEST=0
STATE_DIR=/var/lib/excubra-agent
BIN_DIR=/opt/excubra/bin
PROV_ENV=/etc/excubra/provision.env
HERE="$(cd "$(dirname "$0")" && pwd)"

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --enroll-key) ENROLL_KEY="$2"; shift 2 ;;
    --hostname) HOSTNAME_WANT="$2"; shift 2 ;;
    --netbird-version) NETBIRD_VERSION="$2"; shift 2 ;;
    --netbird-setup-key) NETBIRD_SETUP_KEY="$2"; shift 2 ;;
    --netbird-url) NETBIRD_URL="$2"; shift 2 ;;
    --operator-peer) OPERATOR_PEER=1; shift ;;
    --no-operator-peer) OPERATOR_PEER=0; shift ;;
    --operator-lan-mode) OPERATOR_LAN_MODE="$2"; shift 2 ;;
    --guest) FORCE_GUEST=1; shift ;;
    --ssh-lan) SSH_LAN=1; shift ;;
    *) echo "provision-box: unknown flag $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "provision-box: run as root" >&2; exit 1; }
[ -n "$BINARY" ] && [ -x "$BINARY" ] || { echo "provision-box: --binary <excubra_linux_*> required" >&2; exit 2; }
case "$OPERATOR_LAN_MODE" in nat|macvlan) ;; *) echo "provision-box: --operator-lan-mode nat|macvlan" >&2; exit 2 ;; esac

# Guest or ours? Decided on the first run and remembered: a NetBird that was here before
# us belongs to whoever built this machine (routing peer, exit node), and a firewall or
# a package upgrade from us would cut their tunnel.
NETBIRD_GUEST=""
# shellcheck disable=SC1090
[ -f "$PROV_ENV" ] && . "$PROV_ENV"
if [ -z "${NETBIRD_GUEST:-}" ] || [ "$FORCE_GUEST" = 1 ]; then
  NETBIRD_GUEST=0
  command -v netbird >/dev/null 2>&1 && NETBIRD_GUEST=1
  [ "$FORCE_GUEST" = 1 ] && NETBIRD_GUEST=1
  install -d -m 0755 /etc/excubra
  printf '# written by provision-box.sh on first run; NETBIRD_GUEST=1 means NetBird was here before EX0\nNETBIRD_GUEST=%s\n' "$NETBIRD_GUEST" > "$PROV_ENV"
fi

# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = debian ] || [ "${ID_LIKE:-}" = debian ] || { echo "provision-box: expected Debian, got ${PRETTY_NAME:-unknown}" >&2; exit 1; }
echo "== ${PRETTY_NAME:-unknown} on $(uname -m)$([ "$NETBIRD_GUEST" = 1 ] && echo ' — guest: NetBird was here first, its firewall and packages stay as they are')"
export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get update -qq
[ "$NETBIRD_GUEST" = 1 ] || apt-get -y -qq upgrade
apt-get -y -qq install ca-certificates curl gnupg unattended-upgrades chrony nftables
[ "$NETBIRD_GUEST" = 1 ] || apt-get -y -qq install ufw
apt-get -y -qq autoremove

echo "== automatic security updates, reboot window 04:45"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
cat > /etc/apt/apt.conf.d/51excubra-unattended <<'CONF'
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Raspberry Pi Foundation,codename=${distro_codename}";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:45";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
CONF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

echo "== time"
try timedatectl set-timezone Europe/Berlin
systemctl enable --now chrony >/dev/null 2>&1 || true

if [ -n "$HOSTNAME_WANT" ]; then
  echo "== hostname $HOSTNAME_WANT"
  try hostnamectl set-hostname "$HOSTNAME_WANT"
  grep -q "127.0.1.1[[:space:]]\+$HOSTNAME_WANT" /etc/hosts || printf '127.0.1.1\t%s\n' "$HOSTNAME_WANT" >> /etc/hosts
fi

echo "== sshd: keys only"
install -d -m 0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/50-excubra.conf <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
X11Forwarding no
MaxAuthTries 3
CONF
install -d -m 0755 /run/sshd
sshd -t && systemctl reload ssh || true

echo "== firewall: no inbound port$([ "$SSH_LAN" = 1 ] && echo ' except ssh (pilot)')"
if [ "$NETBIRD_GUEST" = 1 ]; then
  echo "   (übersprungen: NetBird lief hier schon — die Maschine ist z. B. Routing-Peer, ihre Firewall gehört nicht uns; ufw würde das Forwarding kappen)"
elif ufw --force reset >/dev/null 2>&1; then
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  if [ "$SSH_LAN" = 1 ]; then ufw allow 22/tcp comment 'ssh (pilot, LAN)' >/dev/null; fi
  # the decoy ports of the live detection (ADR-0018 §7): they must look open; the agent
  # behind them accepts, waits and closes — no service, no answer
  for p in 445 3389 23 1433 5900; do ufw allow "$p/tcp" comment 'EX0 decoy port' >/dev/null; done
  # the DNS sensor (ADR-0020): only answers once a site switches it on and the router points here
  ufw allow 53/udp comment 'EX0 DNS sensor' >/dev/null
  ufw allow 53/tcp comment 'EX0 DNS sensor' >/dev/null
  ufw --force enable >/dev/null || echo "   (ufw konnte nicht aktiviert werden — Container ohne Netfilter-Rechte; die Box hat ohnehin keinen offenen Port)"
else
  echo "   (ufw nicht verfügbar — Container; die Box hat ohnehin keinen offenen Port)"
fi
ufw_active() { ufw status 2>/dev/null | grep -q '^Status: active'; }

echo "== journald: persistent, capped (SSD-friendly)"
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/50-excubra.conf <<'CONF'
[Journal]
Storage=persistent
SystemMaxUse=256M
MaxRetentionSec=2week
CONF
systemctl restart systemd-journald

echo "== unprivileged ICMP for the agent group"
cat > /etc/sysctl.d/50-excubra.conf <<'CONF'
# lets the agent open ICMP echo sockets without raw-socket rights (ADR-0007)
net.ipv4.ping_group_range = 0 2147483647
CONF
try sysctl -q -p /etc/sysctl.d/50-excubra.conf   # read-only in unprivileged containers; the agent falls back to a raw socket

echo "== user and directories"
id excubra-agent >/dev/null 2>&1 || useradd --system --home "$STATE_DIR" --shell /usr/sbin/nologin excubra-agent
install -d -m 0700 -o excubra-agent -g excubra-agent "$STATE_DIR"
install -d -m 0755 /opt/excubra
install -d -m 0755 -o excubra-agent -g excubra-agent "$BIN_DIR"   # the agent swaps its own binary here (ADR-0006)

echo "== binary"
install -m 0755 -o excubra-agent -g excubra-agent "$BINARY" "$BIN_DIR/excubra.new"
mv "$BIN_DIR/excubra.new" "$BIN_DIR/excubra"
ln -sf "$BIN_DIR/excubra" /usr/local/bin/excubra
"$BIN_DIR/excubra" version

# ---- NetBird: one client binary, two daemons -------------------------------------------
install_netbird() {
  echo "== netbird client $NETBIRD_VERSION"
  curl -fsSL https://pkgs.netbird.io/debian/public.key | gpg --dearmor --yes -o /usr/share/keyrings/netbird-archive-keyring.gpg
  echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list
  apt-get update -qq
  apt-get -y -qq install "netbird=$NETBIRD_VERSION" || apt-get -y -qq install netbird
  apt-mark hold netbird >/dev/null
}
if ! command -v netbird >/dev/null; then
  install_netbird
elif [ "$NETBIRD_GUEST" = 0 ] && [ "$(netbird version 2>/dev/null || true)" != "$NETBIRD_VERSION" ]; then
  install_netbird   # ours to update; the guest's daemon is left alone
fi

echo "== customer peer: netbird.service, idle until a key comes through the console"
# the agent (not root) must reach the daemon socket to run `netbird status` and `netbird up`
install -d -m 0755 /etc/systemd/system/netbird.service.d
cat > /etc/systemd/system/netbird.service.d/50-excubra.conf <<'CONF'
[Service]
ExecStartPost=/bin/sh -c 'for i in $(seq 1 20); do [ -S /var/run/netbird.sock ] && chgrp excubra-agent /var/run/netbird.sock && chmod 0660 /var/run/netbird.sock && exit 0; sleep 0.5; done; exit 0'
CONF
systemctl daemon-reload
if [ "$NETBIRD_GUEST" = 1 ]; then
  # no restart: on a routing peer that would cut the customer's tunnel (and ours); the drop-in
  # takes effect at the next restart, until then the running daemon's socket is adjusted live
  systemctl enable netbird >/dev/null 2>&1 || true
  if [ -S /var/run/netbird.sock ]; then chgrp excubra-agent /var/run/netbird.sock && chmod 0660 /var/run/netbird.sock; fi
else
  systemctl enable --now netbird >/dev/null 2>&1 || true
  systemctl restart netbird || true
fi

# A unit that ran the operator daemon WITHOUT its own namespace: two NetBird daemons in one
# namespace share one nftables table and the second wipes the first's routing rules
# (12.09.2026, the customer LAN went dark). Removed here, whatever put it there.
if [ -f /etc/systemd/system/netbird-operator.service ] && ! grep -q "ip netns exec operator" /etc/systemd/system/netbird-operator.service; then
  echo "== removing a netbird operator daemon without its own namespace"
  systemctl disable --now netbird-operator >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/netbird-operator.service
  systemctl daemon-reload
  systemctl restart netbird || true
fi

install -d -m 0755 /etc/default
printf 'OPERATOR_LAN_MODE=%s\n' "$OPERATOR_LAN_MODE" > /etc/default/netbird-operator
if [ "$OPERATOR_PEER" = 1 ]; then
  echo "== operator peer: netbird in its own namespace ($OPERATOR_LAN_MODE mode), waits for its key from EX0"
  install -d -m 0700 /var/lib/netbird-operator
  if [ "$OPERATOR_LAN_MODE" = macvlan ]; then
    command -v dhclient >/dev/null || command -v udhcpc >/dev/null || apt-get -y -qq install isc-dhcp-client >/dev/null 2>&1 || true
  fi
  # an earlier layout set the namespace up from the daemon unit itself; let it tear down first
  if systemctl is-active --quiet netbird-operator 2>/dev/null && [ ! -f /etc/systemd/system/netbird-operator-netns.service ]; then
    systemctl stop netbird-operator || true
  fi
  install -m 0755 "$HERE/netbird-operator-netns.sh" /opt/excubra/bin/netbird-operator-netns.sh
  install -m 0644 "$HERE/netbird-operator-netns.service" /etc/systemd/system/netbird-operator-netns.service
  install -m 0644 "$HERE/netbird-operator.service" /etc/systemd/system/netbird-operator.service
  install -m 0644 "$HERE/netbird-operator-ssh.service" /etc/systemd/system/netbird-operator-ssh.service
  if ufw_active; then
    # the namespace's way out (nat mode) and the SSH relay's way in, both over the veth pair
    ufw route allow in on veth-op comment 'operator peer to LAN (EX0)' >/dev/null
    ufw allow in on veth-op to any port 22 proto tcp comment 'ssh via operator overlay (EX0)' >/dev/null
  fi
  systemctl daemon-reload
  systemctl enable netbird-operator-netns netbird-operator netbird-operator-ssh >/dev/null 2>&1 || true
  systemctl restart netbird-operator-netns || echo "   namespace did not come up; journalctl -u netbird-operator-netns"
  sleep 3
  /opt/excubra/bin/netbird-operator-netns.sh status || true
  for u in netbird-operator netbird-operator-ssh; do printf '   %-22s %s\n' "$u" "$(systemctl is-active "$u" 2>/dev/null || true)"; done
else
  echo "== operator peer: off (--no-operator-peer)"
  systemctl disable --now netbird-operator-ssh netbird-operator netbird-operator-netns >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/netbird-operator-ssh.service /etc/systemd/system/netbird-operator.service /etc/systemd/system/netbird-operator-netns.service
  systemctl daemon-reload
fi

if [ -n "$NETBIRD_SETUP_KEY" ] && command -v netbird >/dev/null; then
  echo "== netbird up (hand-provisioned box)"
  umask 077; printf '%s' "$NETBIRD_SETUP_KEY" > /root/.nb-setup-key
  netbird up --management-url "$NETBIRD_URL" --setup-key-file /root/.nb-setup-key --hostname "${HOSTNAME_WANT:-$(hostname)}" 2>&1 | tail -1 || true
  rm -f /root/.nb-setup-key
  netbird status 2>/dev/null | grep -E "Management|NetBird IP" || true
fi

if [ -n "$ENROLL_KEY" ]; then
  echo "== enrollment key"
  install -m 0600 -o excubra-agent -g excubra-agent /dev/null "$STATE_DIR/enroll"
  printf '%s\n' "$ENROLL_KEY" > "$STATE_DIR/enroll"
fi

echo "== systemd unit"
install -m 0644 "$HERE/excubra-agent.service" /etc/systemd/system/excubra-agent.service
# the root helper that lets a release ask for a capability from the allowlist (ADR-0006)
install -d -m 0755 /usr/local/lib/excubra
install -m 0755 -o root -g root "$HERE/excubra-agent-unit.sh" /usr/local/lib/excubra/excubra-agent-unit.sh
install -m 0644 "$HERE/excubra-agent-unit.path" /etc/systemd/system/excubra-agent-unit.path
install -m 0644 "$HERE/excubra-agent-unit.service" /etc/systemd/system/excubra-agent-unit.service
systemctl daemon-reload
systemctl enable excubra-agent excubra-agent-unit.path excubra-agent-unit.service >/dev/null 2>&1 || systemctl enable excubra-agent >/dev/null
systemctl start excubra-agent-unit.path 2>/dev/null || true
systemctl restart excubra-agent
sleep 5
systemctl --no-pager --lines=0 status excubra-agent | sed -n '1,3p'
echo "== last lines"
journalctl -u excubra-agent --no-pager -n 6 -o cat
echo
nb_line() { netbird "$@" status 2>/dev/null | grep -E "Management|NetBird IP" | tr -s ' \n' ' ' || true; }
echo "provision-box: done. The package:"
printf '   agent           %s · %s\n' "$(systemctl is-active excubra-agent)" "$("$BIN_DIR/excubra" version | head -1)"
if [ "$OPERATOR_PEER" = 1 ]; then
  op="$(nb_line --daemon-addr unix:///var/run/netbird-operator.sock)"
  printf '   operator peer   %s · %s\n' "$(systemctl is-active netbird-operator 2>/dev/null || true)" "${op:-waits for its key from EX0 (assign the box to a site)}"
fi
cu="$(nb_line)"
printf '   customer peer   %s · %s\n' "$(systemctl is-active netbird 2>/dev/null || true)" "${cu:-idle until a key is put in through the console (opt-in)}"
echo "Open ports:"
ss -tlnp | awk 'NR>1{print "   " $4}' | sort -u || true
echo "   (SSH only if --ssh-lan was given, plus port 22 inside the operator namespace for the relay — that is the point)"
