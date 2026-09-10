#!/bin/bash
# Turns a fresh Debian (Raspberry Pi OS Lite, a mini PC, a VM) into an EX0 box.
# Idempotent; run again for a binary update. Run ON the box as root:
#
#   provision-box.sh --binary ./excubra_linux_amd64 --enroll-key 'EX0:1:…' \
#                    [--hostname ex0-box-buero] [--netbird-version 0.78.1] [--ssh-lan]
#                    [--netbird-url https://kunde.vpn.viico-cloud.de --netbird-setup-key KEY]
#
# What a box is (salt: Konzept, "Die Box"): one unprivileged agent, no listening
# port, outbound only. SSH is bound to the NetBird interface once that exists;
# --ssh-lan keeps it reachable on the LAN for the pilot in the office.
set -euo pipefail

BINARY=""
ENROLL_KEY=""
HOSTNAME_WANT=""
NETBIRD_VERSION=""
NETBIRD_SETUP_KEY=""
NETBIRD_URL=""
SSH_LAN=0
STATE_DIR=/var/lib/excubra-agent
BIN_DIR=/opt/excubra/bin

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --enroll-key) ENROLL_KEY="$2"; shift 2 ;;
    --hostname) HOSTNAME_WANT="$2"; shift 2 ;;
    --netbird-version) NETBIRD_VERSION="$2"; shift 2 ;;
    --netbird-setup-key) NETBIRD_SETUP_KEY="$2"; shift 2 ;;
    --netbird-url) NETBIRD_URL="$2"; shift 2 ;;
    --ssh-lan) SSH_LAN=1; shift ;;
    *) echo "provision-box: unknown flag $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "provision-box: run as root" >&2; exit 1; }
[ -n "$BINARY" ] && [ -x "$BINARY" ] || { echo "provision-box: --binary <excubra_linux_*> required" >&2; exit 2; }

# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = debian ] || [ "${ID_LIKE:-}" = debian ] || { echo "provision-box: expected Debian, got ${PRETTY_NAME:-unknown}" >&2; exit 1; }
echo "== ${PRETTY_NAME:-unknown} on $(uname -m)"
export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get update -qq
apt-get -y -qq upgrade
apt-get -y -qq install ca-certificates curl gnupg unattended-upgrades chrony ufw
apt-get -y -qq autoremove

echo "== automatic security updates, reboot window 04:45"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/51excubra-unattended <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Raspberry Pi Foundation,codename=${distro_codename}";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:45";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
EOF
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

echo "== time"
timedatectl set-timezone Europe/Berlin
systemctl enable --now chrony >/dev/null 2>&1 || true

if [ -n "$HOSTNAME_WANT" ]; then
  echo "== hostname $HOSTNAME_WANT"
  hostnamectl set-hostname "$HOSTNAME_WANT"
  grep -q "127.0.1.1[[:space:]]\+$HOSTNAME_WANT" /etc/hosts || printf '127.0.1.1\t%s\n' "$HOSTNAME_WANT" >> /etc/hosts
fi

echo "== sshd: keys only"
install -d -m 0755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/50-excubra.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
X11Forwarding no
MaxAuthTries 3
EOF
install -d -m 0755 /run/sshd
sshd -t && systemctl reload ssh || true

echo "== firewall: no inbound port$([ "$SSH_LAN" = 1 ] && echo ' except ssh (pilot)')"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
if [ "$SSH_LAN" = 1 ]; then ufw allow 22/tcp comment 'ssh (pilot, LAN)' >/dev/null; fi
ufw --force enable >/dev/null

echo "== journald: persistent, capped (SSD-friendly)"
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/50-excubra.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=256M
MaxRetentionSec=2week
EOF
systemctl restart systemd-journald

echo "== unprivileged ICMP for the agent group"
cat > /etc/sysctl.d/50-excubra.conf <<'EOF'
# lets the agent open ICMP echo sockets without raw-socket rights (ADR-0007)
net.ipv4.ping_group_range = 0 2147483647
EOF
sysctl -q -p /etc/sysctl.d/50-excubra.conf

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

if [ -n "$NETBIRD_VERSION" ]; then
  echo "== netbird client $NETBIRD_VERSION"
  if ! command -v netbird >/dev/null || [ "$(netbird version 2>/dev/null || true)" != "$NETBIRD_VERSION" ]; then
    curl -fsSL https://pkgs.netbird.io/debian/public.key | gpg --dearmor --yes -o /usr/share/keyrings/netbird-archive-keyring.gpg
    echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' > /etc/apt/sources.list.d/netbird.list
    apt-get update -qq
    apt-get -y -qq install "netbird=$NETBIRD_VERSION" || apt-get -y -qq install netbird
    apt-mark hold netbird >/dev/null
  fi
  # the agent (not root) must reach the daemon socket to run `netbird status` and `netbird up`
  install -d -m 0755 /etc/systemd/system/netbird.service.d
  cat > /etc/systemd/system/netbird.service.d/50-excubra.conf <<'EOF'
[Service]
ExecStartPost=/bin/sh -c 'for i in $(seq 1 20); do [ -S /var/run/netbird.sock ] && chgrp excubra-agent /var/run/netbird.sock && chmod 0660 /var/run/netbird.sock && exit 0; sleep 0.5; done; exit 0'
EOF
  systemctl daemon-reload
  systemctl enable --now netbird >/dev/null 2>&1 || true
  systemctl restart netbird || true
fi
if command -v netbird >/dev/null && [ ! -f /etc/systemd/system/netbird.service.d/50-excubra.conf ]; then
  echo "== netbird already installed: opening its daemon socket to the agent group"
  install -d -m 0755 /etc/systemd/system/netbird.service.d
  cat > /etc/systemd/system/netbird.service.d/50-excubra.conf <<'EOF'
[Service]
ExecStartPost=/bin/sh -c 'for i in $(seq 1 20); do [ -S /var/run/netbird.sock ] && chgrp excubra-agent /var/run/netbird.sock && chmod 0660 /var/run/netbird.sock && exit 0; sleep 0.5; done; exit 0'
EOF
  systemctl daemon-reload
  systemctl restart netbird || true
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
install -m 0644 "$(dirname "$0")/excubra-agent.service" /etc/systemd/system/excubra-agent.service
systemctl daemon-reload
systemctl enable excubra-agent >/dev/null
systemctl restart excubra-agent
sleep 5
systemctl --no-pager --lines=0 status excubra-agent | sed -n '1,3p'
echo "== last lines"
journalctl -u excubra-agent --no-pager -n 6 -o cat
echo
echo "provision-box: done. Open ports:"
ss -tlnp | awk 'NR>1{print "   " $4}' | sort -u || true
echo "   (SSH only if --ssh-lan was given; otherwise none — that is the point)"
