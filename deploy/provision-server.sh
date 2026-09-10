#!/bin/bash
# Turns a fresh Debian into a running EX0 server. Idempotent: run it again after a
# binary update or a config change. Everything it does is described in
# deploy/README.md; nothing here is specific to one host except what it reads from
# the flags.
#
#   provision-server.sh --binary ./dist/excubra_linux_amd64 \
#                       --ingest-host ingest.ex0.example.test \
#                       [--overlay 127.0.0.1:8080] [--hostname ex0] [--allow-ubuntu]
#
# Run it ON the target host as root (the deploy helper copies it there).
set -euo pipefail

BINARY=""
INGEST_HOST=""
OVERLAY="127.0.0.1:8080"
HOSTNAME_WANT=""
ALLOW_UBUNTU=0
KEEP_DAYS=90

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="$2"; shift 2 ;;
    --ingest-host) INGEST_HOST="$2"; shift 2 ;;
    --overlay) OVERLAY="$2"; shift 2 ;;
    --hostname) HOSTNAME_WANT="$2"; shift 2 ;;
    --keep-days) KEEP_DAYS="$2"; shift 2 ;;
    --allow-ubuntu) ALLOW_UBUNTU=1; shift ;;
    *) echo "provision: unknown flag $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "provision: run as root" >&2; exit 1; }
[ -n "$BINARY" ] && [ -x "$BINARY" ] || { echo "provision: --binary <path to excubra_linux_*> required" >&2; exit 2; }
[ -n "$INGEST_HOST" ] || { echo "provision: --ingest-host <name the boxes dial> required" >&2; exit 2; }

# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != "debian" ] && [ "$ALLOW_UBUNTU" != 1 ]; then
  echo "provision: this host runs ${PRETTY_NAME:-unknown}, expected Debian." >&2
  echo "            Rebuild the server with Debian 13, or pass --allow-ubuntu." >&2
  exit 1
fi
echo "== ${PRETTY_NAME:-unknown} on $(uname -m), $(nproc) vCPU"

export DEBIAN_FRONTEND=noninteractive

echo "== packages"
apt-get update -qq
apt-get -y -qq upgrade
# curl for the restore test, ufw as the host-level firewall, unattended-upgrades for the OS,
# ca-certificates because the webhook worker talks to public HTTPS endpoints.
apt-get -y -qq install ufw curl ca-certificates unattended-upgrades chrony
apt-get -y -qq autoremove

echo "== automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/51excubra-unattended <<'EOF'
// EX0: security updates automatically, reboots at a quiet hour when the kernel needs it.
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
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
AllowAgentForwarding no
MaxAuthTries 3
EOF
install -d -m 0755 /run/sshd
sshd -t && systemctl reload ssh

echo "== firewall: inbound 22 and 443 only"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp comment 'ssh' >/dev/null
ufw allow 443/tcp comment 'excubra ingest' >/dev/null
ufw --force enable >/dev/null

echo "== journald: persistent, capped"
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/50-excubra.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=512M
MaxRetentionSec=1month
EOF
systemctl restart systemd-journald

echo "== user and directories"
id excubra >/dev/null 2>&1 || useradd --system --home /var/lib/excubra --shell /usr/sbin/nologin excubra
install -d -m 0700 -o excubra -g excubra /var/lib/excubra
install -d -m 0750 -o root -g excubra /etc/excubra
install -d -m 0750 -o excubra -g excubra /var/backups/excubra

echo "== binary"
install -m 0755 "$BINARY" /usr/local/bin/excubra.new
mv /usr/local/bin/excubra.new /usr/local/bin/excubra   # atomic: never a half-written binary
/usr/local/bin/excubra version

echo "== configuration"
if [ ! -f /etc/excubra/server.env ]; then
  cat > /etc/excubra/server.env <<EOF
# EX0 server — the one configuration file (ADR-0009). Everything else is data in the
# database and edited in the console. Options: deploy/server.env.example in the repo.
EXCUBRA_DATA_DIR=/var/lib/excubra
EXCUBRA_INGEST_LISTEN=:443
EXCUBRA_INGEST_PUBLIC_HOST=$INGEST_HOST
EXCUBRA_OVERLAY_LISTEN=$OVERLAY
EXCUBRA_OVERLAY_TLS=off
EXCUBRA_LOG_LEVEL=info
EXCUBRA_LOG_FORMAT=text
EXCUBRA_TIMEZONE=Europe/Berlin
EOF
  echo "   wrote /etc/excubra/server.env"
else
  # keep the operator's edits, only correct the two values this run was told about
  sed -i "s|^EXCUBRA_INGEST_PUBLIC_HOST=.*|EXCUBRA_INGEST_PUBLIC_HOST=$INGEST_HOST|" /etc/excubra/server.env
  sed -i "s|^EXCUBRA_OVERLAY_LISTEN=.*|EXCUBRA_OVERLAY_LISTEN=$OVERLAY|" /etc/excubra/server.env
  echo "   kept existing /etc/excubra/server.env (ingest host and overlay updated)"
fi
chown root:excubra /etc/excubra/server.env
chmod 0640 /etc/excubra/server.env

echo "== systemd units and timers"
UNIT_SRC="$(dirname "$0")"
install -m 0644 "$UNIT_SRC"/systemd/excubra-server.service /etc/systemd/system/
install -m 0644 "$UNIT_SRC"/systemd/excubra-prune.service /etc/systemd/system/
install -m 0644 "$UNIT_SRC"/systemd/excubra-prune.timer /etc/systemd/system/
install -m 0644 "$UNIT_SRC"/systemd/excubra-backup.service /etc/systemd/system/
install -m 0644 "$UNIT_SRC"/systemd/excubra-backup.timer /etc/systemd/system/
install -m 0644 "$UNIT_SRC"/systemd/excubra-restore-test.service /etc/systemd/system/
install -m 0644 "$UNIT_SRC"/systemd/excubra-restore-test.timer /etc/systemd/system/
install -m 0755 "$UNIT_SRC"/restore-test.sh /usr/local/bin/excubra-restore-test
sed -i "s|--keep 90|--keep $KEEP_DAYS|" /etc/systemd/system/excubra-prune.service
systemctl daemon-reload
systemctl enable --now excubra-prune.timer excubra-backup.timer excubra-restore-test.timer >/dev/null
systemctl enable excubra-server >/dev/null
systemctl restart excubra-server

echo "== smoke test"
ok=1
for i in $(seq 1 15); do
  if curl -fsS "http://$OVERLAY/healthz" >/dev/null 2>&1; then ok=0; break; fi
  sleep 1
done
if [ "$ok" != 0 ]; then
  echo "provision: FAILED — the server did not answer on http://$OVERLAY/healthz" >&2
  journalctl -u excubra-server --no-pager -n 20 -o cat >&2
  exit 1
fi
echo "   healthz: $(curl -fsS "http://$OVERLAY/healthz")"
code=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:443/v1/config)
[ "$code" = 401 ] || { echo "provision: ingest answered $code without a client certificate, expected 401" >&2; exit 1; }
echo "   ingest without client certificate: 401 (correct)"
echo "   CA fingerprint: $(journalctl -u excubra-server --no-pager -n 50 -o cat | grep -o 'fingerprint=[0-9a-f]*' | tail -1 | cut -d= -f2)"
echo
echo "provision: done. Next:"
echo "  excubra server user add <name>      # console login, prints password and TOTP once"
echo "  ssh -L 8080:$OVERLAY <this host>    # then open http://127.0.0.1:8080"
