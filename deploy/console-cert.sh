#!/usr/bin/env bash
# Gives the console a certificate from a public CA, so an operator reaches it
# without installing anything first.
#
#   deploy/console-cert.sh konsole.ex0.example.test
#
# How it works, and why this way. Let's Encrypt's DNS-01 challenge proves a name
# by writing a TXT record, never by connecting to the host. The console therefore
# stays exactly where it is — reachable only through the overlay — and still
# carries a certificate every browser trusts. The A record may point at the
# overlay address; 100.64.0.0/10 is not routable on the internet, so publishing it
# tells nobody anything they can use.
#
# The ingest is deliberately left alone. Boxes pin our own CA there (ADR-0002),
# which is stronger for a channel we control on both ends, and it must not depend
# on a third party being reachable.
#
# Before running this:
#   1. Delegate the subzone (ex0.example.test) to a DNS provider with an API, so
#      the token below can only touch that subzone and never the parent.
#   2. Create an A record for the name, pointing at the overlay address.
#   3. Put the provider's token in /etc/excubra/dns.env as the variable lego wants
#      (HETZNER_API_KEY, CF_DNS_API_TOKEN, …), mode 0600, root only.
set -euo pipefail

NAME="${1:-}"
MAIL="${ACME_MAIL:-hostmaster@${NAME#*.}}"
PROVIDER="${DNS_PROVIDER:-hetzner}"
DIR=/etc/excubra/acme
ENVFILE=/etc/excubra/dns.env
SERVER_ENV=/etc/excubra/server.env

[ -n "$NAME" ] || { echo "usage: $0 <console-name>" >&2; exit 2; }
[ -r "$ENVFILE" ] || { echo "$ENVFILE is missing; put the DNS API token there first" >&2; exit 2; }
command -v lego >/dev/null || { echo "lego is not installed: apt-get install -y lego" >&2; exit 2; }

install -d -m 0700 "$DIR"

# shellcheck disable=SC1090
set -a; . "$ENVFILE"; set +a

run() {
  lego --accept-tos --email "$MAIL" --dns "$PROVIDER" --domains "$NAME" --path "$DIR" "$1"
}

# "run" renews when it is due and exits 0 when it is not, so the timer below can
# call this script every day without thinking.
if [ -f "$DIR/certificates/$NAME.crt" ]; then
  run renew
else
  run run
fi

CRT="$DIR/certificates/$NAME.crt"
KEY="$DIR/certificates/$NAME.key"
install -o excubra -g excubra -m 0644 "$CRT" /etc/excubra/console.crt
install -o excubra -g excubra -m 0600 "$KEY" /etc/excubra/console.key
echo "certificate in place for $NAME, valid until $(openssl x509 -enddate -noout -in /etc/excubra/console.crt | cut -d= -f2)"

# The server re-reads the pair within half a minute; no restart, no dropped
# session. It only needs telling once which files to read.
if ! grep -q '^EXCUBRA_OVERLAY_TLS=files' "$SERVER_ENV" 2>/dev/null; then
  cat <<'EOF'

Now add this to /etc/excubra/server.env and restart once:

  EXCUBRA_OVERLAY_TLS=files
  EXCUBRA_OVERLAY_CERT=/etc/excubra/console.crt
  EXCUBRA_OVERLAY_KEY=/etc/excubra/console.key
  EXCUBRA_CONSOLE_URL=https://<name>

To drop the port from the console's address, bind the ingest to the public
address instead of every address, which frees 443 on the overlay:

  EXCUBRA_INGEST_LISTEN=<public ip>:443
  EXCUBRA_OVERLAY_LISTEN=<overlay ip>:443

Then install the daily renewal:

  systemctl enable --now excubra-console-cert.timer
EOF
fi
