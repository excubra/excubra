#!/bin/sh
# Restores the backup in $1 into a temporary directory, starts a throwaway server
# against it on loopback ports, checks /healthz, and fails loudly otherwise.
# Installed as /usr/local/bin/excubra-restore-test by the deployment.
set -eu
BACKUP="${1:?usage: excubra-restore-test <backup-dir>}"
TMP="$(mktemp -d)"
trap 'kill "$PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT
cp -a "$BACKUP"/. "$TMP/data"
test -s "$TMP/data/main.db" || { echo "restore-test: no main.db in $BACKUP" >&2; exit 1; }
test -s "$TMP/data/ca/ca.key" || { echo "restore-test: no CA key in $BACKUP" >&2; exit 1; }
cat > "$TMP/server.env" <<ENV
EXCUBRA_DATA_DIR=$TMP/data
EXCUBRA_INGEST_LISTEN=127.0.0.1:18443
EXCUBRA_INGEST_PUBLIC_HOST=127.0.0.1:18443
EXCUBRA_OVERLAY_LISTEN=127.0.0.1:18080
EXCUBRA_LOG_LEVEL=warn
ENV
# the backup holds sealed keys and tokens; the restore needs the same secret key
KEYFILE="$(sed -n 's/^EXCUBRA_SECRET_KEY_FILE=//p' /etc/excubra/server.env 2>/dev/null)"
if [ -n "$KEYFILE" ] && [ -r "$KEYFILE" ]; then echo "EXCUBRA_SECRET_KEY_FILE=$KEYFILE" >> "$TMP/server.env"; fi
/usr/local/bin/excubra server run --env-file "$TMP/server.env" &
PID=$!
for i in $(seq 1 20); do
  if curl -fsS http://127.0.0.1:18080/healthz >/dev/null 2>&1; then
    echo "restore-test: OK — restored server answers, $(/usr/local/bin/excubra server tenant list --env-file "$TMP/server.env" | wc -l) tenant(s)"
    exit 0
  fi
  sleep 1
done
echo "restore-test: FAILED — restored server did not come up" >&2
exit 1
