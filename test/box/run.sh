#!/bin/bash
# Tries the box installers the way a rollout meets them — before a release, not at
# a customer. A local server, a Debian 13 with systemd in Docker, real enrollments:
#
#   test/box/run.sh            every scenario
#   test/box/run.sh T1 P3      only these
#   KEEP=1 test/box/run.sh T1  leave the container (ex0box-T1) standing to look inside
#
# What it covers:
#   T…  provision-box.sh on a machine of its own, with a build of the working tree
#   P…  ex0-box-pct.sh end to end on a pretend Proxmox (pve-stubs: the "container"
#       is the machine itself), with ex0-box.sh downloading the latest signed
#       release and the scripts of this checkout (EX0_RAW_BASE)
#
# Needs Docker, Go, python3 and the internet (apt, the NetBird repository, the
# release on GitHub). It joins no overlay: the test server has no operator stack.
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"
W="$(mktemp -d /tmp/ex0box.XXXXXX)"   # short: a Unix socket path has to fit
PORT_INGEST=18443 PORT_CONSOLE=18080 PORT_FILES=18099
IMAGE=ex0-test-debian13
PUB="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGlvZi4wdGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleQ test@ex0"
ONLY=("$@")
PASSED=() FAILED=()

cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  [ -n "${FILES_PID:-}" ] && kill "$FILES_PID" 2>/dev/null || true
  if [ "${KEEP:-0}" != 1 ]; then
    local ids; ids="$(docker ps -aq --filter name=ex0box- 2>/dev/null || true)"
    # shellcheck disable=SC2086
    [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
    rm -rf "$W"
  else
    echo "kept: $W and the containers ex0box-*"
  fi
}
trap cleanup EXIT

wanted() { [ ${#ONLY[@]} -eq 0 ] && return 0; local s; for s in "${ONLY[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }
pass() { PASSED+=("$1"); echo "PASS $1"; }
fail() { FAILED+=("$1: $2"); echo "FAIL $1: $2"; }
# has <file> <text>: the log contains the text
has() { grep -qF -- "$2" "$1"; }

echo "== build"
ARCH="$(docker info --format '{{.Architecture}}' | sed 's/aarch64/arm64/; s/x86_64/amd64/')"
go build -o "$W/excubra" ./cmd/excubra
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$W/excubra_linux_$ARCH" ./cmd/excubra
docker build -q -t "$IMAGE" test/box >/dev/null

echo "== server"
mkdir -p "$W/data"
openssl rand -base64 32 > "$W/secret.key"
cat > "$W/server.env" <<EOF
EXCUBRA_DATA_DIR=$W/data
EXCUBRA_INGEST_LISTEN=127.0.0.1:$PORT_INGEST
EXCUBRA_INGEST_PUBLIC_HOST=host.docker.internal:$PORT_INGEST
EXCUBRA_OVERLAY_LISTEN=127.0.0.1:$PORT_CONSOLE
EXCUBRA_SECRET_KEY_FILE=$W/secret.key
EXCUBRA_SELF_UPDATE=off
EXCUBRA_RELEASE_CATALOG=off
EXCUBRA_FEEDS=off
EXCUBRA_VULNS=off
EXCUBRA_BLOCKLIST=off
EOF
"$W/excubra" server run --env-file "$W/server.env" > "$W/server.log" 2>&1 &
SERVER_PID=$!
python3 -m http.server "$PORT_FILES" --bind 127.0.0.1 --directory "$ROOT" > "$W/files.log" 2>&1 &
FILES_PID=$!
for _ in $(seq 1 50); do [ -S "$W/data/mcp.sock" ] && break; sleep 0.2; done
[ -S "$W/data/mcp.sock" ] || { echo "the server did not come up:"; tail -5 "$W/server.log"; exit 1; }

# mcp <tool> <json arguments>: one call through the server's socket, the text of the answer
mcp() {
  printf '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$1" "$2" \
    | "$W/excubra" server mcp --env-file "$W/server.env" --actor box-test 2>/dev/null \
    | python3 -c 'import sys,json; r=json.loads(sys.stdin.readline())["result"]; print(r["content"][0]["text"]); sys.exit(1 if r.get("isError") else 0)'
}
newkey() { mcp ex0_new_box "{\"site_id\":\"$1\"}" | python3 -c 'import sys,json,re; print(re.search(r"EX0:1:[^\x27 ]+", json.load(sys.stdin)["commands"][0]["cmd"]).group(0))'; }
mcp ex0_create_tenant '{"slug":"test","name":"Test GmbH"}' >/dev/null
mcp ex0_create_site '{"tenant_id":"ten_test","slug":"buero","name":"Büro"}' >/dev/null
mcp ex0_create_site '{"tenant_id":"ten_test","slug":"lager","name":"Lager"}' >/dev/null
mcp ex0_create_site '{"tenant_id":"ten_test","slug":"filiale","name":"Filiale"}' >/dev/null

# fresh <name>: a new machine; pkg <name>: the package of this working tree on it
fresh() {
  docker rm -f "ex0box-$1" >/dev/null 2>&1 || true
  docker run -d --name "ex0box-$1" --hostname "ex0box-$1" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$IMAGE" >/dev/null
  for _ in $(seq 1 40); do docker exec "ex0box-$1" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded' && return 0; sleep 0.5; done
  echo "systemd did not come up in ex0box-$1" >&2; return 1
}
pkg() {
  docker exec "ex0box-$1" mkdir -p /root/pkg
  local f
  for f in provision-box.sh netbird-operator-netns.sh netbird-operator-netns.service netbird-operator.service netbird-operator-ssh.service excubra-agent-unit.sh excubra-agent-unit.path excubra-agent-unit.service; do
    docker cp -q "image/$f" "ex0box-$1:/root/pkg/$f"
  done
  docker cp -q deploy/systemd/excubra-agent.service "ex0box-$1:/root/pkg/excubra-agent.service"
  docker cp -q "$W/excubra_linux_$ARCH" "ex0box-$1:/root/pkg/excubra"
  docker exec "ex0box-$1" chmod +x /root/pkg/provision-box.sh /root/pkg/excubra
}
# provision <name> <args…>: run the package's script, log to $W/<name>.log, return its status
provision() { local n="$1"; shift; docker exec ${EX0_ENROLL_WAIT:+-e EX0_ENROLL_WAIT=$EX0_ENROLL_WAIT} "ex0box-$n" /root/pkg/provision-box.sh --binary /root/pkg/excubra "$@" > "$W/$n.log" 2>&1; }
boxid() { docker exec "ex0box-$1" sh -c 'cat /var/lib/excubra-agent/box.id 2>/dev/null' | tr -d '[:space:]'; }

# ---- provision-box.sh ---------------------------------------------------------------------
if wanted T1; then
  echo "== T1: a key, a technician's key — the box enrolls and says so"
  fresh T1; pkg T1; KEY1="$(newkey site_buero)"
  if provision T1 --enroll-key "$KEY1" --hostname ex0-test-buero --ssh-key "$PUB"; then
    B="$(boxid T1)"
    if ! has "$W/T1.log" "EX0-RESULT: ok box=$B"; then fail T1 "no result line for $B"
    elif ! mcp ex0_site '{"site_id":"site_buero"}' | grep -qF "$B"; then fail T1 "the server does not have the box at its site"
    elif [ "$(docker exec ex0box-T1 grep -c . /root/.ssh/authorized_keys)" != 1 ]; then fail T1 "authorized_keys"
    elif ! docker exec ex0box-T1 sh -c 'ssh-keyscan -T 3 127.0.0.1 2>/dev/null | grep -q ssh-'; then fail T1 "sshd does not answer"
    elif docker exec ex0box-T1 test -e /var/lib/excubra-agent/enroll; then fail T1 "the key file was not consumed"
    else
      # the server's side of the same story, the way a session asks for it: the
      # box is there and has said which network it sits in
      ok=0
      for _ in $(seq 1 45); do
        mcp ex0_rollout_status '{"site_id":"site_buero"}' > "$W/T1.status" 2>/dev/null || true
        if python3 - "$W/T1.status" <<'PY2'
import json, sys
st = {s["step"]: s["state"] for s in json.load(open(sys.argv[1]))["steps"]}
sys.exit(0 if st.get("box") == "ok" and st.get("lan") == "ok" and st.get("version") == "ok" else 1)
PY2
        then ok=1; break; fi
        sleep 2
      done
      if [ "$ok" = 1 ]; then pass T1; else fail T1 "ex0_rollout_status does not show the box with its LAN: $(tr -d '\n' < "$W/T1.status" | cut -c1-300)"; fi
    fi
  else fail T1 "exit $? — $(tail -1 "$W/T1.log")"; fi

  if wanted T2; then
    echo "== T2: the same command again — nothing breaks, nothing doubles"
    if provision T1 --enroll-key "$KEY1" --hostname ex0-test-buero --ssh-key "$PUB"; then
      if ! has "$W/T1.log" "EX0-RESULT: ok box=$(boxid T1)"; then fail T2 "no result line"
      elif [ "$(docker exec ex0box-T1 grep -c . /root/.ssh/authorized_keys)" != 1 ]; then fail T2 "the key is in authorized_keys twice"
      elif docker exec ex0box-T1 test -e /var/lib/excubra-agent/enroll; then fail T2 "a spent key was left lying in the state directory"
      else pass T2; fi
    else fail T2 "exit $? — $(tail -1 "$W/T1.log")"; fi
  fi

  if wanted T3; then
    echo "== T3: a key that was used before — refused, and the script says refused"
    fresh T3; pkg T3
    if provision T3 --enroll-key "$KEY1" --hostname ex0-test-zwei; then fail T3 "a spent key reported success"
    elif has "$W/T3.log" "EX0-RESULT: failed" && has "$W/T3.log" "refused the enrollment key"; then pass T3
    else fail T3 "$(tail -1 "$W/T3.log")"; fi
  fi
fi

if wanted T4; then
  echo "== T4: the server cannot be reached — failed, with the reason"
  fresh T4; pkg T4
  KEY4="$(newkey site_lager | sed -E "s/:$PORT_INGEST:/:1:/")"   # nothing listens on port 1
  if EX0_ENROLL_WAIT=20 provision T4 --enroll-key "$KEY4" --hostname ex0-test-lager; then fail T4 "an unreachable server reported success"
  elif has "$W/T4.log" "EX0-RESULT: failed" && has "$W/T4.log" "does not reach the server"; then pass T4
  else fail T4 "$(tail -1 "$W/T4.log")"; fi
fi

if wanted T5; then
  echo "== T5: what is not a public key does not get into authorized_keys"
  fresh T5; pkg T5
  if provision T5 --enroll-key "EX0:1:x:1:x:x" --ssh-key 'command="id" ssh-ed25519 AAAA'; then fail T5 "accepted"
  elif has "$W/T5.log" "not a public key" && ! docker exec ex0box-T5 test -e /root/.ssh/authorized_keys; then pass T5
  else fail T5 "$(tail -1 "$W/T5.log")"; fi
fi

# ---- ex0-box-pct.sh on a pretend Proxmox --------------------------------------------------
# pve <name> <args…>: run this checkout's ex0-box-pct.sh with the stubs on PATH
pve() {
  local n="$1"; shift
  docker exec -e EX0_RAW_BASE="http://host.docker.internal:$PORT_FILES" ${PVE_STUB_ROOTDIR:+-e PVE_STUB_ROOTDIR="$PVE_STUB_ROOTDIR"} ${RAW_OVERRIDE:+-e EX0_RAW_BASE="$RAW_OVERRIDE"} \
    "ex0box-$n" env PATH=/opt/pve:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash /opt/ex0-box-pct.sh "$@" > "$W/$n.log" 2>&1
}
pvehost() {
  fresh "$1"
  docker exec "ex0box-$1" mkdir -p /opt/pve /etc/pve/lxc
  local f; for f in pct pveam pvesm pvesh; do docker cp -q "test/box/pve-stubs/$f" "ex0box-$1:/opt/pve/$f"; done
  docker cp -q image/ex0-box-pct.sh "ex0box-$1:/opt/ex0-box-pct.sh"
  docker exec "ex0box-$1" ip link add vmbr0 type bridge
}

if wanted P1; then
  echo "== P1: the command of a rollout, complete — a container, an enrolled box, one result line"
  pvehost P1; KEYP="$(newkey site_lager)"
  if pve P1 --enroll-key "$KEYP" --hostname ex0-test-lager --ctid 200 --storage local-zfs --ssh-key "$PUB"; then
    B="$(boxid P1)"
    if ! has "$W/P1.log" "EX0-RESULT: ok ctid=200 hostname=ex0-test-lager box=$B"; then fail P1 "result line: $(grep EX0-RESULT "$W/P1.log" || true)"
    elif ! docker exec ex0box-P1 grep -q '^--rootfs local-zfs:8' /etc/pve/lxc/200.args; then fail P1 "the storage that was named was not used"
    elif ! mcp ex0_site '{"site_id":"site_lager"}' | grep -qF "$B"; then fail P1 "the server does not have the box at its site"
    elif [ "$(docker exec ex0box-P1 grep -c . /root/.ssh/authorized_keys)" != 1 ]; then fail P1 "the technician's key did not arrive in the container"
    else pass P1; fi
  else fail P1 "exit $? — $(grep EX0-RESULT "$W/P1.log" || tail -1 "$W/P1.log")"; fi

  if wanted P2; then
    echo "== P2: the same command again — its own container, no second one"
    if pve P1 --enroll-key "$KEYP" --hostname ex0-test-lager --storage local-zfs --ssh-key "$PUB"; then
      if ! has "$W/P1.log" "container 200 exists and is an EX0 box"; then fail P2 "it did not recognise its own container"
      elif [ "$(docker exec ex0box-P1 sh -c 'ls /etc/pve/lxc/*.conf | wc -l')" != 1 ]; then fail P2 "a second container was made"
      elif ! has "$W/P1.log" "EX0-RESULT: ok ctid=200"; then fail P2 "no result line"
      else pass P2; fi
    else fail P2 "exit $? — $(grep EX0-RESULT "$W/P1.log" || tail -1 "$W/P1.log")"; fi
  fi
fi

if wanted P3; then
  echo "== P3: the installer cannot be downloaded — failed, not »is an EX0 box«"
  pvehost P3
  if RAW_OVERRIDE="http://host.docker.internal:1/nothing" pve P3 --enroll-key "$(newkey site_lager)" --hostname ex0-test-p3 --version 0.0.1; then fail P3 "a failed download reported success"
  elif has "$W/P3.log" "EX0-RESULT: failed step=installer" && has "$W/P3.log" "could not download ex0-box.sh" && has "$W/P3.log" "Run the same command again"; then pass P3
  else fail P3 "$(grep EX0-RESULT "$W/P3.log" || tail -1 "$W/P3.log")"; fi
fi

if wanted P4; then
  echo "== P4: values that cannot work are refused before anything is made"
  pvehost P4; ok=1
  pve P4 --enroll-key "EX0:1:x:1:x:x" --hostname ex0-test-p4 --version 0.0.1 --bridge vmbr9 && ok=0
  has "$W/P4.log" "EX0-RESULT: failed step=bridge" && has "$W/P4.log" "nothing was created" || ok=0
  pve P4 --enroll-key "EX0:1:x:1:x:x" --hostname ex0-test-p4 --version 0.0.1 --storage tank && ok=0
  has "$W/P4.log" "storage tank does not exist here" || ok=0
  pve P4 --enroll-key "EX0:1:x:1:x:x" --hostname ex0-test-p4 --version 0.0.1 --ip 127.0.0.1/8 --gw 127.0.0.2 && ok=0
  has "$W/P4.log" "already answers on the network" || ok=0
  pve P4 --enroll-key "EX0:1:x:1:x:x" --hostname ex0-test-p4 --version 0.0.1 --ip 10.9.9.9 && ok=0
  has "$W/P4.log" "needs the prefix length" || ok=0
  docker exec ex0box-P4 sh -c 'printf "#somebody elses container\nhostname: nas\n" > /etc/pve/lxc/150.conf; echo running > /etc/pve/lxc/150.state'
  pve P4 --enroll-key "EX0:1:x:1:x:x" --hostname ex0-test-p4 --version 0.0.1 --ctid 150 && ok=0
  has "$W/P4.log" "exists and is not an EX0 box" || ok=0
  [ "$(docker exec ex0box-P4 sh -c 'ls /etc/pve/lxc/*.conf | wc -l')" = 1 ] || ok=0
  if [ "$ok" = 1 ]; then pass P4; else fail P4 "$(grep EX0-RESULT "$W/P4.log" || tail -1 "$W/P4.log")"; fi
fi

if wanted P5; then
  echo "== P5: a host without local-lvm or local-zfs — the first storage that takes a container"
  pvehost P5
  if PVE_STUB_ROOTDIR="tank" pve P5 --enroll-key "$(newkey site_filiale)" --hostname ex0-test-filiale; then
    if docker exec ex0box-P5 grep -q '^--rootfs tank:8' /etc/pve/lxc/100.args && has "$W/P5.log" "EX0-RESULT: ok ctid=100"; then pass P5
    else fail P5 "storage or result line"; fi
  else fail P5 "exit $? — $(grep EX0-RESULT "$W/P5.log" || tail -1 "$W/P5.log")"; fi
fi

echo
echo "passed: ${PASSED[*]:-none}"
if [ ${#FAILED[@]} -gt 0 ]; then
  printf 'FAILED: %s\n' "${FAILED[@]}"
  echo "logs: $W (run with KEEP=1 to keep them)"
  KEEP=1
  exit 1
fi
