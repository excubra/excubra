# Box provisioning

A box is a Debian machine with one package on it, always the same three parts
(salt: Konzept, "Die Box"; ADR-0016):

1. **the EX0 agent** — unprivileged, enrolls, monitors, updates itself; the only
   ports it opens are decoys that look like SMB, RDP, telnet, MSSQL and VNC and
   report who knocks (ADR-0018 §7)
2. **the operator peer** — a NetBird client in the operator's own overlay, in its own
   network namespace. Always on. EX0 hands it its key once the box is assigned to a
   site; technicians then reach the box (`ssh root@<its overlay address>`) and,
   once switched on per site, its LAN — from the one tunnel they already sit in.
3. **the customer peer** — a NetBird client for the customer's own VPN, installed and
   idle. The opt-in: if the customer gets an overlay of their own, put management
   URL and setup key in under Box → *Kunden-NetBird*; the box joins once.

Nobody touches a box after it is plugged in (ADR-0017): the key is made for a
site, the box assigns itself, joins the operator stack, reports its LAN, and the
server switches remote access on. Ten boxes on the shelf differ in nothing but
their key.

## The normal way: one command, complete

A session makes it with `ex0_new_box`, a person in the console under **Neue Box**
(pick the site; container values and technicians' keys under "Container und
SSH-Schlüssel"). The key appears once, inside two commands. What is known about
the container is in the command — nothing is appended by hand (ADR-0024).

On a **Proxmox host** (creates and provisions the container):

```bash
curl -fsSL https://raw.githubusercontent.com/excubra/excubra/v0.20.0/image/ex0-box-pct.sh -o /tmp/ex0-box-pct.sh && bash /tmp/ex0-box-pct.sh --enroll-key 'EX0:1:…' --hostname ex0-kunde-standort --version 0.20.0 --ctid 200 --ip 192.168.10.60/24 --gw 192.168.10.1 --storage local-lvm --ssh-key 'ssh-ed25519 AAAA… name'
```

On the **box itself** (fresh Debian 13, as root: a mini PC or a Raspberry Pi — never
a hypervisor or a server that does something else; the script refuses a Proxmox host):

```bash
curl -fsSL https://raw.githubusercontent.com/excubra/excubra/v0.20.0/image/ex0-box.sh -o /tmp/ex0-box.sh && bash /tmp/ex0-box.sh --enroll-key 'EX0:1:…' --hostname ex0-kunde-standort --version 0.20.0 --ssh-key 'ssh-ed25519 AAAA… name'
```

A file first, a run second: piped straight into a shell, a download that fails is
an empty script that ends quietly.

`ex0-box.sh` downloads the release, verifies `SHA256SUMS` against the release public
key and runs `provision-box.sh`. `ex0-box-pct.sh` fetches the Debian 13 template if
missing, creates an unprivileged container with nesting and `/dev/net/tun`, starts
it and runs `ex0-box.sh` inside. Its defaults when a value is not given: the next
free container id, `vmbr0` (else the bridge of the host's default route), DHCP,
`local-lvm` or `local-zfs` (else the first storage that takes a container), 8 GiB,
1024 MiB. A fixed address is the better choice — the box is the LAN's router for
the technicians — and one that already answers on the network is refused.

## What it says at the end

Every script ends with one line, and its exit status says the same:

```
EX0-RESULT: ok ctid=200 hostname=ex0-kunde-standort box=box_…
EX0-RESULT: failed step=installer — the installer inside container 200 failed — …
```

`provision-box.sh` waits for the enrollment before it says `ok`, and tells a key
the server refused (used, expired, revoked) from a server the box cannot reach
(outbound 443 blocked, TLS inspection). After a failure the same command can be
run again: `ex0-box-pct.sh` finds its own container by hostname and carries on in
it. `ex0_rollout_status` shows the server's side of the same story.

## From a checkout (development)

`image/deploy-box.sh root@<box> …` and `image/deploy-box-pct.sh root@<proxmox> <ctid> …`
build the binary from the working tree and provision over SSH; everything after
the target is passed to `provision-box.sh`.

In unprivilegierten Containern sind `sysctl`, `ufw`, `hostnamectl` und `timedatectl`
schreibgeschützt; das Skript überspringt sie mit Hinweis. Der Agent weicht dann für Ping auf
einen Raw-Socket aus (CAP_NET_RAW hat der Container), und ohne offenen Port braucht die Box
keine lokale Firewall.

## Options

- `--ssh-key 'ssh-ed25519 AAAA… name'` (repeatable) puts a technician's public key
  into root's `authorized_keys`. Without one nobody can log in: sshd takes keys only
  and the box has no password. The keys come with the command, never from the
  server (ADR-0024 §3). To add one later, run the installer again without an
  enrollment key and with `--ssh-key`.
- `--ssh-lan` keeps SSH reachable on the LAN (pilot in the office). Without it the box
  has no open port on the LAN; SSH comes over the operator overlay.
- `--netbird-version 0.78.1` pins the client (the default is in the script). A guest
  machine's NetBird is never updated by us.
- `--no-operator-peer` removes the operator peer; `--operator-lan-mode macvlan` gives
  it an address of its own on the LAN from DHCP instead of the default `nat` (veth pair
  to the root namespace, nothing new on the LAN — see `netbird-operator-netns.sh`).
- `--netbird-url … --netbird-setup-key …` joins the customer peer by hand instead of
  through the console.
- `--guest` forces guest mode (see below).

Run the script again for a binary update or to change an option; it is idempotent.
The console shows the same one-liner without a key ("Installer erneut ausführen")
for a box whose installation predates a release's needs — the helper below makes
that a one-time thing.

**The unit follows the release.** `excubra-agent-unit.path` watches the agent's
request for capabilities (`/var/lib/excubra-agent/unit.request`) and a root
helper (`/usr/local/lib/excubra/excubra-agent-unit.sh`) grants what is on its
allowlist (`CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`) as a drop-in, restarting the
agent once. A new release that needs one of them asks for it itself (ADR-0006).

**Guest mode.** A machine that already ran NetBird before its first provisioning (a
hand-built routing peer, an exit node) belongs to whoever built it: no firewall from
us, no package upgrades, its NetBird untouched. Decided on the first run, remembered
in `/etc/excubra/provision.env`. The operator peer still comes along — in its own
namespace it cannot touch the guest's daemon.

The agent enrolls with the key, deletes it, and heartbeats. A key made for a site
puts the box there at once; a key without a site leaves it under Boxen →
"nicht zugeordnet" until somebody assigns it. Within minutes the inventory fills,
the operator peer appears in the technicians' stack, and the LAN the box reports
is switched on for remote access.

## Trying a change before it is released

`test/box/run.sh` runs the installers the way a rollout meets them: a local server,
a Debian 13 with systemd in Docker, a pretend Proxmox whose "container" is the
machine itself (`test/box/pve-stubs`), real enrollments — and the failure paths: a
spent key, a server out of reach, a download that fails, values that cannot work.
`EX0_RAW_BASE` points the scripts at a checkout served locally; the binary still
has to verify against the release public key.

## Raspberry Pi (arm64)

Same script with `EXCUBRA_ARCH=arm64`. The reproducible `.img` build with a
read-only root and the hardware watchdog is the next step (image/build-pi.sh, not
written yet); until then a Pi is provisioned like a mini PC over SSH.

## What the script sets

- Debian security updates automatically, reboot window 04:45
- chrony, Europe/Berlin, persistent journald capped at 256 MB (SSD-friendly)
- sshd keys-only; ufw: inbound nothing but the five decoy ports of the live detection
  (445, 3389, 23, 1433, 5900 — the agent accepts, waits and closes; ADR-0018 §7) and
  port 53 for the DNS sensor (answers only where a site switched it on; ADR-0020), or
  22 too with `--ssh-lan`, plus the two rules for the operator namespace's veth pair
- `net.ipv4.ping_group_range` open so the agent pings without raw-socket rights
  (it falls back to a raw socket via CAP_NET_RAW if that sysctl is missing)
- user `excubra-agent`, state in `/var/lib/excubra-agent` (0700), binary in
  `/opt/excubra/bin` owned by the agent so the signed self-update can swap it
- the agent unit with CAP_NET_RAW and CAP_NET_BIND_SERVICE only (raw sockets for
  ARP, ICMP and the SYN watcher; the decoy ports below 1024), CPU 20 %, memory
  256 MB, strict filesystem protection
- the pinned NetBird client with both daemon sockets opened to the agent group, so
  `netbird up` works without root; `netbird-operator-netns.service` (namespace),
  `netbird-operator.service` (the daemon in it), `netbird-operator-ssh.service` (the
  SSH relay in it, unprivileged)
