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

## The normal way: one command, printed by the console

In the console: **Neue Box** → pick the site → the key appears once, together with
two commands. Copy the one you need.

On a **Proxmox host** (creates and provisions the container):

```bash
curl -fsSL https://raw.githubusercontent.com/excubra/excubra/v0.2.8/image/ex0-box-pct.sh | bash -s -- --enroll-key 'EX0:1:…' --hostname ex0-kunde-standort --version 0.2.8
```

On the **box itself** (fresh Debian 13, as root: mini PC, Raspberry Pi, VM):

```bash
curl -fsSL https://raw.githubusercontent.com/excubra/excubra/v0.2.8/image/ex0-box.sh | bash -s -- --enroll-key 'EX0:1:…' --hostname ex0-kunde-standort --version 0.2.8
```

`ex0-box.sh` downloads the release, verifies `SHA256SUMS` against the release public
key and runs `provision-box.sh`. `ex0-box-pct.sh` fetches the Debian 13 template if
missing, creates an unprivileged container with nesting and `/dev/net/tun`, starts
it and runs `ex0-box.sh` inside (`--ctid`, `--bridge`, `--ip`/`--gw`, `--storage`,
`--disk`, `--memory` when the defaults do not fit).

## From a checkout (development)

`image/deploy-box.sh root@<box> …` and `image/deploy-box-pct.sh root@<proxmox> <ctid> …`
build the binary from the working tree and provision over SSH; everything after
the target is passed to `provision-box.sh`.

In unprivilegierten Containern sind `sysctl`, `ufw`, `hostnamectl` und `timedatectl`
schreibgeschützt; das Skript überspringt sie mit Hinweis. Der Agent weicht dann für Ping auf
einen Raw-Socket aus (CAP_NET_RAW hat der Container), und ohne offenen Port braucht die Box
keine lokale Firewall.

## Options

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
