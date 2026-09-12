# Box provisioning

A box is a Debian machine with one package on it, always the same three parts
(salt: Konzept, "Die Box"; ADR-0016):

1. **the EX0 agent** — unprivileged, opens no port, enrolls, monitors, updates itself
2. **the operator peer** — a NetBird client in the operator's own overlay, in its own
   network namespace. Always on. EX0 hands it its key once the box is assigned to a
   site; technicians then reach the box (`ssh root@<its overlay address>`) and,
   once switched on per site, its LAN — from the one tunnel they already sit in.
3. **the customer peer** — a NetBird client for the customer's own VPN, installed and
   idle. The opt-in: if the customer gets an overlay of their own, put management
   URL and setup key in under Box → *Kunden-NetBird*; the box joins once.

`provision-box.sh` makes this out of a fresh Debian: a mini PC, Raspberry Pi OS
Lite, a VM, or an LXC container on the customer's Proxmox. Ten boxes on the shelf
are provisioned the same way and differ in nothing but their enrollment key.

## Mini PC or VM (amd64)

1. Install Debian 13 netinst: minimal, only "SSH server" and "standard system
   utilities", a root SSH key, wired network, hostname e.g. `ex0-box-buero`.
2. In the console: Keys → create one enrollment key, copy it.
3. From the repository root:

```
image/deploy-box.sh root@<box> --enroll-key 'EX0:1:…' --hostname ex0-box-buero --ssh-lan
```

## Container on a Proxmox host (same package, no SSH into the container)

Files go in with `pct push`, the provisioning runs with `pct exec`, over SSH to the
host. The container needs `features: nesting=1` (for the namespace) and `/dev/net/tun`:

```bash
image/deploy-box-pct.sh root@<proxmox> <ctid> --enroll-key 'EX0:1:…' --hostname muster-box
```

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

The agent enrolls with the key, deletes it, and heartbeats. The box shows up under
Boxen → "nicht zugeordnet"; assign it to a site, and within minutes the inventory
fills and the operator peer appears in the technicians' stack.

## Raspberry Pi (arm64)

Same script with `EXCUBRA_ARCH=arm64`. The reproducible `.img` build with a
read-only root and the hardware watchdog is the next step (image/build-pi.sh, not
written yet); until then a Pi is provisioned like a mini PC over SSH.

## What the script sets

- Debian security updates automatically, reboot window 04:45
- chrony, Europe/Berlin, persistent journald capped at 256 MB (SSD-friendly)
- sshd keys-only; ufw: inbound nothing (or 22 with `--ssh-lan`), plus the two rules
  for the operator namespace's veth pair
- `net.ipv4.ping_group_range` open so the agent pings without raw-socket rights
  (it falls back to a raw socket via CAP_NET_RAW if that sysctl is missing)
- user `excubra-agent`, state in `/var/lib/excubra-agent` (0700), binary in
  `/opt/excubra/bin` owned by the agent so the signed self-update can swap it
- the agent unit with CAP_NET_RAW only, CPU 20 %, memory 256 MB, strict
  filesystem protection
- the pinned NetBird client with both daemon sockets opened to the agent group, so
  `netbird up` works without root; `netbird-operator-netns.service` (namespace),
  `netbird-operator.service` (the daemon in it), `netbird-operator-ssh.service` (the
  SSH relay in it, unprivileged)
