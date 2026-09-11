# Box provisioning

A box is a Debian machine that runs one unprivileged agent and opens no port
(salt: Konzept, "Die Box"). `provision-box.sh` makes one out of a fresh Debian:
Raspberry Pi OS Lite, a mini PC, or a VM on the customer's hypervisor.

## Mini PC or VM (amd64)

1. Install Debian 13 netinst: minimal, only "SSH server" and "standard system
   utilities", a root SSH key, wired network, hostname e.g. `ex0-box-buero`.
2. In the console: Keys → create one enrollment key, copy it.
3. From the repository root:

```
image/deploy-box.sh root@<box> --enroll-key 'EX0:1:…' --hostname ex0-box-buero --ssh-lan
```


Ist die Box ein LXC-Container auf einem Proxmox-Host des Kunden (kein SSH in den Container
nötig), läuft dasselbe über den Host — Dateien per `pct push`, Provisionierung per `pct exec`:

```bash
image/deploy-box-pct.sh root@<proxmox> <ctid> --enroll-key 'EX0:1:…' --hostname muster-box
```

In unprivilegierten Containern sind `sysctl`, `ufw`, `hostnamectl` und `timedatectl`
schreibgeschützt; das Skript überspringt sie mit Hinweis. Der Agent weicht dann für Ping auf
einen Raw-Socket aus (CAP_NET_RAW hat der Container), und ohne offenen Port braucht die Box
keine lokale Firewall.

`--ssh-lan` keeps SSH reachable on the LAN. Without it the box has no open port at
all; add `--netbird-version <pinned>` once the customer's NetBird stack exists, then
SSH is reachable only over the overlay. Add `--netbird-version` from the start for a
customer box.

The agent enrolls with the key, deletes it, and heartbeats. The box shows up under
Boxen → "nicht zugeordnet"; assign it to a site, and the inventory fills within a
few minutes.

## Raspberry Pi (arm64)

Same script with `EXCUBRA_ARCH=arm64`. The reproducible `.img` build with a
read-only root and the hardware watchdog is the next step (image/build-pi.sh, not
written yet); until then a Pi is provisioned like a mini PC over SSH.

## What the script sets

- Debian security updates automatically, reboot window 04:45
- chrony, Europe/Berlin, persistent journald capped at 256 MB (SSD-friendly)
- sshd keys-only; ufw: inbound nothing (or 22 with `--ssh-lan`)
- `net.ipv4.ping_group_range` open so the agent pings without raw-socket rights
  (it falls back to a raw socket via CAP_NET_RAW if that sysctl is missing)
- user `excubra-agent`, state in `/var/lib/excubra-agent` (0700), binary in
  `/opt/excubra/bin` owned by the agent so the signed self-update can swap it
- the systemd unit with CAP_NET_RAW only, CPU 20 %, memory 256 MB, strict
  filesystem protection
- optionally the pinned NetBird client with its daemon socket opened to the agent
  group, so `netbird up` works without root
