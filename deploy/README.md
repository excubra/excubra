# Deployment

**The operating system is Debian.** The box image is Debian too (Raspberry Pi OS Lite),
so server and box share one set of runbooks, one apt behaviour and one systemd
generation. `provision-server.sh` refuses anything else unless you pass
`--allow-ubuntu`.

## One command

From the repository root, with SSH access to the target as root:

```
deploy/deploy.sh root@<host> --ingest-host <name the boxes dial> --hostname ex0
```

It builds the binary from the current commit, copies it with the units and the
provisioning script, and runs the provisioning. It is idempotent: run it again for a
binary update, it keeps `/etc/excubra/server.env` and the data directory. What it does:

- `apt upgrade`, then `ufw` (inbound 22 and 443 only), sshd keys-only, Europe/Berlin,
  chrony, persistent capped journald
- automatic **security** updates with a 04:45 reboot window when the kernel needs one
- user `excubra`, `/var/lib/excubra` (0700), `/etc/excubra` (0750), `/var/backups/excubra`
- the binary in `/usr/local/bin/excubra`, swapped atomically
- `/etc/excubra/server.env` on the first run only, then only the ingest host and overlay
  address are corrected
- units and timers: server, prune (daily 04:15), backup (daily 03:30), restore test
  (monthly)
- a smoke test: `/healthz` answers, and the ingest answers 401 without a client
  certificate. It fails loudly instead of leaving a half-provisioned host.

After that, on the host:

```
excubra server user add jeremia        # prints the initial password and the TOTP secret once
excubra server tenant add viico "VIICO GmbH"
excubra server site add ten_viico buero "Büro"
excubra server key new --count 5 --note "erste Boxen"
excubra server token new --name crm    # for the VIICO CRM (status API)
```

Firewall at the Hetzner Cloud level as the outer layer: inbound 22/tcp and 443/tcp,
nothing else. `ufw` on the host says the same thing a second time, on purpose — a
cloud firewall rule someone widens by accident should not open the console.
Console and API listen on the NetBird address (before NetBird exists: `127.0.0.1:8080`,
reachable with `ssh -L 8080:127.0.0.1:8080 root@<host>`).

**Container:** `deploy/Dockerfile` and `deploy/compose.yml`. The published overlay
port is bound to the host's NetBird address in the compose file; do not publish it
on all interfaces.

Backups land in `/var/backups/excubra` daily; sync that directory to an
append-only object store (rclone with `--immutable`, or a bucket with object lock).
The monthly restore test starts a throwaway server from the backup and fails
loudly if it does not come up — read the journal of `excubra-restore-test`.
