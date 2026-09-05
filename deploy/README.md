# Deployment

Two ways to run the server — the same binary, the same one config file.

**systemd (recommended for the VIICO server):**

```
useradd --system --home /var/lib/excubra --shell /usr/sbin/nologin excubra
install -m 0755 excubra_linux_amd64 /usr/local/bin/excubra
install -d -m 0750 /etc/excubra
install -m 0640 -g excubra deploy/server.env.example /etc/excubra/server.env   # then edit
install -m 0644 deploy/systemd/excubra-*.service deploy/systemd/excubra-*.timer /etc/systemd/system/
install -m 0755 deploy/restore-test.sh /usr/local/bin/excubra-restore-test
systemctl daemon-reload
systemctl enable --now excubra-server excubra-prune.timer excubra-backup.timer excubra-restore-test.timer
excubra server user add jeremia        # prints the initial password and the TOTP secret once
excubra server tenant add viico "VIICO GmbH"
excubra server site add ten_viico buero "Büro"
excubra server key new --count 5 --note "erste Boxen"
excubra server token new --name crm    # for the VIICO CRM (status API)
```

Firewall on the host: inbound only 443/tcp (ingest) and — after NetBird is up —
nothing else from the internet. Console and API are on the NetBird address.

**Container:** `deploy/Dockerfile` and `deploy/compose.yml`. The published overlay
port is bound to the host's NetBird address in the compose file; do not publish it
on all interfaces.

Backups land in `/var/backups/excubra` daily; sync that directory to an
append-only object store (rclone with `--immutable`, or a bucket with object lock).
The monthly restore test starts a throwaway server from the backup and fails
loudly if it does not come up — read the journal of `excubra-restore-test`.
