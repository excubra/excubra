# ADR-0018: The continuous service scan — inside from the box, outside from an outpost

Status: accepted · Date: 2026-09-12 · Replaces the "no port scan" rule of ADR-0007 (decision E20) · §7 live detection and §8 CVE matching added 2026-09-12 (decision E22)

## Context

The owner's requirement: EX0 detects the way the VIICO vulnerability analysis does,
continuously and at every customer, and an AI evaluates centrally. A connector per
device vendor is the wrong road for detection (too much upkeep); connectors stay
where configuration and updates are sold (FortiGate, STARFACE). Most small customers
run a consumer router with no API and no logs; knocking at their perimeter is
background noise. What counts is whether a door is open and whether somebody walks
inside — both visible without a firewall.

ADR-0007 said the box runs no port scan, not even behind a flag, because a scanning
box looks like an attacker and a server-controlled scanner is the tool an attacker
wants. The tool is now the product: open, announced, with the customer's consent.

## Decision

1. **The box scans its LAN on a schedule** (`internal/agent/scan`): a rate-limited
   TCP connect scan of the devices the discovery knows, over a curated port list,
   reading banners (SSH, FTP, SMTP, VNC, MySQL), HTTP status, `Server` header and
   title, and TLS certificates (subject, issuer, expiry, self-signed, negotiated
   version — old versions are offered on purpose to learn whether the server still
   speaks them). It enumerates and reads. It never exploits and never tries a
   credential.
2. **Switched on per site, never on call.** `sites.scan_enabled` is a switch in the
   console (Standort → Box & Technik) and on the CLI; the schedule comes with the
   config (daily, at most 20 connection attempts per second, hard cap 50). There is no
   task "scan now": the server cannot make a box scan at a moment of its choosing.
3. **Results live per device.** `services` keeps what listens on which device with
   first and last sighting; a service a later round no longer sees is marked gone,
   not deleted. The round is bookkept in `scan_rounds`. Reports travel in the
   heartbeat in chunks of at most 50 hosts, acknowledged like sightings.
4. **Rules speak first** (`rules.EvaluateScan`): telnet, FTP, VNC, an unauthenticated
   Docker API, databases open to the network, RDP, WinRM and LDAP without TLS,
   Webmin, expired or expiring certificates, self-signed certificates, TLS below
   1.2. Findings sync per device under the source `scan`, so they open, stay and
   resolve like connector findings and share the acknowledgement flow.
5. **The outside view comes from an outpost.** The server learns each site's
   public address from where its box's heartbeats arrive (`boxes.public_ip`). A
   box with `role = outpost` — the agent on our own server, enrolled like any box,
   made an outpost on the CLI — gets those addresses as its targets (every site
   with the scan switched on), scans them hourly with the external port list, and
   leaves the network it stands in alone (no hosts, no sweep). The server accepts
   an outside report only from an outpost and only for an address the site's own
   box reported. What it sees hangs on one device per site that stands for the
   public address (`devices.external`), kept out of the LAN inventory, judged by
   the stricter external rules (`rules.EvaluateExternal`: outside, every open door
   is a finding, remote control and file sharing are urgent, admin login pages are
   urgent, self-signed certificates one grade worse than inside). Version and
   end-of-life matching against a feed the server keeps, and the AI's evaluation
   (E21), build on the same tables.

6. **Versions are judged against a feed.** `internal/server/feed` keeps
   end-of-life and latest-release data per product from endoflife.date, cached in
   the store (`feeds`), fetched only for products the scan or a connector actually
   identified, refreshed daily; the request names a product, never a customer. A
   release line past its end is an urgent finding, one about to end warns, a newer
   release in the line is a note (source `version`). When the feed changes, every
   device is re-assessed without waiting for the next round. `EXCUBRA_FEEDS=off`
   switches it off; a different base URL points at a mirror.

7. **Live detection sits on the box** (`internal/agent/sentinel`, decision E22).
   The scan finds open doors; this finds someone trying them, within the minute.
   Three sources, none of them sends a packet:
   - **Decoy ports.** The box listens on 445, 3389, 23, 1433 and 5900 (SMB, RDP,
     telnet, MSSQL, VNC): what ransomware, worms and a hand on the keyboard look
     for first, and what no healthy device asks a monitoring box for. A listener
     accepts, waits three seconds and closes; nothing answers a byte of protocol,
     so there is nothing to exploit. 22 is never a decoy.
   - **A SYN watcher.** An `AF_PACKET` socket with a classic BPF filter keeps only
     TCP SYNs addressed to the box. A packet socket sees a frame before the
     firewall does, so a knock the firewall drops still counts. A decoy hit is a
     `canary` signal; eight distinct ports from one source within a minute is a
     `port_scan`.
   - **ARP.** The passive discovery listener hands every ARP frame to the
     sentinel. A hundred distinct addresses asked by one MAC within a minute is
     an `arp_scan`; the gateway's address claimed by a second MAC is an
     `arp_spoof` at once, any other address only when it flaps three times in ten
     minutes (a new DHCP lease is one change, not a fight).
   Signals travel in the heartbeat (at most 200, oldest dropped first, acknowledged
   like sightings). The server hangs a finding on the source device (source
   `signal`, rules `signal.canary|port_scan|arp_scan|arp_spoof`, all urgent — a
   healthy LAN produces none of them; the one legitimate producer, an inventory
   or monitoring tool, is known and acknowledged once) and publishes one
   `security.alert` event when a finding opens; the same signal again only grows
   the count. A signal that has been quiet for a day resolves on its own: these
   are incidents, not states. The switch is `sites.canary_enabled`, on by default
   — a box that listens harms nobody; the provisioning opens the decoy ports in
   ufw and gives the agent `CAP_NET_BIND_SERVICE` for the two below 1024. An
   outpost has no decoys. What the box does not see: a SYN scan of *other*
   devices (it is not in their path), and anything on a switch port it does not
   share — the decoys are the answer to that, because a scanner that reaches the
   subnet reaches the box.

8. **Known vulnerabilities per version** (`internal/server/vuln`). Every version
   the scan or a connector identifies is matched against the public databases:
   NVD by CPE for the upstream view (OpenSSH, nginx, Apache httpd, mail and FTP
   servers, databases, FortiOS, RouterOS — a curated map; Windows and IIS are
   not judged this way, their version string never changes with a patch), OSV for
   the distribution's package where the banner names it (`Debian-2+deb12u9`,
   `Ubuntu-3ubuntu13.19` → the package version in `Debian:12` or
   `Ubuntu:24.04:LTS`): OSV knows which fixes were backported, so only what the
   distribution still lists as open survives, and the fixing package version
   comes with it. CISA's KEV list marks what is exploited in the wild. One
   finding per service (`vuln.known`, source `vuln`): urgent when a CVE is
   exploited or scored 7 or more, otherwise medium, low below 4; the detail names
   the three that matter and the fix. Results are cached in `vulns`, fetched
   only for versions a customer actually runs, refreshed daily, paused a quarter
   hour after a failure; the request names a product and a version, never a
   customer. NVD allows five requests per half minute without a key and fifty
   with one (`vuln.nvd_key`, console → Einstellungen). `EXCUBRA_VULNS=off`
   switches it off.

## Rejected

- **Syslog as the first step**: needs a receiver port and device settings per
  vendor; deferred (V5).
- **A connector per device as the detection path**: upkeep without end.
- **Watching the perimeter knock**: every internet connection is scanned all day;
  the signal is in the open door, not in the knocking. Inside the LAN the
  opposite holds, which is why §7 counts every knock there.
- **Decoys that speak the protocol (a full honeypot)**: more signal, but a
  service to keep safe on a box that must never be the way in.
- **A promiscuous tap of the whole LAN**: sees more on a hub, nothing more on a
  switch, and turns the box into a sniffer of customer traffic.
- **Judging distribution packages by upstream CVEs alone**: Debian's 9.2p1 with
  the regreSSHion fix backported would be blamed for it forever; that is the
  false positive every scanner is known for, and OSV answers it exactly.
- **Mirroring NVD**: gigabytes for a few dozen product versions; the cache holds
  what the customers run and nothing else.
- **Exploit checks or credential guessing on the box**: the box must never do harm
  (ADR-0007); it tells, it does not try.

## Consequences

- A box that scans is visible to endpoint protection as a scanner; the customer
  agrees to it in the contract and the scan is announced. The rate limit keeps it
  slower than any real attacker.
- Discovery still decides what exists; the scan only asks known devices. Unknown
  devices get their first scan one round after they appear.
- The box has open ports now (§7). They are fake and silent, but a port scan of
  the customer's network shows them; the customer knows why (the contract) and
  the console shows which ports are armed.
- Windows network discovery and security tools touch 445 on every host they
  find. They do not find the box (it announces nothing), but a tool that walks
  the subnet will, once — that finding is the operator's to acknowledge.
- ADR-0007's discovery limits (no ARP storms, sweep rate caps) stay in force; only
  its port-scan sentence is replaced.
