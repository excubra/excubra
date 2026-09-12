# ADR-0018: The continuous service scan — inside from the box, outside from an outpost

Status: accepted · Date: 2026-09-12 · Replaces the "no port scan" rule of ADR-0007 (decision E20)

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

## Rejected

- **Syslog as the first step**: needs a receiver port and device settings per
  vendor; deferred (V5).
- **A connector per device as the detection path**: upkeep without end.
- **Watching the perimeter knock**: every internet connection is scanned all day;
  the signal is in the open door, not in the knocking.
- **Exploit checks or credential guessing on the box**: the box must never do harm
  (ADR-0007); it tells, it does not try.

## Consequences

- A box that scans is visible to endpoint protection as a scanner; the customer
  agrees to it in the contract and the scan is announced. The rate limit keeps it
  slower than any real attacker.
- Discovery still decides what exists; the scan only asks known devices. Unknown
  devices get their first scan one round after they appear.
- ADR-0007's discovery limits (no ARP storms, sweep rate caps) stay in force; only
  its port-scan sentence is replaced.
