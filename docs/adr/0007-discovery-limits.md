# ADR-0007: Discovery limits — passive + sweep, never port scans

Status: accepted · Date: 2026-09-05

## Context

A box that behaves like an attacker triggers the customer's EDR and, worse, a
server-controlled scanner is exactly the tool an attacker would want (salt:
Entscheidungen E6). Discovery must be complete enough to build an inventory and
gentle enough to be invisible.

## Decision

**Two modes, nothing else.** The config field `discovery.mode` is `passive` or `sweep`;
any other value is reported as a config error and treated as `passive`.

**Passive (always on).** An `AF_PACKET` socket on the box's LAN interface receives ARP
replies/requests and IPv6 Neighbor Advertisements (ICMPv6 type 136) — read only, no
transmission. Every frame updates the sighting table (MAC, IP, last seen).

**Sweep (when enabled).** Every `sweep_interval_s` (default 900):

- an ARP request to every address of the box's own IPv4 subnet (mask from the
  interface; capped at /22 = 1024 addresses);
- an ICMP echo request to every address of each configured additional subnet
  (`discovery.subnets`, each capped at /22, at most 8 subnets);
- a token bucket limits transmission to `max_pps` packets per second (default 50,
  hard maximum 100), so a /22 takes about 20 s.

Replies are received passively (ARP) or on the ICMP socket. No TCP or UDP packet is ever
sent by discovery.

**Names and vendors.** Vendor from an embedded IEEE OUI table (`discovery/oui.gz`,
refreshed with releases). Hostname best effort: reverse DNS through the system
resolver (1 s timeout, 8 in flight) and one mDNS PTR query for the reverse name to
`224.0.0.251:5353` / `[ff02::fb]:5353` (stdlib UDP, hand-built DNS message via
`golang.org/x/net/dns/dnsmessage`). Failures are silent; a device without a name is
still a device.

**What does not exist in the code base.** No port scanner, no banner grabbing, no SNMP
walk, no NetBIOS/SMB probing, no SSDP/UPnP discovery, no traffic capture beyond ARP/NDP
headers. Not as a flag, not as a hidden mode. The only sockets that connect to a
port are the configured host checks (`tcp:<port>`, `http`), and each of them targets
exactly one explicitly configured address.

**Privileges.** The agent runs as an unprivileged user with
`AmbientCapabilities=CAP_NET_RAW` (ICMP echo, ARP, `AF_PACKET`). It never needs
`CAP_NET_ADMIN`. The unit sets `CPUQuota=20%`, `MemoryMax=256M`, `ProtectSystem=strict`,
`ReadWritePaths=<statedir>`.

**Reporting.** The agent reports sightings since the last successful heartbeat
(ADR-0003); it keeps no long-term inventory. Rate: a device is reported at most once
per heartbeat.

## Consequences

- VLANs without a tagged interface on the box are only reachable by ICMP sweep, so
  MACs and vendors are missing there. Documented; tagged interfaces are the fix.
- A /16 customer network is not swept; the operator configures the /22s that matter.

## Rejected

- nmap-style continuous scanning (E6).
- SNMP discovery in Phase 1: needs credentials on the box, and credentials on the box
  are a Phase 2 question with its own security review.
- Passive-only: misses silent devices (printers, PLCs) for hours; a gentle sweep every
  15 minutes is the compromise.
