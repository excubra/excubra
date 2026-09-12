# ADR-0020: The DNS sensor — the box as the LAN's resolver

Status: accepted · Date: 2026-09-12 · Decision E24

## Context

The live detection (ADR-0018 §7) sees what reaches the box: knocks on its
decoys, ARP on the wire, a FortiGate's logs where there is one. What it does
not see is what the devices *ask for*: the first thing malware does after
landing is resolve the name of its server, and a phishing click resolves the
name of the fake page. Every device in a LAN asks the router's resolver, and
most small sites have no firewall that would log it. The one place every
device's questions pass through, if the router says so, is a resolver we run.

## Decision

1. **The box runs a forwarding resolver** (`internal/agent/dnswatch`) on its
   LAN address, port 53 UDP and TCP, when the site's switch is on. It forwards
   every query untouched to the upstream resolvers (the site's, else the box's
   own that are not loopback, else Quad9 and Cloudflare) and hands the answer
   back. It keeps no log of who asked what: counters only, and the three signals
   below. At most 128 queries in flight; beyond that a query is dropped and the
   client asks again, as DNS clients do.
2. **The router hands the box out.** Nothing in EX0 changes the customer's
   network: the operator switches the sensor on in the console (Standort →
   Technik → DNS-Sensor), the console shows the box's address, and someone
   enters it in the router as the DNS server for the LAN, with the router itself
   as the second one so the devices are never without names when the box is
   down. The switch is off by default. A loop (the router forwards to the box
   and the box's own resolver is the router) is refused with SERVFAIL and noted
   once; the console lets the operator name other upstreams.
3. **Three signals**, through the sentinel's queue like the LAN's own:
   - `dns_block`: a query for a domain on the blocklist, or a subdomain of one.
     With blocking on, the box answers NXDOMAIN; otherwise it forwards and
     reports. Blocking is a second switch, off by default.
   - `dns_dga`: one client asked for twenty random-looking names within five
     minutes that do not exist (NXDOMAIN): a domain generation algorithm
     looking for its server. Real names that look random (CDN hashes) exist and
     resolve, so they never count; Chrome's three probes at start stay far below.
   - `dns_tunnel`: one client sent thirty long (fifty characters or more, a
     label of twenty) or TXT/NULL queries to one domain within five minutes.
   All three are findings on the asking device, urgent, and one
   `security.alert` event when a finding opens (ADR-0018 §7 semantics).
4. **The blocklist comes from the server** (`internal/server/blocklist`):
   abuse.ch URLhaus (hosts of active malware URLs) and ThreatFox (recent
   command-and-control and payload domains), refreshed daily, plus the
   operator's own domains from the settings page (`dns.block_extra` — a test
   domain there is the simplest end-to-end check). Kept in the store, served to
   the boxes at `GET /v1/blocklist` as one domain per line with a version as
   ETag; the config names the version, the box fetches when it differs and keeps
   the list on disk across restarts. No addresses, no single labels, no
   localhost.
5. **What the console shows**: the switch, the blocking switch, the upstreams,
   the box's report (listening address, list version and size, the upstream in
   use, an error when port 53 could not be opened), the day's totals per site
   (`dns_days`), and open findings. Port 53 needs `CAP_NET_BIND_SERVICE`, which
   the provisioning gives the agent unit (ADR-0018 §7); a box without it says so
   in its notes with the fix.

## Rejected

- **Logging every query**: a record of every name every device asked for is
  personal data of the customer's staff; the signals need none of it.
- **A caching resolver**: a cache changes what the LAN sees (stale answers
  after a change) and is a second thing to get right; the upstream is one hop
  away.
- **Blocking by default**: a wrong entry in a feed would break a customer's
  application at once; reporting first, blocking where the customer wants it.
- **Advertising feeds (hosts files with hundreds of thousands of entries)**:
  not a security signal, and a list that size on a small box for nothing.
- **DoH/DoT to the upstream**: worth having for privacy on the WAN, but the
  router's resolver is the upstream at most sites and speaks neither; later.

## Consequences

- The box is in the path of name resolution once the router points at it: a
  box that dies takes DNS with it unless the router is the second server. The
  console says so at the switch, and the box never buffers or delays a query
  for the sake of a signal.
- Security products do TXT lookups for reputation (antivirus, mail filters):
  the tunnel rule will name them once; the operator acknowledges the finding,
  and the same domain from the same device stays acknowledged.
- The blocklist is the operator's responsibility as much as the feeds': an
  entry added by hand blocks it for every site with blocking on.
