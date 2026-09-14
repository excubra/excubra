# ADR-0021: Patch state from an endpoint manager

Status: accepted · Date: 2026-09-14 · Decision E27

## Context

The CVE matching (ADR-0018 §8) holds every version the scan or a connector
reads against NVD, OSV and the CISA list. It is blind in exactly one place, and
it is the place where most of the risk sits: a Windows machine. A scan reads
what a service announces on the wire, and the client software on a workstation
or server announces nothing — no banner for the VPN client, the PDF reader, the
browser, the backup agent. Those are the products whose holes get exploited.
The version is knowable, but only from inside the machine, and EX0 has no agent
on a Windows machine and is not going to grow one for this (V7 is its own
question).

We already run an endpoint manager for patching at several customers. It has an
agent on every machine, a full software inventory, the missing updates and its
own vulnerability list with deadlines and KEV flags. It has a read API. The
information EX0 lacks is sitting there, per machine, already collected.

## Decision

1. **Read-only, server-side.** `internal/server/action1` talks to the manager's
   REST API with OAuth2 client credentials from the settings store. It reads
   organizations, endpoints, missing updates, vulnerabilities and per-endpoint
   software. It has no call that changes anything over there: deployment stays a
   decision a person makes in the manager, and EX0 does not act on customer
   systems (E15, E16). The credential is a read-only API user, so the boundary
   is enforced on their side too, not only by what we call.
2. **It does not go through the box.** Unlike a connector (ADR-0015), the
   manager is a cloud service we already reach from the server, and its data is
   about a whole organization rather than one device on one LAN. Routing it
   through a box would buy nothing and would make a customer's patch state
   depend on their box being up. Credentials live in the server's settings, like
   NetBird's and NVD's, not in a sealed connector record.
3. **Which organization is which customer is decided by a person.** The mapping
   lives in `patch_orgs`, one row per tenant, written from the customer page
   from a list the credential actually returns — never a typed id, never a
   guess by name. A customer with no row is not read at all. The reason is
   blunt: one wrong row shows one customer another customer's machines.
4. **A machine is matched to a device, or it is named unmatched.** The join is
   the hostname without its domain, lowercased. A machine the manager knows and
   EX0 does not produces no finding and appears in the sync status by name.
   Inventing a device would break the rule that a device is something a box saw.
5. **One finding per machine, not per hole.** `rules.EvaluatePatch` folds a
   machine's missing updates and matched CVEs into a single finding of rule
   `patch.endpoint`, with the worst CVE in the title and the rest in the
   evidence. A machine with twenty pending updates is one line of work for a
   technician, not twenty. Severity: a known-exploited hole or one that is both
   high-CVSS and past its deadline is High, either alone is Medium, missing
   updates without a known hole is Low. A machine the manager has not reached in
   14 days is its own Medium finding — an agent that stopped reporting is not
   evidence of a patched machine.
6. **The per-CVE endpoint does not name machines; the per-endpoint software
   report does.** The manager's vulnerability list says which products and
   versions are affected, not which machines run them. The join that makes a
   finding attributable is (product, version) from the machine's own software
   inventory against that list, exact after lowercasing and trimming. This is
   why the software report is read per endpoint despite costing a request each.
7. **Rate limit before anything else.** The API allows under 30 requests per
   minute per tenant. The client holds a token bucket at 20 per minute, burst 5,
   and the sync runs hourly. Being throttled out of our own patch data because
   we polled too eagerly would be a self-inflicted outage.

## Consequences

- A Windows machine's patch state appears in Prävention as source „Patch-Stand",
  next to what the scan and the CVE matching found, on the same device page.
- EX0 depends on a third-party SaaS for this one source. When it is unreachable
  the sync status says so and the existing findings stay as they are; nothing
  else degrades. Removing the credential stops all of it.
- A second manager later needs a second client and a `provider` value in the
  mapping row, which is already there. The rule and the sync service do not
  change.
- The customer names of the organizations are never stored in this repository;
  they arrive from the API and live only in the server's database.
