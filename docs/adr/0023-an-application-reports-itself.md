# ADR-0023: An application reports itself — the source

Status: accepted · Date: 2026-09-25 · Decision E29

## Context

Since 25.09.2026 VIIDOC — the CRM, its own repository — is reachable from the
whole internet at viidoc.de. Its ADR-0080 decides that it stays public, hardened
in three layers, and that the third layer is EX0: "EX0 must watch it, every
activity. That was part of the plan: protect the internal tools too." The two
machines share a private network (10.100.10.3 and 10.100.10.2, ADR-0022).

What EX0 has for this today is little:

- No log reception. V5 (syslog on the box) is planned, not built; the device
  page has an empty "Logs" tab reserved since ADR-0013.
- No route to post anything on the API; tokens can read their tenants and set
  maintenance windows, and there is no difference between reading and writing.
- No way to send anything but the webhook — which goes to the CRM, the very
  system that would be watched.
- The outpost checks the public addresses of boxes, not names.

A box on the VIIDOC host is out of the question: the box is never installed on
a host that does something else (Jeremia, 19.09.2026), and it would bring decoy
ports and raw sockets onto an application server.

## Decision

**1. A source is an application that reports itself.** An operator registers
it on a site — console, CLI — and gets a token that can do exactly one thing:
post that source's events. It reads nothing, sets nothing, and fails on every
other route. Tenant and device come from the token, never from the payload.
A source has a name of at most 64 characters and an IP address — where it runs,
not a host name; a second source at the same address on the same site is
refused. Revoking its token ends the source: its posts are refused, it is no
longer watched for silence, and its state findings resolve after a quiet day.

The source is a device of its own on that site, without a MAC, under its name.
ADR-0021 says a device is something a box saw; this ADR adds exactly one case:
a device a person registered as a source, which then reports itself with the
token issued for it. Nothing else creates a device by hand.

**2. One route.** `POST /v1/source/events` on the API listeners — in practice the
one on the private network (ADR-0022). The body carries up to 500 events and an
optional status; 1 MiB at most. Every accepted post is the source's heartbeat:
the device's `last_seen` moves with it. Operator tokens cannot post here.

**3. The event.** Each carries:

| Field | Meaning |
| --- | --- |
| `event_id` | assigned by the source, stable across retries |
| `occurred_at` | the source's clock (RFC 3339) |
| `kind` | dotted, e.g. `auth.login`, `settings.bank`, `personal.viewed` |
| `actor` | who did it, as the source names them |
| `ip` | from where |
| `target` | what it concerned |
| `summary` | one line |

The server adds `received_at`; correlation uses it (ADR-0003). Events are stored
in the tenant's day file of their `occurred_at`, table `logs` — the name is not
tied to applications: syslog lines from V5 will land in the same table with
another source. Delivery is at-least-once; `(device_id, event_id)` is the
primary key, and a retry keeps its `occurred_at`, so it finds the same file and
is dropped there.

These are logs, not events in the sense of the CRM contract: `events` stays the
table of transitions (ADR-0004).

**4. Rules** (`rules/app.go`, deterministic, table-tested) turn a source's events
into findings on its device, source `app`:

- single events that always deserve a look: emergency access used, admin rights
  granted, the bank account on the invoices changed, a key to another service
  changed, a sign-in from a new device, an HR file opened outside working hours,
  link guessing braked, an account closed because Entra switched it off;
- counts in a window: refused sign-ins, denied requests, downloads by one person.

An incident finding resolves after a quiet day, like a live signal (ADR-0018 §7).
When a finding opens, one `security.alert` event is emitted, as for signals.

**5. Silence.** A source that has not posted for ten minutes gets `app.silent`
(high); the next post resolves it. The status may carry the source's own
certificate expiry; `app.cert_expiring` opens at 14 days, `app.cert_expired`
when it has passed. These state findings alert once when they open, too.

**6. The console.** A source is registered on the API tokens page ("Quelle
anlegen": site, name, address; the token is shown once), marked there as a
source, and revoked like any token. Its device is of the kind "Anwendung" and
has a page of its own shape: whether it still talks (last contact, silent after
ten minutes), its open findings, when it was registered — and no watch switch,
no ping, scan, connector or patch tabs, because no box sees it. The Logs tab is
its first tab: newest first, up to 500 entries, one to ninety days, filtered by
the kind's family (`auth`, `user`, `settings`, …) and by free text, refreshed
every 30 seconds while open. Kinds the rules always call urgent are red, kinds
they judge grey, the rest plain. Findings of a source name their origin
"Meldung der Anwendung".

**7. No alert channel yet.** Jeremia on 25.09.2026: findings in the console for
now. The `security.alert` event goes where webhooks go; for incidents at the CRM
itself that is the watched system, so a direct channel follows in a decision of
its own.

## Rejected

- **A box on the VIIDOC host.** See the context: never on a host that does
  something else, and not decoys on an application server.
- **The public ingest for sources.** Its identity is the box certificate; an
  application is not a box, and a second kind of client at the one public door
  widens it.
- **EX0 fetching VIIDOC's audit log.** The server contacts no watched system;
  sources push, as boxes do.
- **A generic log endpoint for any token.** The API grows per feature (ADR-0013).
- **The CRM's read token for writing.** One token, one purpose: a token that
  reads devices would then also write logs.
- **Logs in `events`.** That table is the contract's transitions; mixing both
  would make every consumer of `GET /v1/tenants/{id}/events` sift.

## Consequences

- `api_tokens.device_id`: empty for operator tokens, the source's device for a
  source token.
- Day files get table `logs`; retention is the day files' (90 days by default).
- A source that stops is a finding within ten minutes, like a silent box is a
  transition.
- The device page's Logs tab is the place V5 fills later with syslog; until
  then a device that is no source says so there.
- The design preview (`go test -tags preview -run TestPreviewServe`, see
  `web/README.md`) seeds a source with a day of events.
- VIIDOC's side of the contract is its ADR-0082.
