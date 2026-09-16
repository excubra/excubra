# ADR-0022: An API listener on a network of our own

Status: accepted · Date: 2026-09-16 · Decision E28

## Context

VIIDOC — the CRM (its own repository) — asks EX0 two questions: which sites and
which devices it knows for a tenant. It puts the answer beside what the file
says, and the difference is the point: a device EX0 sees and nobody documented
is the interesting list.

Since 16.09.2026 the two run as two machines at the same hoster with a private
network between them, 10.100.10.3 and 10.100.10.2. Until now VIIDOC asked over
the overlay address, which has two problems. It depends on NetBird being up,
and NetBird belongs to a different piece of work. And it had never once worked:
EX0 issues its own certificate, VIIDOC checked against the public list, and the
device tab fell back to "only the file" without a word. VIIDOC now trusts our
root (its ADR-0017), so the overlay path works — but it still goes through a
third machine for two servers that are cabled together.

Measured on the box: from 10.100.10.3, port 443 on 10.100.10.2 answers (the
ingest listener binds every interface) and 8080 does not. The console and API
listener is bound to the NetBird address alone, exactly as `EXCUBRA_OVERLAY_LISTEN`
demands.

## Decision

`EXCUBRA_LAN_LISTEN` is an **additional listener that serves the API and
nothing else**: `/v1/` and `/healthz`. No console, no sign-in form, no session.
Empty — the default — means there is none, and nothing changes for anybody.

The invariant stays as written: **the console lives on the overlay listener**.
What becomes reachable on the private network is the machine-readable half,
and it asks for the same bearer token, scoped to the same tenants. A token is
still the thing that decides what may be seen; the network is a layer in front
of that, not a replacement for it.

Three checks, all at startup:

- A specific address, never a wildcard and never a name. The same rule the
  overlay listener has, and for the same reason: "listen everywhere" is how an
  internal service ends up on the internet.
- **A private address.** RFC 1918, loopback, link-local, or the range NetBird
  hands out. A public address here would be the API on the internet, and there
  is no development flag for it — there is no case where that is what somebody
  meant.
- Not the same address as the overlay listener, because a port can only be
  handed out once and that failure would otherwise arrive at start.

**Without TLS, and that is not an oversight.** Between two of our own machines
on the same private network nobody is in between. A certificate for an address
like 10.100.10.2 is one only we could issue, and checking it would prove
something that already holds. VIIDOC refuses `http://` to anything that is not
a private address, so the plaintext option cannot quietly become a public one.

## Consequences

- The ingest listener (mTLS, 443) remains the only public endpoint. Unchanged.
- The server on a host without a private network runs exactly as before: the
  variable is empty and no second listener exists.
- A future consumer on the same network — a second CRM instance, a report
  runner — gets the same door, with its own token.

**Rejected: making `EXCUBRA_OVERLAY_LISTEN` a list.** Fewer lines, and it would
have put the console on the private network as well. The console is where
somebody signs in and acknowledges findings; the smaller surface is worth one
more listener.

**Rejected: putting NetBird on the CRM machine.** It works today and needs no
change here. It also makes two servers that are cabled together depend on a
third one, and on an overlay that belongs to another piece of work.
