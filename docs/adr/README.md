# Architecture Decision Records

Binding technical decisions for `excubra`. Product scope, security and operating
invariants come from the EX0 pages in salt.md (workspace *Entwicklung* → Systeme →
EX0); an ADR never overrides them, it makes them concrete.

Rules:

- One decision per file, numbered, never deleted. A reversed decision gets a new ADR
  that points at the old one; the old one gets `Status: superseded by ADR-XXXX`.
- Every ADR states what was rejected and why. Nobody asks later why something was
  *not* built — and then it gets proposed a second time.
- A new third-party dependency is not allowed without a line in ADR-0008.

| ADR | Title |
| --- | --- |
| [0001](0001-repository-layout-and-build.md) | Repository layout, build and versioning |
| [0002](0002-transport.md) | Transport: HTTP/1.1 + JSON over mTLS |
| [0003](0003-event-and-heartbeat-schema.md) | Event, heartbeat and config schema |
| [0004](0004-state-machine.md) | State machine: transitions, suppression, maintenance |
| [0005](0005-storage-layout.md) | Storage layout: SQLite files per tenant and day |
| [0006](0006-update-mechanics.md) | Signed self-update with rollback |
| [0007](0007-discovery-limits.md) | Discovery limits: passive + sweep, never port scans |
| [0008](0008-dependencies.md) | Dependency policy and the allowed list |
| [0009](0009-configuration-and-listeners.md) | Configuration and the two listeners |
| [0010](0010-enrollment-and-pki.md) | Enrollment, internal CA and box identity |
| [0011](0011-console-auth.md) | Console authentication, sessions and audit |
| [0012](0012-webhook-delivery.md) | Webhook delivery: HMAC, retry, idempotency |
| [0013](0013-console-spa.md) | The console is a single-page app, built at build time and embedded |
| [0014](0014-box-tasks.md) | Box tasks: a closed list, pulled with the config, run once |
