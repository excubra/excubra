# ADR-0010: Enrollment, internal CA and box identity

Status: accepted · Date: 2026-09-05

## Context

A box leaves VIICO with nothing but an enrollment key on it. It must end up with an
identity the server can trust, without anybody typing on the box and without the box
being able to choose its tenant. Certificates must be revocable per box.

## Decision

### Internal CA

Created by the server on first start under `<data>/ca/`: an ECDSA P-256 root
(`ca.key` 0600, `ca.crt`, 10 years). The same CA issues the **ingest server
certificate** (`ingest.crt`, SAN = `EXCUBRA_INGEST_PUBLIC_HOST`, 1 year, renewed by the
server when < 30 days remain, reloaded via `GetCertificate`) and every **box client
certificate**. Nothing else is ever signed by it. CA rotation is out of scope for Phase 1
(it means re-enrolling every box; the ten-year validity buys the time for a later ADR).

### Enrollment key

Created in the console (Boxen → new key) or by `excubra server key new [--count N]`
for image production. Format, printable and QR-able:

```
EX0:1:<host>:<port>:<ca_fp>:<secret>
```

- `1` — key format version
- `host`, `port` — the ingest (`EXCUBRA_INGEST_PUBLIC_HOST`)
- `ca_fp` — the first 16 bytes of SHA-256 over the CA certificate's
  SubjectPublicKeyInfo, lower-case hex (32 chars); the agent pins the CA with it
- `secret` — 20 random bytes, Crockford base32 (32 chars); the server stores only
  `sha256(secret)`

Properties: single use (marked with `used_at`, `box_id`); expires after 30 days by
default; revocable in the console; carries **no tenant** — assignment happens in the
console after enrollment, so a stolen key can only produce an unassigned box that the
operator sees and deletes.

### Enrollment flow

1. The agent generates an ECDSA P-256 key (`box.key`, 0600) and a CSR (CN = hw_id,
   ignored by the server).
2. `POST /v1/enroll {key, hw_id, csr, agent_version, os, arch}` over TLS. The agent
   verifies the server certificate chains to a CA whose SPKI fingerprint matches
   `ca_fp`; system roots are not consulted.
3. The server validates the key (exists, unused, unexpired, unrevoked), creates the box
   (`box_<12 random>`), issues a certificate: subject CN `box_<id>`, SAN URI
   `urn:excubra:box:<id>`, validity 90 days, serial recorded. Response: `box_id`,
   certificate, CA certificate, `not_after`.
4. The agent stores `box.crt`, `ca.crt`, `server`; deletes `/etc/excubra/enroll` if the
   key came from there; starts heartbeating. The box is "unassigned" until the
   console assigns it to a site.

Rate limit on `/v1/enroll`: 5 per minute per source IP; failures are logged with the
key's first 8 characters only.

### Renewal and revocation

`POST /v1/renew {csr}` with the current certificate when < 30 days remain (the agent
checks daily). The new certificate replaces the old one atomically; the old serial is
recorded as superseded. Revocation is per box in the console: the box's current serial
goes into `revoked_certs`, the box is flagged, and the ingest middleware rejects the
certificate on the next request (the deny list is loaded into memory and refreshed on
change — no CRL distribution, the server is the only verifier).

### Identity rules

- Tenant and site are always derived from the certificate → box → site → tenant.
  A payload never names them.
- `hw_id` = hex of SHA-256 over `/etc/machine-id` and, if readable, the DMI product
  UUID. Informational only (shown in the console to match a box with a sticker).
- A box that re-enrolls (new key) gets a new box_id; the operator merges in the console
  by reassigning; the old box is deleted. There is no "take over this box_id" path.

### NetBird hand-over

After assignment the config carries `netbird_pending: true`. The agent calls
`POST /v1/netbird/claim`; the server answers once with `{management_url, setup_key}` and
marks the key consumed. The agent runs `netbird up --management-url … --setup-key …`
and reports the outcome in the next heartbeat's `netbird` block. A consumed key that
never led to `connected` shows in the console as "claimed, not connected"; the operator
re-issues. The setup key is never written to disk by the agent.

## Consequences

- No public CA, no DNS challenge, no clock-sensitive ACME renewals on the ingest.
- A stolen box has a certificate that is revoked with one click.
- The CA key on the server is the crown jewel: it is a file with 0600, in the backup,
  and the reason the server host has no other job.

## Rejected

- A shared bearer token per tenant (30.08 idea): no per-box revocation, and the token
  would name the tenant — the box could choose its tenant.
- Public CA for the ingest: see ADR-0002.
- CRLs/OCSP: the server is the only relying party; a deny list in memory is the same
  thing without the distribution problem.
