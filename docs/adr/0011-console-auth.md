# ADR-0011: Console authentication, sessions and audit

Status: accepted · Date: 2026-09-05

## Context

The console may write (assign boxes, monitor/ignore devices, maintenance windows,
webhook targets) and is reachable only inside the NetBird overlay. Local accounts with
TOTP now; OIDC via the VIICO Zitadel later (salt: Konzept, Konsole).

## Decision

**Accounts.** `excubra server user add <name>` creates a user, asks for a password
(twice, min 12 characters, no composition rules), generates a TOTP secret and prints
the `otpauth://` URI and the base32 secret once. `user disable` locks an account; there
is no self-service registration.

**Passwords.** `crypto/pbkdf2` with SHA-256, 600 000 iterations, 16-byte random salt,
stored as `pbkdf2-sha256$<iter>$<salt-b64>$<hash-b64>` so the parameters can be raised
later without a migration. Comparison in constant time.

**TOTP.** RFC 6238, SHA-1, 6 digits, 30 s step, window ±1 step. The last accepted
counter is stored per user; a code at or below it is rejected (replay protection).
Login = password and code on one form; the error message is the same for every failure
mode. Five failures lock the account for 15 minutes.

**Sessions.** 32 random bytes, stored as SHA-256 hash in `sessions` with user, created,
last seen, IP. Cookie `excubra_session`: `HttpOnly`, `SameSite=Strict`, `Path=/`,
`Secure` when the overlay listener uses TLS. Idle timeout 12 h, absolute 7 days.
Logout deletes the row.

**CSRF.** Every state-changing request (`POST`, `PUT`, `DELETE`) must carry the session's
CSRF token — as a hidden field in forms and as `X-CSRF-Token` for htmx requests (set
via `hx-headers` on `<body>`). Combined with `SameSite=Strict` this closes both the
classic and the htmx variant.

**Authorisation.** Phase 1 has one role: operator. Everybody who can log in can do
everything the console offers. Roles arrive with OIDC.

**API tokens** (status API, ADR contract): 32 random bytes shown once, stored as
SHA-256 hash, with a name and a tenant scope (a list of tenant ids or `*`). Presented
as `Authorization: Bearer …`. Tokens can be revoked; every use updates `last_used_at`.

**Audit log.** Every write through console or API appends to `audit_log`: time, actor
(user or token name), action, target id, and a short JSON summary of the change. The
console shows it as a page; nothing deletes rows.

**Headers.** `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options:
nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`. htmx is served from
`/static/` with a hashed filename, no inline scripts.

## Consequences

- No dependency for authentication at all.
- A password database leak costs the attacker 600 000 SHA-256 per guess and still needs
  the TOTP device.

## Rejected

- Basic auth behind NetBird only: no second factor, no session revocation, no audit
  identity.
- OIDC in Phase 1: needs the Zitadel that is being built in parallel; not on the
  critical path.
- bcrypt/argon2: a dependency for a marginal gain at this user count.
