# ADR-0002: Transport — HTTP/1.1 + JSON over mTLS, versioned under `/v1`

Status: accepted · Date: 2026-09-05

## Context

Traffic is tiny: one heartbeat per box per minute, a config pull now and then. It must
pass through any customer network (NAT, proxies, hotel Wi-Fi), be debuggable with curl,
and add no dependencies. The connection is always opened by the box; the server never
pushes.

## Decision

**Ingest listener.** HTTPS on the configured public port (443 by default), TLS 1.3
minimum. The server certificate is issued by the server's own internal CA (ADR-0010),
not by a public CA. Agents pin that CA: its fingerprint travels inside the enrollment
key, and the CA certificate is stored in the agent state directory after enrollment.
Consequences: no ACME, no public DNS requirement, the server works on a bare IP, and a
compromised public CA cannot impersonate the ingest.

**Client authentication.** The listener uses `tls.VerifyClientCertIfGiven` with the
internal CA as the only client CA. A middleware then requires a verified and unrevoked
client certificate on every route except `POST /v1/enroll`. Box identity is the
certificate's subject CN (`box_<id>`); site and tenant are looked up server-side from
the box. Identity fields in a payload are never trusted.

**Routes on the ingest listener (the complete list):**

| Route | Purpose |
| --- | --- |
| `POST /v1/enroll` | one-time key + CSR → box_id + certificate (no client cert yet) |
| `POST /v1/renew` | new CSR with the current certificate → renewed certificate |
| `POST /v1/heartbeat` | box state, check rounds, discovery sightings (ADR-0003) |
| `GET /v1/config` | the box's current configuration; `If-None-Match` supported |
| `POST /v1/netbird/claim` | one-time hand-over of the NetBird setup key after assignment |
| `GET /v1/update` | update metadata for the box's channel (never a binary) |

**Cadence.** Heartbeat every 60 s. The heartbeat response carries `config_version`; the
agent fetches `/v1/config` when that differs from the version it runs, and at least every
15 minutes regardless. This keeps "config is pulled, never pushed" and avoids a second
request per minute for a document that rarely changes.

**Encoding.** JSON via `encoding/json`. Field names snake_case. Timestamps RFC 3339 in
UTC with millisecond precision. Durations are integers with a unit suffix (`_s`, `_ms`),
sizes are integers with `_bytes`. Request bodies are limited to 1 MiB; server timeouts:
read header 10 s, read 30 s, write 30 s, idle 120 s. Responses are gzip-free (payloads are
small; gzip is one more code path).

**Errors.** `{"error": "<stable_code>", "message": "<human text>"}` with the matching
HTTP status. Codes are part of the protocol and never renamed.

**Version negotiation.** The agent sends `X-Excubra-Agent-Version: <semver>`. The server
accepts an agent whose MAJOR equals its own and whose MINOR is within two of its own,
in either direction. Otherwise it answers `426 Upgrade Required`; the agent updates
before doing anything else. Additive JSON changes never bump `/v1`; breaking changes get
`/v2` beside `/v1` for the length of the compatibility window.

**The way back stays open.** `GET /v1/update` and `POST /v1/renew` are answered
regardless of the window. An agent that is refused everywhere cannot be told to update
either: it asks for metadata, is refused, and stays silent for good. That is not a
theoretical risk — it took both pilot boxes off the air on 13.09.2026, and it is the one
failure mode a compatibility window must never produce. A refused agent therefore keeps
exactly two doors: the one that tells it what to install, and the one that keeps its
certificate valid while it gets there.

**Rate limits.** Per client certificate: token bucket, 10 requests/min sustained, burst 30.
Per source IP on `/v1/enroll`: 5/min. Exceeding returns `429` with `Retry-After`.

**Overlay listener.** A separate `http.Server` with its own mux and handlers, bound to
the configured overlay address only (ADR-0009). Nothing on the ingest mux references it;
there is no reverse proxy, redirect or shared handler between the two.

## Consequences

- Everything is inspectable with curl and a client certificate.
- Zero transport dependencies; `net/http` and `crypto/tls` only.
- Polling once a minute is the only "push" there will ever be.

## Rejected

- **gRPC**: protobuf and grpc dependencies (large, frequent CVEs), tooling, and no
  benefit at one request per minute.
- **WebSocket/SSE for config changes**: a server-initiated channel contradicts
  "the server never pushes", and a 60 s poll is nothing.
- **Public CA (Let's Encrypt) on the ingest**: needs ACME plus DNS or port 80 or a DNS API
  token on the server. Pinning our own CA is simpler and stronger.
- **Tunnelling the ingest through NetBird**: decided against on the salt page
  (Entscheidungen, E5) — the two channels must fail independently.
