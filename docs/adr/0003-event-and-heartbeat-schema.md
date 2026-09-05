# ADR-0003: Event, heartbeat and config schema

Status: accepted · Date: 2026-09-05

## Context

Phase 1 produces state-transition events; Phase 2 adds security events derived from
logs. Both must share one envelope so rules, reports and the CRM contract have a single
code path. The CRM contract v1 (salt: "Schnittstelle EX0 → CRM") fixes the webhook body;
the internal envelope is a superset of it.

## Decision

### Event envelope (internal, all phases)

| Field | Type | Meaning |
| --- | --- | --- |
| `event_id` | string | `evt_` + 26 chars Crockford base32: 48-bit ms timestamp + 80 random bits. Sortable, unique, stable. |
| `type` | string | see catalogue below |
| `severity` | string | `info` · `warning` · `critical` |
| `occurred_at` | time | when the transition was decided (server clock) |
| `received_at` | time | when the data that caused it arrived at the server; equals `occurred_at` for server-generated transitions. Phase 2 log events put the agent's observation time in `occurred_at` and the arrival time here. |
| `since` | time? | start of the condition: first failed round, first missed heartbeat, first sighting |
| `tenant_id` `site_id` `box_id` | string | scope; `box_id` empty for tenant/site-level maintenance |
| `host_id` `device_id` | string? | when the event is about a host or a device |
| `source` | string | who produced it: `server.state`, `server.maintenance`, `server.discovery`, `console`; Phase 2: `agent.<source>` |
| `payload` | object | type-specific (below) |

**Correlation uses server time.** Box clocks appear only inside payloads (`box_time`).
This is deliberate: a customer with broken NTP must not be able to break the evaluation.

### Type catalogue, Phase 1

| `type` | severity | payload |
| --- | --- | --- |
| `box.silent` | critical | `{missed_heartbeats, last_heartbeat_at}` |
| `box.back` | info | `{silent_for_s, agent_version}` |
| `host.down` | warning | `host{name,ip,mac,vendor}`, `details{checks_failed[], consecutive_failures, box_time}` |
| `host.up` | info | `host{…}`, `details{down_for_s, consecutive_successes}` |
| `device.new` | info | `device{ip,mac,vendor,hostname,first_seen}` |
| `device.gone` | info | `device{ip,mac,vendor,hostname,last_seen}` |
| `maintenance.started` | info | `maintenance{scope: tenant|site|host, until, reason, set_by}` |
| `maintenance.ended` | info | `maintenance{scope, reason, ended: expired|cleared}` |
| `test.ping` | info | `{target_id, triggered_by}` |

Phase 2 adds `security.alert` (warning…critical) with a rule payload; nothing else changes.

### Webhook body

The webhook body is the contract v1 projection of the envelope: `event_id`, `type`,
`occurred_at`, `tenant_id`, `site_id`, `box_id`, `host_id`, `host`, `since`, `severity`,
`details`, `link` — exactly as written in the contract. `device`, `maintenance` are
added as top-level objects for their event types. Fields are only ever added.

### Heartbeat (agent → server), `POST /v1/heartbeat`

```json
{
  "sent_at": "2026-09-05T10:00:00.000Z",
  "agent": {"version": "0.1.0", "uptime_s": 86400, "boot_id": "…"},
  "box": {"disk_total_bytes": 0, "disk_free_bytes": 0, "load1": 0.1, "mem_total_bytes": 0, "mem_free_bytes": 0, "clock_offset_ms": null},
  "netbird": {"status": "not_configured|connected|disconnected|error", "ip": "100.64.0.5", "version": "…", "management_url": "…"},
  "config_version": "cfg_…",
  "config_errors": ["unknown check type snmp for host_x"],
  "hosts": [
    {"host_id": "host_…", "rounds": [
      {"at": "…", "ok": false, "checks": [
        {"type": "icmp", "ok": false, "error": "timeout", "latency_ms": null},
        {"type": "tcp:443", "ok": true, "latency_ms": 3}
      ]}
    ]}
  ],
  "discovery": {"seen": [
    {"mac": "00:09:0f:aa:bb:cc", "ip": "192.168.1.1", "ipv6": [], "vendor": "Fortinet", "hostname": "fw01", "last_seen": "…"}
  ]},
  "buffer": {"queued": 0, "dropped": 0}
}
```

- A **round** is one execution of all configured checks of a host. A round is `ok`
  iff every check is ok. The agent sends the rounds completed since the previous
  successful heartbeat, oldest first, at most 10 per host (older ones are dropped, the
  drop counted in `buffer.dropped`).
- `discovery.seen` lists every device seen since the previous successful heartbeat
  (bounded to 2000 entries). The server derives *new* / *gone* from its own `devices`
  table; the agent keeps no long-term inventory.
- `config_errors` is the agent refusing something it does not know. The server shows it
  in the console; it never changes the agent's behaviour.

Response: `{"server_time": "…", "config_version": "cfg_…", "assigned": true}`.

### Config (server → agent), `GET /v1/config`

```json
{
  "version": "cfg_…",
  "assigned": true,
  "intervals": {"heartbeat_s": 60, "check_s": 30, "config_max_age_s": 900},
  "hosts": [
    {"host_id": "host_…", "address": "192.168.1.1",
     "checks": [{"type": "icmp"}, {"type": "tcp", "port": 443}, {"type": "http", "url": "https://192.168.1.1/", "expect_status": [200, 399]}]}
  ],
  "discovery": {"mode": "passive|sweep", "subnets": ["192.168.10.0/24"], "sweep_interval_s": 900, "max_pps": 50},
  "netbird_pending": false,
  "update": {"channel": "stable|canary"}
}
```

`version` is a hash of the canonical config document, also returned as `ETag`. Check
types are a closed enumeration (`icmp`, `tcp`, `http`); the agent ignores and reports
anything else. An unassigned box receives `assigned: false`, an empty host list and
`discovery.mode: passive`, and does nothing but heartbeat and pull.

## Consequences

- One envelope for Phase 1 and Phase 2; the webhook projection is the only place that
  knows the contract's field names.
- Server-clock correlation means a box with a wrong clock still produces correct
  transitions; its clock offset is visible in the heartbeat and becomes a
  self-monitoring event later.

## Rejected

- Sending only the latest check result per host: the state machine needs the sequence
  to count consecutive failures correctly across a heartbeat.
- Agent-side inventory with new/gone deltas: a box reboot would re-announce every
  device; the server owns first/last seen anyway.
- UUIDs as event ids: not sortable, and the contract's examples want prefixed ids.
