# ADR-0004: State machine — transitions, suppression, maintenance

Status: accepted · Date: 2026-09-05

## Context

EX0 reports transitions, not measurements (salt: Entscheidungen E2, E7). Without
flap protection, dependency suppression and maintenance windows the system produces
ticket spam and gets switched off. The machine must be pure (no I/O) so that every
transition has a table test.

## Decision

Package `internal/server/state`. The machine holds per-box and per-host state, takes
inputs, returns events. Persistence is the caller's job (ADR-0005).

### Inputs

| Input | Origin |
| --- | --- |
| `HeartbeatReceived{box_id, at, hosts[]{host_id, rounds[]}}` | ingest |
| `Tick{at}` | a timer, every 10 s: silence detection, maintenance expiry |
| `MaintenanceSet{scope, id, until, reason, by}` / `MaintenanceCleared{…}` | console, status API |
| `HostAdded/Removed/Changed{host_id, box_id, parent_host_id, is_uplink}` | console |
| `BoxAssigned{box_id, site_id, tenant_id}` / `BoxUnassigned` | console |

### Box

States `online`, `silent`. A box is `silent` when no heartbeat arrived for
`3 × heartbeat_interval + 30 s` (default 210 s), decided on `Tick`. The next heartbeat
makes it `online`.

| From | Input | Condition | To | Event |
| --- | --- | --- | --- | --- |
| online | Tick | `at − last_heartbeat ≥ 210 s` | silent | `box.silent` (since = last_heartbeat) |
| silent | Heartbeat | — | online | `box.back` |
| any | Heartbeat | box unassigned | (tracked) | none |

An unassigned box never produces events; there is nobody to send them to.

### Host

Each host keeps **two states**: `observed` (what the checks say) and `reported` (what
was last emitted to the outside). Both take the values `unknown`, `up`, `down`. Plus
counters `consecutive_failures`, `consecutive_successes`, and `since` (when `observed`
was entered). `maintenance` is not a stored state but a condition derived from the
active windows; the API presents it as state `maintenance`.

**Step 1 — apply rounds** (each round from a heartbeat, in order, using the heartbeat's
server receive time as `at`; the round's box time goes into details):

| observed | round | counters after | new observed | since |
| --- | --- | --- | --- | --- |
| any | ok | successes+1, failures=0 | `up` if successes ≥ 2 and observed ≠ up | first ok of the run |
| any | failed | failures+1, successes=0 | `down` if failures ≥ 3 and observed ≠ down | first failure of the run |
| unknown | ok | successes+1 | `up` when successes ≥ 2 | — |

Thresholds: **3 consecutive failed rounds → down, 2 consecutive ok rounds → up.**

**Step 2 — reconcile** the host (after rounds, after `Tick`, after any suppression
change). A host is *suppressed* when any of these holds:

1. its box is `silent`;
2. an active maintenance window covers it (host, its site, or its tenant);
3. an uplink ancestor (`parent_host_id` chain, any depth) has `observed = down`.

| suppressed | observed | reported | Result |
| --- | --- | --- | --- |
| yes | any | any | nothing |
| no | unknown | any | nothing |
| no | up | unknown | reported := up, **no event** |
| no | up | up | nothing |
| no | up | down | reported := up, **`host.up`** |
| no | down | up | reported := down, **`host.down`** |
| no | down | unknown | reported := down, **`host.down`** |
| no | down | down | nothing |

Consequences the contract may rely on: `host.down` and `host.up` alternate for a host;
a freshly monitored host that is up says nothing; a freshly monitored host that is
down says `host.down`.

**Silence.** While a box is silent no rounds arrive, so nothing changes, and rule 1
keeps every reconciliation quiet. On `box.back` the counters continue from where they
were; hosts that died meanwhile reach `down` after three fresh failures. Exactly one
`box.silent`, never a burst of `host.down`.

**Uplink.** When an uplink's `observed` becomes `down`, its descendants become
suppressed; a child that already emitted `host.down` a moment earlier stays as it is
(order of failure cannot be predicted, and a wrong suppression would hide a real
outage). When the uplink's `observed` returns to `up`, every descendant is reconciled
and at most one event per host is emitted.

**Maintenance.** `MaintenanceSet` emits `maintenance.started` once per window (scope
tenant, site or host). During the window rounds are still applied — `observed`
keeps following reality — but rule 2 keeps reconciliation quiet. When the window
expires (`Tick`) or is cleared, `maintenance.ended` is emitted and the covered hosts are
reconciled: a host that went down during maintenance now emits exactly one
`host.down`; a host that recovered emits `host.up` only if `reported` was `down`.

**Configuration changes.** `HostAdded`: observed/reported = unknown, counters zero.
`HostRemoved`: state dropped, no event. `HostChanged` (parent/uplink): reconcile the
host and its descendants. `BoxUnassigned`: all its hosts' states are dropped.

### Devices

`device.new` when a sighting arrives for a MAC the tenant has never seen.
`device.gone` on `Tick` when `now − last_seen ≥ 24 h` and the device is not already
gone; a later sighting reverts it (and produces `device.new` again only if it had been
gone for more than 24 h — a reappearing device is `device.new` again by definition of
the contract: "unknown device discovered"). Devices belong to the site of the box that
saw them.

### Tests

`state_test.go` has one table test per row above, plus scenarios: flapping
(fail, fail, ok, fail, fail, fail → exactly one `host.down`), silence with dead hosts,
uplink down with children failing before and after, maintenance covering a failure,
maintenance covering a recovery, nested maintenance (site window while a host window
is active), reassignment.

## Consequences

- Two states per host is the price of "one event when suppression lifts" — it is the
  smallest model that gets this right.
- All decisions use the server clock; the machine has no timers of its own and is
  driven by `Tick`, which makes tests deterministic.

## Rejected

- Forwarding every check result and de-duplicating in the CRM (E7).
- Delaying child events until the parent is evaluated: adds latency to every outage
  and a timer to the machine; a rare early child event is the smaller harm.
- Treating maintenance as a stored state that overwrites `observed`: loses the
  information needed to emit the correct single event when the window ends.
