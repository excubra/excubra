# ADR-0014: Box tasks — a closed list, pulled with the config, run once

Status: accepted · Date: 2026-09-11

## Context

An operator who sees a problem wants to act now: sweep the network again, check every
host this second, pull an update, restart a stuck agent. Waiting for the next tick
(15 minutes for a sweep, a day for an update) is unusable during an incident. At the
same time the invariant stands: the server cannot trigger anything at the customer;
it only chooses from a fixed list of check kinds and hands out subnets (ADR-0002,
ADR-0007). Kaseya's failure mode was a server that could run arbitrary commands on
every endpoint. That surface must never exist here.

## Decision

1. **A task is a word.** `wire.Task{ID, Kind, IssuedAt}` with `Kind` from a closed
   list: `sweep`, `recheck`, `update`, `restart`. No parameters, no addresses, no
   shell. Every kind is something the box already does on its own; the server only
   chooses the moment. Adding a kind is a code change on both sides and an entry in
   this ADR.
2. **Pull, not push.** Tasks travel inside `Config.Tasks`. Queueing one changes the
   config version, the box notices at its next heartbeat (≤ 60 s), pulls, runs the
   task, reports `TaskResult{ID, Kind, OK, Detail, FinishedAt}` in the following
   heartbeat. The ingest listener still only answers questions the box asks.
3. **Exactly once.** The agent remembers the ids it has run (`tasks.json` in the
   state directory, last 200) so a re-pulled config or a restart never repeats a
   task. The server marks a task done when the result arrives and refuses a second
   result for the same id. A task the box has not picked up within an hour expires
   as failed ("not picked up").
4. **At most one pending task per kind per box.** The console cannot pile up sweeps.
5. **Audit.** Queueing and completion are audit entries; the box page shows the last
   tasks with their results.

## Rejected

- **A generic command channel** (`{"cmd": "...", "args": [...]}`): the Kaseya
  surface. Not even behind a flag.
- **Server-initiated connections** to trigger things immediately: violates the
  one-direction rule and needs a listener on the box.
- **Only waiting for the next tick:** correct in theory, unusable at 02:00 with a
  customer on the phone.
- **Tasks as events:** they are not state transitions; results live on the task row
  and in the audit log, not in the webhook stream.

## Consequences

- Latency is one heartbeat to pick up plus one to report — up to two minutes. The
  console says so instead of pretending to be instant.
- The agent keeps a small file of done task ids; nothing else grows.
- Pushing configuration to customer systems (firewalls, PBXs) is a separate decision
  and not covered by this ADR.
