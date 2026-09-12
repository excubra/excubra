# ADR-0019: The AI reads and proposes; a person decides

Status: accepted · Date: 2026-09-12 · Decision E21 in salt

## Context

Rules and the version feed find what they are told to find. The owner wants a
model that reads everything a site reports and says what matters, before it
becomes an outage — and wants it soon, without a firewall at every customer.
Customer data leaves the server for that; whose model, and what exactly, must be
decided per tenant, and the model must never act.

## Decision

1. **The provider is exchangeable.** `internal/server/ai` speaks two shapes: the
   Anthropic Messages API and the chat-completions API that OpenAI, Ollama (local
   or cloud) and most others offer. Settings on the server: provider, base URL,
   model, key (`ai.*`; the key is never shown again). Default: Anthropic with the
   newest model, because quality on security judgement and a data-processing
   agreement are what the owner asked for first; a local Ollama is the road for a
   tenant whose data must stay in the house.
2. **Per tenant a switch says what may leave** (`tenants.ai_scope`): `off`
   (default: nothing) or `facts` — inventory, services with banners and
   certificates, findings, the day's events, connector facts with anything that
   looks like a credential removed, box and remote-access state. No raw logs (there
   are none yet), never sealed credentials.
3. **The situation of one site is one request.** A fixed German system prompt asks
   for JSON only: an overall risk, a summary of a few sentences, at most six
   priorities with a concrete action, and at most eight findings for things the
   rules do not already report, each bound to a device of the packet. The answer is
   parsed tolerantly and sanitised: unknown devices, severities and lengths are
   clipped; findings become findings of source `ki` and share the acknowledgement
   flow; the brief (`ai_briefs`) keeps the whole answer, thirty per site.
4. **When:** once a night per site with a box (05:00 local), and on demand from
   the site's card. Every call is audited with provider, model, bytes and tokens
   sent and received, duration and outcome.
5. **What it never does:** run anything, draft a job that a box would execute, or
   see a credential. Job drafts wait for E16 (signed operator jobs).

## Rejected

- **Ollama Cloud as the first provider**: young service, thinner contractual
  footing, weaker models on this task. Reachable through the same interface when
  wanted.
- **A local model first**: needs GPU hardware that does not exist yet.
- **Streaming the whole log stream through a model**: no logs yet, and volume is
  not insight; the packet is the situation, not the traffic.

## Consequences

- Before the switch goes on for a tenant, the data-processing agreement with the
  provider is in place and the customer contract allows the evaluation.
- Cost is one request per site per day plus manual runs; the packet is capped
  (200 devices, 800 services, 200 findings, 100 events).
- The prompt lives in the code; changing it is a commit with a test.
