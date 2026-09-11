# ADR-0015: Connectors read devices from the box; credentials are sealed to the box

Status: accepted · Date: 2026-09-11

## Context

The product goal grew from "is it reachable" to "what is it, how is it doing, what
is configured on it" for firewalls, PBXs, hypervisors and storage (salt: EX0
Vollausbau). Those devices have APIs, the APIs need credentials, and a central
server holding every customer's firewall token is the Kaseya asset nobody wants to
own. The invariants say the box talks to the customer LAN and the server only
listens; ADR-0014 already lets the server choose the moment for box-local work.

## Decision

1. **A connector is box-side code for one device kind**, registered in
   `internal/agent/connect` (`fortigate`, `starface`, later more). It reads through
   the device's API and returns **facts** (a JSON document about the device),
   **metrics** (numbers for charts) and the TLS fingerprint the device presented.
   Reading only; nothing in the package changes a device. Writing needs signed
   operator jobs (a later ADR).
2. **Credentials are sealed to the box.** Every box owns an X25519 seal key
   (`seal.key` in the state directory, created on first start) and reports the public
   half in each heartbeat. The console seals a credential in the browser with
   WebCrypto (`web/src/lib/seal.ts`): ephemeral X25519 against the box key, HKDF-SHA256
   with salt = ephemeral public ‖ box public and info `excubra-seal-v1`, AES-256-GCM
   with that info as additional data. `internal/seal` is the Go mirror; a fixture
   produced by the browser code is part of its tests. The server stores ciphertext,
   who sealed it and when. A person compares the key's fingerprint with the box
   once, like the CA fingerprint at enrollment.
3. **Configuration and readings ride the existing pull.** `Config.Connectors` lists
   the connectors of an assigned box with a version derived from URL, ciphertext,
   pin and interval; a change restarts the reader. `Heartbeat.Connectors` carries the
   latest reading of each connector; facts travel only when they changed since the
   server acknowledged them, metrics every time. Bounds: 64 connectors per box,
   32 KiB of facts per reading.
4. **Device certificates are pinned, not ignored.** Devices use self-signed
   certificates. The box records the fingerprint it saw; the operator may pin it,
   after which a different certificate fails the reading loudly.
5. **Readings are not events.** A failed reading is state on the connector row and
   a problem on the overview (acknowledgeable); transitions that should reach the
   CRM (tunnel down, licence expired) become events in the prevention step, with
   fixtures, not here.

## Rejected

- **Server reads the devices over the overlay.** Works only with NetBird up, puts
  every customer credential on the server, and turns the server into the thing an
  attacker wants. The box is already in the LAN.
- **Credentials typed on the box** (console-less, like the enrollment key):
  unusable for an operator with a hundred customers; the sealed path is one dialog.
- **A generic HTTP connector** ("call this URL with this header"): the box would
  execute operator-supplied requests against the customer network. Kinds are code.
- **Storing readings as full documents per interval**: facts change rarely, so the
  row keeps the latest and the day databases keep the numbers.

## Consequences

- Node's WebCrypto must support X25519 for the fixture and the browser must for the
  dialog (Chrome 133+, Safari 17+, Firefox 130+); older browsers get a clear error.
- The seal key is a second secret in the state directory; a stolen state directory
  still needs the sealed blobs from the server to yield a credential.
- The STARFACE reader stores version, state and licence answers as the PBX returns
  them; their exact shape differs per release and is documented only in the PBX's
  own Swagger file.
