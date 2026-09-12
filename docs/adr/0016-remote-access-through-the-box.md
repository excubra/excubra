# ADR-0016: Remote access through the box — the customer LAN in the operator's overlay

Status: accepted · Date: 2026-09-12

## Context

Every customer has its own NetBird stack (its VPN, its staff, the box as routing
peer). Technicians therefore switched tunnels per customer, and nothing reached
two customers at once. The operator wants every customer LAN reachable from the
one tunnel they already sit in, switched per site from the console, with nothing
opened at the customer.

## Decision

1. **The box is a second peer, in the operator's own stack, in its own network
   namespace.** `netbird-operator.service` runs a second NetBird daemon inside the
   namespace `operator`, which owns a macvlan interface on the LAN with an address
   of its own from DHCP (`image/netbird-operator-netns.sh`). It has its own
   WireGuard interface, its own firewall table and its own routes; the customer's
   daemon in the root namespace never sees it. The socket
   `/var/run/netbird-operator.sock` is what the agent talks to. Installed only with
   `provision-box.sh --operator-peer`. *Why the namespace:* two NetBird daemons in
   one namespace share one nftables table, and the second wipes the first's routing
   rules on start — that cut the pilot customer's LAN on 12.09.2026 for a quarter of
   an hour. A unit without the namespace is removed by the provisioning script.
2. **EX0 wires the operator's stack through its API.** Settings on the server: the
   management URL and an API token of a dedicated admin user of *our* stack (this is
   our infrastructure, not a customer's; the token is revocable there). Switching a
   site on creates: the box group and the LAN group if missing, one policy
   `technicians → customer LANs`, a one-off setup key in the box group, a network
   `Customer · Site` with the LAN as resource in the LAN group, and the box's peer
   as router with masquerading. Switching off disables the resource; removing
   deletes the network. State lives in `remote_access`, every step is audited.
3. **The key reaches the box the way keys always do.** `netbird_keys` now has a
   profile per box (`customer`, `operator`); the config says a key waits, the box
   claims it once, `POST /v1/netbird/claim?profile=operator`. The box reports the
   second client's state and overlay address in its heartbeat; the server matches
   the peer by that address before it makes it a router.
4. **Overlapping LANs are refused**, not remapped. Two sites with 192.168.0.0/24
   cannot both be on; the console says which one is in the way. Address translation
   on the box (NETMAP) is a later step and gets its own decision.

## Rejected

- **Policies between customer stacks**: NetBird overlays are separate networks by
  design; there is no path from one stack into another.
- **A hand-built bridge container per customer**: what the first bridge for the
  pilot customer was. Works, but every customer costs an afternoon and nothing
  shows in the console; the box already stands in the LAN and already speaks
  NetBird.
- **The server as router or the server holding customer credentials**: the server
  routes nothing and knows only our stack's token.
- **One NetBird daemon with two managements**: the client holds one management
  connection; profiles switch, they do not run concurrently.

## Consequences

- Existing boxes get the operator peer only through an explicit
  `provision-box.sh --operator-peer`, after the namespace setup was tried on our own
  infrastructure first; images do not carry it by default.
- The LAN must offer DHCP (or `OPERATOR_LAN_IF` and a static address later); the
  host kernel must have macvlan.
- The operator stack's token on the server can create networks and policies there;
  it belongs to a dedicated admin user, is audited on every use and can be revoked
  in the NetBird dashboard.
- Technicians see every switched-on LAN in their client and can deselect a
  network they do not need.
