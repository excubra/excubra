# ADR-0016: Remote access through the box — the customer LAN in the operator's overlay

Status: accepted · Date: 2026-09-12 · Amended 2026-09-12 (the box image is one package)

## Context

Every customer has its own NetBird stack (its VPN, its staff, the box as routing
peer). Technicians therefore switched tunnels per customer, and nothing reached
two customers at once. The operator wants every customer LAN reachable from the
one tunnel they already sit in, switched per site from the console, with nothing
opened at the customer.

## Decision

1. **The box is a second peer, in the operator's own stack, in its own network
   namespace — and that is part of every box.** The box image is one package with
   three parts: the EX0 agent, the *operator peer* (`netbird-operator.service`, a
   NetBird daemon inside the namespace `operator`, always installed, idle until EX0
   hands it a key) and the *customer peer* (`netbird.service` in the root
   namespace, installed and idle, joins only when a customer key is put in through
   the console — the opt-in for customers with an overlay of their own). The operator
   daemon has its own WireGuard interface, its own firewall table and its own
   routes; the customer's daemon in the root namespace never sees it. The socket
   `/var/run/netbird-operator.sock` is what the agent talks to.
   *Why the namespace:* two NetBird daemons in one namespace share one nftables
   table, and the second wipes the first's routing rules on start — that cut the
   pilot customer's LAN on 12.09.2026 for a quarter of an hour. A unit without the
   namespace is removed by the provisioning script.
   *The way out* (`image/netbird-operator-netns.sh`, `/etc/default/netbird-operator`):
   by default **nat** — a veth pair to the root namespace, which forwards for it and
   masquerades `169.254.222.0/30` in its own nftables table `ex0op`. Nothing new
   appears on the LAN (no second MAC, no DHCP lease), so it works on a bridge, in an
   LXC container and behind port security; NetBird's own rules in the root namespace
   match only its WireGuard interface, so they and ours never meet. **macvlan** stays
   available for a peer with an address of its own on the LAN.
   *The way in:* technicians reach the box itself at its operator-overlay address.
   `netbird-operator-ssh.service` runs `excubra agent forward` inside the namespace,
   unprivileged, and relays port 22 over the veth pair to the box's sshd in the root
   namespace (a DNAT would be dropped by NetBird's forward filter, which only allows
   routed networks; a relay is ordinary inbound traffic under the policy
   `technicians → boxes`).
2. **EX0 wires the operator's stack through its API, and every box joins by
   itself.** Settings on the server: the management URL and an API token of a
   dedicated admin user of *our* stack (this is our infrastructure, not a
   customer's; the token is revocable there). Once a box is assigned to a site and
   reports its operator daemon, the server mints a one-off setup key in the box
   group and the box claims it — no switch needed; a key nobody fetched within an
   hour, or one whose daemon is still unconfigured two hours after the claim, is
   replaced. Switching a site on then creates: the groups and the two policies
   `technicians → customer LANs` and `technicians → customer boxes` if missing, a
   network `Customer · Site` with the LAN as resource in the LAN group, and the
   box's peer as router with masquerading. Switching off disables the resource;
   removing deletes the network — the box stays a peer, that is the image's
   business, not the site's. State lives in `remote_access`, every step is audited.
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

- Every box provisioned with `image/provision-box.sh` carries the operator peer;
  `--no-operator-peer` removes it. A machine that ran NetBird before its first
  provisioning is a guest (no firewall, no upgrades, its NetBird untouched) — the
  operator peer still comes along, in its namespace. The namespace mechanics (nat
  mode, relay, teardown) and the join into our stack were tried in a container on
  our own machine before any customer box got them.
- nat mode needs `nftables` and `ip_forward`; ufw boxes get two rules for the veth
  pair (`route allow in on veth-op`, `allow in on veth-op … port 22`). macvlan mode
  needs a LAN with DHCP (or `OPERATOR_LAN_IF`) and a NIC that accepts a second MAC.
- A technician reaches box and LAN from the one tunnel: `ssh root@<overlay address
  of the box>` for the box, the routed network for the LAN.
- The operator stack's token on the server can create networks and policies there;
  it belongs to a dedicated admin user, is audited on every use and can be revoked
  in the NetBird dashboard.
- Technicians see every switched-on LAN in their client and can deselect a
  network they do not need.
