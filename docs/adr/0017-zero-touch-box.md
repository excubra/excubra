# ADR-0017: A box needs nobody after it is plugged in

Status: accepted · Date: 2026-09-12

## Context

Rolling out the pilot box took a day of commands: provision, enroll, assign in the
console, mint a key for the operator stack, type the LAN, switch it on. The owner's
requirement is the opposite: put a box on the shelf or a container on the customer's
Proxmox, and everything else happens in EX0. ADR-0016 (amended) already made the box
image one package; this decision removes the remaining hands.

## Decision

1. **An enrollment key can be made for a site.** `enrollment_keys.site_id` is set in
   the console ("Neue Box": pick the site) and the box is assigned to that site the
   moment it enrolls — on the server, from the key record, never from anything the
   box sends. A key without a site still works: the box appears unassigned, as before.
2. **The box reports its own networks.** The heartbeat carries `box.lan`: the private
   IPv4 networks of its interfaces, the one with the default route first; overlay,
   veth, container and VPN interfaces are left out. The console shows it on the box
   card and suggests it for remote access.
3. **The server switches the LAN on by itself.** Once a box is a peer in the operator
   stack and reports a network, the reconcile loop enables remote access for its site
   with that network, actor `auto` (setting `remote.auto_lan`, "1" by default). A site
   that already has a row is left alone: switched off by a person, removed (the row
   stays as "off"), or refused earlier — the refusal (an overlapping LAN, a network
   somebody routes by hand) lands in the row so the site's card shows it and a person
   can enter another network.
4. **Two one-liners, printed by the console.** "Neue Box" mints the key and prints the
   command for a Proxmox host (`image/ex0-box-pct.sh`: template, unprivileged
   container with nesting and `/dev/net/tun`, then the box installer inside) and for
   a machine (`image/ex0-box.sh`: downloads the release, verifies `SHA256SUMS` against
   the release public key, runs `provision-box.sh`). Both fetch the files of the
   server's own release tag; a development server points at `main`.

## Rejected

- **The box choosing its site** (by name, by LAN, by a customer secret): the tenant
  must come from the server side only, that is an invariant.
- **Remapping overlapping LANs automatically**: NETMAP is a later step with its own
  decision; today an overlap is a message, not a surprise.
- **A registration portal on the box or a QR code**: more moving parts than a key on
  a command line the console already prints.

## Consequences

- The normal rollout is: console → Neue Box → command on the Proxmox host or the box →
  done. Updates go through the channels in the console; nothing on the box is touched
  by hand.
- A box provisioned before this decision still works; it reports its LAN after its
  next update, and gets its remote access switched on then.
- `remote.auto_lan = 0` keeps the switch manual for operators who want it that way.

## Amendment, 19.09.2026: the three clicks before the key are a session's job too

The rollout had one remaining seam. Everything after the key needs nobody, but
the key itself — and the customer and site it is made for — were three clicks
in the console, and a session that prepares a rollout has no console account and
no business typing into one. The owner's requirement is the same as in the
Context above: no hand work.

5. **The MCP server (`excubra server mcp`) can create a tenant, create a site and
   mint an enrollment key** (`ex0_create_tenant`, `ex0_create_site`,
   `ex0_new_box`). They call the same store functions as the console, are
   audited under the actor the MCP runs as, and `ex0_new_box` returns exactly
   what the console shows once: the key inside the two one-liners, with this
   server's release version. A site with an address is looked up on the server
   and placed on the map. The one-liners live in `internal/server/installer`, so
   the console and the MCP cannot drift apart.

What does not change: the box still assigns itself from the key, never from
anything it sends; the key is one-time and revocable until used; the MCP still
acknowledges nothing and switches nothing at a customer. And the command on the
customer's hypervisor is still run by a person with root there — the seam that
should stay, because it is the customer's machine.
