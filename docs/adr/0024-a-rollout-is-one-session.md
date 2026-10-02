# ADR-0024: A rollout is one session

Status: accepted · Date: 2026-10-02 · Decision E30

## Context

ADR-0017 set the goal: a box needs nobody after it is plugged in, and its
amendment let a session create the customer, the site and the key. The second
customer's rollout on 29.09.2026 showed how far that was from true. One
afternoon, seven places where a person had to step in or was misled:

1. The session could not mint the enrollment key. `excubra server mcp` ran as a
   process of its own; the CA's private key is sealed at rest (ADR-0009), and
   the process could not open it. A click in the console after all.
2. The command on the hypervisor printed "is an EX0 box" over a container with
   nothing in it. The inner installer came through a pipe; a failed download
   was an empty script that ended quietly.
3. The container's values (id, address, storage) were handed over next to the
   command and forgotten: the next free id, an address from DHCP.
4. The customer's LAN is a /24 out of public address space — numbered long ago,
   not renumberable. The box reported no LAN, the server switched no remote
   access on, the site's card said nothing.
5. Nobody could log in to the new box: sshd takes keys, the installer left none.
6. What to watch was a list of clicks in the console; the session could read
   the proposal and act on nothing.
7. The customer's own VPN was a separate piece of manual work on another host.

Six of these are the same finding: after the key, a rollout went back to a
person. The owner's requirement is one session per customer — a customer wants
EX0, a session builds all of it.

## Decision

### 1. The MCP server lives in the running server

The server answers MCP on a Unix socket in its data directory
(`mcp.sock`, mode 0600, in a directory only the service user and root can
enter). `excubra server mcp`, still started through SSH from a machine in the
operator overlay, carries a session's lines to that socket and the answers
back. A request that meets a restarting server waits for it — a release must
not end the session that is rolling a customer out — and a tool call that died
half-way is not repeated behind the session's back.

Inside the server the tools are the console's own functions: the unsealed CA,
the engine with its sites and hosts in memory, remote access. A second process
could not have been given these — whatever it wrote into the store went past
the engine, which would have learned of a new host at its next restart.

Nothing new listens on a network. Without a server on the socket the command
answers from the files as before: everything that reads, and the set-up steps
that are plain rows. The pin an enrollment key carries is read from the CA
*certificate* (`pki.CAFingerprint`); minting a key never opens the sealed key.

### 2. Set-up is a session's work; operating is a person's

The tools a session has, each audited under the actor it runs as:

| Tool | What it does |
| --- | --- |
| `ex0_create_tenant`, `ex0_create_site` | as before (ADR-0017 amendment) |
| `ex0_new_box` | the key, inside the complete command: container id, bridge, address and gateway, storage, disk, memory, and the technicians' SSH keys |
| `ex0_rollout_status` | every step of a rollout with its state (`ok`, `open`, `waiting`, `optional`) and the next move; `done: true` is the acceptance |
| `ex0_site_lan` | remote access for another network than the reported one, or for one outside RFC 1918 (§4) |
| `ex0_customer_vpn` | hands the site's box the customer's own NetBird stack (management URL, setup key); the server forgets the key once the box claimed it |
| `ex0_watch_suggestion`, `ex0_watch` | the console's "beobachten, was zählt" and single devices with their checks — the closed list of check types (ADR-0003) is the only thing it can ask for |
| `ex0_site_scan` | the service scan; switching it on takes the customer's consent as a sentence, which goes into the audit log (ADR-0018, E20) |

The line that does not move: the server still cannot make a box do anything
but what the closed lists allow, a box still assigns itself from its key, and
a session **acknowledges nothing and operates nothing** — findings, outages,
maintenance windows, the DNS sensor (somebody has to change the customer's
router) and a device's credentials (typed by a person, sealed to the box,
ADR-0015) stay in the console.

### 3. The installer says what happened

`ex0-box-pct.sh`, `ex0-box.sh` and `provision-box.sh` end with one line a person
and a program can both read, and an exit status that agrees:

    EX0-RESULT: ok ctid=200 hostname=ex0-kunde-standort box=box_…
    EX0-RESULT: failed step=installer — and why

- A script is loaded into a file and then run (`curl -o … && bash …`), and
  every script's body is one function called on its last line: a failed
  download is a failure, half a download runs nothing.
- `provision-box.sh` waits for the enrollment and tells a refused key ("used,
  expired or revoked") from a server that cannot be reached ("outbound 443
  blocked, or TLS inspection in the way?").
- `ex0-box-pct.sh` finds its own container by hostname on a second run instead
  of making another, refuses a fixed address that already answers, a bridge or
  storage that does not exist, and a container id that belongs to something
  else.
- `ex0-box.sh` refuses to run on a Proxmox host: a box is a machine of its own
  or a container, never a hypervisor.
- The scripts set their own umask. Called under 077, the NetBird keyring was
  written unreadable for apt's sandbox user and the installation died of "the
  repository is not signed".
- `--ssh-key` puts a technician's public key into root's `authorized_keys`.
  The keys travel in the command a person runs on the box. They are never
  something the server hands a box afterwards: a server that could add a key
  could open a door at a customer, and that it cannot is an invariant.

`test/box/run.sh` tries all of it before a release — a local server, a Debian 13
with systemd in Docker, a pretend Proxmox (the "container" is the machine
itself), real enrollments, the failure paths included.

### 4. A LAN outside RFC 1918 is declared, per site

"Private" was the definition of a LAN in six places. It is now two facts:

- **What the box sits in.** The heartbeat carries `box.lan_other`: directly
  attached IPv4 networks of hosts (/8 to /30) that are not RFC 1918 and are
  ordinary unicast space. Reported, stored (`boxes.lan_other`), never switched
  on by themselves. A single address (a server at a hoster), a point-to-point
  link, link-local and multicast are never anybody's LAN.
- **What an operator declared.** `sites.local_nets`: this network is the
  customer's own. Only a network the site's box reports can be declared, and
  none that overlaps the /16 the operator overlay numbers its peers from.

From the declaration on, remote access is switched on for that network like
for any LAN (and by itself, if it was declared before the box arrived), the
rules count its addresses as inside (`fgt.admin_on_wan`, the origin of a failed
login), and the DNS sensor answers its clients (`dns.local` in the box's
config, bounded and validated on the box). Until then the site's remote-access
row says why nothing happened, instead of staying empty.

The declaration needs a person's word — a checkbox in the console,
`confirm_public` for a session, which is told to get that word first — because
a route to public address space in the technicians' overlay takes their real
traffic for that range with it. It is in the audit log.

## Rejected

- **Unsealing the CA for the MCP process.** It would have fixed the first of
  seven points and left the process outside the engine. It also means a second
  place that holds the open key.
- **A TCP control port for the MCP**, even on localhost: a new listener is a
  new thing to protect. The socket's protection is the directory's.
- **Treating every directly attached network as the LAN.** A box on a public
  /29 at a hoster would put that range into the technicians' overlay by itself.
- **Renumbering the customer's network.** Right in principle, not on offer: a
  domain controller, DHCP, a firewall and every phone, during business hours.
  The product has to cope with networks as they are found.
- **NETMAP for the public range** (presenting it as a private one in the
  overlay): it solves the route's side effect, at the price of addresses that
  mean something else on each side. A later step with its own decision, like
  NETMAP for overlapping LANs (ADR-0016).
- **SSH keys from the server** (a setting the boxes pull, an
  `AuthorizedKeysCommand`): central and convenient, and exactly the channel into
  a customer's network that the server must not have. Rotating technician keys
  across the fleet belongs to the operator signature (V2), where an order is
  signed by a person and not by the server.
- **A session that acknowledges and operates.** What a rollout needs is set-up.
  The rest is the judgement the product exists to keep with people.
- **Auto-switching the scan for every new site.** It needs consent; a tool that
  asks for the sentence is the smallest thing that keeps the question alive.

## Consequences

- A session rolls a customer out end to end; the one step that needs somebody
  else is the command on the customer's hypervisor or box, run by whoever has
  root there — the session itself, when it was given that access.
- The MCP's tool list grew from eleven to seventeen. Its instructions carry the
  order of a rollout.
- A box that reports `lan_other` to an older server changes nothing there: the
  field is unknown and ignored. An older box behind a newer server reports only
  private networks, as before.
- `ex0_new_box` warns when it is called without SSH keys. A box made earlier has
  none; the installer without a key and with `--ssh-key`, run once on the box,
  adds them.
- The command is longer. It is also complete: nothing is appended by hand.
