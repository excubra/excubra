# ADR-0006: Signed self-update with rollback

Status: accepted · Date: 2026-09-05

## Context

Kaseya 2021: the server that distributes updates must not be able to sign them. Updates
must be atomic and self-healing on a box that nobody can reach if it breaks.

## Decision

**Signing (release pipeline only).** GitHub Actions builds the static binaries and signs
each one with `cosign sign-blob --key` (ECDSA P-256, private key and password are
repository secrets, never on any server). The signature is the base64 DER ECDSA
signature over the SHA-256 digest of the binary — exactly what cosign produces for a
blob. Released artefacts: `excubra_linux_<arch>`, `excubra_linux_<arch>.sig`,
`SHA256SUMS`.

**Verification (agent and server).** `internal/sig` verifies with the standard library
only: `ecdsa.VerifyASN1(pub, sha256(blob), sig)` against the public key embedded at
build time (`internal/sig/release.pub`, committed — it is public). No cosign, no
Sigstore client, no Rekor lookup on the box. A build without a real release key (the
placeholder in the repo) refuses every update with `sig: no release key embedded`.

**Metadata (server → agent).** `GET /v1/update?os=linux&arch=arm64` answers
`{"version", "url", "sha256", "signature", "min_agent_version"}` for the box's channel
(`stable` or `canary`, set per box in the console), or `204 No Content`. The server
holds no binaries; `url` points at GitHub Releases (or any HTTPS host the operator
configures). The signature check makes the download host irrelevant for integrity.

**Procedure (agent):**

1. Download to `<statedir>/update/excubra.new` (10 MiB limit, 5 min timeout), verify
   SHA-256 and the signature. Any failure: delete, report in the next heartbeat, retry
   next day.
2. **Trial run**: execute `excubra.new agent selftest --state-dir …`, which loads the
   certificate and performs one heartbeat. Non-zero exit → delete, report.
3. Swap atomically: `rename(current, current.prev)`, `rename(new, current)`, fsync the
   directory. Write `<statedir>/update/pending` with the previous version.
4. Exit with code 75 (`EX_TEMPFAIL`); the systemd unit has `Restart=always`, so the new
   binary starts.
5. **Health check after restart**: while `pending` exists, the new process must
   complete a successful heartbeat within 5 minutes. On success it deletes `pending`
   and keeps `current.prev` (for a manual rollback). On failure — or if the process
   cannot start and systemd restarts it repeatedly — the next start finds `pending`
   older than 5 minutes, renames `current.prev` back over `current`, writes
   `rolled-back` for the heartbeat to report, and exits 75 again.

Step 5 needs a process that runs at all; step 2 covers the binary that cannot start.
Together they cover both failure classes without a separate supervisor.

**Canary.** The console sets the channel per box. Release order is fixed in the operating
docs: VIICO's own systems, then five customer boxes, then the rest; the code only knows
channels.

**Server.** Same package, same procedure; the health check is "the ingest listener
accepts a request". Disabled inside a container (the image is the update) and enabled
for the systemd deployment.

## Consequences

- The update path has no dependency beyond `net/http` and `crypto`.
- A box that installs a bad build recovers on its own within ~10 minutes and says so.
- Keeping `current.prev` costs one binary of disk (~15 MB) — accepted.

## Rejected

- **Sigstore keyless signing**: verification needs Fulcio roots and a Rekor lookup on
  the box — network, trust roots and code we cannot audit in a day. A plain key pair is
  auditable in an afternoon.
- **TUF** with rollback protection and threshold keys: planned for the end-game, not
  Phase 1 (salt: non-goals). `min_agent_version` gives basic downgrade protection now.
- **Package manager / distro packages**: a distribution matrix and a second update
  mechanism next to the one the agent has anyway.
- **Server-side signing**: the Kaseya failure mode.

## Amendment 2026-09-11: signing without cosign, a release catalog, and what an operator needs

**Signing.** The release workflow signs with a plain ECDSA P-256 key held as the
repository secret `RELEASE_KEY_PEM` (`openssl dgst -sha256 -sign`); the output is the
same DER signature over SHA-256 that cosign produces for a blob, so `internal/sig`
is unchanged. cosign is no longer required anywhere. The public half is committed as
`internal/sig/release.pub`; `tools/sigcheck` verifies a freshly signed binary with
the embedded key before the release is published, so a key mismatch fails the
pipeline, not a box.

**Catalog.** Every release ships `manifest.json` (`tools/manifest`): version, minimum
agent version, and per binary URL, SHA-256 and signature. The server reads the
project's release list (`EXCUBRA_RELEASE_CATALOG`, default the GitHub API of
`excubra/excubra`, `off` to disable) hourly and stores new releases; the console
shows them, and pointing a channel at one stays a click by an operator. The server
still holds no binaries and cannot sign.

**What this means for someone who runs EX0.** Nothing beyond installing it: the
binaries trust the project's key, the catalog fills itself, boxes download from
GitHub over HTTPS and verify. No organisation, no key, no password manager. Only a
fork that builds its own binaries needs its own key pair (replace `release.pub`,
sign with the matching private key, point `EXCUBRA_RELEASE_CATALOG` at its own
releases). A LAN that blocks GitHub will get a mirror through the ingest later.

**Server self-update (2026-09-11).** Same updater, same procedure as the box:
`internal/server/selfupdate` follows the setting `server.channel` (stable, canary or
off), checks daily and on request (console button, `excubra server update now`,
which writes `<datadir>/update/now`), verifies against the compiled-in key, trial-runs
`excubra server selftest`, swaps and exits 75; the new process confirms once both
listeners are bound, otherwise the next start rolls back and audits it. The binary
lives in `/opt/excubra/bin` (owned by the service user, in `ReadWritePaths`), with
`/usr/local/bin/excubra` as a symlink for people. `EXCUBRA_SELF_UPDATE=off` in
containers, where the image is the update.
