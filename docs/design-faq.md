# Design FAQ — why this isn't NFS, and how it handles the hard parts

> Fodder for the eventual write-up. Context: Noel's challenge, 2026-11-06 —
> *"you just reinvented NFS"* followed by *"how does the 'solution' handle
> synchronous conflicts and time deltas also packet loss"*. The answers below
> are the design story, with receipts from the live sessions (2026-11-05/06).

---

## "You just reinvented NFS"

Forgive him — but he's describing a system where the network is pretending to
be a disk. We built the opposite: a system where **two real disks disagree and
have to make up**. That difference is the entire product.

### Where Noel's right (steelman first, he'd only get louder)

At 10,000 feet, both "make remote files appear on your machine." And in the
happy path — connected, no divergence — ours *behaves* like a slow file pull.
If all you ever did was sync-while-connected, Noel would be 80% right and we'd
have built NFS with extra steps and worse kernel integration.

### The five load-bearing differences

**1. Copies.** NFS has **one** authoritative copy (the server) and clients
borrow it. We have **two** authoritative copies — the laptop and the PVC are
both *real, fast, local filesystems*. That's not an implementation detail,
it's the whole design: opencode in the sandbox stays instant when your laptop
is shut, and your laptop stays instant when the cluster is dark. NFS gives you
neither — unmount it and the files are gone; mount it over WAN and every tool
call pays a round-trip.

**2. Disconnection is a mode, not a failure.** Pull the network on an NFS
mount and your workflow dies — stale handles, I/O errors, hung processes.
Ours: edit on the train, accumulate changes, reconcile when the pipe returns.
Lived this today — the cluster API went dark mid-session, agents restarted,
the relay was the only path, and the laptop never noticed beyond a paused
sync.

**3. Divergence has a protocol.** NFS *cannot express* "both of us edited
this file while the other wasn't looking" — there's only ever one copy, so
there's no question to answer. We carry an **ancestor archive** (the three-way
base), detect divergence per-file by digest, surface conflicts to a human (UI
or the in-sandbox MCP), stage conflict copies, and guard against mass
deletions — which *caught a genuine mass-deletion plan* during M3 when two
sandboxes briefly shared an archive key. Noel's NFS has no equivalent
machinery because NFS never lets the question arise. Our question arises
constantly, because reality.

**4. The "server" is ephemeral and self-assembling.** NFS presumes a durable
server with a stable IP and exports. Ours: the sandbox PVC gets created,
re-pointed, wiped, and re-created (the subpath policy); the agent
**self-installs onto the PVC**, and the daemon **auto-provisions** per-root
agents when a target points at a root nobody serves. The closest NFS
experience is remounting onto a fresh empty volume and wondering where your
files went.

**5. The transport is ours, not the kernel's.** Noise-encrypted libp2p with
per-sandbox derived keys, TOFU→strict peer pinning, NAT traversal through a
relay with relayed→direct upgrade attempts — one outbound dial,
cluster-egress-policy friendly, no inbound exposure, no Kerberos, no root
daemons. And it moves **content digests + chunked staging**, not VFS
operations.

### The one-liner for Noel

> NFS answers *"where do the files live?"* — one place, and you go to them.
> We answer *"the files live in two places, the network between them is
> hostile, and here's the protocol for them to converge anyway."*

Everything the project fought in its first week — conflict staging, the
deletion guard, pair-keyed archives, relay fallback, auto-provisioning —
exists **only** because we chose two authoritative copies. NFS never has to
solve any of it, and NFS also can't survive any of the afternoon we just had.

---

## "How does the 'solution' handle synchronous conflicts, time deltas, and packet loss?"

Noel's asking the right three questions — these are exactly where sync
systems fall over.

### 1. Synchronous conflicts

First, the honest framing: in any state-based system, a *truly simultaneous*
edit is indistinguishable from a *sequential* divergence — both look like
"each side changed since we last agreed." So the design doesn't try to detect
simultaneity; it makes divergence **well-defined** instead:

- Every pass scans both trees and compares each against the **ancestor
  archive** — the last state both sides agreed on (pair-keyed, so re-points
  get fresh safe bases).
- Changed on A only → A wins. Changed on B only → B wins. Changed on both,
  identical digests → converged, no-op. Changed on both, different content →
  **conflict**: whole-file granularity, the loser's content preserved as a
  conflict copy, winner materialized, and the conflict surfaces in the UI or
  the sandbox MCP with explicit keep-laptop / keep-sandbox resolution. No
  silent merge, no silent last-write-wins.
- No distributed locking — neither side is a cache of the other, both are
  authoritative, so divergence is *expected state*, not an error to prevent.
  That's the inversion from NFS Noel keeps missing.
- Within-pass races are handled too: digests are verified against stat size
  mid-scan (a file changing under the scanner becomes a `Problematic` entry,
  never a silent skip), and deletes re-verify against the scan cache before
  doing anything destructive. Plus the large-deletion guard — a plan removing
  too much of the tree halts and demands a human. That guard caught a genuine
  mass-deletion plan during M3.

### 2. Time deltas

The engine **never compares clocks across machines**. Fingerprints are mtime
+ blake3 digest, mutagen-model: mtimes only power the *local* warm-scan
quick-check (skip re-hashing when size+mtime are unchanged), while every
cross-machine decision — "did this file change?" — is settled by **content
digest against the archive base**.

This isn't theoretical: the sandbox clock ran **ten hours behind** the laptop
during the live sessions. The sync converged anyway, because a 10-hour skew
costs at most a warm-cache miss (a re-hash), never a wrong decision. There's
no "which timestamp is newer" tiebreaker anywhere in the reconcile — the base
decides, digests prove.

### 3. Packet loss

The wire is TCP (libp2p over TCP, noise-encrypted, yamux-multiplexed) —
retransmission and ordering are TCP's job, so loss below the stream is
invisible to the sync logic and costs only latency. What the sync *does*
handle is what loss implies: **torn and dead connections**.

- The wire framing validates magic/length on every message — a mid-stream EOF
  is detected, not guessed (`stream ended mid-frame/handshake` — seen live
  when a session died under us).
- On any session death: drop it, reconnect with backoff (interval × 1–5),
  re-run the pass. An interrupted pass leaves **no partial truth**: staged
  writes go to `.sync-agent-tmp-*` temps and rename in atomically — a killed
  transfer leaves a temp, never a half-written target; the archive only
  advances when a pass *completes*.
- So a pass killed at 80% is completely safe: the 80% applied now matches on
  both sides (converged, idempotent by digest), the remaining 20% is still
  divergent and gets re-planned next pass. The agent clears its staging on
  every session start.
- Between passes, the agent holds the relay reservation and re-establishes it
  on loss — the daemon's persistent session reconnects into it.

### The one-line summary

**Packet loss is TCP's problem, clock skew is digests' problem, and conflicts
are the product** — the first two are plumbing, the third is why the ancestor
archive exists at all.

---

## Live receipts (2026-11-05/06)

- Cluster API outage mid-session: sync paused, laptop unaffected, resumed
  when the API returned.
- Mid-flight human edit (a one-line addition to a synced file) plus an editor
  `~`-backup file: both replicated byte-for-byte, including a sandbox-side
  write that raced the pass.
- Sandbox re-pointed across subpaths repeatedly (subpath root policy): each
  re-point got a fresh, safe no-base archive — the pair key includes the
  root.
- Sandbox deleted its own infrastructure dir mid-session: full recovery from
  the laptop's authoritative master key + agent binary in one pass.
- A mass-deletion plan (two sandboxes sharing one archive key): halted by the
  large-deletion guard, never applied.
- 10-hour clock skew between laptop and sandbox: zero effect on correctness
  (digests decide).
