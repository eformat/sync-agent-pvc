# Architecture

`sync-agent-pvc` keeps a laptop `$HOME` directory and an OpenShell sandbox's PVC
sync root converging — bidirectionally, over a noise-encrypted P2P link — and
tunnels laptop services (the memory MCP) to sandbox agents through the same
link. This document is the map; `docs/design-faq.md` is the *why*; the animated
walk-through lives at
[eformat.github.io/sync-agent-pvc](https://eformat.github.io/sync-agent-pvc/)
(source: `docs/flow-story.html`).

## The big picture

```mermaid
flowchart LR
    subgraph laptop["Laptop ($HOME)"]
        user["🧑 User / OpenCode"]
        daemon["sync daemon (crates/cli)<br/>watch · scan · bisync pass<br/>systemd --user"]
        api["HTTP API + UI<br/>127.0.0.1:7391<br/>PatternFly (vendored BFF)"]
        mem["mcp-memory.service<br/>127.0.0.1:7999<br/>(the memory SSoT)"]
        state[("pair state<br/>~/.local/state/sync-agent-pvc<br/>archive + caches")]
        key[("master key<br/>~/.config/sync-agent-pvc · 0600")]
        daemon --- state
        daemon --- key
        user --> daemon
        daemon --> api
    end

    subgraph vps["VPS (untrusted)"]
        relay["sync-relay<br/>rendezvous + circuit relay<br/>DCUtR · sees ciphertext only"]
    end

    subgraph openshift["OpenShift (ocp5-1) — OpenShell sandbox pod"]
        agent["sync-agent p2p<br/>crates/agent · dials OUT"]
        mcp["sync-agent mcp<br/>stdio · 6 control-plane tools"]
        oc["OpenCode agent<br/>reads its $HOME here"]
        pvc[("PVC root<br/>/sandbox/&lt;root&gt;")]
        sstate[("/sandbox/.sync-agent<br/>agents · staging · state")]
        agent --- pvc
        mcp --- sstate
        oc --> mcp
        oc --- pvc
    end

    daemon <-- "noise + yamux<br/>bisync + tunnel streams" --> relay
    agent <-- "one outbound dial<br/>(egress-policy friendly)" --> relay
    mem -. "tunnelled MCP" .-> agent
```

Two authoritative copies — the laptop and the PVC are both *real, local
filesystems*. Neither is a cache of the other; divergence is expected state
that the engine converges, not an error to prevent. That inversion (vs NFS) is
the whole design; see [docs/design-faq.md](docs/design-faq.md).

## A bisync pass

Every pass is the same shape, whichever transport (P2P stream or `oc exec`
fallback) carries it:

```mermaid
sequenceDiagram
    autonumber
    participant W as watcher (fsnotify + 60s rescan)
    participant D as daemon (run_pass)
    participant E as engine (crates/core)
    participant A as sandbox agent

    W->>D: change detected / interval tick
    D->>D: pass_lock (per-target serialization)
    D->>E: load ancestor archive + scan caches<br/>(corrupt/missing ⇒ safe no-base)
    D->>A: session handshake (MAGIC, version, hello)
    D->>A: scan request → blake3 fingerprints
    E->>E: 3-way reconcile vs ancestor archive<br/>(A vs B vs base, per path)
    alt changed on one side
        E->>A: StageFile (digest-keyed staging, hashed on arrival)
        A->>A: materialize: temp → fsync → rename (atomic)
    else changed on both, different content
        E->>E: conflict: winner materialized, loser preserved<br/>as *.sync-conflict-* copy, surfaced in UI/MCP
    else delete
        E->>E: re-verify against cache + large-deletion guard
    end
    D->>D: post-apply re-scan (self-writes are visible)
    D->>D: archive advances ONLY on a completed pass
    D-->>W: report → UI (applied/deleted/failed/conflicts)
```

Load-bearing details:

- **No clock trust across machines.** Fingerprints are mtime + blake3; mtimes
  only power the *local* warm-scan quick-check. Every cross-machine "did this
  change?" is settled by content digest against the ancestor archive — a
  10-hour sandbox clock skew (seen live) costs a re-hash, never a wrong
  decision.
- **No partial truth.** Staged writes go to `.sync-agent-tmp-*` temps and
  rename into place atomically; the archive only advances when a pass
  *completes*. A pass killed at 80% leaves both sides converged on the applied
  80% (idempotent by digest) and the rest re-planned next pass.
- **Corrupt archive ⇒ safe no-base.** Undecodable/version-mismatched/foreign
  archives load as `None` and the pass becomes a full rescan with deletes
  disabled ("no-base never deletes" — deletion needs positive evidence).

## Transport ladder

```mermaid
sequenceDiagram
    autonumber
    participant D as laptop daemon
    participant R as VPS relay
    participant A as sandbox agent

    Note over A: bootstrapped once via oc exec<br/>(binary + master key on the PVC)
    A->>R: dial OUT + relay reservation
    D->>R: dial + reservation (rendezvous on the VPS)
    D->>A: noise session over the relayed circuit<br/>(first bytes ride the relay)
    D->>A: DCUtR hole-punch attempt (bounded window)
    alt punch lands
        Note over D,A: DIRECT TCP connection —<br/>the sync stream migrates, circuit torn down
    else punch fails / NAT wins
        Note over D,A: stays relayed (fallback data path)
    end
```

The relay is untrusted infrastructure: it sees only noise-encrypted traffic.
Neither side ever listens inbound — everything is an outbound dial, so cluster
egress policy needs exactly one allowance (the VPS). Agent identities are
derived, not enrolled: `PeerId = derive(master_key, sandbox_id)`, pinned TOFU
and matched strictly thereafter.

## The memory tunnel (M5)

Sandbox OpenCode gets the laptop's memory MCP — the same tools, the laptop
store as the single source of truth — through the P2P link:

```mermaid
sequenceDiagram
    autonumber
    participant OC as OpenCode (sandbox)
    participant L as agent loopback listener<br/>127.0.0.1:7402
    participant DA as laptop daemon (tunnel service)
    participant AL as [[tunnel.services]] allowlist
    participant M as mcp-memory.service<br/>127.0.0.1:7999

    OC->>L: tools/call memory_store (plain HTTP MCP)
    L->>DA: P2P stream /sync-agent-pvc/tunnel/1<br/>SAPVTUN1 handshake (service name)
    DA->>AL: authorize peer + service
    alt service allowlisted
        DA->>M: raw pipe (copy_bidirectional)
        M-->>OC: MCP result (the laptop store answers)
    else unknown / unauthorized
        DA-->>L: one status byte + clean close (never a hang)
    end
```

- **Default-deny on the laptop.** The allowlist lives in the daemon's config —
  an agent cannot opt itself into a service, and unlisted services are refused
  cleanly. This is the "memory access broker" pattern: future laptop services
  are new allowlist entries.
- **Offline writes spool.** While the tunnel is down, spool-listed write tools
  are appended to `<root>/.sync-agent/tunnel-spool/<service>.jsonl`
  (scanner-skipped) and answered with an honest "write spooled" result; reads
  fail fast to a clean miss. On reconnect a FIFO flush replays the spool —
  idempotent because the store is content-addressed.
- **Deterministic tunnel identity.** The daemon's tunnel PeerId is derived
  from the shared master key, so agents compute it with no rendezvous.

## Control plane (MCP)

The sandbox's `opencode.json` carries two MCP servers:

| Server | Transport | Tools | Purpose |
|---|---|---|---|
| `sync-agent` | stdio (`sync-agent mcp`) | `sync_status`, `sync_pause/resume`, `sync_resolve_conflict`, `sync_now`, `sync_ignore_add` | the agent sees and steers its own sync |
| `memory` | Streamable HTTP → tunnel | the laptop memory toolset (`memory_store`, `memory_search`, …) | same memory tools as laptop OpenCode |

The control plane reads the daemon-written `sync-state.json` and writes
`control-requests.json` (pause/resume/resolutions/ignore-adds) which the next
pass fetches and honors — no bulk file data ever rides it.

## State layout

| Location | Contents |
|---|---|
| `~/.local/state/sync-agent-pvc/pairs/<pair-hash>/` | laptop: ancestor archive + scan caches (legacy `<root>/.sync-agent` migrated on first run) |
| `/sandbox/.sync-agent/agents/<version>/` | versioned agent binaries + `current` symlink (GC'd on install) |
| `/sandbox/.sync-agent/agent/<hash>/` | sandbox: digest-keyed staging |
| `<root>/.sync-agent/` | scanner-skipped state dir: control files, tunnel spool, `.syncignore` lives beside it |

`.syncignore` (mutagen glob syntax) is synced content — edit it on either side.

## Crate map

```mermaid
flowchart TD
    proto["crates/proto<br/>wire framing · tunnel protocol · control types"]
    core["crates/core<br/>scan · 3-way reconcile · archive · excludes"]
    agent["crates/agent<br/>serve (exec) · p2p · tunnel client · mcp · install"]
    cli["crates/cli<br/>daemon · API + UI · transports · tunnel service"]
    ui["crates/cli/ui<br/>PatternFly dashboard (vendored)"]
    core --> proto
    agent --> proto
    cli --> core
    cli --> ui
```

| Crate | Role |
|---|---|
| `crates/core` | sync engine: scan (blake3), 3-way reconcile, archive, excludes (vendored copia cores) |
| `crates/proto` | MAGIC handshake + bounded-length CBOR/bincode frames, tunnel handshake, control types |
| `crates/agent` | remote agent: `serve` (exec/stdio), `p2p` (driver + transports), tunnel client + spool, MCP server, self-installing binaries |
| `crates/cli` | laptop daemon: per-target pass loops, localhost API + vendored PatternFly UI, P2P/exec transports, tunnel service + allowlist |

## Failure semantics (the chaos gate)

| Failure | Behavior |
|---|---|
| Daemon killed mid-pass | staged temps only; archive not advanced; next pass re-plans the remainder |
| Agent/pod killed mid-transfer | staging hashed on arrival; digest mismatch = retry, never a corrupt apply |
| Corrupt archive (and its `.bak`) | safe no-base: full rescan, deletes disabled, re-seeds the archive |
| Cluster/API outage | pass errors are per-target; laptop unaffected; resumes when reachable |
| Mass deletion (bad pair key, stale tree) | large-deletion guard halts the pass and demands a human |
| Tunnel down | writes spool (FIFO, idempotent), reads miss cleanly, flush converges on reconnect |
| Unknown tunnel service / stranger peer | one status byte + clean close; counted in `/api/tunnel` refusals |
