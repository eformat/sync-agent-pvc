// Wire types mirroring the daemon's JSON API (crates/cli/src/api.rs).

export type Phase = "idle" | "syncing" | "paused" | "error";

/** GET /api/targets and GET /api/targets/{name} */
export interface TargetSnapshot {
  name: string;
  root: string;
  sandbox: string;
  /** "p2p" | "exec" */
  transport: string;
  /** Live connection path: "exec" | "direct" | "relayed" (p2p only). */
  path: string;
  phase: Phase;
  paused: boolean;
  last_pass_unix: number;
  applied: number;
  deleted: number;
  failed: number;
  conflicts_left: string[];
  conflicts_resolved: string[];
  honored: string[];
  problems: string[];
  archive_saved: boolean;
  trust_base: boolean;
  last_error: string | null;
  daemon_version: string;
  /** Sandbox-side health (p2p targets; absent until the first probe). */
  sandbox_status?: SandboxStatus | null;
  /** Held first-run preview (M6): the first pass parked as a dry-run. */
  first_preview?: FirstPreview | null;
  /** Live pass progress (present only while a pass runs). */
  pass_progress?: PassProgress | null;
}

/** Live pass progress: stage + file/byte counters (staging only). */
export interface PassProgress {
  /** "connecting" | "scanning" | "staging" | "applying" | "verifying" */
  stage: string;
  files_total: number;
  files_done: number;
  bytes_total: number;
  bytes_done: number;
}

/** Counts a brand-new target's held first pass WOULD have applied. */
export interface FirstPreview {
  applied: number;
  deleted: number;
  conflicts_left: string[];
  problems: string[];
  halted: string | null;
}

/** The sandbox-side agent + MCP convention health (daemon probe). */
export interface SandboxStatus {
  /** The qualified agent's binary version, "unknown", or "none" (not running). */
  agent_version: string;
  /** Tunnel specs the agent was spawned with, e.g. ["memory@7402"]. */
  tunnel: string[];
  /** The stable MCP binary path exists (agents/current/sync-agent). */
  mcp_binary: boolean;
  /** opencode.json references the stable MCP binary path. */
  mcp_config: boolean;
  /** The target's remote root exists. */
  root_ok: boolean;
}

/** GET /api/tunnel — the service tunnel's live state. */
export interface TunnelServiceStatus {
  name: string;
  upstream: string;
  agent_port: number;
  connected_agents: number;
  /** Of the connected agents: direct (DCUtR-punched) vs relayed circuits. */
  direct_agents: number;
  relayed_agents: number;
  active_streams: number;
  refusals: number;
  last_activity_unix: number | null;
}

export interface TunnelLinkStatus {
  /** Live agent ↔ daemon tunnel connections (held by the agent's driver). */
  agents: number;
  direct: number;
  relayed: number;
}

export interface TunnelStatus {
  enabled: boolean;
  link: TunnelLinkStatus;
  services: TunnelServiceStatus[];
  daemon_version?: string;
}

/** SSE `snapshot` event payload on /api/events */
export interface SnapshotEvent {
  target: string;
  snapshot: TargetSnapshot;
}

/** GET /api/health */
export interface Health {
  version: string;
  started_unix: number;
  targets: number;
}

/** POST /api/targets/{name}/dry-run — 200 body */
export interface DryRunReport {
  paused: boolean;
  planned_removes: number;
  planned_materializes: number;
  applied: number;
  deleted: number;
  failed: number;
  conflicts_resolved: string[];
  conflicts_left: string[];
  honored: string[];
  problems: string[];
  trust_base: boolean;
  halted: string | null;
}

/** GET /api/fs */
export interface FsEntry {
  name: string;
  is_dir: boolean;
  size: number;
  modified_unix: number;
}

export interface FsListing {
  path: string;
  entries: FsEntry[];
}

/** POST /api/targets (create) */
export interface CreateTargetBody {
  name: string;
  root: string;
  sandbox: string;
  workspace?: string;
  relay?: string;
  excludes?: string[];
  /** Override the sandbox-side path (default /sandbox/<name>); the wizard's
   * "OpenCode plans" preset sends /sandbox/.opencode/plan. */
  root_remote?: string;
}

/** {"ok":true,"message":…} action replies */
export interface OkReply {
  ok: boolean;
  message: string;
}
