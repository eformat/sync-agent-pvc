//! M4: the long-lived laptop daemon (`sync daemon`).
//!
//! Owns one loop thread per configured target (config.toml): fsnotify events
//! (debounced) and a periodic safety re-scan trigger sync passes; a SyncReport
//! lands on the sandbox after every pass (M3.5 driver). UI-side controls act
//! daemon-side: resolves go into `RemoteConfig.local_resolutions` for the next
//! pass (the laptop owns the data plane — see remote_driver); pause/resume/
//! sync-now only steer the loop.
//!
//! Threading: target loops are plain std threads (each pass re-dials through
//! the blocking transport bridge, M3 style); the HTTP API lives on a tokio
//! runtime (api.rs). State crosses threads as serializable snapshots over a
//! `tokio::sync::broadcast` event bus (`send` is sync — fine from std threads).
//!
//! Config lives at `~/.config/sync-agent-pvc/config.toml` and is hot-reloaded:
//! edits add/update/remove targets without a daemon restart.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::remote_driver::{
    report_progress, sync_local_to_remote, PassProgress, ProgressSink, RemoteConfig, RemoteReport,
};
use crate::{
    build_transport, load_master_key, open_session, shutdown_quietly, TargetArgs, TransportKind,
    VERSION,
};
use sync_proto::control::ConflictResolution;

pub const DEFAULT_BIND: &str = "127.0.0.1:7301";
pub const DEFAULT_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_DEBOUNCE_MS: u64 = 500;

// ---------------------------------------------------------------------------
// configuration (config.toml)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub defaults: Defaults,
    /// Skip-serialize when empty: an empty `targets = []` line at the top of
    /// the file collides with any later `[[targets]]` blocks ("duplicate
    /// key") — e.g. after deleting all syncs, then re-adding one (2026-11-06).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<TargetConfig>,
    /// M5 memory access broker: the opt-in laptop service tunnel (default
    /// deny — see crates/cli/src/tunnel.rs). Disabled unless `[tunnel]`
    /// `enabled = true` with at least one `[[tunnel.services]]` entry.
    #[serde(
        default,
        skip_serializing_if = "crate::tunnel::TunnelConfig::is_default"
    )]
    pub tunnel: crate::tunnel::TunnelConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ServerConfig {
    /// Bind address for the localhost UI/API. Loopback enforced.
    pub bind: Option<String>,
}

/// Values every target inherits unless it overrides them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Defaults {
    pub relay: Option<String>,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_debounce")]
    pub debounce_ms: u64,
    pub master_key_file: Option<PathBuf>,
    #[serde(default)]
    pub master_key_env: bool,
    /// When a brand-new p2p target's root isn't served by any agent, start a
    /// per-root agent in the sandbox via the exec fallback (qualified
    /// sandbox-id `<sandbox>+<name>`) and qualify the target's config.
    /// Established targets always keep the loud error. Kill switch.
    #[serde(default = "default_true")]
    pub auto_provision: bool,
    /// Attempt the DCUtR hole-punch upgrade on p2p sessions (direct
    /// connection when NAT allows, relayed circuit otherwise). Kill switch.
    #[serde(default = "default_true")]
    pub hole_punch: bool,
    /// Kubeconfig for oc calls (exec fallback transport + auto-provision).
    /// Inherited by targets that don't set their own — without this, oc
    /// falls back to the default ~/.kube/config, which may point at a
    /// long-dead cluster (the wizard's "no such host" error).
    #[serde(default)]
    pub kubeconfig: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

impl Default for Defaults {
    fn default() -> Self {
        Defaults {
            relay: None,
            interval_secs: DEFAULT_INTERVAL_SECS,
            debounce_ms: DEFAULT_DEBOUNCE_MS,
            master_key_file: None,
            master_key_env: false,
            auto_provision: true,
            hole_punch: true,
            kubeconfig: None,
        }
    }
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECS
}

fn default_debounce() -> u64 {
    DEFAULT_DEBOUNCE_MS
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TargetConfig {
    /// Unique target name (the UI id).
    pub name: String,
    /// Local directory (side A).
    pub root: PathBuf,
    /// Sandbox: full CR name (`default--sync-oc`) or short name + workspace.
    pub sandbox: String,
    #[serde(default)]
    pub workspace: Option<String>,
    /// Relay multiaddr — p2p transport when present, oc exec otherwise.
    #[serde(default)]
    pub relay: Option<String>,
    /// Extra ignore patterns (mutagen syntax) merged over both .syncignores.
    #[serde(default)]
    pub excludes: Vec<String>,
    /// Safety re-scan interval override (seconds).
    #[serde(default)]
    pub interval_secs: Option<u64>,
    /// fs settle window (ms) after an fs-event burst before scanning.
    #[serde(default)]
    pub debounce_ms: Option<u64>,
    #[serde(default)]
    pub master_key_file: Option<PathBuf>,
    #[serde(default)]
    pub master_key_env: bool,
    #[serde(default)]
    pub kubeconfig: Option<PathBuf>,
    /// The sync root inside the sandbox.
    #[serde(default = "default_root_remote")]
    pub root_remote: String,
    /// Inherited from defaults (see Defaults.auto_provision).
    #[serde(default)]
    pub auto_provision: bool,
    /// M6 first-run dry-run UX (default ON): a brand-new target's first pass
    /// (no archive yet, never synced) runs plan-only and is HELD — the
    /// snapshot carries `first_preview` and the UI offers "Sync now" to
    /// confirm. Set `first_run_dry_run = false` to propagate immediately.
    #[serde(default)]
    pub first_run_dry_run: Option<bool>,
    /// Attempt the DCUtR hole-punch upgrade before opening the sync stream
    /// (p2p transport). Inherited from defaults; false = always relayed.
    #[serde(default = "default_true")]
    pub hole_punch: bool,
    /// M5: names of `[tunnel]` services this target's agent may reach
    /// (resolved into `--tunnel` spawn args by parse_config; unknown names
    /// fail the config LOUDLY). Empty = the agent gets no tunnel client.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tunnel_services: Vec<String>,
    /// Resolved `--tunnel NAME@PORT[:TOOLS]` args (computed from
    /// `tunnel_services` + the `[tunnel]` service table at config load —
    /// never parsed from the file).
    #[serde(skip)]
    pub tunnel_args: Vec<String>,
    /// M8: keep `opencode serve` running inside the sandbox for this
    /// target's root (the attach workflow's server side — laptop
    /// `opencode --server` over a port forward). Default ON for p2p
    /// targets; `serve = false` opts out. The daemon self-heals it via
    /// the sandbox probe (same drift path as the agent).
    #[serde(default)]
    pub serve: Option<bool>,
    /// Explicit serve port. Default: derived deterministically from the
    /// qualified sandbox id (stable across daemon restarts, distinct per
    /// target — see [`serve_port`]).
    #[serde(default)]
    pub serve_port: Option<u16>,
}

fn default_root_remote() -> String {
    "/sandbox".to_string()
}

impl TargetConfig {
    /// Inherit defaults, resolve the tunnel spawn args, and validate names.
    pub(crate) fn resolve(mut self, tunnel: &crate::tunnel::TunnelConfig) -> io::Result<Self> {
        for name in &self.tunnel_services {
            let svc = tunnel
                .services
                .iter()
                .find(|s| &s.name == name)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "target {:?}: tunnel_services lists {:?} which is not in [[tunnel.services]] \
                             (the laptop allowlist is the source of truth — add it there first)",
                            self.name, name
                        ),
                    )
                })?;
            let mut arg = format!("{}@{}", svc.name, svc.agent_port);
            if !svc.spool_tools.is_empty() {
                arg.push(':');
                arg.push_str(&svc.spool_tools.join(","));
            }
            self.tunnel_args.push(arg);
        }
        Ok(self)
    }

    /// Fill unset fields from the daemon defaults (relay, interval, key refs).
    pub fn inherited(mut self, d: &Defaults) -> Self {
        if self.relay.is_none() {
            self.relay = d.relay.clone();
        }
        if self.interval_secs.is_none() {
            self.interval_secs = Some(d.interval_secs);
        }
        if self.debounce_ms.is_none() {
            self.debounce_ms = Some(d.debounce_ms);
        }
        if self.master_key_file.is_none() && !self.master_key_env {
            self.master_key_file = d.master_key_file.clone();
            self.master_key_env = d.master_key_env;
        }
        if self.kubeconfig.is_none() {
            self.kubeconfig = d.kubeconfig.clone();
        }
        if !self.auto_provision {
            self.auto_provision = d.auto_provision;
        }
        if !self.hole_punch {
            self.hole_punch = d.hole_punch;
        }
        self
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs.unwrap_or(DEFAULT_INTERVAL_SECS).max(1))
    }

    fn debounce(&self) -> Duration {
        Duration::from_millis(self.debounce_ms.unwrap_or(DEFAULT_DEBOUNCE_MS))
    }

    pub fn to_target_args(&self) -> TargetArgs {
        TargetArgs {
            sandbox: self.sandbox.clone(),
            workspace: self.workspace.clone(),
            transport: if self.relay.is_some() {
                TransportKind::P2p
            } else {
                TransportKind::Exec
            },
            relay: self.relay.clone(),
            relay_peer: None,
            master_key_env: self.master_key_env,
            master_key_file: self.master_key_file.clone(),
            root_remote: self.root_remote.clone(),
            kubeconfig: self.kubeconfig.clone(),
            hole_punch: self.hole_punch,
            agent_path: None,
            agent_bin: None,
        }
    }
}

pub fn load_config(path: &Path) -> io::Result<DaemonConfig> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("cannot read daemon config {}: {e}", path.display()),
        )
    })?;
    parse_config(&raw)
}

pub fn parse_config(raw: &str) -> io::Result<DaemonConfig> {
    let mut cfg: DaemonConfig = toml::from_str(raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("config.toml: {e}")))?;
    // Zero targets is a VALID state (deleting all syncs from the UI once
    // crash-looped the daemon, 2026-11-06): run with an empty set — the UI
    // serves the empty dashboard + attach wizard, and the config hot-reload
    // picks up targets the moment they're added. Only the one-shot CLI sync
    // needs a target to mean anything.
    // Normalize: inherit defaults, enforce unique names.
    let mut seen = std::collections::HashSet::new();
    for t in &mut cfg.targets {
        *t = t.clone().inherited(&cfg.defaults);
        *t = t.clone().resolve(&cfg.tunnel)?;
        if !seen.insert(t.name.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config.toml: duplicate target name {:?}", t.name),
            ));
        }
        if t.root.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config.toml: target {:?} has no root", t.name),
            ));
        }
    }
    Ok(cfg)
}

/// Sandbox-side health, probed once per pass via the exec fallback (p2p
/// targets with a kubeconfig): the running agent's version + tunnel specs
/// (from /proc) and the MCP convention compliance (stable `agents/current`
/// symlink + the opencode.json reference). Surfaced in the UI target card —
/// the sandbox OpenCode MCP panel failing silently was a blind spot (2026-11-07:
/// "should we add some status to the sync-agent UI?").
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct SandboxStatus {
    /// The qualified agent's binary version as seen in /proc ("0.1.3"),
    /// "unknown" when running but unparseable, "none" when not running.
    pub agent_version: String,
    /// Tunnel specs the running agent was spawned with, e.g. ["memory@7402"].
    pub tunnel: Vec<String>,
    /// The stable MCP binary path exists + executable
    /// (`/sandbox/.sync-agent/agents/current/sync-agent`).
    pub mcp_binary: bool,
    /// opencode.json exists and references the stable MCP binary path.
    pub mcp_config: bool,
    /// The target's remote root exists.
    pub root_ok: bool,
    /// M8: an `opencode serve` process for THIS root (cwd match) is alive
    /// with the target's serve port. Absent/false = the attach workflow
    /// would have nothing to talk to; the pass self-heals it.
    #[serde(default)]
    pub serve_ok: bool,
    /// M8: the port this target's serve listens on (deterministic per
    /// target — see [`serve_port`]). Set by the probe caller, not the pod.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_port: Option<u16>,
}

impl SandboxStatus {
    /// Drift = the running agent is not the built version, or its tunnel
    /// specs differ from what the target's config resolves to. Drift triggers
    /// a self-upgrading re-provision (kill stale → spawn current + args).
    pub fn drifted_from(&self, version: &str, wanted_tunnel: &[String]) -> bool {
        self.agent_version != version || self.tunnel != wanted_tunnel
    }
}

/// The deterministic per-target serve port (M8): stable across daemon
/// restarts, distinct per target, inside a private-ish high range so it
/// never collides with the sync agent's own listeners. Config
/// `serve_port` overrides.
///
/// M9: the DEFAULT derivation lives in the proto crate
/// ([`sync_proto::p2p::forward_serve_port`]) because the AGENT derives the
/// same port from its sandbox id — the p2p forward's dial target must agree
/// without a config channel.
pub(crate) fn serve_port(cfg: &TargetConfig, qualified: &str) -> u16 {
    if let Some(p) = cfg.serve_port {
        return p;
    }
    sync_proto::p2p::forward_serve_port(qualified)
}

/// The UI/API must never leave localhost: the daemon serves sync controls with
/// no authentication by design (plan §4: bind 127.0.0.1 only, tokens at 0600).
pub fn resolve_bind(cfg: &DaemonConfig, override_bind: Option<&str>) -> io::Result<String> {
    let bind = override_bind
        .map(|s| s.to_string())
        .or_else(|| cfg.server.bind.clone())
        .unwrap_or_else(|| DEFAULT_BIND.to_string());
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(&bind);
    let ip: IpAddr = host.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("server.bind {bind:?} is not host:port"),
        )
    })?;
    if !ip.is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "server.bind {bind:?} refused — the daemon UI/API binds LOOPBACK only \
                 (no auth on this surface); use 127.0.0.1:<port>"
            ),
        ));
    }
    Ok(bind)
}

// ---------------------------------------------------------------------------
// runtime state + events
// ---------------------------------------------------------------------------

/// Counts from a HELD first-run dry-run (M6 first-run dry-run UX): the
/// target has never synced, `first_run_dry_run` is on (the default), and no
/// archive exists yet — the pass ran plan-only and these are the counts it
/// WOULD have applied. "Sync now" confirms; the next pass runs for real.
#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct FirstPreview {
    /// Plan size, not applied counters: the held pass is a dry-run (applies
    /// nothing), so these carry what the CONFIRMED pass would apply/delete.
    pub applied: u64,
    pub deleted: u64,
    pub conflicts_left: Vec<String>,
    pub problems: Vec<String>,
    pub halted: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetSnapshot {
    pub name: String,
    pub root: String,
    pub sandbox: String,
    pub transport: String,
    /// The live connection path: "exec" | "direct" | "relayed" (p2p only —
    /// M4.5: the UI says whether the session rides the relay or a punched
    /// direct connection).
    pub path: String,
    /// idle | syncing | paused | error
    pub phase: String,
    pub paused: bool,
    pub last_pass_unix: u64,
    pub applied: u64,
    pub deleted: u64,
    pub failed: u64,
    pub conflicts_left: Vec<String>,
    pub conflicts_resolved: Vec<String>,
    pub honored: Vec<String>,
    pub problems: Vec<String>,
    pub archive_saved: bool,
    pub trust_base: bool,
    pub last_error: Option<String>,
    pub daemon_version: String,
    /// Sandbox-side health (p2p targets with a kubeconfig; None until the
    /// first probe, or after a re-provision invalidates it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_status: Option<SandboxStatus>,
    /// Held first-run preview (M6): present while a brand-new target's first
    /// pass is parked as a dry-run awaiting "Sync now".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_preview: Option<FirstPreview>,
    /// Live pass progress (connecting/scanning/staging/applying/verifying with
    /// file+byte counters) — cleared when the pass ends. Without it a
    /// 655-file/110MB first sync is two silent minutes in the card (2026-11-09:
    /// "looks dead while staging").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass_progress: Option<PassProgress>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub target: String,
    /// None = the target was REMOVED (the UI drops its card). A removal is
    /// the LAST event for that target: `TargetShared::update` suppresses
    /// snapshots once `stop` is set, so no stale snapshot can resurrect it.
    pub snapshot: Option<TargetSnapshot>,
}

enum Wake {
    /// fsnotify event (burst → debounced).
    Fs,
    /// API action: resume / sync-now / pause — the loop re-reads the flags.
    Manual,
}

pub struct TargetShared {
    pub cfg: std::sync::RwLock<TargetConfig>,
    pub state: Mutex<TargetSnapshot>,
    pub paused: AtomicBool,
    pub stop: AtomicBool,
    /// UI-side conflict resolutions for the NEXT pass (drained exactly once).
    pub pending_resolutions: Mutex<Vec<ConflictResolution>>,
    /// Loop wakeups: fsnotify events + API manual actions.
    wake_tx: Mutex<std::sync::mpsc::Sender<Wake>>,
    pub events: broadcast::Sender<Event>,
    /// One sync pass at a time per target (the loop blocking-locks it during a
    /// pass; the API's dry-run try-locks inside its blocking task → 409 busy).
    /// tokio::sync::Mutex so an async handler can hold it across `.await`.
    pub pass_lock: tokio::sync::Mutex<()>,
    /// Set after the first successful pass — auto-provisioning only fires for
    /// targets that have NEVER synced (established targets keep loud errors).
    pub ever_synced: AtomicBool,
    /// M6 first-run dry-run: set by the API's sync-now ("run the first real
    /// pass"); while false, a brand-new target's passes are held as previews.
    pub first_sync_confirmed: AtomicBool,
    /// Where config.toml lives (the config flip on auto-provision rewrites it).
    pub config_path: PathBuf,
    /// Auto-provision provenance ("auto-provisioned agent …"). Kept on the
    /// shared state and re-inserted into every snapshot update — the per-pass
    /// report replaces `honored`, and a one-pass note was too easy to miss.
    /// Cleared only by a daemon restart.
    pub provision_note: Mutex<Option<String>>,
    /// M8: latched when the sandbox turns out to have no `opencode` binary —
    /// serve respawn attempts stop for this daemon run (no respawn storm
    /// against a missing binary). Cleared only by a daemon restart.
    pub serve_missing: AtomicBool,
}

impl TargetShared {
    fn update(&self, f: impl FnOnce(&mut TargetSnapshot)) {
        // A stopped target is being (or has been) removed — stay silent so a
        // late pass-update can't resurrect a deleted card in the UI.
        if self.stop.load(Ordering::Relaxed) {
            return;
        }
        {
            let mut st = self.state.lock().unwrap();
            f(&mut st);
        }
        let snap = self.state.lock().unwrap().clone();
        let _ = self.events.send(Event {
            target: snap.name.clone(),
            snapshot: Some(snap),
        });
    }

    fn set_phase(&self, phase: &str) {
        // Dedupe: the loop-top reconciliation runs every iteration; sending an
        // identical snapshot each time flooded the SSE stream (UI freeze).
        {
            let st = self.state.lock().unwrap();
            if st.phase == phase {
                return;
            }
        }
        self.update(|s| s.phase = phase.to_string());
    }

    /// Drain UI-side resolutions — consumed exactly once per pass.
    pub fn drain_resolutions(&self) -> Vec<ConflictResolution> {
        std::mem::take(&mut self.pending_resolutions.lock().unwrap())
    }

    /// Put drained resolutions back — the pass that consumed them was HALTED
    /// (or ran plan-only), so the decision never took effect. Restored at the
    /// FRONT: the oldest operator decision applies first.
    pub fn restore_resolutions(&self, rs: Vec<ConflictResolution>) {
        if rs.is_empty() {
            return;
        }
        let mut pending = self.pending_resolutions.lock().unwrap();
        pending.splice(0..0, rs);
    }

    pub fn add_resolution(&self, r: ConflictResolution) {
        self.pending_resolutions.lock().unwrap().push(r);
    }

    /// Wake the loop (sync-now, resume, pause phase refresh, config change).
    pub fn wake(&self) {
        let _ = self.wake_tx.lock().unwrap().send(Wake::Manual);
    }

    pub fn snapshot(&self) -> TargetSnapshot {
        self.state.lock().unwrap().clone()
    }

    /// Immediate UI feedback for pause/resume: reflect the flag in the
    /// snapshot now (the loop reconciles phase at its next transition).
    pub fn touch_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
        self.update(|s| {
            s.paused = paused;
            s.phase = if paused {
                "paused".to_string()
            } else {
                "idle".to_string()
            };
        });
    }
}

fn initial_snapshot(cfg: &TargetConfig) -> TargetSnapshot {
    TargetSnapshot {
        first_preview: None,
        name: cfg.name.clone(),
        root: cfg.root.display().to_string(),
        sandbox: cfg.sandbox.clone(),
        transport: if cfg.relay.is_some() { "p2p" } else { "exec" }.to_string(),
        path: if cfg.relay.is_some() {
            "relayed"
        } else {
            "exec"
        }
        .to_string(),
        phase: "idle".to_string(),
        paused: false,
        last_pass_unix: 0,
        applied: 0,
        deleted: 0,
        failed: 0,
        conflicts_left: Vec::new(),
        conflicts_resolved: Vec::new(),
        honored: Vec::new(),
        problems: Vec::new(),
        archive_saved: false,
        trust_base: false,
        pass_progress: None,
        last_error: None,
        daemon_version: VERSION.to_string(),
        sandbox_status: None,
    }
}

fn mismatch_error(cfg: &TargetConfig, serving: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "agent serves root {serving:?} but target {:?} expects {:?} — restart the \
             sandbox agent with --root {:?} (or fix the target's root_remote)",
            cfg.name, cfg.root_remote, cfg.root_remote
        ),
    )
}

/// Auto-provision eligibility: a brand-new p2p target whose sandbox id is
/// still unqualified. Established targets and already-qualified ids keep the
/// loud root-mismatch error.
fn should_provision(cfg: &TargetConfig, ever_synced: bool) -> bool {
    cfg.auto_provision && cfg.relay.is_some() && !ever_synced && !cfg.sandbox.contains('+')
}

/// Bracket-class the first character of a guard literal. The provisioning
/// script runs as `bash -c <script>` — the script's OWN cmdline contains the
/// script text, patterns included, so a literal pattern would self-match and
/// exit "already-serving" without ever spawning (the 2026-11-06 e2e bug).
/// `[x]est` matches the runtime text `xest` but the script source — which
/// contains `[x]est` — does not contain `xest` at the pattern position.
/// Guard literals are slugs/absolute paths, so the first char is safe inside
/// a glob bracket class.
fn self_guard_safe(literal: &str) -> String {
    match literal.chars().next() {
        Some(c) => format!("[{}]", c) + &literal[c.len_utf8()..],
        None => literal.to_string(),
    }
}

/// The remote provisioning script (pure — testable): create the root, find the
/// installed agent binary (per-root base OR the shared `/sandbox` install —
/// the M5 rollout installs into the shared base), refuse on a missing master
/// key, SELF-UPGRADE a stale/arg-drifted agent (kill -> respawn with the
/// current binary + tunnel args — this is the M5 auto-rollout), skip when this
/// exact (id, root, version, args) is already served, else spawn detached.
///
/// The BIN lookup EXCLUDES the `agents/current` symlink: `sort -V` would
/// order "current" after every version ("c" > "0"), so spawned agents would
/// carry the symlink path in their cmdline and the version-drift check
/// (which matches `agents/<VERSION>/`) would loop kill+respawn forever.
///
/// Self-upgrade correctness (the 2026-11-06 duplicate-agents incident class):
/// the /proc scan COLLECTS across all matching PIDs before deciding — kill
/// every stale match, keep one current match; spawn only when nothing current
/// survived. Guard patterns are self_guard_safe'd (the script's own cmdline).
fn provision_script(cfg: &TargetConfig, qualified: &str) -> String {
    let root = cfg.root_remote.trim_end_matches('/');
    let base = Path::new(root)
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/sandbox".to_string());
    let relay = cfg.relay.clone().unwrap_or_default();
    // Guard patterns must not match the script's own cmdline — see
    // self_guard_safe. `$$` skip is belt-and-braces for the same reason.
    let qualified_pat = self_guard_safe(qualified);
    let relay_pat = self_guard_safe(&relay);
    let root_pat = self_guard_safe(root);
    let version_pat = self_guard_safe(&format!("agents/{VERSION}/sync-agent"));
    // Tunnel specs as UNQUOTED glob fragments (a QUOTED [m] is a literal
    // three-char string in a case pattern — the guard trick only works
    // unquoted; the M5 rollout's duplicate-spawn loop came from exactly this).
    let tunnel_frags: String = cfg
        .tunnel_args
        .iter()
        .map(|a| format!("*--tunnel\\ {}*", self_guard_safe(a)))
        .collect();
    format!(
        r#"set -e
mkdir -p '{root}' '{base}/.sync-agent' '/sandbox/.sync-agent'
BIN=$(ls -1 {base}/.sync-agent/agents/*/sync-agent /sandbox/.sync-agent/agents/*/sync-agent 2>/dev/null | grep -v '/agents/current/' | sort -V | tail -1)
[ -n "$BIN" ] || {{ echo "no agent binary under {base}/.sync-agent/agents or /sandbox/.sync-agent/agents — install one first"; exit 3; }}
KEY='{base}/.sync-agent/master.key'
[ -f "$KEY" ] || KEY='/sandbox/.sync-agent/master.key'
[ -f "$KEY" ] || {{ echo "no master key at {base}/.sync-agent/master.key or /sandbox/.sync-agent/master.key"; exit 4; }}
OK=0
STALE=0
for p in /proc/[0-9]*; do
  case "$p" in "/proc/$$") continue ;; esac
  c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null) || continue
  case "$c" in
    *--sandbox-id\ {qualified_pat}\ *)
      case "$c" in
        *{version_pat}\ p2p*{tunnel_frags}*) OK=$((OK + 1)) ;;
        *) kill "$(basename "$p")" 2>/dev/null || true; STALE=$((STALE + 1)) ;;
      esac ;;
    *sync-agent\ p2p\ --relay\ {relay_pat}*--root\ {root_pat}\ *) echo "root-already-served"; exit 0 ;;
  esac
done
[ "$STALE" != "0" ] && echo "killed $STALE stale agent(s); upgrading" && sleep 1
[ "$OK" != "0" ] && echo "already-serving" && exit 0
echo ready-to-spawn
"#
    )
}

/// The AGENT SPAWN alone — run through the MEDIATED exec path
/// ([`run_remote_mediatted`]) by [`provision_agent`]. On the 0.1.8-pre.33
/// sandbox runtime the network_broker egress-denies every process created via
/// `oc exec` (DNS AND TCP), so an oc-exec-spawned agent cannot reach the relay
/// (hit live 2026-11-11: "Failed to negotiate transport protocol(s)" on every
/// relay dial). A process created through the CLI's mediated exec inherits the
/// admission registration for life.
fn agent_spawn_script(cfg: &TargetConfig, qualified: &str) -> String {
    let root = cfg.root_remote.trim_end_matches('/');
    let base = Path::new(root)
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/sandbox".to_string());
    let relay = cfg.relay.clone().unwrap_or_default();
    let tunnel_args = cfg
        .tunnel_args
        .iter()
        .map(|a| format!(" --tunnel '{a}'"))
        .collect::<Vec<_>>()
        .join("");
    format!(
        r#"set -e
BIN=$(ls -1 {base}/.sync-agent/agents/*/sync-agent /sandbox/.sync-agent/agents/*/sync-agent 2>/dev/null | grep -v '/agents/current/' | sort -V | tail -1)
[ -n "$BIN" ] || {{ echo "no agent binary to spawn"; exit 3; }}
KEY='{base}/.sync-agent/master.key'
[ -f "$KEY" ] || KEY='/sandbox/.sync-agent/master.key'
[ -f "$KEY" ] || {{ echo "no master key"; exit 4; }}
nohup "$BIN" p2p --relay '{relay}' --sandbox-id '{qualified}'   --master-key-file "$KEY" --root '{root}'{tunnel_args}   >> {base}/.sync-agent/p2p.log 2>&1 < /dev/null &
sleep 5
echo spawned
"#
    )
}

/// The sandbox health probe (pure — testable): key=value lines describing the
/// qualified agent (version + tunnel specs, from /proc) and the MCP
/// convention compliance (stable `agents/current` symlink + the opencode.json
/// reference). Parsed by [`parse_sandbox_status`].
fn sandbox_probe_script(cfg: &TargetConfig, qualified: &str) -> String {
    let root = cfg.root_remote.trim_end_matches('/');
    let qualified_pat = self_guard_safe(qualified);
    let serve_port_hex = format!("{:04X}", serve_port(cfg, qualified));
    format!(
        r#"FOUND=0
for p in /proc/[0-9]*; do
  case "$p" in "/proc/$$") continue ;; esac
  c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null) || continue
  case "$c" in
    *--sandbox-id\ {qualified_pat}\ *)
      FOUND=1
      V=$(echo "$c" | sed -n 's|.*agents/\([0-9][0-9.]*\)/sync-agent.*|\1|p' | head -1)
      echo "agent_version=${{V:-unknown}}"
      echo "$c" | grep -oE -e '--tunnel [^ ]*' | sed 's/^--tunnel //' | while IFS= read -r t; do echo "tunnel=$t"; done
      ;;
  esac
done
[ "$FOUND" = "1" ] || echo "agent_version=none"
[ -x /sandbox/.sync-agent/agents/current/sync-agent ] && echo "mcp_binary=1" || echo "mcp_binary=0"
grep -q 'agents/current/sync-agent' /sandbox/.config/opencode/opencode.json 2>/dev/null && echo "mcp_config=1" || echo "mcp_config=0"
[ -d '{root}' ] && echo "root=1" || echo "root=0"
# M8: is our serve port LISTENING inside the pod? NOTE: /proc/PID/cwd is
# unreadable here (the bun runtime sets dumpable=0 — permission denied even
# same-uid), so cwd-based detection is impossible; the port allocation is
# daemon-owned (deterministic per target), which makes the socket the truth.
SERVE=0
[ -r /proc/net/tcp ] && awk '$2 ~ /:{serve_port_hex}$/ && $4 == "0A" {{ s=1 }} END {{ exit s ? 0 : 1 }}' /proc/net/tcp >/dev/null 2>&1 && SERVE=1
echo "serve_ok=$SERVE"
"#,
    )
}

/// Parse [`sandbox_probe_script`]'s output. Unknown/absent keys default
/// honestly (a partial probe must never read as "everything healthy").
fn parse_sandbox_status(out: &str) -> SandboxStatus {
    let mut status = SandboxStatus {
        agent_version: "none".to_string(),
        ..Default::default()
    };
    for line in out.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "agent_version" => status.agent_version = v.trim().to_string(),
            "tunnel" => {
                let t = v.trim();
                if !t.is_empty() {
                    status.tunnel.push(t.to_string())
                }
            }
            "mcp_binary" => status.mcp_binary = v.trim() == "1",
            "mcp_config" => status.mcp_config = v.trim() == "1",
            "root" => status.root_ok = v.trim() == "1",
            "serve_ok" => status.serve_ok = v.trim() == "1",
            _ => {}
        }
    }
    status
}

/// Probe the sandbox (exec fallback) and parse the result. Errors are the
/// caller's to log — a failed probe must never fail the sync pass.
fn probe_sandbox(cfg: &TargetConfig, qualified: &str, oc: &str) -> io::Result<SandboxStatus> {
    let out = run_remote(cfg, oc, &sandbox_probe_script(cfg, qualified))?;
    Ok(parse_sandbox_status(&out))
}

/// Run one remote command via `oc exec` (same argv shape as the exec
/// Run one remote command via `oc exec` (same argv shape as the exec
/// transport, minus the session plumbing — this is a one-shot command).
///
/// The pod resolves from the sandbox CR — the part BEFORE any `+` qualifier
/// (`sync-oc+plan` is an AGENT identity inside the `default--sync-oc` pod).
pub(crate) fn run_remote(cfg: &TargetConfig, oc: &str, script: &str) -> io::Result<String> {
    let base_sandbox = cfg.sandbox.split('+').next().unwrap_or(&cfg.sandbox);
    let workspace = cfg.workspace.as_deref().unwrap_or("default");
    let resolved =
        crate::resolver::resolve(base_sandbox, workspace, cfg.kubeconfig.as_deref(), oc)?;
    let mut cmd = std::process::Command::new(oc);
    if let Some(kc) = &cfg.kubeconfig {
        cmd.arg("--kubeconfig").arg(kc);
    }
    cmd.args([
        "exec",
        "-n",
        &resolved.namespace,
        &resolved.pod,
        "--",
        "bash",
        "-c",
        script,
    ]);
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "remote provisioning failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Run `script` inside the sandbox through the MEDIATED exec path
/// (`openshell sandbox exec`) instead of `oc exec`. On the 0.1.8-pre.33
/// sandbox runtime the network_broker only relays DNS for sockets created
/// under its syscall mediation — processes spawned via `oc exec` sit outside
/// that regime, so an `opencode serve` spawned this way cannot resolve the
/// model endpoint (hit live 2026-11-11: inference EAI_AGAIN while every
/// tunnel/MCP path was green). Processes created through the CLI's exec are
/// mediated, so their DNS works. Needs the openshell CLI + a live gateway
/// session (falls back to `run_remote` at the call sites on any error).
pub(crate) fn run_remote_mediatted(cfg: &TargetConfig, script: &str) -> io::Result<String> {
    let base_sandbox = cfg.sandbox.split('+').next().unwrap_or(&cfg.sandbox);
    let gateway = std::env::var("SYNC_AGENT_GATEWAY").unwrap_or_else(|_| "openshift".to_string());
    let out = std::process::Command::new("openshell")
        .args([
            "sandbox",
            "exec",
            base_sandbox,
            "-g",
            &gateway,
            "--",
            "sh",
            "-c",
            script,
        ])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "mediated exec failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Serve remote exec with the mediated path preferred: `run_remote_mediatted`
/// first (DNS-capable on the pre.33 runtime), `run_remote` (oc exec) as the
/// fallback when the openshell CLI or the gateway session is unavailable.
pub(crate) fn serve_remote(cfg: &TargetConfig, oc: &str, script: &str) -> io::Result<String> {
    match run_remote_mediatted(cfg, script) {
        Ok(out) => Ok(out),
        Err(e) => {
            eprintln!("daemon: mediated exec unavailable ({e}) — falling back to oc exec");
            run_remote(cfg, oc, script)
        }
    }
}

/// The M8 serve (re)spawn script (pure — testable): ensures the target's
/// serve port is LISTENING inside the sandbox — the attach workflow's server
/// side. Idempotent:
/// - port already listening         → "serve-already"
/// - opencode missing               → "serve-missing-opencode" (exit 0; the
///   caller latches this and stops retrying — never a respawn loop)
/// - otherwise                       → spawn (nohup, like the agent) →
///   "serve-spawned"
///
/// NOTE: there is deliberately NO /proc/PID/cwd check — the bun runtime sets
/// dumpable=0 (cwd unreadable even same-uid); the port allocation is
/// daemon-owned (deterministic per target), so the socket IS the truth.
fn serve_spawn_script(cfg: &TargetConfig, port: u16) -> String {
    let root = cfg.root_remote.trim_end_matches('/');
    let base = Path::new(root)
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "/sandbox".to_string());
    // The serve is SANDBOX-level (its port derives from the qualified sandbox
    // id), and the attach workflow should land the TUI in the sandbox ROOT —
    // not in the target's sync root (Mike: "i want to just land in /sandbox").
    // The first path component of root_remote IS the sandbox root.
    let sandbox_root = root
        .split('/')
        .take(2)
        .collect::<Vec<_>>()
        .join("/");
    let port_hex = format!("{:04X}", port);
    format!(
        r#"set -e
command -v opencode >/dev/null 2>&1 || {{ echo "serve-missing-opencode"; exit 0; }}
if awk '$2 ~ /:{port_hex}$/ && $4 == "0A" {{ s=1 }} END {{ exit s ? 0 : 1 }}' /proc/net/tcp >/dev/null 2>&1; then
  echo "serve-already"; exit 0
fi
cd '{sandbox_root}'
nohup opencode serve --port {port} >> {base}/.sync-agent/serve.log 2>&1 < /dev/null &
sleep 2
echo serve-spawned
"#
    )
}

/// Restart the sandbox's daemon-owned serve (API route `serve-restart`): kill
/// the serve processes for THIS port (SIGTERM, escalating to SIGKILL — the bun
/// runtime ignores TERM live), wait for the socket to free, then re-run the
/// spawn body (whose port gate is the safety net against a non-freed socket).
/// Self-match-safe: the /proc scan pattern is bracketed and skips $$.
pub(crate) fn serve_restart_script(cfg: &TargetConfig, port: u16) -> String {
    let spawn = serve_spawn_script(cfg, port);
    let port_hex = format!("{:04X}", port);
    format!(
        r#"set -e
PIDS=""
for p in /proc/[0-9]*; do
  case "$p" in "/proc/$$") continue ;; esac
  c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null) || continue
  case "$c" in
    *"opencode [s]erve --port {port}"*) PIDS="$PIDS ${{p#/proc/}}" ;;
  esac
done
if [ -n "$PIDS" ]; then
  for pid in $PIDS; do kill -TERM "$pid" 2>/dev/null || true; done
  i=0
  while [ "$i" -lt 8 ]; do
    if ! awk '$2 ~ /:{port_hex}$/ && $4 == "0A" {{ s=1 }} END {{ exit s ? 0 : 1 }}' /proc/net/tcp >/dev/null 2>&1; then break; fi
    i=$((i+1))
    if [ "$i" -eq 4 ]; then for pid in $PIDS; do kill -KILL "$pid" 2>/dev/null || true; done; fi
    sleep 1
  done
  if awk '$2 ~ /:{port_hex}$/ && $4 == "0A" {{ s=1 }} END {{ exit s ? 0 : 1 }}' /proc/net/tcp >/dev/null 2>&1; then
    echo "serve-restart-busy (port {port} never freed)"; exit 0
  fi
  echo "serve-restart: killed:$PIDS"
else
  echo "serve-restart: nothing running on {port}"
fi
{spawn}
"#
    )
}

/// Qualify the target's sandbox id in config.toml (persisted — survives
/// restarts; the hot-reload watcher sees a no-diff since we also patch memory).
fn qualify_target_in_config(config_path: &Path, name: &str, qualified: &str) -> io::Result<()> {
    let raw = std::fs::read_to_string(config_path)?;
    let mut cfg: DaemonConfig = toml::from_str(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("config.toml: {e}")))?;
    let t = cfg
        .targets
        .iter_mut()
        .find(|t| t.name == name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("target {name:?}")))?;
    if t.sandbox == qualified {
        return Ok(());
    }
    t.sandbox = qualified.to_string();
    let out = toml::to_string_pretty(&cfg).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("config serialize: {e}"))
    })?;
    std::fs::write(config_path, out)?;
    Ok(())
}

/// Remove a target from config.toml (the DELETE API). The local directory and
/// the sandbox-side files are untouched — this only detaches the sync. The
/// hot-reload watcher applies the removal (stops the loop, drops the state).
pub(crate) fn remove_target_in_config(config_path: &Path, name: &str) -> io::Result<bool> {
    let raw = std::fs::read_to_string(config_path)?;
    let mut cfg: DaemonConfig = toml::from_str(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("config.toml: {e}")))?;
    let before = cfg.targets.len();
    cfg.targets.retain(|t| t.name != name);
    if cfg.targets.len() == before {
        return Ok(false);
    }
    let out = toml::to_string_pretty(&cfg).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("config serialize: {e}"))
    })?;
    std::fs::write(config_path, out)?;
    Ok(true)
}

/// Start a per-root agent for this target (qualified id) and qualify its
/// config. Returns the qualified id for the honored entry.
/// The qualified agent id for a target: `sandbox+name` unless the sandbox is
/// already qualified (an established target whose config was flipped by a
/// previous provision — re-qualifying would produce `sync-oc+plan+plan`).
pub(crate) fn qualified_sandbox(cfg: &TargetConfig) -> String {
    if cfg.sandbox.contains('+') {
        cfg.sandbox.clone()
    } else {
        format!("{}+{}", cfg.sandbox, cfg.name)
    }
}

fn provision_agent(shared: &TargetShared, oc: &str) -> io::Result<String> {
    let cfg = shared.cfg.read().unwrap().clone();
    let qualified = qualified_sandbox(&cfg);
    let out = run_remote(&cfg, oc, &provision_script(&cfg, &qualified))?;
    if cfg.sandbox != qualified {
        qualify_target_in_config(&shared.config_path, &cfg.name, &qualified)?;
    }
    {
        let mut c = shared.cfg.write().unwrap();
        c.sandbox = qualified.clone();
    }
    // The SPAWN goes through the mediated exec path: on the 0.1.8-pre.33
    // sandbox runtime an oc-exec-spawned agent is egress-denied by the
    // network_broker (relay dials fail "Failed to negotiate"). The staged
    // check + kill-stale ran via oc exec above; only the long-lived spawn
    // needs the runtime's admission regime.
    let mut detail = format!("{qualified} ({out})");
    if !out.contains("already-serving") && !out.contains("root-already-served") {
        match run_remote_mediatted(&cfg, &agent_spawn_script(&cfg, &qualified)) {
            Ok(spawn_out) => detail = format!("{qualified} ({out} → {spawn_out}) [mediated]"),
            Err(e) => {
                eprintln!(
                    "daemon: mediated agent spawn failed ({e}) — falling back to oc exec \
                     (the agent will run but its egress is denied by the sandbox runtime)"
                );
                let spawn_out = run_remote(&cfg, oc, &agent_spawn_script(&cfg, &qualified))?;
                detail = format!("{qualified} ({out} → {spawn_out}) [oc-exec fallback]");
            }
        }
    }
    Ok(detail)
}

/// Global per-pair engine state dir (2026-11-06: "move them to a global
/// top level — else we will pollute a lot of folders"). The archive + scan
/// caches for the pair `(sandbox, root_remote)` live under
/// `~/.local/state/sync-agent-pvc/pairs/<pair-hash>/` instead of inside the
/// synced root — synced git repos stay clean, and the state survives casual
/// root cleanup. Keyed by the pair (not the target name) so renames
/// keep their base; re-points get a fresh dir exactly like they get a fresh
/// pair key.
pub(crate) fn pair_state_dir(sandbox: &str, root_remote: &str) -> PathBuf {
    let hash = blake3::hash(format!("sync-agent-pvc/pair/{sandbox}:{root_remote}").as_bytes());
    let hex: String = hash.to_hex().to_string()[..16].to_string();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home)
        .join(".local/state/sync-agent-pvc/pairs")
        .join(hex)
}

/// Move a pair's engine state from the legacy in-root location
/// (`<root>/.sync-agent/`) to the global dir. Preserves the base — no
/// no-base re-reconcile after the upgrade. Best-effort: if anything fails
/// the pass simply runs without a base (safe for converged trees).
pub(crate) fn migrate_legacy_state(root_a: &Path, state_dir: &Path) {
    let legacy = root_a.join(".sync-agent");
    if !legacy.is_dir() || legacy == state_dir {
        return;
    }
    if std::fs::create_dir_all(state_dir).is_err() {
        return;
    }
    for name in [
        "archive.bin",
        "archive.bin.bak",
        "cache-a.bin",
        "cache-b.bin",
    ] {
        let from = legacy.join(name);
        if !from.exists() {
            continue;
        }
        let to = state_dir.join(name);
        // Rename first (same fs → atomic); copy+delete across filesystems.
        if std::fs::rename(&from, &to).is_err() && std::fs::copy(&from, &to).is_ok() {
            let _ = std::fs::remove_file(&from);
        }
    }
    // The legacy dir is ours (scanner-skipped, engine-internal) — whatever
    // remains (staging leftovers, old conflict copies) is stale.
    let _ = std::fs::remove_dir_all(&legacy);
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One sync pass against the target's sandbox, REUSING the persistent session
/// (one relayed circuit per target — fresh dials per pass exhausted the
/// relay's resource limits within minutes). Dials on first use; any error
/// drops the session so the next pass reconnects. Never panics, never exits
/// the loop: errors land in the snapshot (`phase: error`, `last_error`).
fn run_pass(
    shared: &Arc<TargetShared>,
    oc: &str,
    session_slot: &mut Option<sync_proto::session::Session<Box<dyn crate::transport::ReadWrite>>>,
) -> io::Result<()> {
    // Held for the whole pass: the API's dry-run try-locks the same mutex and
    // reports 409 instead of racing the archive. (std thread → blocking_lock.)
    let _pass = shared.pass_lock.blocking_lock();
    // M6 pass tracing: one timing + outcome line per pass, the observable the
    // journal greps for (stderr only — exec transports own stdout).
    let pass_started = std::time::Instant::now();
    shared.update(|s| {
        s.phase = "syncing".to_string();
        s.last_error = None;
    });
    // Live progress sink → the target snapshot. Throttled: ≥400ms between
    // ticks, stage flips always shown — the SSE channel hates floods (the
    // 2026-11-06 UI freeze), but a silent 2-minute staging pass looks dead.
    let progress: Option<ProgressSink> = {
        let shared = shared.clone();
        let last = Mutex::new((Instant::now() - Duration::from_secs(1), String::new()));
        Some(ProgressSink(Arc::new(move |p: PassProgress| {
            let mut guard = last.lock().unwrap();
            let (t, stage) = &mut *guard;
            if *stage == p.stage && t.elapsed() < Duration::from_millis(400) {
                return;
            }
            *t = Instant::now();
            *stage = p.stage.clone();
            shared.update(|s| s.pass_progress = Some(p.clone()));
        })))
    };
    // Cold dial? Tell the UI — a first p2p connect can take 15-20s (relay
    // reservation + hole-punch). A warm session skips this (no flash every
    // interval pass).
    if session_slot.is_none() {
        report_progress(&progress, "connecting", 0, 0, 0, 0);
    }
    let cfg = shared.cfg.read().unwrap().clone();
    // M6 first-run dry-run gate (evaluated up front; the archive-existence
    // half is re-checked inside the closure where the pair state dir is
    // known — a daemon restart must NOT re-hold an already-synced target).
    let preview_gate_armed = cfg.first_run_dry_run.unwrap_or(true)
        && !shared.ever_synced.load(Ordering::Relaxed)
        && !shared.first_sync_confirmed.load(Ordering::Relaxed);
    // The archive half of the gate lives here (not inside the pass): a daemon
    // restart must NOT re-hold an already-synced target — an existing archive
    // means the target synced before, preview or not.
    let pair_state = pair_state_dir(&cfg.sandbox, &cfg.root_remote);
    let preview_pass =
        preview_gate_armed && !pair_state.join(sync_core::archive::ARCHIVE_FILE).exists();
    let result = (|| -> io::Result<RemoteReport> {
        // M5: sandbox health probe + SELF-UPGRADING re-provision (p2p targets
        // with a kubeconfig). The probe never fails the pass; drift (an old
        // binary or missing tunnel args — e.g. after a version bump or a
        // tunnel rollout) kills the stale agent and respawns it with the
        // current binary + tunnel args, so this pass's dial picks it up. The
        // auto_provision kill switch governs the upgrade too.
        if cfg.relay.is_some() && cfg.kubeconfig.is_some() {
            let probe_qualified = qualified_sandbox(&cfg);
            match probe_sandbox(&cfg, &probe_qualified, oc) {
                Ok(mut status) => {
                    let drift = status.drifted_from(VERSION, &cfg.tunnel_args);
                    // M8: the serve port is daemon-derived — stamp it so the
                    // API/UI/wrapper all read one source of truth.
                    status.serve_port = Some(serve_port(&cfg, &probe_qualified));
                    shared.update(|s| s.sandbox_status = Some(status.clone()));
                    if drift {
                        if cfg.auto_provision {
                            eprintln!(
                                "daemon: sandbox agent drift on {probe_qualified} (running {} wanted {VERSION}, tunnel {:?} wanted {:?}) — re-provisioning",
                                status.agent_version, status.tunnel, cfg.tunnel_args
                            );
                            provision_agent(shared, oc)?;
                            // The probe no longer describes the (new) agent.
                            shared.update(|s| s.sandbox_status = None);
                        } else {
                            eprintln!(
                                "daemon: sandbox agent drift on {probe_qualified} (running {} wanted {VERSION}) but auto_provision is off — leaving as-is",
                                status.agent_version
                            );
                        }
                    }
                    // M8: opencode serve self-heal (the attach workflow's
                    // server side). Same never-fail-the-pass rule; respawn
                    // is serve-scoped (never touches the agent). A sandbox
                    // without opencode latches off for this daemon run —
                    // no respawn storm against a missing binary.
                    if cfg.serve.unwrap_or(true) && !status.serve_ok {
                        let port = serve_port(&cfg, &probe_qualified);
                        match serve_remote(&cfg, oc, &serve_spawn_script(&cfg, port)) {
                            Ok(out) => {
                                let out = out.trim();
                                if out == "serve-missing-opencode" {
                                    if !shared.serve_missing.swap(true, Ordering::Relaxed) {
                                        eprintln!(
                                            "daemon: opencode not found in sandbox {probe_qualified} — serve disabled until daemon restart"
                                        );
                                    }
                                } else if out != "serve-already" {
                                    eprintln!("daemon: serve on {probe_qualified}: {out} (port {port})");
                                }
                            }
                            Err(e) => {
                                eprintln!("daemon: serve spawn failed (pass continues): {e}")
                            }
                        }
                    }
                }
                Err(e) => eprintln!("daemon: sandbox probe failed (pass continues): {e}"),
            }
        }
        if session_slot.is_none() {
            // Fail fast on a missing/rotated master key rather than erroring deep.
            if cfg.relay.is_some() {
                let targs = cfg.to_target_args();
                load_master_key(&targs)?;
            }
            let mut transport = build_transport(&cfg.to_target_args(), oc)?;
            let (session, path) = open_session(&mut transport)?;
            shared.update(|s| s.path = path.to_string()); // Root-match rail: the agent serves ONE root (bound at its --root);
                                                          // a mismatch would sync paths into the wrong layout silently.
            let hello = session.hello().clone();
            if hello.root != cfg.root_remote {
                drop(session);
                // Brand-new p2p target pointing at a root nobody serves?
                // Provision the per-root agent ourselves (qualified id via the
                // exec fallback), flip the config, re-dial. Established targets
                // and already-qualified ids keep the loud error.
                if !should_provision(&cfg, shared.ever_synced.load(Ordering::Relaxed)) {
                    return Err(mismatch_error(&cfg, &hello.root));
                }
                let qualified = provision_agent(shared, oc)?;
                // Re-read the (now qualified) config; wait for the relay
                // reservation the spawned agent is establishing.
                let cfg = shared.cfg.read().unwrap().clone();
                let mut attempts = 0;
                loop {
                    std::thread::sleep(Duration::from_secs(4));
                    attempts += 1;
                    let mut transport = match build_transport(&cfg.to_target_args(), oc) {
                        Ok(t) => t,
                        Err(e) if attempts < 3 => {
                            eprintln!("daemon: provision dial retry {attempts}: {e}");
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    match open_session(&mut transport) {
                        Ok((s2, path)) => {
                            let h2 = s2.hello().clone();
                            if h2.root != cfg.root_remote {
                                if attempts < 3 {
                                    continue;
                                }
                                return Err(mismatch_error(&cfg, &h2.root));
                            }
                            *shared.provision_note.lock().unwrap() = Some(format!(
                                "auto-provisioned agent {qualified} for {}",
                                cfg.root_remote
                            ));
                            shared.update(|s| s.path = path.to_string());
                            *session_slot = Some(s2);
                            break;
                        }
                        Err(e) if attempts < 3 => {
                            eprintln!("daemon: provision dial retry {attempts}: {e}");
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
            } else {
                *session_slot = Some(session);
            }
        }
        let session = session_slot.as_mut().unwrap();
        let state_dir = pair_state_dir(&cfg.sandbox, &cfg.root_remote);
        migrate_legacy_state(&cfg.root, &state_dir);
        // M6 first-run dry-run: a brand-new target (never synced, no archive
        // yet, not confirmed via sync-now) runs plan-only and the result is
        // HELD in the snapshot as `first_preview` — the UI shows what the
        // first real pass WOULD do and requires an explicit "Sync now". The
        // plan.md 0-byte incident shipped inside a first pass; nothing
        // propagates before a human has seen the plan. ever_synced stays
        // false until the confirmed real pass. (preview_pass is computed by
        // the caller — see preview_gate_armed above.)
        let rcfg = RemoteConfig {
            force: false,
            dry_run: preview_pass,
            extra_ignores: cfg.excludes.clone(),
            limits: Default::default(),
            // Pair key includes the ROOT: re-pointing a target's root_remote
            // (or two targets sharing a sandbox at different subpaths) yields a
            // FRESH archive — safe no-base first sync, never a stale base.
            remote_endpoint: format!("{}:{}", cfg.sandbox, cfg.root_remote),
            local_resolutions: shared.drain_resolutions(),
            state_dir: Some(state_dir),
            progress,
        };
        let result = sync_local_to_remote(&cfg.root, session, &rcfg);
        if result.is_err() {
            // The session is suspect (framing/state after a mid-pass failure):
            // drop it — the next pass reconnects cleanly.
            *session_slot = None;
        }
        result
    })();
    match result {
        Ok(report) => {
            if preview_pass {
                let preview = FirstPreview {
                    // The dry-run applied NOTHING — report.applied/deleted are
                    // always 0 on this path. The UI's "would apply N file(s)"
                    // must show the PLAN size: the driver populates planned_*
                    // before its dry-run return (2026-11-09: a 30k-file repo
                    // previewed as "would apply 0", reading like a no-op).
                    applied: report.planned_materializes as u64,
                    deleted: report.planned_removes as u64,
                    conflicts_left: report
                        .conflicts_left
                        .iter()
                        .map(|p| p.as_str().to_string())
                        .collect(),
                    problems: report
                        .problems
                        .iter()
                        .map(|(p, m)| format!("{}: {m}", p.as_str()))
                        .collect(),
                    halted: report.halted.as_ref().map(|h| format!("{h:?}")),
                };
                eprintln!(
                    "daemon: {} first-run dry-run HELD — would apply {} / delete {} / {} conflict(s); sync-now to confirm",
                    cfg.name, preview.applied, preview.deleted, preview.conflicts_left.len()
                );
                shared.update(|s| {
                    s.phase = "idle".to_string();
                    s.last_pass_unix = now_unix();
                    s.first_preview = Some(preview);
                    s.pass_progress = None;
                    s.paused = shared.paused.load(Ordering::Relaxed);
                });
                // Plan-only pass: the drained resolutions never took effect —
                // restore them so the confirmed pass applies the decision.
                shared.restore_resolutions(report.restored_resolutions.clone());
                return Ok(());
            }
            shared.update(|s| {
                s.phase = "idle".to_string();
                s.last_pass_unix = now_unix();
                s.applied = report.applied;
                s.deleted = report.deleted;
                s.failed = report.failed;
                s.conflicts_left = report
                    .conflicts_left
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect();
                s.conflicts_resolved = report
                    .conflicts_resolved
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect();
                s.honored = report.honored.clone();
                s.problems = report
                    .problems
                    .iter()
                    .map(|(p, m)| format!("{}: {m}", p.as_str()))
                    .collect();
                s.archive_saved = report.archive_saved;
                s.trust_base = report.trust_base;
                // The confirmed real pass clears the held preview.
                s.first_preview = None;
                s.pass_progress = None;
                s.paused = shared.paused.load(Ordering::Relaxed);
                if let Some(note) = shared.provision_note.lock().unwrap().as_deref() {
                    s.honored.insert(0, note.to_string());
                }
            });
            // A halted pass consumed the operator's resolutions into a plan
            // that mutated nothing — restore them so the decision survives
            // until a healthy pass can honor it (2026-11-08 lesson).
            shared.restore_resolutions(report.restored_resolutions.clone());
            shared.ever_synced.store(true, Ordering::Relaxed);
            // M6 pass-tracing line. Take the state lock ONCE into locals —
            // two lock() calls inside one eprintln! statement would
            // self-deadlock (the first temporary guard is still alive when
            // the second expression runs; std Mutex is not reentrant).
            let (conflicts_left, link_path) = {
                let s = shared.state.lock().unwrap();
                (s.conflicts_left.len(), s.path.clone())
            };
            if let Some(h) = &report.halted {
                // Not "pass ok" — a halted pass mutated nothing and updated no
                // state; the UI problems list carries the reason.
                eprintln!(
                    "daemon: {} pass HALTED ({h}) in {:.1?} — applied {} deleted {} failed {} conflict(s) left {} (path {}, archive held)",
                    cfg.name,
                    pass_started.elapsed(),
                    report.applied,
                    report.deleted,
                    report.failed,
                    conflicts_left,
                    link_path,
                );
            } else {
                eprintln!(
                    "daemon: {} pass ok in {:.1?} — applied {} deleted {} failed {} conflict(s) left {} (path {}, archive {})",
                    cfg.name,
                    pass_started.elapsed(),
                    report.applied,
                    report.deleted,
                    report.failed,
                    conflicts_left,
                    link_path,
                    if report.archive_saved { "advanced" } else { "held" },
                );
            }
            Ok(())
        }
        Err(e) => {
            shared.update(|s| {
                s.phase = "error".to_string();
                s.last_pass_unix = now_unix();
                s.last_error = Some(e.to_string());
                s.pass_progress = None;
                s.paused = shared.paused.load(Ordering::Relaxed);
            });
            Err(e)
        }
    }
}

/// The per-target loop: fsnotify events (debounced) and the interval safety
/// re-scan trigger passes; pause halts scanning entirely; stop exits.
fn target_loop(shared: Arc<TargetShared>, oc: String) {
    let (interval, debounce) = {
        let cfg = shared.cfg.read().unwrap();
        (cfg.interval(), cfg.debounce())
    };
    let (wake_tx, wake_rx) = std::sync::mpsc::channel::<Wake>();
    *shared.wake_tx.lock().unwrap() = wake_tx.clone();

    // fsnotify → Wake::Fs. The watcher lives in this thread's scope; a missing
    // watch degrades to interval-only scans (logged once).
    let mut watcher =
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            // ONLY content changes wake the pass loop. notify 8 watches IN_OPEN,
            // and the scanner's own tree walk OPENS every directory — waking on
            // read events made every scan queue the next one: a self-perpetuating
            // ~6s scan oscillator on every target (interval never honored, phase
            // stuck "syncing" ~90% of the time, the UI's Sync-now button disabled
            // in that window — 2026-11-09). Access events are reads, never
            // changes; everything else (create/modify/remove/rename/attrs) wakes.
            if let Ok(ev) = res {
                if matches!(ev.kind, notify::EventKind::Access(_)) {
                    return;
                }
                let _ = wake_tx.send(Wake::Fs);
            }
        }) {
            Ok(w) => Some(w),
            Err(e) => {
                eprintln!("daemon: fsnotify unavailable ({e}) — interval-only scans");
                None
            }
        };
    if let Some(w) = watcher.as_mut() {
        let root = shared.cfg.read().unwrap().root.clone();
        if let Err(e) = w.watch(&root, RecursiveMode::Recursive) {
            eprintln!(
                "daemon: cannot watch {}: {e} — interval-only scans",
                root.display()
            );
        }
    }

    let mut session_slot: Option<
        sync_proto::session::Session<Box<dyn crate::transport::ReadWrite>>,
    > = None;
    let mut consecutive_failures: u32 = 0;
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            if let Some(mut s) = session_slot.take() {
                shutdown_quietly(&mut s);
            }
            return;
        }
        if shared.paused.load(Ordering::Relaxed) {
            shared.set_phase("paused");
        }
        // Wait: manual wake, fs event, or interval tick — with backoff while
        // dial failures repeat (the sandbox may be down; don't hammer it).
        // The +1 FLOOR keeps the multiplier ≥1. (The 2026-11-06 "UI freeze"
        // back-to-back scans were NOT a 0-multiplier — the real cause was the
        // scanner's own IN_OPEN events re-waking the loop, fixed in the
        // watcher closure above; the floor stays as dial-failure backoff.)
        let wait = interval.saturating_mul(1 + consecutive_failures.min(4));
        match wake_rx.recv_timeout(wait) {
            Ok(Wake::Fs) | Ok(Wake::Manual) | Err(_) => {}
        }
        if shared.stop.load(Ordering::Relaxed) {
            if let Some(mut s) = session_slot.take() {
                shutdown_quietly(&mut s);
            }
            return;
        }
        if shared.paused.load(Ordering::Relaxed) {
            // No scan while paused (M3.5 contract: nothing scanned, nothing
            // mutated) — drop any queued fs events.
            while wake_rx.try_recv().is_ok() {}
            continue;
        }
        // Debounce: let an fs-event burst settle before scanning, then drop
        // the queued events — the pass re-scans fully anyway.
        let deadline = Instant::now() + debounce;
        while let Ok(more) =
            wake_rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            let _ = more;
        }
        match run_pass(&shared, &oc, &mut session_slot) {
            Ok(()) => consecutive_failures = 0,
            Err(_) => {
                consecutive_failures += 1;
            }
        }
    }
}

/// Spawn one target's loop thread (used by startup and config hot-reload).
pub fn spawn_target(
    cfg: TargetConfig,
    oc: &str,
    events: broadcast::Sender<Event>,
    config_path: PathBuf,
) -> Arc<TargetShared> {
    let shared = Arc::new(TargetShared {
        cfg: std::sync::RwLock::new(cfg.clone()),
        state: Mutex::new(initial_snapshot(&cfg)),
        paused: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        pending_resolutions: Mutex::new(Vec::new()),
        wake_tx: Mutex::new({
            let (tx, _rx) = std::sync::mpsc::channel();
            tx // replaced by the loop thread immediately
        }),
        events: events.clone(),
        pass_lock: tokio::sync::Mutex::new(()),
        ever_synced: AtomicBool::new(false),
        first_sync_confirmed: AtomicBool::new(false),
        config_path,
        provision_note: Mutex::new(None),
            serve_missing: AtomicBool::new(false),
    });
    {
        let snap = shared.state.lock().unwrap().clone();
        let _ = events.send(Event {
            target: snap.name.clone(),
            snapshot: Some(snap),
        });
    }
    let oc = oc.to_string();
    let s = shared.clone();
    std::thread::spawn(move || target_loop(s, oc));
    shared
}

/// Diff old vs new target lists for hot-reload: which names to add, update
/// (keep the loop, refresh config), and remove (stop the loop).
pub fn plan_config_diff(
    old: &HashMap<String, TargetConfig>,
    new: &HashMap<String, TargetConfig>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut add = Vec::new();
    let mut update = Vec::new();
    let mut remove = Vec::new();
    for (name, tc) in new {
        match old.get(name) {
            Some(o) if o != tc => update.push(name.clone()),
            Some(_) => {}
            None => add.push(name.clone()),
        }
    }
    for name in old.keys() {
        if !new.contains_key(name) {
            remove.push(name.clone());
        }
    }
    (add, update, remove)
}

// ---------------------------------------------------------------------------
// startup: spawn targets, hot-reload watcher, localhost API
// ---------------------------------------------------------------------------

pub fn run(config_path: &Path, bind_override: Option<&str>) -> io::Result<()> {
    let cfg = load_config(config_path)?;
    let bind = resolve_bind(&cfg, bind_override)?;
    let oc = crate::oc_binary();
    let (events, _) = broadcast::channel(512);

    let mut map: HashMap<String, Arc<TargetShared>> = HashMap::new();
    for tc in &cfg.targets {
        let sh = spawn_target(tc.clone(), &oc, events.clone(), config_path.to_path_buf());
        map.insert(tc.name.clone(), sh);
    }
    // M9: p2p reverse-forward runtimes (serve-enabled p2p targets) — the
    // laptop attach path with no openshell/OIDC. Collected here (master key +
    // ports resolve once), spawned onto the runtime below. A serve_port
    // OVERRIDE is incompatible with the p2p forward (the agent dials the
    // DERIVED port) — such targets fall back to the openshell forward.
    let mut forward_runs: Vec<crate::forward::ForwardRun> = Vec::new();
    let mut forward_statuses: Vec<std::sync::Arc<crate::forward::ForwardStatus>> = Vec::new();
    for tc in &cfg.targets {
        if tc.relay.is_none() || !tc.serve.unwrap_or(true) {
            continue;
        }
        let qualified = qualified_sandbox(tc);
        if tc.serve_port.is_some() {
            eprintln!(
                "daemon forward: {} — serve_port override set; p2p forward skipped (the agent dials the derived port), use the openshell forward",
                tc.name
            );
            continue;
        }
        match load_master_key(&tc.to_target_args()) {
            Ok(master) => {
                let status = std::sync::Arc::new(crate::forward::ForwardStatus {
                    target: tc.name.clone(),
                    local_port: serve_port(tc, &qualified),
                    ..Default::default()
                });
                forward_statuses.push(status.clone());
                forward_runs.push(crate::forward::ForwardRun {
                    relay: tc.relay.clone().unwrap_or_default(),
                    qualified: qualified.clone(),
                    master,
                    local_port: serve_port(tc, &qualified),
                    status,
                });
            }
            Err(e) => eprintln!("daemon forward: {} DISABLED (master key: {e})", tc.name),
        }
    }
    // M5: resolve the tunnel synchronously (it owns the live-status handle the
    // API serves); a broken tunnel config logs loudly and never blocks the API.
    let tunnel_run = match crate::tunnel::prepare(&cfg) {
        Ok(Some(run)) => Some(run),
        Ok(None) => None,
        Err(e) => {
            eprintln!("daemon tunnel: DISABLED ({e})");
            None
        }
    };
    let tunnel_status = tunnel_run.as_ref().map(|r| r.status.clone());
    let state = Arc::new(crate::api::ApiState {
        targets: Mutex::new(map),
        events: events.clone(),
        started_unix: now_unix(),
        oc,
        config_path: config_path.to_path_buf(),
        tunnel_status,
        forward_statuses,
    });
    spawn_config_watcher(config_path.to_path_buf(), state.clone());
    eprintln!(
        "daemon: {} target(s); UI/API on http://{bind} (v{VERSION})",
        state.targets.lock().unwrap().len()
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        if let Some(run) = tunnel_run {
            tokio::spawn(async move {
                if let Err(e) = crate::tunnel::run_service(run).await {
                    eprintln!("daemon tunnel: service stopped: {e}");
                }
            });
        }
        for run in forward_runs {
            tokio::spawn(async move {
                if let Err(e) = crate::forward::run_service(run).await {
                    eprintln!("daemon forward: service stopped: {e}");
                }
            });
        }
        let listener = tokio::net::TcpListener::bind(&bind).await?;
        axum::serve(listener, crate::api::router(state))
            .with_graceful_shutdown(shutdown_signal())
            .await
    })?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("daemon: shutting down");
}

/// Watch config.toml: parse, diff against the running set, add/update/remove
/// targets live. An unparsable edit keeps the old config (logged, retried on
/// the next event).
fn spawn_config_watcher(config_path: PathBuf, state: Arc<crate::api::ApiState>) {
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let mut watcher =
            match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                if res.is_ok() {
                    let _ = tx.send(());
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("daemon: config watcher unavailable ({e}) — restart to apply edits");
                    return;
                }
            };
        let dir = config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
            eprintln!("daemon: config watcher: {e} — restart to apply edits");
            return;
        }
        loop {
            match rx.recv() {
                Ok(()) => {
                    // Debounce editor writes (write+rename pairs).
                    std::thread::sleep(Duration::from_millis(400));
                    while rx.try_recv().is_ok() {}
                    match load_config(&config_path) {
                        Ok(new) => apply_config_diff(&state, &new),
                        Err(e) => eprintln!("daemon: config reload skipped: {e}"),
                    }
                }
                Err(_) => return,
            }
        }
    });
}

fn apply_config_diff(state: &Arc<crate::api::ApiState>, new: &DaemonConfig) {
    let mut map = state.targets.lock().unwrap();
    let old_cfgs: HashMap<String, TargetConfig> = map
        .iter()
        .map(|(k, v)| (k.clone(), v.cfg.read().unwrap().clone()))
        .collect();
    let new_cfgs: HashMap<String, TargetConfig> = new
        .targets
        .iter()
        .map(|t| (t.name.clone(), t.clone()))
        .collect();
    let (add, update, remove) = plan_config_diff(&old_cfgs, &new_cfgs);
    for name in &add {
        if let Some(tc) = new_cfgs.get(name) {
            let sh = spawn_target(
                tc.clone(),
                &state.oc,
                state.events.clone(),
                state.config_path.clone(),
            );
            map.insert(name.clone(), sh);
            eprintln!("daemon: target {name:?} added");
        }
    }
    for name in &update {
        if let (Some(sh), Some(tc)) = (map.get(name), new_cfgs.get(name)) {
            *sh.cfg.write().unwrap() = tc.clone();
            sh.wake();
            eprintln!("daemon: target {name:?} updated");
        }
    }
    for name in &remove {
        if let Some(sh) = map.remove(name) {
            sh.stop.store(true, Ordering::Relaxed);
            sh.wake();
            // Tell the UI: the card disappears without a page refresh.
            let _ = sh.events.send(Event {
                target: name.clone(),
                snapshot: None,
            });
            eprintln!("daemon: target {name:?} removed");
        }
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drained_resolutions_survive_a_halted_pass_via_restore() {
        // 2026-11-08: a halted pass (OneSideRootEmptied — a recreated sandbox's
        // empty root) consumed the operator's keep-laptop resolutions into a
        // plan that mutated nothing, so the conflicts re-flagged every pass
        // and the UI decision was silently lost. The contract: restore puts
        // them back, oldest first, exactly once.
        let mk_target = || TargetConfig {
            name: "t".into(),
            root: PathBuf::from("/tmp/t"),
            sandbox: "default--t".into(),
            workspace: None,
            relay: None,
            excludes: Vec::new(),
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: default_root_remote(),
            auto_provision: false,
            first_run_dry_run: None,
            hole_punch: false,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
            serve: None,
            serve_port: None,
        };
        let shared = Arc::new(TargetShared {
            cfg: std::sync::RwLock::new(mk_target()),
            state: Mutex::new(initial_snapshot(&mk_target())),
            paused: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            pending_resolutions: Mutex::new(Vec::new()),
            wake_tx: Mutex::new({
                let (tx, _rx) = std::sync::mpsc::channel();
                tx
            }),
            events: broadcast::channel(4).0,
            pass_lock: tokio::sync::Mutex::new(()),
            ever_synced: AtomicBool::new(false),
            first_sync_confirmed: AtomicBool::new(false),
            config_path: PathBuf::from("/tmp/t-config.toml"),
            provision_note: Mutex::new(None),
            serve_missing: AtomicBool::new(false),
        });
        shared.add_resolution(ConflictResolution {
            path: ".agents".into(),
            choice: "keep-local".into(),
        });
        shared.add_resolution(ConflictResolution {
            path: ".git".into(),
            choice: "keep-local".into(),
        });
        // The pass drains…
        let consumed = shared.drain_resolutions();
        assert_eq!(consumed.len(), 2);
        assert!(shared.drain_resolutions().is_empty(), "drain is once-only");
        // …the pass halts and hands them back…
        shared.restore_resolutions(consumed);
        // …and the next pass sees them again, oldest first.
        let next = shared.drain_resolutions();
        assert_eq!(next.len(), 2);
        assert_eq!(next[0].path, ".agents");
        assert_eq!(next[1].path, ".git");
    }

    #[test]
    fn parse_config_inherits_defaults_into_targets() {
        let raw = r#"
[server]
bind = "127.0.0.1:7399"

[defaults]
relay = "/ip4/203.0.113.7/tcp/4001/p2p/RELAY"
interval_secs = 30
debounce_ms = 250
master_key_file = "/keys/mk"

[[targets]]
name = "sync-oc"
root = "/home/u/proj"
sandbox = "default--sync-oc"

[[targets]]
name = "notes"
root = "/home/u/notes"
sandbox = "default--notes"
relay = "/ip4/203.0.113.9/tcp/4001/p2p/OTHER"
excludes = ["node_modules"]
interval_secs = 10
"#;
        let cfg = parse_config(raw).unwrap();
        assert_eq!(cfg.targets.len(), 2);
        let t0 = &cfg.targets[0];
        assert_eq!(
            t0.relay.as_deref(),
            Some("/ip4/203.0.113.7/tcp/4001/p2p/RELAY")
        );
        assert_eq!(t0.interval_secs, Some(30));
        assert_eq!(t0.debounce_ms, Some(250));
        assert_eq!(
            t0.master_key_file.as_deref(),
            Some(Path::new("/keys/mk")),
            "master key inherited from defaults"
        );
        assert_eq!(t0.root_remote, "/sandbox");
        let t1 = &cfg.targets[1];
        assert_eq!(
            t1.relay.as_deref(),
            Some("/ip4/203.0.113.9/tcp/4001/p2p/OTHER")
        );
        assert_eq!(t1.interval_secs, Some(10));
        assert_eq!(t1.excludes, vec!["node_modules".to_string()]);
    }

    #[test]
    fn parse_config_rejects_empty_and_duplicate_names() {
        // Zero targets is VALID (the daemon runs an empty dashboard; the
        // one-shot CLI errors later if it has nothing to sync).
        assert!(parse_config("[defaults]\ninterval_secs = 5\n").is_ok());
        assert!(parse_config("[defaults]\ninterval_secs = 5\n")
            .unwrap()
            .targets
            .is_empty());
        let dup = r#"
[[targets]]
name = "a"
root = "/tmp/a"
sandbox = "s1"

[[targets]]
name = "a"
root = "/tmp/b"
sandbox = "s2"
"#;
        let err = parse_config(dup).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn bind_must_be_loopback() {
        let cfg = DaemonConfig {
            server: ServerConfig { bind: None },
            defaults: Defaults::default(),
            targets: vec![TargetConfig {
                name: "t".into(),
                root: "/tmp/t".into(),
                sandbox: "s".into(),
                workspace: None,
                relay: None,
                excludes: vec![],
                interval_secs: None,
                debounce_ms: None,
                master_key_file: None,
                master_key_env: false,
                kubeconfig: None,
                root_remote: "/sandbox".into(),
                auto_provision: false,
                first_run_dry_run: None,
                hole_punch: false,
                tunnel_services: Vec::new(),
                tunnel_args: Vec::new(),
                serve: None,
                serve_port: None,
            }],
            tunnel: crate::tunnel::TunnelConfig::default(),
        };
        assert_eq!(resolve_bind(&cfg, None).unwrap(), DEFAULT_BIND);
        assert_eq!(
            resolve_bind(&cfg, Some("127.0.0.1:9999")).unwrap(),
            "127.0.0.1:9999"
        );
        let err = resolve_bind(&cfg, Some("0.0.0.0:7301")).unwrap_err();
        assert!(err.to_string().contains("LOOPBACK"), "{err}");
        assert!(resolve_bind(&cfg, Some("not-an-addr")).is_err());
    }

    #[test]
    fn pending_resolutions_drain_exactly_once() {
        let (events, _rx) = broadcast::channel(8);
        let shared = TargetShared {
            cfg: std::sync::RwLock::new(TargetConfig {
                name: "t".into(),
                root: "/tmp/t".into(),
                sandbox: "s".into(),
                workspace: None,
                relay: None,
                excludes: vec![],
                interval_secs: None,
                debounce_ms: None,
                master_key_file: None,
                master_key_env: false,
                kubeconfig: None,
                root_remote: "/sandbox".into(),
                auto_provision: false,
                first_run_dry_run: None,
                hole_punch: false,
                tunnel_services: Vec::new(),
                tunnel_args: Vec::new(),
                serve: None,
                serve_port: None,
            }),
            state: Mutex::new(TargetSnapshot {
                first_preview: None,
                name: "t".into(),
                root: "/tmp/t".into(),
                sandbox: "s".into(),
                transport: "exec".into(),
                path: "exec".into(),
                phase: "idle".into(),
                paused: false,
                last_pass_unix: 0,
                applied: 0,
                deleted: 0,
                failed: 0,
                conflicts_left: vec![],
                conflicts_resolved: vec![],
                honored: vec![],
                problems: vec![],
                archive_saved: false,
                trust_base: false,
                last_error: None,
                daemon_version: "0".into(),
                sandbox_status: None,
                pass_progress: None,
            }),
            paused: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            pending_resolutions: Mutex::new(vec![ConflictResolution {
                path: "link".into(),
                choice: "keep-remote".into(),
            }]),
            wake_tx: Mutex::new({
                let (tx, _rx) = std::sync::mpsc::channel();
                tx
            }),
            events,
            pass_lock: tokio::sync::Mutex::new(()),
            ever_synced: AtomicBool::new(false),
            first_sync_confirmed: AtomicBool::new(false),
            config_path: PathBuf::from("/tmp/nonexistent-config.toml"),
            provision_note: Mutex::new(None),
            serve_missing: AtomicBool::new(false),
        };
        assert_eq!(shared.drain_resolutions().len(), 1);
        assert!(
            shared.drain_resolutions().is_empty(),
            "consumed requests never re-fire"
        );
        shared.add_resolution(ConflictResolution {
            path: "x".into(),
            choice: "keep-local".into(),
        });
        assert_eq!(shared.drain_resolutions().len(), 1);
    }

    #[test]
    fn config_diff_plans_add_update_remove() {
        let mk = |excl: &str| TargetConfig {
            name: "a".into(),
            root: "/tmp/a".into(),
            sandbox: "s".into(),
            workspace: None,
            relay: None,
            excludes: vec![excl.to_string()],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox".into(),
            auto_provision: false,
            first_run_dry_run: None,
            hole_punch: false,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
            serve: None,
            serve_port: None,
        };
        let mut old = HashMap::new();
        old.insert("a".to_string(), mk("node_modules"));
        old.insert("b".to_string(), mk("target/"));
        let mut new = HashMap::new();
        new.insert("a".to_string(), mk("node_modules")); // unchanged
        new.insert("a2".to_string(), mk(".git")); // added
        new.insert("b".to_string(), mk("target/\n*.log")); // changed
        let (add, update, remove) = plan_config_diff(&old, &new);
        assert_eq!(add, vec!["a2".to_string()]);
        assert_eq!(update, vec!["b".to_string()]);
        assert!(remove.is_empty(), "b still exists — nothing removed");
        new.remove("b");
        let (add, update, remove) = plan_config_diff(&old, &new);
        assert_eq!(add, vec!["a2".to_string()], "a2 was never in old");
        assert!(update.is_empty());
        assert_eq!(remove, vec!["b".to_string()]);
    }

    #[test]
    fn provision_script_contains_the_essentials() {
        let cfg = TargetConfig {
            name: "vllm".into(),
            root: "/tmp/vllm".into(),
            sandbox: "sync-oc".into(),
            workspace: None,
            relay: Some("/ip4/203.0.113.7/tcp/4001/p2p/RELAY".into()),
            excludes: vec![],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox/vllm".into(),
            auto_provision: true,
            first_run_dry_run: None,
            hole_punch: true,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
            serve: None,
            serve_port: None,
        };
        let script = provision_script(&cfg, "sync-oc+vllm");
        assert!(script.contains("mkdir -p '/sandbox/vllm'"), "{script}");
        // 2026-11-11: the SPAWN moved OUT of the provision script — it runs
        // through the mediated exec path (agent_spawn_script) so the agent's
        // sockets land in the runtime's admission regime (oc-exec-spawned
        // processes are egress-denied by the pre.33 network_broker). The
        // provision script keeps only the guard patterns (bracket-classed).
        assert!(
            !script.contains("nohup"),
            "the provision script must not spawn (mediated spawn owns it): {script}"
        );
        assert!(script.contains("ready-to-spawn"), "{script}");
        assert!(
            script.contains("[s]ync-oc+vllm") || script.contains("sync-oc+vllm"),
            "the qualified guard pattern survives: {script}"
        );
        assert!(
            script.contains("already-serving"),
            "idempotence guard: {script}"
        );
        assert!(
            script.contains("[s]ync-oc+vllm"),
            "bracket-classed guard: {script}"
        );
        // Regression (2026-11-06 e2e): the script runs as `bash -c <script>`,
        // so its own cmdline contains the script text. A space-terminated
        // literal guard pattern would self-match → "already-serving" → exit 0
        // with NO agent spawned, while the config still flips.
        assert!(
            !script.contains("--sandbox-id sync-oc+vllm "),
            "guard literal would self-match the script's own cmdline"
        );
        assert!(
            !script.contains(&format!(
                "sync-agent p2p --relay {} ",
                cfg.relay.clone().unwrap_or_default()
            )),
            "relay guard literal would self-match"
        );
        assert!(
            !script.contains("p2p-claude-plan"),
            "base derived from the root's parent, not the root itself"
        );
    }

    #[test]
    fn parse_config_resolves_tunnel_services_into_spawn_args() {
        let raw = r#"
[defaults]
relay = "/ip4/203.0.113.7/tcp/4001/p2p/RELAY"
master_key_file = "/keys/mk"

[tunnel]
enabled = true

[[tunnel.services]]
name = "memory"
upstream = "http://127.0.0.1:7999"
agent_port = 7402
spool_tools = ["memory_store", "memory_delete"]

[[targets]]
name = "plan"
root = "/tmp/plan"
sandbox = "sync-oc"
relay = "/ip4/203.0.113.7/tcp/4001/p2p/RELAY"
tunnel_services = ["memory"]
first_run_dry_run = false

[[targets]]
name = "no-tunnel"
root = "/tmp/other"
sandbox = "sync-oc"
"#;
        let cfg = parse_config(raw).expect("valid config");
        let plan = cfg.targets.iter().find(|t| t.name == "plan").unwrap();
        assert_eq!(
            plan.tunnel_args,
            vec!["memory@7402:memory_store,memory_delete".to_string()],
            "resolved --tunnel arg (name@port:tools)"
        );
        // M6 first-run dry-run knob: explicit false overrides the on-by-default
        // gate; a target without the key defaults to None (= gate armed).
        assert_eq!(plan.first_run_dry_run, Some(false));
        let other = cfg.targets.iter().find(|t| t.name == "no-tunnel").unwrap();
        assert!(
            other.tunnel_args.is_empty(),
            "no tunnel_services → no tunnel client"
        );
        assert_eq!(other.first_run_dry_run, None);

        // The provisioned spawn line carries the resolved args — in the
        // MEDIATED spawn script (the provision script only stages + kills).
        let spawn = agent_spawn_script(plan, "sync-oc+plan");
        assert!(
            spawn.contains("--tunnel 'memory@7402:memory_store,memory_delete'"),
            "the mediated spawn carries the tunnel spec: {spawn}"
        );
        assert!(
            spawn.contains("--sandbox-id 'sync-oc+plan'"),
            "the mediated spawn carries the qualified id: {spawn}"
        );
        let script = provision_script(plan, "sync-oc+plan");
        assert!(
            !script.contains("nohup"),
            "the provision script must not spawn: {script}"
        );
        // The root guard still matches (tunnel args ride AFTER --root);
        // self_guard_safe bracket-classes the pattern's first char, and the
        // case patterns are UNQUOTED (a quoted [x] is a literal, not a class
        // — the M5 rollout's duplicate-spawn loop came from exactly that).
        assert!(
            script.contains("--root\\ [/]sandbox\\ "),
            "guard shape intact: {script}"
        );
    }

    #[test]
    fn parse_config_rejects_unknown_tunnel_service_names() {
        let raw = r#"
[defaults]
relay = "/ip4/203.0.113.7/tcp/4001/p2p/RELAY"

[[targets]]
name = "plan"
root = "/tmp/plan"
sandbox = "sync-oc"
relay = "/ip4/203.0.113.7/tcp/4001/p2p/RELAY"
tunnel_services = ["nosuch"]
"#;
        let err = parse_config(raw).unwrap_err();
        assert!(
            err.to_string().contains("not in [[tunnel.services]]"),
            "loud refusal with the allowlist pointer: {err}"
        );
    }

    #[test]
    fn sandbox_status_parse_defaults_honestly() {
        // Empty output → agent "none", everything unhealthy.
        let s = parse_sandbox_status("");
        assert_eq!(s.agent_version, "none");
        assert!(!s.mcp_binary && !s.mcp_config && !s.root_ok);
        assert!(s.tunnel.is_empty());

        // A full healthy probe.
        let s = parse_sandbox_status(
            "agent_version=0.1.3\ntunnel=memory@7402\ntunnel=slides@7403\nmcp_binary=1\nmcp_config=1\nroot=1\n",
        );
        assert_eq!(s.agent_version, "0.1.3");
        assert_eq!(s.tunnel, vec!["memory@7402", "slides@7403"]);
        assert!(s.mcp_binary && s.mcp_config && s.root_ok);

        // Unknown lines are ignored; a bare agent line without a value stays honest.
        let s = parse_sandbox_status("agent_version=unknown\nmcp_binary=1\nnoise");
        assert_eq!(s.agent_version, "unknown");
        assert!(s.mcp_binary);
        assert!(
            !s.mcp_config,
            "absent key defaults to unhealthy, never to ok"
        );
    }

    #[test]
    fn sandbox_status_drift_detection() {
        let healthy = SandboxStatus {
            agent_version: "0.1.3".into(),
            tunnel: vec!["memory@7402".into()],
            mcp_binary: true,
            mcp_config: true,
            root_ok: true,
            serve_ok: true,
            serve_port: Some(4100),
        };
        assert!(!healthy.drifted_from("0.1.3", &["memory@7402".to_string()]));
        // Version drift (the 0.1.2 → 0.1.3 rollout shape).
        let mut old = healthy.clone();
        old.agent_version = "0.1.2".into();
        assert!(old.drifted_from("0.1.3", &["memory@7402".to_string()]));
        // Tunnel-args drift (an agent spawned without the tunnel flag).
        let mut no_tunnel = healthy.clone();
        no_tunnel.tunnel = Vec::new();
        assert!(no_tunnel.drifted_from("0.1.3", &["memory@7402".to_string()]));
        // A dead agent is drift (re-provision brings it back).
        let mut dead = healthy.clone();
        dead.agent_version = "none".into();
        assert!(dead.drifted_from("0.1.3", &["memory@7402".to_string()]));
        // MCP health does NOT drive drift (the provision fixes the binary;
        // the mcp_config fix is a config edit, not a respawn).
        let mut mcp_stale = healthy.clone();
        mcp_stale.mcp_config = false;
        assert!(!mcp_stale.drifted_from("0.1.3", &["memory@7402".to_string()]));
    }

    #[test]
    fn provision_script_self_upgrades_stale_agents() {
        let cfg = TargetConfig {
            name: "plan".into(),
            root: "/tmp/plan".into(),
            sandbox: "sync-oc+plan".into(),
            workspace: None,
            relay: Some("/ip4/203.0.113.7/tcp/4001/p2p/RELAY".into()),
            excludes: vec![],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox/.opencode/plan".into(),
            auto_provision: true,
            first_run_dry_run: None,
            hole_punch: true,
            tunnel_services: vec!["memory".into()],
            tunnel_args: vec!["memory@7402:memory_store,memory_delete".into()],
            serve: None,
            serve_port: None,
        };
        let script = provision_script(&cfg, "sync-oc+plan");
        // The BIN lookup covers BOTH the per-root base and the shared install.
        assert!(
            script.contains("/sandbox/.sync-agent/agents/*/sync-agent"),
            "shared-base lookup present: {script}"
        );
        // The version + tunnel check rides the SAME /proc match, and a stale
        // agent is killed rather than skipped.
        assert!(
            script.contains("STALE"),
            "self-upgrade bookkeeping: {script}"
        );
        assert!(
            script.contains("kill \"$(basename \"$p\")\""),
            "stale agents are killed: {script}"
        );
        // Current = built version + the tunnel spec, as bracket-safe patterns.
        assert!(
            script.contains(&self_guard_safe(&format!("agents/{VERSION}/sync-agent"))),
            "version pattern present: {script}"
        );
        assert!(
            script.contains(&format!(
                "*--tunnel\\ {}*",
                self_guard_safe("memory@7402:memory_store,memory_delete")
            )),
            "tunnel-arg pattern present (guard-safe, unquoted class): {script}"
        );
        // The master key falls back to the shared base (the live sandbox's
        // qualified agents were spawned with /sandbox/.sync-agent/master.key).
        assert!(
            script.contains("KEY='/sandbox/.sync-agent/master.key'"),
            "{script}"
        );
        // A current agent still short-circuits (no respawn storm).
        assert!(script.contains("already-serving"), "{script}");
        // Guards never self-match: no unbracketed literal patterns.
        assert!(
            !script.contains("--sandbox-id sync-oc+plan "),
            "guard literal self-match: {script}"
        );
    }

    #[test]
    fn sandbox_probe_script_covers_agent_mcp_and_root() {
        let cfg = TargetConfig {
            name: "plan".into(),
            root: "/tmp/plan".into(),
            sandbox: "sync-oc+plan".into(),
            workspace: None,
            relay: Some("/ip4/203.0.113.7/tcp/4001/p2p/RELAY".into()),
            excludes: vec![],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox/.opencode/plan".into(),
            auto_provision: true,
            first_run_dry_run: None,
            hole_punch: true,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
            serve: None,
            serve_port: None,
        };
        let script = sandbox_probe_script(&cfg, "sync-oc+plan");
        assert!(script.contains("agent_version="), "{script}");
        assert!(script.contains("mcp_binary="), "{script}");
        assert!(script.contains("mcp_config="), "{script}");
        assert!(script.contains("root=1"), "{script}");
        // The agent match is bracket-safe (a /proc scan of the script's own
        // cmdline must not self-match).
        assert!(script.contains("[s]ync-oc+plan"), "{script}");
        assert!(!script.contains("--sandbox-id sync-oc+plan "), "{script}");
        // M8: the serve health line is present, keyed on the daemon-derived
        // port's HEX form (the /proc/net/tcp socket check — cwd-based
        // detection is impossible: the bun runtime sets dumpable=0).
        assert!(script.contains("serve_ok="), "{script}");
        let port = serve_port(&cfg, "sync-oc+plan");
        let hex = format!("{:04X}", port);
        assert!(
            script.contains(&format!(":{hex}$")),
            "derived port {port} (hex {hex}) drives the socket check: {script}"
        );
    }

    #[test]
    fn serve_port_is_deterministic_and_config_overridable() {
        let mut cfg = TargetConfig {
            name: "plan".into(),
            root: "/tmp/plan".into(),
            sandbox: "sync-oc+plan".into(),
            workspace: None,
            relay: Some("/ip4/203.0.113.7/tcp/4001/p2p/RELAY".into()),
            excludes: vec![],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox/.opencode/plan".into(),
            auto_provision: true,
            first_run_dry_run: None,
            hole_punch: true,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
            serve: None,
            serve_port: None,
        };
        let a = serve_port(&cfg, "sync-oc+plan");
        let b = serve_port(&cfg, "sync-oc+plan");
        assert_eq!(a, b, "same qualified id → same port (stable across restarts)");
        assert!(
            (4100..4500).contains(&a),
            "derived port stays inside the reserved range: {a}"
        );
        cfg.serve_port = Some(5099);
        assert_eq!(serve_port(&cfg, "sync-oc+plan"), 5099, "explicit override wins");
    }

    #[test]
    fn serve_spawn_script_is_idempotent_and_self_match_safe() {        let cfg = TargetConfig {
            name: "plan".into(),
            root: "/tmp/plan".into(),
            sandbox: "sync-oc+plan".into(),
            workspace: None,
            relay: Some("/ip4/203.0.113.7/tcp/4001/p2p/RELAY".into()),
            excludes: vec![],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox/.opencode/plan".into(),
            auto_provision: true,
            first_run_dry_run: None,
            hole_punch: true,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
            serve: None,
            serve_port: None,
        };
        let port = serve_port(&cfg, "sync-oc+plan");
        let script = serve_spawn_script(&cfg, port);
        // Missing opencode degrades cleanly (exit 0) — never a respawn loop.
        assert!(script.contains("serve-missing-opencode"), "{script}");
        // Idempotent happy path: the /proc/net/tcp LISTEN check gates the
        // spawn (the socket is the truth — /proc/PID/cwd is unreadable).
        assert!(script.contains("serve-already"), "{script}");
        let hex = format!("{:04X}", port);
        assert!(
            script.contains(&format!(":{hex}$")),
            "socket check keyed on port {port} (hex {hex}): {script}"
        );
        assert!(
            script.contains(&format!("nohup opencode serve --port {port}")),
            "{script}"
        );
        // M9 follow-up: the serve roots at the SANDBOX root (the attach TUI
        // lands there), not the target's sync root.
        assert!(script.contains("cd '/sandbox'"), "{script}");
        assert!(!script.contains("cd '/sandbox/.opencode/plan'"), "{script}");
        // REGRESSION (2026-11-10): awk exits 0 on NO match — the bare pattern
        // form made "serve-already" unconditional and the self-heal dead
        // (serve_ok was vacuously true forever). The gate must exit non-zero
        // when the socket is absent.
        assert!(script.contains("END { exit s ? 0 : 1 }"), "{script}");
    }

    #[test]
    fn serve_restart_script_kills_then_respawns() {
        let cfg = TargetConfig {
            name: "plan".into(),
            root: "/tmp/plan".into(),
            sandbox: "sync-oc+plan".into(),
            workspace: None,
            relay: Some("/ip4/203.0.113.7/tcp/4001/p2p/RELAY".into()),
            excludes: vec![],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox/.opencode/plan".into(),
            auto_provision: true,
            first_run_dry_run: None,
            hole_punch: true,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
            serve: None,
            serve_port: None,
        };
        let port = serve_port(&cfg, "sync-oc+plan");
        let script = serve_restart_script(&cfg, port);
        // The kill pattern is bracket-safe (the script's own cmdline contains
        // the pattern text; the /proc scan must not self-match) and skips $$.
        assert!(
            script.contains(&format!("*\"opencode [s]erve --port {port}\"*")),
            "{script}"
        );
        assert!(script.contains("\"/proc/$$\""), "{script}");
        // TERM → wait → KILL escalation, and the busy path never respawns
        // onto a socket that never freed.
        assert!(script.contains("kill -TERM"), "{script}");
        assert!(script.contains("kill -KILL"), "{script}");
        assert!(script.contains("serve-restart-busy"), "{script}");
        // Same awk regression guard as the spawn gate: the socket checks must
        // be match-counting (awk alone exits 0 on no-match).
        assert!(script.matches("END { exit s ? 0 : 1 }").count() >= 2, "{script}");
        // The respawn body is the spawn script verbatim (cd /sandbox + nohup).
        assert!(script.contains("cd '/sandbox'"), "{script}");
        assert!(
            script.contains(&format!("nohup opencode serve --port {port}")),
            "{script}"
        );
    }

    #[test]
    fn should_provision_eligibility() {
        let base = TargetConfig {
            name: "t".into(),
            root: "/tmp/t".into(),
            sandbox: "sync-oc".into(),
            workspace: None,
            relay: Some("/ip4/203.0.113.7/tcp/4001/p2p/RELAY".into()),
            excludes: vec![],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: None,
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox/t".into(),
            auto_provision: true,
            first_run_dry_run: None,
            hole_punch: true,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
            serve: None,
            serve_port: None,
        };
        assert!(
            should_provision(&base, false),
            "brand-new unqualified p2p target"
        );
        assert!(
            !should_provision(&base, true),
            "established target keeps loud errors"
        );
        let qualified = TargetConfig {
            sandbox: "sync-oc+t".into(),
            ..base.clone()
        };
        assert!(!should_provision(&qualified, false), "already qualified");
        let off = TargetConfig {
            auto_provision: false,
            first_run_dry_run: None,
            hole_punch: false,
            ..base.clone()
        };
        assert!(!should_provision(&off, false), "kill switch");
        let exec = TargetConfig {
            relay: None,
            ..base
        };
        assert!(
            !should_provision(&exec, false),
            "exec targets resolve roots themselves"
        );
    }

    #[test]
    fn qualify_target_in_config_roundtrip() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
[defaults]
interval_secs = 30

[[targets]]
name = "t"
root = "/tmp/t"
sandbox = "sync-oc"
root_remote = "/sandbox/t"
"#,
        )
        .unwrap();
        qualify_target_in_config(&path, "t", "sync-oc+t").unwrap();
        let cfg = crate::daemon::load_config(&path).unwrap();
        assert_eq!(cfg.targets[0].sandbox, "sync-oc+t");
        // Idempotent: a second call is a no-op, not an error.
        qualify_target_in_config(&path, "t", "sync-oc+t").unwrap();
        assert!(qualify_target_in_config(&path, "missing", "x").is_err());
    }

    #[test]
    fn legacy_state_migrates_to_the_global_dir() {
        let td = tempfile::tempdir().unwrap();
        let root = td.path().join("repo");
        std::fs::create_dir_all(root.join(".sync-agent")).unwrap();
        std::fs::write(root.join(".sync-agent/archive.bin"), b"archive-bytes").unwrap();
        std::fs::write(root.join(".sync-agent/cache-a.bin"), b"a").unwrap();
        let state_dir = td.path().join("global/pairs/abc123");
        migrate_legacy_state(&root, &state_dir);
        assert_eq!(
            std::fs::read(state_dir.join("archive.bin")).unwrap(),
            b"archive-bytes"
        );
        assert!(state_dir.join("cache-a.bin").exists());
        assert!(!root.join(".sync-agent").exists(), "legacy dir removed");
        // Idempotent: a second run with nothing to migrate is a no-op.
        migrate_legacy_state(&root, &state_dir);
        assert!(state_dir.join("archive.bin").exists());
    }

    #[test]
    fn pair_state_dir_is_stable_and_pair_keyed() {
        let a = pair_state_dir("sync-oc+plan", "/sandbox/.opencode/plan");
        let b = pair_state_dir("sync-oc+plan", "/sandbox/.opencode/plan");
        assert_eq!(a, b, "same pair → same dir");
        let c = pair_state_dir("sync-oc+plan", "/sandbox/plan");
        assert_ne!(a, c, "re-point → fresh dir (fresh pair key)");
        let d = pair_state_dir("sync-oc", "/sandbox/p2p-claude-plan");
        assert_ne!(a, d, "different sandbox → different dir");
        assert!(a
            .to_string_lossy()
            .contains(".local/state/sync-agent-pvc/pairs/"));
    }

    #[test]
    fn snapshot_serializes_the_api_shape() {
        let (events, mut rx) = broadcast::channel(8);
        let shared = TargetShared {
            cfg: std::sync::RwLock::new(TargetConfig {
                name: "t".into(),
                root: "/tmp/t".into(),
                sandbox: "s".into(),
                workspace: None,
                relay: None,
                excludes: vec![],
                interval_secs: None,
                debounce_ms: None,
                master_key_file: None,
                master_key_env: false,
                kubeconfig: None,
                root_remote: "/sandbox".into(),
                auto_provision: false,
                first_run_dry_run: None,
                hole_punch: false,
                tunnel_services: Vec::new(),
                tunnel_args: Vec::new(),
                serve: None,
                serve_port: None,
            }),
            state: Mutex::new(initial_snapshot(&TargetConfig {
                name: "t".into(),
                root: "/tmp/t".into(),
                sandbox: "s".into(),
                workspace: None,
                relay: None,
                excludes: vec![],
                interval_secs: None,
                debounce_ms: None,
                master_key_file: None,
                master_key_env: false,
                kubeconfig: None,
                root_remote: "/sandbox".into(),
                auto_provision: false,
                first_run_dry_run: None,
                hole_punch: false,
                tunnel_services: Vec::new(),
                tunnel_args: Vec::new(),
                serve: None,
                serve_port: None,
            })),
            paused: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            pending_resolutions: Mutex::new(Vec::new()),
            wake_tx: Mutex::new({
                let (tx, _rx) = std::sync::mpsc::channel();
                tx
            }),
            events,
            pass_lock: tokio::sync::Mutex::new(()),
            ever_synced: AtomicBool::new(false),
            first_sync_confirmed: AtomicBool::new(false),
            config_path: PathBuf::from("/tmp/nonexistent-config.toml"),
            provision_note: Mutex::new(None),
            serve_missing: AtomicBool::new(false),
        };
        shared.set_phase("syncing");
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.target, "t");
        let snap = ev.snapshot.expect("phase update carries a snapshot");
        assert_eq!(snap.phase, "syncing");
        let json = serde_json::to_value(&snap).unwrap();
        for key in [
            "name",
            "root",
            "sandbox",
            "transport",
            "phase",
            "paused",
            "last_pass_unix",
            "applied",
            "deleted",
            "failed",
            "conflicts_left",
            "honored",
            "problems",
            "archive_saved",
            "last_error",
            "daemon_version",
        ] {
            assert!(json.get(key).is_some(), "missing {key}");
        }
    }
}
