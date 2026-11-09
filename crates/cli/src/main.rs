//! sync (sync-cli) — the laptop side.
//!
//! M3: thin control CLI over the two transports (`exec` = oc-exec fallback
//! with agent auto-injection, `p2p` = libp2p over our relay) and the remote
//! bisync driver. All logic lives in the modules:
//! - [`transport`] — Transport trait, OcExec (+ agent injection), P2p, pins
//! - [`resolver`] — AgentSandbox CR → running pod (via the `oc` subprocess)
//! - [`remote_driver`] — one local ⇄ remote bisync pass (driver.rs semantics)
//!
//! M4 delivers the long-lived daemon (watch, loop, localhost API + UI).

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

mod api;
mod daemon;
mod remote_driver;
mod resolver;
mod transport;
mod tunnel;

use remote_driver::{sync_local_to_remote, RemoteConfig, RemoteReport};
use transport::{PeerPins, Transport};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sync: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, io::Error> {
    match cli.cmd {
        Cmd::Sync(args) => cmd_sync(args),
        Cmd::Status(args) => cmd_status(args),
        Cmd::Ping(args) => cmd_ping(args),
        Cmd::Daemon(args) => cmd_daemon(args),
    }
}

/// Expand the leading `~` in the config path (clap default includes it).
fn expand_home(p: &Path) -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        if let Some(rest) = p.to_str().and_then(|s| s.strip_prefix("~/")) {
            return Path::new(&home).join(rest);
        }
    }
    p.to_path_buf()
}

fn cmd_daemon(args: DaemonArgs) -> Result<ExitCode, io::Error> {
    let config_path = expand_home(&args.config);
    daemon::run(&config_path, args.bind.as_deref())?;
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "sync",
    version = VERSION,
    about = "Bidirectional sync between this laptop and an OpenShell agent sandbox (M3)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// One bisync pass: local DIR ⇄ the sandbox's sync root.
    Sync(SyncArgs),
    /// Connect and report the agent's identity + root facts (§8 hello).
    Status(TargetArgs),
    /// Connect, Ping → Pong, report versions (the M0 spike (a) driver, real).
    Ping(TargetArgs),
    /// Long-lived daemon: per-target sync loops + localhost UI/API (M4).
    Daemon(DaemonArgs),
}

/// Everything needed to reach one sandbox.
#[derive(Args)]
pub(crate) struct TargetArgs {
    /// Sandbox: full AgentSandbox CR name (`default--sync-oc`) or short name
    /// plus --workspace.
    #[arg(long)]
    pub(crate) sandbox: String,
    /// Workspace prefix for short sandbox names (OpenShell: default).
    #[arg(long)]
    pub(crate) workspace: Option<String>,
    /// Transport: p2p (libp2p over the relay), exec (oc exec fallback), or
    /// auto (p2p when --relay is given, else exec).
    #[arg(long, value_enum, default_value_t = TransportKind::Auto)]
    pub(crate) transport: TransportKind,
    /// Relay multiaddr for the p2p transport
    /// (e.g. /ip4/VPS/tcp/4002/p2p/RELAY_PEER).
    #[arg(long)]
    pub(crate) relay: Option<String>,
    /// Relay PeerId when the --relay multiaddr does not carry one.
    #[arg(long)]
    pub(crate) relay_peer: Option<String>,
    /// Read the per-sandbox master key from $SYNC_AGENT_MASTER_KEY (64 hex).
    #[arg(long, conflicts_with = "master_key_file")]
    pub(crate) master_key_env: bool,
    /// Read the per-sandbox master key from a 0600 file (64 hex).
    #[arg(long)]
    pub(crate) master_key_file: Option<PathBuf>,
    /// The sync root inside the sandbox (the PVC workspace).
    #[arg(long, default_value = "/sandbox")]
    pub(crate) root_remote: String,
    /// Explicit kubeconfig (default: oc's own resolution — KUBECONFIG env).
    #[arg(long)]
    pub(crate) kubeconfig: Option<PathBuf>,
    /// Attempt a DCUtR hole-punch before opening the sync stream (p2p
    /// transport): direct connection when NAT allows, relayed circuit
    /// otherwise. Disable to always ride the relay (M4.5 fallback).
    #[arg(long = "no-hole-punch", action = clap::ArgAction::SetFalse, default_value_t = true)]
    pub(crate) hole_punch: bool,
    /// Override the remote agent binary path (default: the versioned install
    /// path on the sync root).
    #[arg(long)]
    pub(crate) agent_path: Option<String>,
    /// Local sync-agent binary for agent injection (exec transport). Default:
    /// sibling target dir, then ~/.local/lib/sync-agent-pvc/sync-agent.
    #[arg(long)]
    pub(crate) agent_bin: Option<PathBuf>,
}

/// One bisync run.
#[derive(Args)]
struct SyncArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// Local directory to sync (side A).
    #[arg(long)]
    root: PathBuf,
    /// Bypass the large-deletion guard (mutagen --force semantics).
    #[arg(long)]
    force: bool,
    /// Plan only: scan, reconcile, safety-check, classify conflicts —
    /// mutate nothing anywhere, write no state.
    #[arg(long)]
    dry_run: bool,
    /// Extra ignore pattern (mutagen syntax; repeatable).
    #[arg(long = "ignore")]
    ignores: Vec<String>,
}

/// Run the long-lived daemon.
#[derive(Args)]
struct DaemonArgs {
    /// Daemon config: [[targets]] + [server].bind.
    #[arg(long, default_value = "~/.config/sync-agent-pvc/config.toml")]
    config: PathBuf,
    /// UI/API bind override (loopback enforced).
    #[arg(long)]
    bind: Option<String>,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransportKind {
    Auto,
    Exec,
    P2p,
}

// ---------------------------------------------------------------------------
// shared plumbing
// ---------------------------------------------------------------------------

/// The oc binary: env `SYNC_OC` (testability — tests point it at a shim) or
/// plain `oc` from PATH.
pub(crate) fn oc_binary() -> String {
    match std::env::var("SYNC_OC") {
        Ok(v) if !v.is_empty() => v,
        _ => "oc".into(),
    }
}

/// Default remote agent path — the versioned install layout of the agent's
/// own `install` subcommand (agent install.rs: `<root>/.sync-agent/agents/<v>/sync-agent`).
pub(crate) fn default_agent_path(root_remote: &str) -> String {
    format!("{root_remote}/.sync-agent/agents/{VERSION}/sync-agent")
}

/// Master key from env or file (never printed, never logged).
pub(crate) fn load_master_key(args: &TargetArgs) -> io::Result<[u8; 32]> {
    let raw = if args.master_key_env {
        std::env::var("SYNC_AGENT_MASTER_KEY").map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--master-key-env set but $SYNC_AGENT_MASTER_KEY is not (64 hex chars)",
            )
        })?
    } else if let Some(path) = &args.master_key_file {
        std::fs::read_to_string(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot read master key file {}: {e}", path.display()),
            )
        })?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the p2p transport needs the per-sandbox master key: pass --master-key-env \
             (reads $SYNC_AGENT_MASTER_KEY) or --master-key-file <path>",
        ));
    };
    sync_proto::p2p::parse_master_key(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("master key: {e}")))
}

/// Build the transport chosen by --transport (auto: p2p with --relay, else exec).
pub(crate) fn build_transport(args: &TargetArgs, oc: &str) -> io::Result<Box<dyn Transport>> {
    let want_p2p = match args.transport {
        TransportKind::Auto => args.relay.is_some(),
        TransportKind::Exec => false,
        TransportKind::P2p => true,
    };
    if want_p2p {
        let master_key = load_master_key(args)?;
        let relay = args.relay.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the p2p transport requires --relay <multiaddr>",
            )
        })?;
        Ok(Box::new(transport::P2p {
            relay_multiaddr: relay.to_string(),
            relay_peer: args.relay_peer.clone(),
            sandbox_id: args.sandbox.clone(),
            master_key,
            root: args.root_remote.clone(),
            hole_punch: args.hole_punch,
            path: std::cell::Cell::new("relayed"),
        }))
    } else {
        let workspace = args.workspace.as_deref().unwrap_or("default");
        let resolved = resolver::resolve(&args.sandbox, workspace, args.kubeconfig.as_deref(), oc)?;
        let mut t = transport::OcExec::new(&resolved.namespace, &resolved.pod, &args.root_remote);
        t.remote_agent_path = args
            .agent_path
            .clone()
            .unwrap_or_else(|| default_agent_path(&args.root_remote));
        t.kubeconfig = args.kubeconfig.clone();
        t.oc_binary = oc.to_string();
        t.agent_bin = args.agent_bin.clone();
        Ok(Box::new(t))
    }
}

/// ensure-agent (probe/inject where applicable) + handshake + Hello. Also
/// returns the transport path the session landed on ("exec" | "direct" |
/// "relayed") for the target snapshot / UI badge.
pub(crate) fn open_session(
    t: &mut Box<dyn Transport>,
) -> io::Result<(
    sync_proto::session::Session<Box<dyn transport::ReadWrite>>,
    &'static str,
)> {
    t.ensure_agent()?;
    let stream = t.connect()?;
    let path = t.last_path();
    Ok((sync_proto::session::Session::client(stream)?, path))
}

/// Best-effort clean end (the agent GCs its staging area on Shutdown/Bye).
pub(crate) fn shutdown_quietly<S: io::Read + io::Write>(
    session: &mut sync_proto::session::Session<S>,
) {
    let _ = session.call(&sync_proto::messages::Request::Shutdown);
}

fn cmd_sync(args: SyncArgs) -> Result<ExitCode, io::Error> {
    let oc = oc_binary();
    let mut transport = build_transport(&args.target, &oc)?;
    eprintln!("sync: {} (v{VERSION})", transport.describe());
    let (mut session, _path) = open_session(&mut transport)?;
    let hello = session.hello().clone();
    if hello.root != args.target.root_remote {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "agent serves root {:?} but --root-remote is {:?} — restart the sandbox \
                 agent with --root {:?} (or pass the matching --root-remote)",
                hello.root, args.target.root_remote, args.target.root_remote
            ),
        ));
    }
    if !hello.root_writable {
        eprintln!(
            "sync: WARNING — remote sync root {} is not writable by uid={} gid={} (§8: check the \
             PVC mount and SCC)",
            hello.root, hello.uid, hello.gid
        );
    }
    let cfg = RemoteConfig {
        force: args.force,
        dry_run: args.dry_run,
        extra_ignores: args.ignores,
        limits: Default::default(),
        // Archive pair key = sandbox AND remote root: re-pointing --root-remote
        // (or two roots in one sandbox) yields a fresh, safe no-base archive.
        remote_endpoint: format!("{}:{}", args.target.sandbox, args.target.root_remote),
        local_resolutions: Vec::new(),
        state_dir: Some(daemon::pair_state_dir(
            &args.target.sandbox,
            &args.target.root_remote,
        )),
        progress: None,
    };
    // RACE WINDOW (M6, documented): this one-shot CLI shares the daemon's pair
    // state dir with NO cross-process lock — a daemon pass on the same target
    // running concurrently would interleave archive/cache writes (each save is
    // atomic, but the read-modify-write sequences interleave). Use this for
    // debugging an idle target; the daemon's pass_lock owns live targets.
    let result = sync_local_to_remote(&args.root, &mut session, &cfg);
    shutdown_quietly(&mut session);
    let report = result?;
    print_report(&report);
    // Never silent: any failed path, halt, left conflict or problem fails the
    // command (dry-run plans always succeed — nothing was mutated).
    let clean = report.failed == 0
        && report.halted.is_none()
        && report.conflicts_left.is_empty()
        && report.problems.is_empty();
    Ok(match clean {
        true => ExitCode::SUCCESS,
        false => ExitCode::FAILURE,
    })
}

fn cmd_status(args: TargetArgs) -> Result<ExitCode, io::Error> {
    let oc = oc_binary();
    let mut transport = build_transport(&args, &oc)?;
    let (mut session, _path) = open_session(&mut transport)?;
    let hello = session.hello().clone();
    println!("transport: {}", transport.describe());
    println!("agent-version: {}", hello.agent_version);
    println!("remote-uid: {}  remote-gid: {}", hello.uid, hello.gid);
    println!("remote-root: {}", hello.root);
    println!(
        "root-writable: {}  preserves-executability: {}",
        hello.root_writable, hello.preserves_executability
    );
    if args.relay.is_some() {
        // Pin state for the p2p transport (TOFU → strict).
        let pins = PeerPins::load_default()?;
        match pins.get(&args.sandbox) {
            Some(pinned) => println!("peer-pin: {pinned} (strict)"),
            None => println!("peer-pin: none yet (TOFU — recorded on first successful connect)"),
        }
    }
    shutdown_quietly(&mut session);
    Ok(ExitCode::SUCCESS)
}

fn cmd_ping(args: TargetArgs) -> Result<ExitCode, io::Error> {
    let oc = oc_binary();
    let mut transport = build_transport(&args, &oc)?;
    let (mut session, _path) = open_session(&mut transport)?;
    let started = std::time::Instant::now();
    let pong = session.call(&sync_proto::messages::Request::Ping);
    shutdown_quietly(&mut session);
    match pong? {
        sync_proto::messages::Response::Pong => {
            println!(
                "pong from {} (agent v{}, rtt {:?})",
                transport.describe(),
                session.hello().agent_version,
                started.elapsed()
            );
            Ok(ExitCode::SUCCESS)
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected Pong, got {other:?}"),
        )),
    }
}

fn print_report(r: &RemoteReport) {
    if r.paused {
        println!("SKIPPED — sync is PAUSED by the sandbox agent (the MCP resume tool unpauses)");
        for p in &r.problems {
            println!("problem: {}: {}", p.0, p.1);
        }
        return;
    }
    if r.dry_run {
        println!("DRY RUN — nothing was mutated, no state written");
    }
    println!("trust-base: {}", r.trust_base);
    println!(
        "planned: {} remove(s), {} materialize(s)",
        r.planned_removes, r.planned_materializes
    );
    println!(
        "applied: {}  deleted: {}  failed: {}",
        r.applied, r.deleted, r.failed
    );
    for h in &r.honored {
        println!("honored: {h}");
    }
    for p in &r.conflicts_resolved {
        println!(
            "conflict resolved (newest wins): {p} — loser preserved as a .sync-conflict copy on both sides"
        );
    }
    for p in &r.conflicts_left {
        println!("CONFLICT left for manual resolution: {p}");
    }
    if let Some(h) = &r.halted {
        println!("HALTED before any mutation: {h}");
    }
    println!(
        "archive: {}",
        if r.archive_saved {
            "saved (proven convergence)"
        } else {
            "not saved"
        }
    );
    if !r.problems.is_empty() {
        println!("problems:");
        for (path, msg) in &r.problems {
            println!("  {path}: {msg}");
        }
    }
}

// ---------------------------------------------------------------------------
// arg-shape tests (clap surface only — the logic is in the modules)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("sync").chain(args.iter().copied()))
            .unwrap_or_else(|e| panic!("argv should parse: {e}"))
    }

    #[test]
    fn sync_defaults_exec_transport() {
        let cli = parse(&["sync", "--root", "/tmp/x", "--sandbox", "sync-oc"]);
        match cli.cmd {
            Cmd::Sync(s) => {
                assert_eq!(s.target.sandbox, "sync-oc");
                assert_eq!(s.target.transport, TransportKind::Auto);
                assert!(s.target.relay.is_none());
                assert_eq!(s.target.root_remote, "/sandbox");
                assert!(!s.force && !s.dry_run);
                assert!(s.ignores.is_empty());
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn auto_transport_reads_relay_and_master_key_env() {
        let cli = parse(&[
            "sync",
            "--root",
            "/tmp/x",
            "--sandbox",
            "sync-oc",
            "--relay",
            "/ip4/203.0.113.7/tcp/4002",
            "--master-key-env",
        ]);
        match cli.cmd {
            Cmd::Sync(s) => {
                assert!(s.target.relay.is_some());
                assert!(s.target.master_key_env);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn explicit_transport_flags_parse() {
        let cli = parse(&[
            "status",
            "--sandbox",
            "default--sync-oc",
            "--transport",
            "exec",
        ]);
        match cli.cmd {
            Cmd::Status(s) => assert_eq!(s.transport, TransportKind::Exec),
            _ => panic!("wrong subcommand"),
        }
        let cli = parse(&["ping", "--sandbox", "sbx", "--transport", "p2p"]);
        match cli.cmd {
            Cmd::Ping(p) => assert_eq!(p.transport, TransportKind::P2p),
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn ignore_is_repeatable_and_force_dry_run_flags_exist() {
        let cli = parse(&[
            "sync",
            "--root",
            "/tmp/x",
            "--sandbox",
            "sbx",
            "--ignore",
            "node_modules",
            "--ignore",
            "target/",
            "--force",
            "--dry-run",
        ]);
        match cli.cmd {
            Cmd::Sync(s) => {
                assert_eq!(
                    s.ignores,
                    vec!["node_modules".to_string(), "target/".to_string()]
                );
                assert!(s.force && s.dry_run);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn master_key_sources_conflict() {
        let err = match Cli::try_parse_from([
            "sync",
            "sync",
            "--root",
            "/tmp/x",
            "--sandbox",
            "sbx",
            "--relay",
            "/ip4/x/tcp/1",
            "--master-key-env",
            "--master-key-file",
            "/tmp/k",
        ]) {
            Err(e) => e,
            Ok(_) => panic!("conflicting master key sources must not parse"),
        };
        assert!(err.to_string().contains("cannot be used with"));
    }

    #[test]
    fn default_agent_path_matches_the_install_layout() {
        assert_eq!(
            default_agent_path("/sandbox"),
            format!("/sandbox/.sync-agent/agents/{VERSION}/sync-agent")
        );
    }
}
