//! sync-agent — the remote side that runs in the sandbox pod.
//!
//! Roles (plan §1/§2):
//! - `serve`  : stdio mode — speaks the sync protocol on stdin/stdout (M2): Hello
//!   identity, chunked scan, raw-payload read/stage with digest gates, staged
//!   transitions through sync-core primitives. Spawned via `oc exec`
//!   (fallback/bootstrap transport) now, p2p dial-in later.
//! - `install`: self-install — move the uploaded binary to a versioned path on the
//!   sync root + version GC (mutagen install.go pattern, M2).
//! - `p2p`    : daemon mode — dials OUT to the VPS relay (rust-libp2p, M3); runs
//!   in the sync sidecar container; serves the PVC sync root over relayed/direct
//!   libp2p streams (p2p.rs).
//! - `mcp`    : sandbox-side MCP control-plane server on stdio (M3.5, mcp_mode.rs)
//!   — sync status/pause/resume/resolve/now/ignore for the in-sandbox OpenCode
//!   agent. STDOUT IS THE MCP TRANSPORT in this mode.
//!
//! STDOUT IS THE PROTOCOL CHANNEL on exec transports: every log line in serve/install
//! modes goes to stderr. (`--version` is the only stdout user; no protocol is active
//! on that path.)
//!
//! The handshake (magic bytes → version) lives in sync-proto and is the first thing
//! every protocol role does, so banner noise on exec transports fails loudly instead
//! of corrupting frames.

mod install;
mod mcp_mode;
mod p2p;
mod serve;
mod tunnel;

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Join stdin/stdout locks into the single Read+Write the protocol functions expect.
/// (M2 keeps this for the exec transport; the p2p mode uses a libp2p stream instead.)
struct StdDuplex<'a> {
    r: io::StdinLock<'a>,
    w: io::StdoutLock<'a>,
}

impl Read for StdDuplex<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.r.read(buf)
    }
}

impl Write for StdDuplex<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.w.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => cmd_serve(&args[1..]),
        Some("install") => cmd_install(&args[1..]),
        Some("p2p") => cmd_p2p(&args[1..]),
        Some("mcp") => cmd_mcp(&args[1..]),
        Some("--version") | Some("version") | None => {
            println!("sync-agent {VERSION}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!(
                "unknown subcommand: {other}\nusage: sync-agent [serve|install|p2p|mcp|version]"
            );
            ExitCode::FAILURE
        }
    }
}

/// Pull `--root R` / `--root=R` (any position) out of `args`; returns
/// (first non-flag positional, root override).
fn parse_args(args: &[String]) -> (Option<String>, Option<String>) {
    let mut root = None;
    let mut positional = None;
    let mut skip_next = false;
    for (i, a) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if a == "--root" {
            root = args.get(i + 1).cloned();
            skip_next = true;
        } else if let Some(v) = a.strip_prefix("--root=") {
            root = Some(v.to_string());
        } else if positional.is_none() {
            positional = Some(a.clone());
        }
    }
    (positional, root)
}

/// Sync root resolution (serve + install + p2p): `--root` wins, then $SYNC_AGENT_ROOT, then
/// /sandbox when it exists (the OpenShell workspace convention), then `.`. The result
/// is canonicalized: a missing root fails loudly instead of serving a phantom, and
/// Hello reports the real path (scan_with_cache also rejects symlinked roots).
fn resolve_root(override_root: Option<&str>) -> io::Result<PathBuf> {
    let candidate = match override_root {
        Some(r) => PathBuf::from(r),
        None => match std::env::var("SYNC_AGENT_ROOT") {
            Ok(r) if !r.is_empty() => PathBuf::from(r),
            _ => {
                let sandbox = PathBuf::from("/sandbox");
                if sandbox.is_dir() {
                    sandbox
                } else {
                    PathBuf::from(".")
                }
            }
        },
    };
    candidate.canonicalize()
}

/// M2: run the protocol server over stdio until Shutdown or the transport dies.
fn cmd_serve(args: &[String]) -> ExitCode {
    let (_positional, root_arg) = parse_args(args);
    let root = match resolve_root(root_arg.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sync-agent: cannot resolve sync root: {e}");
            return ExitCode::FAILURE;
        }
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut stream = StdDuplex {
        r: stdin.lock(),
        w: stdout.lock(),
    };

    eprintln!("sync-agent {VERSION}: serving {}", root.display());
    match serve::serve(&mut stream, &root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sync-agent: serve failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// M3: `p2p --relay ADDR [--sandbox-id ID] [--master-key-file F] [--root R]` —
/// the daemon mode: dial OUT to the VPS relay, hold a reservation so the daemon
/// can dial us via the relay circuit, and serve the sync root over libp2p streams
/// (see p2p.rs). Identity is derived from (master key, sandbox id) — the daemon
/// computes the same PeerId and needs no rendezvous service.
fn cmd_p2p(args: &[String]) -> ExitCode {
    let pargs = match p2p::parse_p2p_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "sync-agent p2p: {e}\nusage: sync-agent p2p --relay /ip4/VPS/tcp/PORT[/p2p/RELAY_PEER] \
                 [--sandbox-id ID] [--master-key-file F] [--root R] \
                 [--tunnel NAME@PORT[:TOOL,TOOL,...]]... (service tunnel; e.g. --tunnel memory@7402:memory_store,memory_delete)"
            );
            return ExitCode::FAILURE;
        }
    };
    let master = match p2p::load_master_key(pargs.master_key_file.as_deref()) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("sync-agent p2p: {e}");
            return ExitCode::FAILURE;
        }
    };
    let sandbox_id = match p2p::resolve_sandbox_id(pargs.sandbox_id.as_deref()) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("sync-agent p2p: {e}");
            return ExitCode::FAILURE;
        }
    };
    let relay = match pargs.relay.as_deref() {
        Some(r) => match r.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("sync-agent p2p: --relay {r:?} is not a valid multiaddr: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            eprintln!(
                "sync-agent p2p: --relay is required (e.g. /ip4/VPS/tcp/4001/p2p/RELAY_PEER)"
            );
            return ExitCode::FAILURE;
        }
    };
    let root = match resolve_root(pargs.root.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sync-agent p2p: cannot resolve sync root: {e}");
            return ExitCode::FAILURE;
        }
    };

    let tunnel_specs = match tunnel::parse_tunnel_specs(&pargs.tunnel) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sync-agent p2p: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cfg = p2p::P2pConfig {
        master,
        sandbox_id,
        relay,
        root,
        protocol: p2p::P2pConfig::stream_protocol(),
        tunnel: tunnel_specs,
    };
    match run_p2p_runtime(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sync-agent: p2p failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Block on the p2p agent inside a dedicated multi-thread tokio runtime (the
/// swarm + spawn_blocking serve sessions need worker threads).
fn run_p2p_runtime(cfg: p2p::P2pConfig) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    rt.block_on(p2p::run_agent(cfg))
}

/// M3.5: `mcp [--root R]` — the sandbox-side MCP control-plane server on stdio
/// (see mcp_mode.rs). The sync root resolves exactly like serve mode. STDOUT IS
/// THE MCP TRANSPORT here — nothing else may write stdout in this mode (rmcp
/// logs via tracing to stderr; our banners are stderr too).
fn cmd_mcp(args: &[String]) -> ExitCode {
    let (_positional, root_arg) = parse_args(args);
    let root = match resolve_root(root_arg.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sync-agent: cannot resolve sync root: {e}");
            return ExitCode::FAILURE;
        }
    };

    match mcp_mode::run(&root) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sync-agent: mcp server failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// M2: `install <staged-path> [--root R]` — rename the uploaded binary to the
/// versioned path + GC older versions (mutagen install.go pattern).
fn cmd_install(args: &[String]) -> ExitCode {
    let (positional, root_arg) = parse_args(args);
    let Some(staged) = positional else {
        eprintln!("usage: sync-agent install <staged-path> [--root R]");
        return ExitCode::FAILURE;
    };
    let root = match resolve_root(root_arg.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sync-agent: cannot resolve sync root: {e}");
            return ExitCode::FAILURE;
        }
    };

    match install::install(std::path::Path::new(&staged), &root) {
        Ok(path) => {
            // STDOUT IS THE PROTOCOL CHANNEL on exec transports — the final agent
            // path is reported on STDERR only.
            eprintln!("{}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sync-agent: install failed: {e}");
            ExitCode::FAILURE
        }
    }
}
