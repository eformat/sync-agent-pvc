//! Transports (M3): the duplex stream between the laptop CLI and the in-sandbox
//! sync agent, plus the agent self-install path.
//!
//! Two implementations (plan §1 transport ladder):
//! - [`OcExec`] — `oc exec` subprocess with piped stdio (binary-safe non-tty,
//!   M0 spike (a)); the bootstrap/fallback transport. Auto-injects the agent
//!   binary onto the sync root (mutagen install.go pattern; the agent's own
//!   `install` subcommand does versioning + GC).
//! - [`P2p`] — libp2p stream to the in-pod sidecar over our VPS relay
//!   (relay-v2 + best-effort DCUtR hole-punch). The agent's PeerId is
//!   DETERMINISTICALLY derived from (master key, sandbox_id) — the daemon
//!   computes it and dials `<relay>/p2p-circuit/p2p/<agent-peer>` directly
//!   (no DHT, no rendezvous protocol). Trust model (v1): noise encryption on
//!   every link; the daemon TOFU-pins the agent PeerId per sandbox and refuses
//!   a mismatch (a master-key rotation or an impostor both trip the pin —
//!   connecting to a "new" sandbox with stale PVC data silently is exactly
//!   what the pin exists to prevent).
//!
//! All cluster access rides the `oc` subprocess honoring KUBECONFIG — no
//! kube-rs. Every failure mode is a loud `io::Error`; nothing is retried or
//! guessed silently.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use sync_proto::p2p::{derive_sandbox_identity_seed, P2P_STREAM_PROTOCOL};

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

/// A duplex byte stream (exec stdio, libp2p stream bridged to std, in-memory
/// duplex in tests).
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// One connectable path to a sync agent.
pub trait Transport {
    /// Establish a session stream to the remote agent. May block (exec spawn,
    /// relay dial + hole-punch). The stream is raw: the caller wraps it in
    /// `sync_proto::session::Session::client` (magic + version + Hello).
    ///
    /// # Errors
    /// Propagates transport setup failures (oc spawn errors, relay dial
    /// failures, pin mismatches).
    fn connect(&mut self) -> io::Result<Box<dyn ReadWrite>>;

    /// One-line human description for status/UI output.
    fn describe(&self) -> String;

    /// Make sure an up-to-date agent is installed at the remote. Default:
    /// nothing to do (the P2P sidecar bakes the agent into its image; only
    /// the exec transport injects).
    ///
    /// The reference [`OcExec`] implementation probes with a full handshake:
    /// a healthy agent closes the probe; a missing/stale one is uploaded via
    /// `oc exec -i` and installed by the uploaded binary itself. The probe
    /// connection is always torn down — the caller opens its own session
    /// afterwards.
    fn ensure_agent(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// The path the most recent `connect()` landed on. `"exec"` for the exec
    /// transport; `"direct"` / `"relayed"` for p2p (surfaced in the target
    /// snapshot + UI badge — M4.5: the UI should say so).
    fn last_path(&self) -> &'static str {
        "exec"
    }
}

// ---------------------------------------------------------------------------
// OcExec — the oc exec subprocess transport
// ---------------------------------------------------------------------------

/// Transport over `oc exec` stdio. The agent is spawned inside the sandbox pod
/// with piped stdio; our side of the pipes IS the protocol duplex.
#[derive(Debug, Clone)]
pub struct OcExec {
    pub namespace: String,
    pub pod: String,
    /// Absolute root-relative path of the agent binary inside the pod.
    /// Convention (agent install.rs): `<root>/.sync-agent/agents/<version>/sync-agent`.
    pub remote_agent_path: String,
    /// Explicit kubeconfig (None → oc's own resolution: KUBECONFIG env / default).
    pub kubeconfig: Option<PathBuf>,
    /// The sync root the agent serves (`--root`).
    pub root: String,
    /// The oc binary (env SYNC_OC for testability — tests point it at a shim).
    pub oc_binary: String,
    /// Local path of the sync-agent binary for [`OcExec::ensure_agent`]
    /// (None → [`default_agent_bin`] discovery).
    pub agent_bin: Option<PathBuf>,
    /// Agent version pinned at the last successful handshake; later probes
    /// expect equality (drift ⇒ re-inject).
    agent_version: Option<String>,
}

impl OcExec {
    pub fn new(
        namespace: impl Into<String>,
        pod: impl Into<String>,
        root: impl Into<String>,
    ) -> Self {
        OcExec {
            namespace: namespace.into(),
            pod: pod.into(),
            remote_agent_path: String::new(),
            kubeconfig: None,
            root: root.into(),
            oc_binary: "oc".into(),
            agent_bin: None,
            agent_version: None,
        }
    }

    /// The `oc ... exec` argv for one remote command. Kept pure for tests:
    /// `oc [--kubeconfig K] exec [-i] -n NS POD -- CMD...`
    fn exec_argv(&self, interactive: bool, remote_cmd: &[String]) -> Vec<String> {
        let mut argv = vec![self.oc_binary.clone()];
        if let Some(kc) = &self.kubeconfig {
            argv.push("--kubeconfig".into());
            argv.push(kc.display().to_string());
        }
        argv.push("exec".into());
        if interactive {
            argv.push("-i".into());
        }
        argv.push("-n".into());
        argv.push(self.namespace.clone());
        argv.push(self.pod.clone());
        argv.push("--".into());
        argv.extend(remote_cmd.iter().cloned());
        argv
    }

    fn exec_command(&self, interactive: bool, remote_cmd: &[String]) -> Command {
        let argv = self.exec_argv(interactive, remote_cmd);
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd
    }

    /// The remote `serve` command line.
    fn serve_cmd(&self) -> Vec<String> {
        vec![
            self.remote_agent_path.clone(),
            "serve".into(),
            "--root".into(),
            self.root.clone(),
        ]
    }

    /// Spawn the agent with piped stdio. Stdout = protocol channel, stdin =
    /// protocol input, stderr captured (agent logs; included in errors).
    /// `-i` is REQUIRED: without it `oc exec` does not attach stdin and the
    /// agent's handshake reads instant EOF (requests flow client→agent on
    /// stdin — the protocol is bidirectional by design; caught live in the
    /// exec-fallback gate, 2026-11-06).
    fn spawn_serve(&self) -> io::Result<ProcDuplex> {
        let mut cmd = self.exec_command(true, &self.serve_cmd());
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| io::Error::other(format!("spawn {} exec: {e}", self.oc_binary)))?;
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let stdin = child.stdin.take().expect("stdin was piped");
        Ok(ProcDuplex {
            r: stdout,
            w: stdin,
            child: Some(child),
            stderr: Some(stderr),
        })
    }

    /// Whether a connect/handshake failure means the agent should be
    /// (re-)uploaded: a version mismatch, or the exec itself failing because
    /// the binary is missing.
    fn is_reinjectable(e: &io::Error) -> bool {
        let msg = e.to_string();
        msg.contains("protocol version mismatch")
            || msg.contains("executable file not found")
            || msg.contains("did not send the sync-agent magic")
    }

    /// The upload target on the sync root (scanner-skipped name convention).
    fn upload_tmp_path(&self) -> String {
        format!(
            "{}/.sync-agent-tmp-upload-{}",
            self.root,
            std::process::id()
        )
    }

    /// Upload the local agent binary and run its own `install` subcommand:
    /// (1) `oc exec -i ... sh -c 'cat > TMP'` with the binary on stdin,
    /// (2) `oc exec ... sh -c 'chmod +x TMP && TMP install TMP --root ROOT'`.
    /// Two execs: the uploaded file cannot exec itself from inside the cat.
    fn reinject(&mut self) -> io::Result<()> {
        let bin = self
            .agent_bin
            .clone()
            .or_else(default_agent_bin)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "local sync-agent binary not found for agent injection — pass --agent-bin \
                     (the sync-agent binary built from this workspace) or install it at \
                     ~/.local/lib/sync-agent-pvc/sync-agent",
                )
            })?;
        let bytes = fs::read(&bin).map_err(|e| {
            io::Error::other(format!(
                "cannot read local agent binary {}: {e}",
                bin.display()
            ))
        })?;

        // (1) upload: EXACTLY the binary bytes onto the root (M0 spike (a)
        // proved exec stdin binary-safe; ~340KB, far under any limits).
        let tmp = self.upload_tmp_path();
        let mut upload = self.exec_command(
            true,
            &[
                "sh".into(),
                "-c".into(),
                format!("cat > '{}'", sh_quote(&tmp)),
            ],
        );
        upload
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = upload.spawn().map_err(|e| {
            io::Error::other(format!("spawn {} exec (upload): {e}", self.oc_binary))
        })?;
        {
            let mut stdin = child.stdin.take().expect("stdin was piped");
            stdin.write_all(&bytes)?;
            stdin.flush()?;
        } // dropping stdin closes it → sh finishes cat
        let out = child.wait_with_output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "agent upload failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        // (2) install: the UPLOADED binary moves itself to the versioned path
        // and GCs other versions (agent install.rs). Mode bits only (§8).
        let install_cmd = format!(
            "chmod +x '{t}' && '{t}' install '{t}' --root '{r}'",
            t = sh_quote(&tmp),
            r = sh_quote(&self.root),
        );
        let mut install = self.exec_command(false, &["sh".into(), "-c".into(), install_cmd]);
        install.stdout(Stdio::piped()).stderr(Stdio::piped());
        let out = install
            .spawn()
            .map_err(|e| io::Error::other(format!("spawn {} exec (install): {e}", self.oc_binary)))?
            .wait_with_output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "agent install failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    /// Probe the agent with a full handshake. On success the probe connection
    /// is shut down cleanly and the Hello returned (version pinned). On a
    /// missing/stale agent the probe error is [`OcExec::is_reinjectable`].
    fn probe(&mut self) -> io::Result<sync_proto::messages::Hello> {
        let mut stream = self.spawn_serve()?;
        match sync_proto::session::Session::client(&mut stream) {
            Ok(mut session) => {
                let hello = session.hello().clone();
                // Clean end: the agent GCs its staging area on Shutdown/Bye.
                let _ = session.call(&sync_proto::messages::Request::Shutdown);
                drop(stream);
                self.agent_version = Some(hello.agent_version.clone());
                Ok(hello)
            }
            Err(e) => {
                // Capture the child's stderr tail for the error message (oc
                // exec failures explain themselves there).
                let detail = stream.take_stderr_tail();
                drop(stream); // kills the probe child
                let mut msg = format!("agent probe: {e}");
                if !detail.is_empty() {
                    msg.push_str(&format!(" ({detail})"));
                }
                Err(io::Error::new(e.kind(), msg))
            }
        }
    }
}

impl Transport for OcExec {
    fn connect(&mut self) -> io::Result<Box<dyn ReadWrite>> {
        Ok(Box::new(self.spawn_serve()?))
    }

    fn describe(&self) -> String {
        format!(
            "exec pod={}/{} root={} agent={} (via {})",
            self.namespace, self.pod, self.root, self.remote_agent_path, self.oc_binary
        )
    }

    fn ensure_agent(&mut self) -> io::Result<()> {
        for _ in 0..2 {
            match self.probe() {
                Ok(hello) => {
                    if let Some(pinned) = self.agent_version.clone() {
                        if pinned != hello.agent_version {
                            // A different agent version answered at our pinned
                            // path — replace it with OUR binary.
                            self.reinject()?;
                            continue;
                        }
                    }
                    return Ok(());
                }
                Err(e) => {
                    if !Self::is_reinjectable(&e) {
                        return Err(e);
                    }
                    self.reinject()?;
                }
            }
        }
        Err(io::Error::other(
            "agent still unhealthy after two injection attempts",
        ))
    }
}

/// Quote a path for `sh -c` (single-quote shell safety).
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Default discovery order for the local sync-agent binary (used only by the
/// exec transport's injection path):
/// 1. sibling cargo target dir (dev convenience — the workspace target the CLI
///    itself was built into, debug then release; compiled-in path, may not
///    exist for installed binaries),
/// 2. `~/.local/lib/sync-agent-pvc/sync-agent` (the install location for
///    released builds).
fn default_agent_bin() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for profile in ["debug", "release"] {
        let candidate = manifest
            .join("../../target")
            .join(profile)
            .join("sync-agent");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let home = std::env::var("HOME").ok()?;
    let installed = PathBuf::from(home).join(".local/lib/sync-agent-pvc/sync-agent");
    installed.is_file().then_some(installed)
}

/// One spawned `oc exec` process: the protocol rides stdin/stdout; stderr is
/// captured for diagnostics; the child is killed when the duplex is dropped
/// (v1 cancellation idiom — kill/close; the agent exits without corrupting
/// anything and the next session cleans up).
pub struct ProcDuplex {
    r: ChildStdout,
    w: ChildStdin,
    child: Option<Child>,
    stderr: Option<ChildStderr>,
}

impl ProcDuplex {
    /// Best-effort tail of the child's stderr. Only attempted when the child
    /// has EXITED (a live child's stderr pipe would block the read forever);
    /// empty otherwise. Version-mismatch probes carry their own message, so
    /// the tail is diagnostics for the exec-failure case (where oc exits).
    fn take_stderr_tail(&mut self) -> String {
        let exited = self
            .child
            .as_mut()
            .and_then(|c| c.try_wait().ok())
            .flatten()
            .is_some();
        if !exited {
            return String::new();
        }
        let Some(stderr) = self.stderr.take() else {
            return String::new();
        };
        let mut buf = Vec::new();
        let _ = stderr.take(4096).read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).trim().to_string()
    }
}

impl Read for ProcDuplex {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.r.read(buf)
    }
}

impl Write for ProcDuplex {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.w.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

impl Drop for ProcDuplex {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// P2p — libp2p stream over our relay (target transport, plan §1)
// ---------------------------------------------------------------------------

/// Overall timeout for the dial sequence (relay → circuit → protocol stream).
const P2P_DIAL_TIMEOUT: Duration = Duration::from_secs(60);

/// libp2p P2P transport: dials the VPS relay, then the deterministic agent
/// peer through it (`/p2p-circuit`), then opens the sync protocol stream.
/// DCUtR hole-punch upgrade runs best-effort in the background — the relayed
/// connection is fully usable on its own (plan §1: "hole-punch to direct when
/// NAT allows, relayed otherwise").
#[derive(Debug, Clone)]
pub struct P2p {
    /// The relay's listening multiaddr, e.g. `/ip4/<vps>/tcp/4002/p2p/<relay-peer>`.
    pub relay_multiaddr: String,
    /// The relay's PeerId when the multiaddr does not carry one.
    pub relay_peer: Option<String>,
    pub sandbox_id: String,
    /// Per-sandbox master key (never logged, never printed).
    pub master_key: [u8; 32],
    /// The sync root the agent serves (reported in Hello; used by status).
    pub root: String,
    /// Attempt a DCUtR hole-punch upgrade before opening the sync stream
    /// (direct connection when NAT allows, relayed circuit otherwise).
    pub hole_punch: bool,
    /// The path the LAST connect landed on ("direct" | "relayed") — surfaced
    /// by the daemon in the target snapshot / UI badge.
    pub path: std::cell::Cell<&'static str>,
}

/// The agent's PeerId, derived exactly the way the agent derives its own
/// identity (sync_proto::p2p::derive_sandbox_identity_seed → ed25519).
pub fn agent_peer_id(master_key: &[u8; 32], sandbox_id: &str) -> io::Result<libp2p::PeerId> {
    let seed = derive_sandbox_identity_seed(master_key, sandbox_id);
    let keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("identity seed: {e}")))?;
    Ok(keypair.public().to_peer_id())
}

/// Daemon-side libp2p behaviours: the relay CLIENT (circuit dials), identify
/// (learns OUR observed public address from the relay — the punch candidate
/// source), DCUtR (best-effort direct upgrade) and the raw-stream control for
/// `P2P_STREAM_PROTOCOL`.
#[derive(libp2p::swarm::NetworkBehaviour)]
struct P2pBehaviours {
    relay: libp2p::relay::client::Behaviour,
    identify: libp2p::identify::Behaviour,
    dcutr: libp2p::dcutr::Behaviour,
    stream: libp2p_stream::Behaviour,
}

/// Identify protocol version — MUST match the relay's (`crates/relay`), the
/// only peer positioned to observe our NAT'd source address. The relay's
/// identify response reports our public addr as it saw it; the swarm turns
/// that into a `NewExternalAddrCandidate`, which is exactly the candidate
/// list DCUtR exchanges during the punch handshake.
const IDENTIFY_PROTOCOL_VERSION: &str = "sync-agent-pvc/relay/1";

/// How long the dial waits for a DCUtR punch to land before opening the sync
/// stream on whatever connection survives (direct if the punch worked, the
/// relayed circuit otherwise).
const PUNCH_WINDOW: Duration = Duration::from_secs(12);

/// True if the multiaddr is a circuit-relayed address (contains /p2p-circuit).
fn is_relayed_addr(addr: &libp2p::Multiaddr) -> bool {
    addr.iter()
        .any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit))
}

impl P2p {
    /// Build the relayed dial address for the agent peer:
    /// `<relay>/p2p-circuit/p2p/<agent>`. The relay's own PeerId must be
    /// present — from the multiaddr or `relay_peer`.
    fn circuit_addr(&self, agent_peer: libp2p::PeerId) -> io::Result<libp2p::Multiaddr> {
        let mut addr: libp2p::Multiaddr = self.relay_multiaddr.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("relay multiaddr: {e}"))
        })?;
        if addr
            .iter()
            .all(|p| !matches!(p, libp2p::multiaddr::Protocol::P2p(_)))
        {
            let peer = self.relay_peer.as_deref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "relay multiaddr carries no /p2p/<peer> and --relay-peer was not given",
                )
            })?;
            let peer_id: libp2p::PeerId = peer.parse().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("relay peer id: {e}"))
            })?;
            addr.push(libp2p::multiaddr::Protocol::P2p(peer_id));
        }
        addr.push(libp2p::multiaddr::Protocol::P2pCircuit);
        addr.push(libp2p::multiaddr::Protocol::P2p(agent_peer));
        Ok(addr)
    }

    /// Blocking connect: fresh MULTI-THREAD runtime per call (one-shot M3 — the
    /// M4 daemon will hold a long-lived runtime and reuse the swarm).
    /// WHY multi-thread: the swarm pump task must be DRIVEN while the caller is
    /// parked in `Handle::block_on` on the returned stream — a current-thread
    /// runtime's pump starves there and every handshake read hangs forever
    /// (hit live on the first relayed session, 2026-11-06).
    fn dial_and_open(&self, agent_peer: libp2p::PeerId) -> io::Result<OwnedP2pStream> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let circuit = self.circuit_addr(agent_peer)?;
        // The relay's own address (dials go to the relay first, then through
        // the circuit to the agent).
        let relay_addr_base: libp2p::Multiaddr = self.relay_multiaddr.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("relay multiaddr: {e}"))
        })?;
        let relay_peer = {
            // The relay peer id is the /p2p/<peer> on the relay address (or
            // the explicit --relay-peer override).
            let from_addr = relay_addr_base.iter().find_map(|p| match p {
                libp2p::multiaddr::Protocol::P2p(id) => Some(id),
                _ => None,
            });
            match from_addr {
                Some(id) => id,
                None => self
                    .relay_peer
                    .as_deref()
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidInput, format!("relay peer id: {e}"))
                    })?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "relay multiaddr carries no /p2p/<peer> and --relay-peer was not given",
                        )
                    })?,
            }
        };

        let daemon_keypair = libp2p::identity::Keypair::generate_ed25519();
        let mut control_slot: Option<libp2p_stream::Control> = None;
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(daemon_keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default().nodelay(true),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )
            .map_err(|e| io::Error::other(format!("tcp transport: {e}")))?
            .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)
            .map_err(|e| io::Error::other(format!("relay client transport: {e}")))?
            .with_behaviour(|key, relay| {
                let stream_behaviour = libp2p_stream::Behaviour::new();
                control_slot = Some(stream_behaviour.new_control());
                P2pBehaviours {
                    relay,
                    identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                        IDENTIFY_PROTOCOL_VERSION.to_string(),
                        key.public(),
                    )),
                    dcutr: libp2p::dcutr::Behaviour::new(key.public().to_peer_id()),
                    stream: stream_behaviour,
                }
            })
            .map_err(|e| io::Error::other(format!("behaviour: {e}")))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
            .build();

        let mut control = control_slot.take().ok_or_else(|| {
            io::Error::other("internal: stream control was not captured during behaviour build")
        })?;
        let (stream, direct) = rt.block_on(async {
            swarm
                .dial(relay_addr_base)
                .map_err(|e| io::Error::other(format!("relay dial: {e}")))?;
            tokio::time::timeout(P2P_DIAL_TIMEOUT, async {
                let mut relay_up = false;
                let mut agent_up = false;
                let mut circuit_dialed = false;
                // The relayed connection's id (for the post-punch teardown),
                // the punch bookkeeping, and whether we're waiting for the
                // relayed conn's closure before opening the stream on the
                // surviving direct one.
                let mut agent_relayed_conn: Option<libp2p::swarm::ConnectionId> = None;
                let mut direct = false;
                let mut closing_relayed = false;
                let mut punch_deadline: Option<tokio::time::Instant> = None;
                use futures::StreamExt;
                loop {
                    // Punch phase: both links are up and no direct connection
                    // yet — keep polling events under the punch deadline. The
                    // bounded select keeps identify/relay/dcutr traffic moving
                    // while we wait (a plain pending() await would starve the
                    // swarm and the punch could never conclude).
                    let event = if relay_up && agent_up && !direct && !closing_relayed {
                        if !self.hole_punch {
                            break;
                        }
                        let deadline = *punch_deadline
                            .get_or_insert(tokio::time::Instant::now() + PUNCH_WINDOW);
                        if tokio::time::Instant::now() >= deadline {
                            break; // window elapsed — the relayed circuit wins
                        }
                        match tokio::time::timeout_at(deadline, swarm.select_next_some()).await {
                            Ok(ev) => ev,
                            Err(_) => break, // window elapsed
                        }
                    } else {
                        swarm.select_next_some().await
                    };
                    match event {
                        libp2p::swarm::SwarmEvent::ConnectionEstablished {
                            peer_id,
                            connection_id,
                            endpoint,
                            ..
                        } => {
                            if peer_id == relay_peer {
                                relay_up = true;
                            } else if peer_id == agent_peer {
                                if is_relayed_addr(endpoint.get_remote_address()) {
                                    agent_relayed_conn = Some(connection_id);
                                    agent_up = true;
                                } else {
                                    // A direct connection to the agent — the
                                    // punch landed. Retire the relayed circuit:
                                    // the sync stream is opened on the surviving
                                    // DIRECT connection (opening it before the
                                    // migration would bind it to the relayed
                                    // conn — that was the M3 teardown).
                                    direct = true;
                                    if let Some(rc) = agent_relayed_conn {
                                        swarm.close_connection(rc);
                                        closing_relayed = true;
                                    } else {
                                        break;
                                    }
                                }
                            }
                            // Dial the agent through the relay exactly once,
                            // as soon as the relay link is up.
                            if relay_up && !agent_up && !circuit_dialed {
                                swarm
                                    .dial(circuit.clone())
                                    .map_err(|e| io::Error::other(format!("circuit dial: {e}")))?;
                                circuit_dialed = true;
                            }
                        }
                        libp2p::swarm::SwarmEvent::ConnectionClosed { connection_id, .. }
                            if closing_relayed && Some(connection_id) == agent_relayed_conn =>
                        {
                            break;
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2pBehavioursEvent::Dcutr(
                            libp2p::dcutr::Event {
                                remote_peer_id,
                                result,
                            },
                        )) if remote_peer_id == agent_peer && !direct => {
                            // The punch concluded from this side. On success:
                            // retire the relayed connection (the direct one is
                            // established or imminent); on failure keep the
                            // relayed circuit as the session path — libp2p does
                            // NOT close the relayed conn on punch failure
                            // (verified in dcutr 0.15 source: retry ×3, then
                            // an Err event to the app).
                            match result {
                                Ok(_) => {
                                    direct = true;
                                    if let Some(rc) = agent_relayed_conn {
                                        swarm.close_connection(rc);
                                        closing_relayed = true;
                                    } else {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("daemon: hole-punch failed — staying relayed ({e})");
                                    break;
                                }
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(P2pBehavioursEvent::Dcutr(_)) => {}
                        libp2p::swarm::SwarmEvent::OutgoingConnectionError {
                            peer_id,
                            error,
                            ..
                        } => {
                            let target = peer_id.map(|p| p.to_string()).unwrap_or_default();
                            if agent_up {
                                // A failed PUNCH dial (direct attempt at the
                                // agent's candidate address) — not fatal; the
                                // dcutr behaviour retries and reports its own
                                // outcome.
                                eprintln!("daemon: punch dial to {target} failed: {error}");
                                continue;
                            }
                            return Err(io::Error::other(format!(
                                "p2p dial failed ({target}): {error}"
                            )));
                        }
                        _ => {}
                    }
                }
                let opened = control
                    .open_stream(agent_peer, libp2p::StreamProtocol::new(P2P_STREAM_PROTOCOL))
                    .await
                    .map_err(|e| io::Error::other(format!("open sync stream: {e}")))?;
                Ok((opened, direct))
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("p2p dial timed out after {P2P_DIAL_TIMEOUT:?}"),
                )
            })?
        })?;
        // KEEP THE MUXER DRIVEN: the swarm pump must outlive connect() — the
        // dial loop above ENDED, and a stopped pump means yamux frames never
        // move again: every std read on the stream hangs forever (the agent
        // sees EOF mid-handshake when the client is eventually killed; hit
        // live on the first relayed session, 2026-11-06). Handle::spawn keeps
        // it running on the runtime's workers for the life of the session.
        let pump_handle = rt.handle().clone();
        pump_handle.spawn(async move {
            use futures::StreamExt;
            loop {
                swarm.select_next_some().await;
            }
        });
        // libp2p's Stream is !Unpin AND speaks the FUTURES io traits (not
        // tokio's), so tokio_util's SyncIoBridge does not apply; this small
        // equivalent bridges it to blocking std I/O by driving the runtime
        // per call (exactly what SyncIoBridge does internally).
        let stream: std::pin::Pin<Box<libp2p::swarm::Stream>> = Box::pin(stream);
        self.path.set(if direct { "direct" } else { "relayed" });
        Ok(OwnedP2pStream {
            stream,
            handle: rt.handle().clone(),
            _runtime: rt,
        })
    }
}

/// A libp2p stream bridged to blocking std I/O, owning the tokio runtime that
/// drives it. Field order matters: the stream (first) drops before the
/// runtime (second), so the async context outlives every use of the stream.
struct OwnedP2pStream {
    stream: std::pin::Pin<Box<libp2p::swarm::Stream>>,
    handle: tokio::runtime::Handle,
    _runtime: tokio::runtime::Runtime,
}

impl Read for OwnedP2pStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle
            .block_on(futures::AsyncReadExt::read(&mut self.stream, buf))
    }
}

impl Write for OwnedP2pStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle
            .block_on(futures::AsyncWriteExt::write(&mut self.stream, buf))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.handle
            .block_on(futures::AsyncWriteExt::flush(&mut self.stream))
    }
}

impl Transport for P2p {
    fn connect(&mut self) -> io::Result<Box<dyn ReadWrite>> {
        let agent_peer = agent_peer_id(&self.master_key, &self.sandbox_id)?;
        // TOFU pin: strict-first — a recorded pin for this sandbox must match
        // the deterministic peer BEFORE anything dials.
        let mut pins = PeerPins::load_default()?;
        if let Some(pinned) = pins.get(&self.sandbox_id) {
            if pinned != &agent_peer.to_string() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "PEER PIN MISMATCH for sandbox {}: pinned {pinned}, derived {agent_peer}. \
                         Refusing to connect — the master key changed, or something is \
                         impersonating this sandbox. If you rotated the master key on purpose, \
                         delete the pin at {} and re-attach.",
                        self.sandbox_id,
                        PeerPins::default_path().display()
                    ),
                ));
            }
        }
        let stream = self.dial_and_open(agent_peer)?;
        if !pins.contains_key(&self.sandbox_id) {
            // TOFU: first successful connect records the (deterministic) peer.
            pins.insert_and_save(self.sandbox_id.clone(), agent_peer.to_string())?;
        }
        Ok(Box::new(stream))
    }

    fn describe(&self) -> String {
        let peer = agent_peer_id(&self.master_key, &self.sandbox_id)
            .map(|p| p.to_string())
            .unwrap_or_else(|_| "<invalid key>".into());
        format!(
            "p2p sandbox={} agent-peer={peer} relay={} root={} path={}",
            self.sandbox_id,
            self.relay_multiaddr,
            self.root,
            self.last_path()
        )
    }

    fn last_path(&self) -> &'static str {
        self.path.get()
    }
}

// ---------------------------------------------------------------------------
// Peer pins — TOFU → strict (plan §1 key model)
// ---------------------------------------------------------------------------

/// `~/.config/sync-agent-pvc/peer_pins.json` — `{ sandbox_id: peer_id_string }`.
/// First connect records the computed agent PeerId; every later connect is
/// strict (mismatch ⇒ LOUD refusal, never a silent re-pin — a silent re-pin
/// would defeat the whole point of pinning).
#[derive(Debug, Clone, Default)]
pub struct PeerPins {
    path: PathBuf,
    map: std::collections::BTreeMap<String, String>,
}

impl PeerPins {
    /// Pins at the default location (via $HOME — no dirs crate).
    pub fn load_default() -> io::Result<Self> {
        Self::load_at(Self::default_path())
    }

    /// The default pin file path. No dirs crate: $HOME from the environment.
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(home)
            .join(".config")
            .join("sync-agent-pvc")
            .join("peer_pins.json")
    }

    /// Load pins from an explicit path. A MISSING file is an empty map (first
    /// ever connect). A CORRUPT file is a loud error, never a silent reset —
    /// a pin file we cannot parse must not quietly downgrade to "no pins".
    pub fn load_at(path: PathBuf) -> io::Result<Self> {
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(PeerPins {
                    path,
                    map: Default::default(),
                })
            }
            Err(e) => return Err(e),
        };
        let map: std::collections::BTreeMap<String, String> = serde_json::from_slice(&bytes)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "corrupt peer pin file {}: {e} — refusing to downgrade to no pins",
                        path.display()
                    ),
                )
            })?;
        Ok(PeerPins { path, map })
    }

    pub fn get(&self, sandbox_id: &str) -> Option<&String> {
        self.map.get(sandbox_id)
    }

    pub fn contains_key(&self, sandbox_id: &str) -> bool {
        self.map.contains_key(sandbox_id)
    }

    /// Record/update one pin and persist atomically (tmp → rename, 0600).
    pub fn insert_and_save(&mut self, sandbox_id: String, peer_id: String) -> io::Result<()> {
        self.map.insert(sandbox_id, peer_id);
        self.save()
    }

    fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = serde_json::to_vec_pretty(&self.map)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode pins: {e}")))?;
        let tmp = self.path.with_extension("json.tmp");
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                // Pins are trust state — owner-only, same posture as the
                // laptop tokens in plan §4/§9.
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)
    }
}

// ---------------------------------------------------------------------------
// Tests — no cluster, no network: argv/parse/discovery shapes only. The
// protocol-level flows are covered by remote_driver's fake agent; full P2P
// proof is the agent+relay integration (their builders own the loopback test).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use sync_core::types::RelPath;

    fn ocexec() -> OcExec {
        let mut t = OcExec::new("openshell", "default--sync-oc", "/sandbox");
        t.oc_binary = "oc".into();
        t.remote_agent_path = "/sandbox/.sync-agent/agents/0.1.0/sync-agent".into();
        t
    }

    #[test]
    fn exec_argv_carries_exec_ns_pod_and_remote_command() {
        let t = ocexec();
        let cmd = t.serve_cmd();
        // serve is spawned INTERACTIVE (spawn_serve passes true): stdin must be
        // attached or the agent's handshake reads instant EOF.
        let argv = t.exec_argv(true, &cmd);
        assert_eq!(argv[0], "oc");
        assert!(argv.contains(&"exec".to_string()));
        let n = argv.iter().position(|a| a == "-n").unwrap();
        assert_eq!(argv[n + 1], "openshell");
        assert!(argv.contains(&"default--sync-oc".to_string()));
        let dd = argv.iter().position(|a| a == "--").unwrap();
        assert_eq!(
            &argv[dd + 1..],
            &[
                "/sandbox/.sync-agent/agents/0.1.0/sync-agent".to_string(),
                "serve".to_string(),
                "--root".to_string(),
                "/sandbox".to_string()
            ]
        );
        assert!(
            argv.contains(&"-i".to_string()),
            "serve MUST pass stdin (-i): the protocol sends requests client→agent"
        );
    }

    #[test]
    fn exec_argv_kubeconfig_and_interactive_upload() {
        let mut t = ocexec();
        t.kubeconfig = Some(PathBuf::from("/tmp/opencode/kube.cfg"));
        let upload_argv = t.exec_argv(
            true,
            &[
                "sh".into(),
                "-c".into(),
                "cat > '/sandbox/.sync-agent-tmp-upload-1'".into(),
            ],
        );
        assert_eq!(upload_argv[1], "--kubeconfig");
        assert_eq!(upload_argv[2], "/tmp/opencode/kube.cfg");
        assert!(
            upload_argv.contains(&"-i".to_string()),
            "upload needs stdin"
        );
        assert!(upload_argv.iter().any(|a| a.contains("cat > ")));
    }

    #[test]
    fn sh_quote_survives_spaces_and_quotes() {
        assert_eq!(sh_quote("/sandbox/my root"), "'/sandbox/my root'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn reinjectable_classification() {
        assert!(OcExec::is_reinjectable(&io::Error::new(
            io::ErrorKind::InvalidData,
            "protocol version mismatch: peer (0, 2), ours (0, 1)"
        )));
        assert!(OcExec::is_reinjectable(&io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "agent probe: stream ended before the agent magic (noise scan) (exec: \"x\": executable file not found)"
        )));
        assert!(!OcExec::is_reinjectable(&io::Error::other(
            "spawn oc exec: No such file or directory (os error 2)"
        )));
    }

    #[test]
    fn p2p_circuit_address_appends_relay_peer_when_missing() {
        let p = P2p {
            relay_multiaddr: "/ip4/203.0.113.7/tcp/4002".into(),
            relay_peer: Some("12D3KooWQqWcYxCifgqAsynZL2uJUd132gbG3XhZbCQZMs6Dq9Qc".into()),
            sandbox_id: "default--sync-oc".into(),
            master_key: [7u8; 32],
            root: "/sandbox".into(),
            hole_punch: false,
            path: std::cell::Cell::new("relayed"),
        };
        let agent_peer = agent_peer_id(&[7u8; 32], "default--sync-oc").unwrap();
        let addr = p.circuit_addr(agent_peer).unwrap();
        let s = addr.to_string();
        assert!(s.contains("/p2p-circuit/p2p/"), "got {s}");
        assert!(s.ends_with(&agent_peer.to_string()), "got {s}");
        // The relay peer id rides before the circuit hop.
        assert!(s.contains("/p2p/12D3KooW"), "got {s}");
    }

    #[test]
    fn p2p_circuit_address_uses_multiaddr_peer_without_relay_peer() {
        let p = P2p {
            relay_multiaddr:
                "/ip4/203.0.113.7/tcp/4002/p2p/12D3KooWQqWcYxCifgqAsynZL2uJUd132gbG3XhZbCQZMs6Dq9Qc"
                    .into(),
            relay_peer: None,
            sandbox_id: "default--sync-oc".into(),
            master_key: [7u8; 32],
            root: "/sandbox".into(),
            hole_punch: false,
            path: std::cell::Cell::new("relayed"),
        };
        let agent_peer = agent_peer_id(&[7u8; 32], "default--sync-oc").unwrap();
        let addr = p.circuit_addr(agent_peer).unwrap();
        assert!(addr.to_string().contains("/p2p-circuit"));
    }

    #[test]
    fn p2p_circuit_address_requires_a_relay_peer_somehow() {
        let p = P2p {
            relay_multiaddr: "/ip4/203.0.113.7/tcp/4002".into(),
            relay_peer: None,
            sandbox_id: "default--sync-oc".into(),
            master_key: [7u8; 32],
            root: "/sandbox".into(),
            hole_punch: false,
            path: std::cell::Cell::new("relayed"),
        };
        let agent_peer = agent_peer_id(&[7u8; 32], "default--sync-oc").unwrap();
        let err = p.circuit_addr(agent_peer).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn agent_peer_id_is_deterministic_and_key_sensitive() {
        let a1 = agent_peer_id(&[1u8; 32], "default--sync-oc").unwrap();
        let a2 = agent_peer_id(&[1u8; 32], "default--sync-oc").unwrap();
        let b = agent_peer_id(&[2u8; 32], "default--sync-oc").unwrap();
        let other = agent_peer_id(&[1u8; 32], "default--other").unwrap();
        assert_eq!(a1, a2, "deterministic rendezvous");
        assert_ne!(a1, b);
        assert_ne!(a1, other);
    }

    #[test]
    fn peer_pins_tofu_then_strict_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_pins.json");
        let mut pins = PeerPins::load_at(path.clone()).unwrap();
        assert!(pins.get("sbx").is_none(), "no pins on first connect");

        // TOFU: first connect records.
        pins.insert_and_save("sbx".into(), "peer-A".into()).unwrap();
        assert!(path.exists(), "pin file written");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "pins are owner-only trust state");

        // Reload: strict afterwards.
        let pins = PeerPins::load_at(path.clone()).unwrap();
        assert_eq!(pins.get("sbx"), Some(&"peer-A".to_string()));

        // A different peer for the same sandbox is the caller's refusal cue
        // (the Transport refuses; the store just reports what is pinned).
        let pins2 = PeerPins::load_at(path).unwrap();
        assert_ne!(pins2.get("sbx").map(String::as_str), Some("peer-B"));
    }

    #[test]
    fn peer_pins_corrupt_file_is_a_loud_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_pins.json");
        fs::write(&path, b"{not json").unwrap();
        let err = PeerPins::load_at(path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("refusing to downgrade"));
    }

    #[test]
    fn peer_pins_missing_file_is_empty_map() {
        let dir = tempfile::tempdir().unwrap();
        let pins = PeerPins::load_at(dir.path().join("absent.json")).unwrap();
        assert!(pins.get("anything").is_none());
    }

    /// Full transport round trip: OcExec spawn → shim `oc` → the REAL
    /// sync-agent serve loop → handshake → Hello → Ping → scan → Shutdown.
    /// Requires the workspace agent binary (`cargo build --workspace`); skipped
    /// loudly otherwise (`cargo test -p sync-cli` alone does not build it).
    #[test]
    fn ocexec_full_session_flow_through_a_shim_oc() {
        let agent_bin =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/sync-agent");
        if !agent_bin.is_file() {
            eprintln!(
                "skipping: target/debug/sync-agent not built — run `cargo build --workspace`"
            );
            return;
        }
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().to_string_lossy().into_owned();

        // The agent sits at its versioned install path inside the sync root
        // (the layout agent install.rs produces).
        let agent_path = format!("{root}/.sync-agent/agents/0.1.0/sync-agent");
        fs::create_dir_all(
            Path::new(&agent_path)
                .parent()
                .expect("agent path has a parent"),
        )
        .unwrap();
        fs::copy(&agent_bin, &agent_path).unwrap();

        // Shim `oc`: drop everything before `--` and exec the rest — exactly
        // what `oc exec -n NS POD -- CMD` does with CMD's stdio.
        let shim_dir = tempfile::tempdir().unwrap();
        let shim = shim_dir.path().join("oc");
        fs::write(&shim, "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--\" ]; then shift; exec \"$@\"; fi\n  shift\ndone\necho 'shim: no -- in argv' >&2\nexit 9\n")
            .unwrap();
        fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();

        let mut t = OcExec::new("openshell", "default--sync-oc", &root);
        t.oc_binary = shim.display().to_string();
        t.remote_agent_path = agent_path.clone();
        let canonical_root = fs::canonicalize(root_dir.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        t.root = canonical_root.clone();

        // ensure_agent probes (healthy agent → clean probe teardown)…
        t.ensure_agent().expect("probe against the real agent");
        // …then the real connect + session.
        let stream = t.connect().expect("spawn serve through the shim");
        let mut session = sync_proto::session::Session::client(stream).expect("handshake");
        let hello = session.hello().clone();
        assert_eq!(hello.root, canonical_root, "§8 hello reports the real root");
        assert!(hello.root_writable);
        assert_eq!(
            hello.agent_version,
            env!("CARGO_PKG_VERSION"),
            "hello reports the built version"
        );
        assert_eq!(
            session.call(&sync_proto::messages::Request::Ping).unwrap(),
            sync_proto::messages::Response::Pong
        );

        // A file lands on the remote root; a scan sees it; ReadFile returns it.
        fs::write(root_dir.path().join("hello.txt"), "through the exec pipe").unwrap();
        let scan = session
            .scan(&[], &[])
            .expect("chunked scan through the exec transport");
        assert!(scan.tree.contains_key(&RelPath("hello.txt".into())));
        let (size, digest) = match session
            .call(&sync_proto::messages::Request::ReadFile {
                path: "hello.txt".into(),
            })
            .unwrap()
        {
            sync_proto::messages::Response::FileHeader { size, digest, .. } => (size, digest),
            other => panic!("expected FileHeader, got {other:?}"),
        };
        let mut got = Vec::new();
        let verified = session.read_payload_hashed(size, &mut got).unwrap();
        assert_eq!(verified, digest);
        assert_eq!(got, b"through the exec pipe".to_vec());

        // Clean end: Bye, then the child is reaped on drop.
        assert_eq!(
            session
                .call(&sync_proto::messages::Request::Shutdown)
                .unwrap(),
            sync_proto::messages::Response::Bye
        );
    }
}
