//! M3 p2p mode: the agent as a libp2p node serving the sync root over a relayed
//! (and hole-punched direct) connection — plan §1 transport ladder, target rung.
//!
//! Topology (sync_proto::p2p): both endpoints dial OUT to our VPS relay
//! (crates/relay). The rendezvous is cryptographic — the agent's ed25519 identity
//! is DETERMINISTICALLY derived from (master, sandbox_id) — so the daemon computes
//! our PeerId and dials `/…/p2p-circuit/p2p/<agent-peer>` without any DHT or
//! rendezvous protocol. DCUtR upgrades relayed connections to direct when NAT
//! allows; relayed remains the fallback.
//!
//! Wiring per libp2p 0.57 (verified against the v0.57.1 sources / examples):
//! - `SwarmBuilder::…with_relay_client(noise, yamux)` — the builder constructs the
//!   `relay::client::Behaviour` and hands it to the behaviour closure.
//! - A relay RESERVATION (inbound reachability) = `swarm.listen_on(<relay
//!   addr>/p2p-circuit)`; the relay client then dials the relay itself and
//!   requests the reservation (`ReservationReqAccepted`). No manual dial needed
//!   when the relay PeerId is known; an explicit dial is used only to LEARN the
//!   PeerId when `--relay` lacks the `/p2p/<peer>` suffix.
//! - Raw duplex streams: `libp2p_stream::Behaviour` (the 0.57-era raw-stream
//!   mechanism — libp2p 0.57 does NOT bundle a stream behaviour). Accept on
//!   `P2P_STREAM_PROTOCOL`, then bridge each libp2p Stream (futures-style
//!   AsyncRead+AsyncWrite) to a std duplex via
//!   `tokio_util::compat::…compat()` + `SyncIoBridge` and run the UNCHANGED M2
//!   `serve::serve` loop on `spawn_blocking`.
//! - Sessions run detached: a session-level crash logs and never kills the swarm.
//!
//! Resilience: relay disconnects / failed dials / denied reservations re-attempt
//! with 1s → 2s → 5s → 30s(cap) backoff. Every log line goes to stderr (stdout
//! discipline: never a protocol channel in any agent mode).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::core::multiaddr::Protocol;
use libp2p::core::transport::MemoryTransport;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    dcutr, identify, identity, noise, relay, tcp, yamux, Multiaddr, PeerId, Stream, StreamProtocol,
    Transport,
};
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tokio_util::io::SyncIoBridge;

use crate::serve;
use crate::tunnel::{self, TunnelServiceSpec};
use sync_proto::p2p::{derive_daemon_identity_seed, derive_sandbox_identity_seed, P2P_STREAM_PROTOCOL};

/// Identify protocol string (lets the relay + daemon learn our observed address
/// and protocol support; DCUtR requires identify on both sides).
/// Identify protocol version — MUST match the relay's (`crates/relay`,
/// "sync-agent-pvc/relay/1"): the relay is the only peer positioned to
/// observe our NAT'd source address, and its identify RESPONSE is what tells
/// us our own public addr (→ swarm external-address candidate → DCUtR punch
/// candidate). A mismatched protocol string = no candidates = punch attempts
/// with nothing to dial.
const IDENTIFY_PROTOCOL: &str = "sync-agent-pvc/relay/1";

/// Idle-connection timeout. The 0.57 default (10 s) would drop the relay
/// connection between sessions (no ping behaviour in our stack; the client's
/// reservation renewal runs on a ~minute cadence) — keepalive is left to the
/// reservation renewals, so this must comfortably exceed one renewal period.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(600);

/// Reconnect backoff: 1s, 2s, 5s, then the 30s cap (brief §4; no jitter — the
/// deterministic sequence keeps tests reproducible).
const BACKOFF_STEPS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
];
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// The agent's composed behaviour. Field names name the event variants
/// (`AgentBehaviourEvent::RelayClient(…)`, `…::Identify(…)`, …) — the derive
/// names the event enum after the behaviour struct. DCUtR deliberately absent
/// for v1 (relayed-only — see the swarm builder comment).
#[derive(NetworkBehaviour)]
struct AgentBehaviour {
    relay_client: relay::client::Behaviour,
    identify: identify::Behaviour,
    dcutr: dcutr::Behaviour,
    stream: libp2p_stream::Behaviour,
}

// ---------------------------------------------------------------------------
// Identity + config
// ---------------------------------------------------------------------------

/// Derive the agent's libp2p identity from (master, sandbox_id) — the DETERMINISTIC
/// rendezvous: the daemon runs this same derivation to compute our PeerId.
pub fn derive_keypair(master: &[u8; 32], sandbox_id: &str) -> identity::Keypair {
    let seed = derive_sandbox_identity_seed(master, sandbox_id);
    identity::Keypair::ed25519_from_bytes(seed).expect("seed is exactly 32 bytes")
}

/// Resolved p2p-mode configuration (see `cmd_p2p` in main.rs for the flags/env).
pub struct P2pConfig {
    /// Master key material (64 hex bytes; env or 0600 file — NEVER logged).
    pub master: [u8; 32],
    /// Sandbox id scoping the derived identity.
    pub sandbox_id: String,
    /// Relay multiaddr `/ip4/VPS/tcp/PORT[/p2p/RELAY_PEER]` (peer suffix optional;
    /// learned by dialing when absent).
    pub relay: Multiaddr,
    /// Sync root to serve (resolved like serve mode).
    pub root: PathBuf,
    /// The libp2p stream protocol to accept (constant by default, overridable in tests).
    pub protocol: StreamProtocol,
    /// M5 tunnel services (`--tunnel name@port[:spool,tools]`) — empty = no
    /// tunnel client (the sync path is completely unaffected).
    pub tunnel: Vec<TunnelServiceSpec>,
}

impl P2pConfig {
    pub fn stream_protocol() -> StreamProtocol {
        StreamProtocol::new(P2P_STREAM_PROTOCOL)
    }
}

type AgentSwarm = libp2p::Swarm<AgentBehaviour>;

/// Split a relay multiaddr into its dialable base (no `/p2p` component) and an
/// optional trailing relay PeerId. Only the trailing `/p2p/<peer>` is extracted —
/// relay addresses are simple (`/ip4/../tcp/N[/p2p/PEER]`, `/memory/N/...` in tests).
pub(crate) fn split_relay_addr(addr: &Multiaddr) -> (Multiaddr, Option<PeerId>) {
    let mut base = Multiaddr::empty();
    let mut peer = None;
    for proto in addr.iter() {
        match proto {
            Protocol::P2p(id) => peer = Some(id),
            other => base.push(other),
        }
    }
    (base, peer)
}

/// The reservation/listen target: `<base>/p2p/<relay>/p2p-circuit`. The daemon
/// appends `/p2p/<agent-peer>` to reach us (contract in sync_proto::p2p).
fn circuit_listen_addr(base: &Multiaddr, relay_peer: PeerId) -> Multiaddr {
    base.clone()
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit)
}

// ---------------------------------------------------------------------------
// Swarm construction
// ---------------------------------------------------------------------------

/// Production swarm: tcp (direct transport, also the DCUtR hole-punch endpoint)
/// + memory (in-process, used by the loopback test against the SAME code path).
///
/// The relay client behaviour is constructed by the SwarmBuilder itself
/// (`with_relay_client`) and handed to the behaviour closure — do not build it
/// manually.
fn build_agent_swarm(keypair: identity::Keypair) -> Result<AgentSwarm, String> {
    Ok(libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| format!("tcp transport: {e}"))?
        .with_other_transport(|kp| {
            MemoryTransport::default()
                .upgrade(libp2p::core::upgrade::Version::V1)
                // Raw transport chain (unlike with_tcp) takes concrete upgrades,
                // not constructors; a valid keypair cannot fail noise setup.
                .authenticate(noise::Config::new(kp).expect("noise config"))
                .multiplex(yamux::Config::default())
        })
        .map_err(|e| format!("memory transport: {e}"))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| format!("relay client transport: {e}"))?
        .with_behaviour(|keypair, relay_client| AgentBehaviour {
            relay_client,
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL.to_string(),
                keypair.public(),
            )),
            // DCUtR hole-punch upgrade (M4.5): coordinated over the relayed
            // connection with the dialing daemon. On success the swarm gains a
            // DIRECT connection to the daemon and the daemon retires the
            // relayed circuit (its stream reopens on the direct path); on
            // failure the relayed circuit stays — dcutr 0.15 does NOT close it
            // (verified source: retry ×3, then an Err event). The relay
            // reservation is retained regardless (rendezvous + fallback).
            dcutr: dcutr::Behaviour::new(keypair.public().to_peer_id()),
            stream: libp2p_stream::Behaviour::new(),
        })
        .map_err(|e| format!("behaviour: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build())
}

// ---------------------------------------------------------------------------
// Relay link state machine + driver
// ---------------------------------------------------------------------------

/// Exponential-ish backoff over the fixed step table.
struct Backoff {
    step: usize,
}

impl Backoff {
    fn new() -> Self {
        Backoff { step: 0 }
    }
    fn next(&mut self) -> Duration {
        // (unwrap_or would evaluate the index eagerly — an out-of-range step
        // must take the CAP branch, not index the table.)
        let d = match BACKOFF_STEPS.get(self.step) {
            Some(d) => *d,
            None => BACKOFF_CAP,
        };
        self.step += 1;
        d
    }
    fn reset(&mut self) {
        self.step = 0;
    }
}

/// Everything the agent knows about the relay link, plus the serve root/protocol.
/// Shared verbatim between `run_agent` (production) and the in-process loopback
/// test (M3 buildability proof) via [`drive_agent`].
struct AgentDriver {
    root: PathBuf,
    protocol: StreamProtocol,
    /// Relay base address (no /p2p component).
    relay_base: Multiaddr,
    /// Relay PeerId — from `--relay …/p2p/PEER` or learned by dialing.
    relay_peer: Option<PeerId>,
    /// True while waiting for the first ConnectionEstablished to learn the peer id.
    learning_relay: bool,
    relay_connected: bool,
    /// The relay-client listener created by `listen_on(<circuit>)`; its lifetime
    /// tracks the reservation request.
    circuit_listener: Option<libp2p::core::transport::ListenerId>,
    /// Reservation confirmed at least once since the last disconnect.
    reserved: bool,
    backoff: Backoff,
    /// When to attempt the next (re)dial / re-listen. None = nothing pending.
    retry_at: Option<Instant>,
    /// M5: the daemon tunnel target (peer + circuit address) — dialed and held
    /// like the relay link so the tunnel client's `open_stream` (which can only
    /// use an ESTABLISHED connection) finds one whenever it needs it.
    daemon: Option<(PeerId, Multiaddr)>,
    daemon_dialing: bool,
    /// Shared liveness flag for the tunnel client (`tunnel.rs`): true while a
    /// connection to the daemon exists.
    daemon_connected: Arc<AtomicBool>,
}

impl AgentDriver {
    fn new(
        root: PathBuf,
        protocol: StreamProtocol,
        relay: &Multiaddr,
        daemon: Option<(PeerId, Multiaddr)>,
        daemon_connected: Arc<AtomicBool>,
    ) -> Self {
        let (relay_base, relay_peer) = split_relay_addr(relay);
        AgentDriver {
            root,
            protocol,
            relay_base,
            relay_peer,
            learning_relay: relay_peer.is_none(),
            relay_connected: false,
            circuit_listener: None,
            reserved: false,
            backoff: Backoff::new(),
            retry_at: None,
            daemon,
            daemon_dialing: false,
            daemon_connected,
        }
    }

    /// Initial actions: know the relay peer → open the reservation listener (the
    /// relay client dials the relay itself); else dial to learn the peer id.
    /// The daemon tunnel target is dialed ONCE THE RESERVATION IS UP (see the
    /// ReservationReqAccepted handler) — dialing it in parallel with the
    /// reservation request collides inside the relay client ("oneshot
    /// canceled", hit in the M5 loopback test).
    fn start(&mut self, swarm: &mut AgentSwarm) {
        eprintln!(
            "sync-agent p2p: accepting sync streams on {} under root {}",
            self.protocol,
            self.root.display()
        );
        match self.relay_peer {
            Some(peer) => self.listen_on_circuit(swarm, peer),
            None => {
                eprintln!(
                    "sync-agent p2p: relay peer id unknown from {}, dialing to learn it",
                    self.relay_base
                );
                self.dial_relay(swarm);
            }
        }
        if self.daemon.is_some() {
            // Kick the retry state machine: the first tick re-checks the relay,
            // and the reservation handler dials the daemon the moment the
            // relay link is healthy.
            self.schedule_retry();
        }
    }

    fn dial_daemon(&mut self, swarm: &mut AgentSwarm) {
        let Some((_, addr)) = &self.daemon else { return };
        self.daemon_dialing = true;
        match swarm.dial(addr.clone()) {
            Ok(()) => eprintln!("sync-agent p2p: dialing daemon tunnel target {addr}"),
            Err(e) => {
                eprintln!("sync-agent p2p: daemon tunnel dial failed: {e}");
                self.daemon_dialing = false;
                self.schedule_retry();
            }
        }
    }

    fn dial_relay(&mut self, swarm: &mut AgentSwarm) {
        let addr = match self.relay_peer {
            Some(p) => self.relay_base.clone().with(Protocol::P2p(p)),
            None => self.relay_base.clone(),
        };
        match swarm.dial(addr.clone()) {
            Ok(()) => eprintln!("sync-agent p2p: dialing relay {addr}"),
            Err(e) => {
                eprintln!("sync-agent p2p: dialing relay {addr} failed: {e}");
                self.schedule_retry();
            }
        }
    }

    fn listen_on_circuit(&mut self, swarm: &mut AgentSwarm, relay_peer: PeerId) {
        let addr = circuit_listen_addr(&self.relay_base, relay_peer);
        match swarm.listen_on(addr.clone()) {
            Ok(listener) => {
                eprintln!(
                    "sync-agent p2p: requesting relay reservation at {addr} (listener {listener:?})"
                );
                self.circuit_listener = Some(listener);
            }
            Err(e) => {
                eprintln!("sync-agent p2p: listen_on {addr} failed: {e}");
                self.schedule_retry();
            }
        }
    }

    fn schedule_retry(&mut self) {
        let delay = self.backoff.next();
        self.retry_at = Some(Instant::now() + delay);
        eprintln!("sync-agent p2p: next relay attempt in {delay:?}");
    }

    /// Backoff tick: re-dial a disconnected relay, re-request a reservation
    /// while connected but unreserved, and re-dial the daemon tunnel target
    /// while disconnected.
    fn tick(&mut self, swarm: &mut AgentSwarm) {
        self.retry_at = None;
        if !self.relay_connected {
            self.dial_relay(swarm);
        } else if !self.reserved {
            match self.relay_peer {
                Some(peer) if self.circuit_listener.is_none() => {
                    self.listen_on_circuit(swarm, peer)
                }
                _ => {}
            }
        }
        if let Some((peer, _)) = &self.daemon {
            // Re-dial the daemon only over a HEALTHY relay link (the circuit
            // dial rides it); the reservation handler covers the first dial.
            if self.relay_connected && !self.daemon_connected.load(Ordering::SeqCst) && !self.daemon_dialing {
                let peer = *peer;
                eprintln!("sync-agent p2p: re-dialing daemon tunnel target {peer}");
                self.dial_daemon(swarm);
            }
        }
    }

    /// Handle one swarm event. Kept total (no panics on unexpected variants).
    fn handle_event(&mut self, swarm: &mut AgentSwarm, event: SwarmEvent<AgentBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                eprintln!("sync-agent p2p: listening on {address}");
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let via = if endpoint.is_relayed() {
                    "relayed"
                } else {
                    "direct"
                };
                if self.learning_relay {
                    // Before any reservation exists, the only dial we issued is to
                    // the relay — the first established connection is it.
                    eprintln!("sync-agent p2p: learned relay peer id {peer_id}");
                    self.learning_relay = false;
                    self.relay_peer = Some(peer_id);
                }
                if Some(peer_id) == self.relay_peer {
                    self.relay_connected = true;
                    eprintln!("sync-agent p2p: relay {peer_id} connected ({via})");
                    if self.circuit_listener.is_none() && !self.reserved {
                        let peer = peer_id;
                        self.listen_on_circuit(swarm, peer);
                    }
                } else if matches!(&self.daemon, Some((d, _)) if *d == peer_id) {
                    self.daemon_dialing = false;
                    self.daemon_connected.store(true, Ordering::SeqCst);
                    self.backoff.reset();
                    eprintln!("sync-agent p2p: daemon tunnel link up ({via}) — loopback services reachable");
                } else {
                    eprintln!("sync-agent p2p: peer {peer_id} connected ({via})");
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                cause,
                ..
            } => {
                if Some(peer_id) == self.relay_peer && num_established == 0 {
                    eprintln!(
                        "sync-agent p2p: relay {peer_id} disconnected (cause: {}); will reconnect",
                        cause
                            .as_ref()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "n/a".into())
                    );
                    self.relay_connected = false;
                    self.reserved = false;
                    self.circuit_listener = None;
                    self.schedule_retry();
                } else if matches!(&self.daemon, Some((d, _)) if *d == peer_id) && num_established == 0 {
                    eprintln!("sync-agent p2p: daemon tunnel link down; will re-dial");
                    self.daemon_dialing = false;
                    self.daemon_connected.store(false, Ordering::SeqCst);
                    self.schedule_retry();
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                // peer_id is Option<PeerId>: None when the dial had no peer id —
                // exactly our learning-phase relay dial. Treat that as a relay
                // failure too, or a relay down at boot would hang the agent.
                let relay_failure = match (peer_id, self.relay_peer) {
                    (Some(p), Some(relay)) => p == relay,
                    (None, None) => self.learning_relay,
                    _ => false,
                };
                if relay_failure {
                    eprintln!("sync-agent p2p: relay dial failed: {error}");
                    self.relay_connected = false;
                    self.schedule_retry();
                } else if matches!(&self.daemon, Some((d, _)) if Some(*d) == peer_id) {
                    if self.daemon_dialing {
                        // A REAL circuit-dial failure (we initiated one).
                        eprintln!("sync-agent p2p: daemon tunnel dial failed: {error}");
                        self.daemon_dialing = false;
                        self.daemon_connected.store(false, Ordering::SeqCst);
                        self.schedule_retry();
                    } else {
                        // A DCUtR PUNCH-dial failure — benign: dcutr dials the
                        // peer's direct candidate (which may be unroutable,
                        // e.g. hairpin NAT) while the RELAYED link stands. The
                        // M5 live rehearsal hit this on laptop↔laptop (same
                        // public IP, no hairpin) and flapped the link flag.
                        eprintln!("sync-agent p2p: daemon punch dial failed (benign, relayed link stands): {error}");
                    }
                }
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } => {
                if Some(listener_id) == self.circuit_listener {
                    self.circuit_listener = None;
                    match reason {
                        Err(e) => {
                            eprintln!("sync-agent p2p: relay reservation listener failed: {e}");
                            self.schedule_retry();
                        }
                        Ok(()) => {
                            // Closed without error (e.g. relay connection went away
                            // first); re-listen on the next tick if still unreserved.
                            if !self.reserved {
                                self.schedule_retry();
                            }
                        }
                    }
                }
            }
            SwarmEvent::ListenerError {
                listener_id, error, ..
            } => {
                if Some(listener_id) == self.circuit_listener {
                    eprintln!("sync-agent p2p: relay listener error: {error}");
                }
            }
            SwarmEvent::Behaviour(AgentBehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id,
                    renewal,
                    ..
                },
            )) => {
                eprintln!(
                    "sync-agent p2p: relay reservation {} (relay {relay_peer_id}) — inbound relayed connections now reachable",
                    if renewal { "renewed" } else { "established" }
                );
                self.reserved = true;
                self.backoff.reset();
                self.retry_at = None;
                // The relay link is healthy — NOW dial the daemon tunnel
                // target (the deterministic first-dial moment, M5).
                if let Some((peer, _)) = &self.daemon {
                    if !self.daemon_connected.load(Ordering::SeqCst) && !self.daemon_dialing {
                        let peer = *peer;
                        eprintln!("sync-agent p2p: dialing daemon tunnel target {peer} (relay healthy)");
                        self.dial_daemon(swarm);
                    }
                }
            }
            SwarmEvent::Behaviour(AgentBehaviourEvent::RelayClient(
                relay::client::Event::InboundCircuitEstablished { src_peer_id, .. },
            )) => {
                eprintln!("sync-agent p2p: inbound relayed connection from {src_peer_id}");
            }
            SwarmEvent::Behaviour(AgentBehaviourEvent::Identify(identify::Event::Received {
                info: identify::Info { observed_addr, .. },
                ..
            })) => {
                // The relay told us our observed address — advertise it so DCUtR
                // hole-punch candidates include the real path.
                swarm.add_external_address(observed_addr);
            }
            SwarmEvent::Behaviour(AgentBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            })) => match result {
                Ok(_) => {
                    eprintln!(
                        "sync-agent p2p: hole-punch SUCCEEDED — direct connection to {remote_peer_id} (relay retained as fallback)"
                    );
                }
                Err(e) => {
                    eprintln!(
                        "sync-agent p2p: hole-punch failed — staying relayed ({e})"
                    );
                }
            },
            SwarmEvent::Behaviour(_) => {}
            _ => {}
        }
    }
}

/// Drive the agent swarm forever: swarm events (relay link state machine),
/// incoming sync streams (serve sessions), and backoff ticks. Returns only if the
/// swarm stream ends (never in practice).
async fn drive_agent(
    mut swarm: AgentSwarm,
    mut incoming: libp2p_stream::IncomingStreams,
    mut driver: AgentDriver,
) {
    driver.start(&mut swarm);
    loop {
        // Retry deadline copied out so the sleep arm doesn't borrow the driver.
        let retry_at = driver.retry_at;
        tokio::select! {
            event = swarm.next() => match event {
                Some(event) => driver.handle_event(&mut swarm, event),
                None => return,
            },
            maybe_stream = incoming.next() => match maybe_stream {
                Some((peer, stream)) => spawn_serve_session(stream, peer, driver.root.clone()),
                // Accept handle dropped — only possible if we dropped it ourselves.
                None => return,
            },
            _ = async {
                match retry_at {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from(at)).await,
                    None => std::future::pending::<()>().await,
                }
            } => driver.tick(&mut swarm),
        }
    }
}

/// Bridge one libp2p stream to a std duplex and run the UNCHANGED M2 serve loop
/// on a blocking thread. Detached: session-level failures log and never kill the
/// swarm. Multiple sequential (and concurrent) sessions are supported.
fn spawn_serve_session(stream: Stream, peer: PeerId, root: PathBuf) {
    eprintln!("sync-agent p2p: session opened by {peer}");
    let task = tokio::task::spawn_blocking(move || {
        // Compat: libp2p Stream is futures-style AsyncRead/Write; SyncIoBridge
        // wants tokio-style. Constructed inside spawn_blocking so
        // SyncIoBridge::new captures the runtime handle (available there).
        let mut bridge = SyncIoBridge::new(stream.compat());
        let result = serve::serve(&mut bridge, &root);
        // SyncIoBridge has NO Drop shutdown — close the yamux stream explicitly so
        // the peer sees a clean stream end after Shutdown/Bye or a torn session.
        if let Err(e) = bridge.shutdown() {
            eprintln!("sync-agent p2p: closing session stream for {peer}: {e}");
        }
        result
    });
    // Session-outcome watcher: logging only, the swarm loop never awaits sessions.
    tokio::spawn(async move {
        match task.await {
            Ok(Ok(())) => eprintln!("sync-agent p2p: session with {peer} ended"),
            Ok(Err(e)) => eprintln!("sync-agent p2p: session with {peer} failed: {e}"),
            Err(e) => eprintln!("sync-agent p2p: session task for {peer} join error: {e}"),
        }
    });
}

/// Compute the daemon's tunnel target: peer (derived from the shared master
/// key — the same derivation the daemon runs) + circuit address
/// `<relay>/p2p-circuit/p2p/<daemon>`. The DRIVER dials and holds that
/// connection (open_stream can only ride an established one).
fn setup_tunnel(cfg: &P2pConfig) -> Result<(libp2p::PeerId, Multiaddr), String> {
    let (relay_base, relay_peer) = split_relay_addr(&cfg.relay);
    let relay_peer = relay_peer.ok_or_else(|| {
        "--tunnel requires --relay with a /p2p/PEER suffix (the agent dials the daemon's \
         circuit directly — the daemon PeerId is derived from the shared master key)"
            .to_string()
    })?;
    let seed = derive_daemon_identity_seed(&cfg.master);
    let keypair = identity::Keypair::ed25519_from_bytes(seed)
        .map_err(|e| format!("daemon identity seed: {e}"))?;
    let daemon_peer = keypair.public().to_peer_id();
    let circuit = relay_base
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(daemon_peer));
    Ok((daemon_peer, circuit))
}

/// Run the p2p agent (the `p2p` subcommand body). Never returns under normal
/// operation; errors here are startup failures only.
pub async fn run_agent(cfg: P2pConfig) -> Result<(), String> {
    let keypair = derive_keypair(&cfg.master, &cfg.sandbox_id);
    let agent_peer = keypair.public().to_peer_id();
    eprintln!(
        "sync-agent p2p: agent peer id {agent_peer} (sandbox {:?}) — daemon dials via relay circuit",
        cfg.sandbox_id
    );
    eprintln!("sync-agent p2p: serving root {}", cfg.root.display());
    eprintln!("sync-agent p2p: relay {}", cfg.relay);
    eprintln!("sync-agent p2p: stream protocol {}", cfg.protocol);

    let mut swarm = build_agent_swarm(keypair)?;

    // Direct-transport listener: DCUtR hole-punches need a dialable local
    // endpoint (the hole-punching peer connects to us directly). Ephemeral port;
    // unreachable from outside the pod — reachable paths are the relay circuit.
    match swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>().expect("static addr")) {
        Ok(_) => {}
        Err(e) => eprintln!("sync-agent p2p: WARNING no direct transport listener ({e}); hole-punching unavailable, relayed only"),
    }

    let mut control = swarm.behaviour().stream.new_control();
    let incoming = control
        .accept(cfg.protocol.clone())
        .map_err(|_| "sync protocol already registered on a fresh control")?;

    // M5: the tunnel client (memory access broker) — opt-in via --tunnel.
    // Shares the swarm/reservation/identity; the driver dials + holds the
    // daemon connection, the tunnel task opens streams on it. A tunnel
    // failure never touches the sync accept loop above.
    let mut daemon_target = None;
    if !cfg.tunnel.is_empty() {
        match setup_tunnel(&cfg) {
            Ok((daemon_peer, circuit)) => {
                eprintln!("sync-agent p2p: tunnel target: daemon peer {daemon_peer} at {circuit}");
                daemon_target = Some((daemon_peer, circuit));
            }
            Err(e) => eprintln!("sync-agent p2p: tunnel DISABLED ({e})"),
        }
    }
    let daemon_connected = Arc::new(AtomicBool::new(false));
    if let Some(daemon_peer) = daemon_target.as_ref().map(|(p, _)| *p) {
        let runtime = tunnel::TunnelRuntime {
            services: cfg.tunnel.clone(),
            root: cfg.root.clone(),
            daemon_peer,
            daemon_connected: daemon_connected.clone(),
            control: control.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = tunnel::run(runtime).await {
                eprintln!("sync-agent tunnel: stopped: {e}");
            }
        });
    }

    let driver = AgentDriver::new(cfg.root, cfg.protocol, &cfg.relay, daemon_target, daemon_connected);
    drive_agent(swarm, incoming, driver).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Flag parsing (p2p subcommand) — --flag value and --flag=value forms.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct P2pArgs {
    pub relay: Option<String>,
    pub sandbox_id: Option<String>,
    pub master_key_file: Option<PathBuf>,
    pub root: Option<String>,
    /// Repeatable `--tunnel name@port[:tool,tool,...]` specs (M5).
    pub tunnel: Vec<String>,
}

pub(crate) fn parse_p2p_args(args: &[String]) -> Result<P2pArgs, String> {
    let mut out = P2pArgs {
        relay: None,
        sandbox_id: None,
        master_key_file: None,
        root: None,
        tunnel: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        // `--flag=value` splits at the first '='; bare `--flag value` below.
        let (flag, inline_value) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let known = matches!(
            flag.as_str(),
            "--relay" | "--sandbox-id" | "--master-key-file" | "--root" | "--tunnel"
        );
        if !known {
            return Err(format!("unknown p2p flag: {flag}"));
        }
        let value = match inline_value.clone() {
            Some(v) => v,
            None => args
                .get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value"))?,
        };
        match flag.as_str() {
            "--relay" => out.relay = Some(value),
            "--sandbox-id" => out.sandbox_id = Some(value),
            "--master-key-file" => out.master_key_file = Some(PathBuf::from(value)),
            "--root" => out.root = Some(value),
            // Repeatable: every occurrence adds a service spec.
            "--tunnel" => out.tunnel.push(value),
            _ => unreachable!("known flags checked above"),
        }
        i += if inline_value.is_some() { 1 } else { 2 };
    }
    Ok(out)
}

/// Load the master key: `--master-key-file` wins over `SYNC_AGENT_MASTER_KEY`.
/// The CONTENT is never logged; permission checks warn (k8s projected secrets may
/// default looser than 0600 — that is a deployment concern, not a parse error).
pub(crate) fn load_master_key(file: Option<&Path>) -> Result<[u8; 32], String> {
    match file {
        Some(path) => {
            if let Ok(meta) = std::fs::metadata(path) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        eprintln!(
                            "sync-agent p2p: WARNING master key file {} is mode {:o} (group/other readable)",
                            path.display(),
                            mode
                        );
                    }
                }
            }
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("reading master key file {}: {e}", path.display()))?;
            sync_proto::p2p::parse_master_key(&content)
                .map_err(|e| format!("master key file {}: {e}", path.display()))
        }
        None => match std::env::var("SYNC_AGENT_MASTER_KEY") {
            Ok(v) if !v.is_empty() => sync_proto::p2p::parse_master_key(&v)
                .map_err(|e| format!("SYNC_AGENT_MASTER_KEY: {e}")),
            _ => Err(
                "no master key: set SYNC_AGENT_MASTER_KEY (64 hex chars) or pass --master-key-file"
                    .to_string(),
            ),
        },
    }
}

/// Resolve the sandbox id: `--sandbox-id` wins over `SYNC_AGENT_SANDBOX_ID`.
pub(crate) fn resolve_sandbox_id(flag: Option<&str>) -> Result<String, String> {
    match flag {
        Some(id) if !id.is_empty() => Ok(id.to_string()),
        Some(_) => Err("--sandbox-id must not be empty".to_string()),
        None => match std::env::var("SYNC_AGENT_SANDBOX_ID") {
            Ok(id) if !id.is_empty() => Ok(id),
            _ => Err("no sandbox id: set SYNC_AGENT_SANDBOX_ID or pass --sandbox-id".to_string()),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests. The centerpiece is the IN-PROCESS LOOPBACK: a relay swarm (stand-in for
// crates/relay), the agent under test (production driver code, memory transport),
// and a mini daemon client — asserting reservation → relayed dial → stream →
// the UNCHANGED M2 protocol end to end.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use sync_proto::messages::{read_response, send_request, Request, Response};
    use sync_proto::{client_handshake, exchange_versions_client};

    // ----- identity (the deterministic rendezvous) -----

    #[test]
    fn identity_peerid_stable_across_derivations_and_sandboxes() {
        let master = [9u8; 32];
        let a = derive_keypair(&master, "default--sync-oc")
            .public()
            .to_peer_id();
        let a2 = derive_keypair(&master, "default--sync-oc")
            .public()
            .to_peer_id();
        let b = derive_keypair(&master, "default--other")
            .public()
            .to_peer_id();
        let c = derive_keypair(&[10u8; 32], "default--sync-oc")
            .public()
            .to_peer_id();
        assert_eq!(
            a, a2,
            "same (master, sandbox) → same PeerId (daemon can precompute ours)"
        );
        assert_ne!(a, b, "different sandbox → isolated identity");
        assert_ne!(a, c, "different master → isolated identity");
    }

    // ----- relay address parsing (the --relay contract) -----

    #[test]
    fn backoff_follows_1s_2s_5s_then_caps_and_resets() {
        let mut b = Backoff::new();
        assert_eq!(b.next(), Duration::from_secs(1));
        assert_eq!(b.next(), Duration::from_secs(2));
        assert_eq!(b.next(), Duration::from_secs(5));
        assert_eq!(
            b.next(),
            Duration::from_secs(30),
            "cap after the step table"
        );
        assert_eq!(b.next(), Duration::from_secs(30));
        b.reset();
        assert_eq!(
            b.next(),
            Duration::from_secs(1),
            "reset on healthy reservation"
        );
    }

    #[test]
    fn relay_addr_split_with_and_without_peer_suffix() {
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();

        let addr: Multiaddr = format!("/ip4/203.0.113.42/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        let (base, got) = split_relay_addr(&addr);
        assert_eq!(got, Some(peer));
        assert_eq!(base.to_string(), "/ip4/203.0.113.42/tcp/4001");
        // Reservation target the agent listens on (daemon appends /p2p/<agent>).
        assert_eq!(
            circuit_listen_addr(&base, peer).to_string(),
            format!("/ip4/203.0.113.42/tcp/4001/p2p/{peer}/p2p-circuit")
        );

        let bare: Multiaddr = "/ip4/203.0.113.42/tcp/4001".parse().unwrap();
        let (base2, got2) = split_relay_addr(&bare);
        assert_eq!(got2, None, "peer suffix optional — learned by dialing");
        assert_eq!(base2, base);
    }

    // ----- flag/env wiring -----

    #[test]
    fn p2p_args_dashdash_value_and_inline_forms() {
        let args: Vec<String> = [
            "--relay",
            "/ip4/1.2.3.4/tcp/4001",
            "--sandbox-id=default--sync-oc",
            "--root",
            "/sandbox",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let parsed = parse_p2p_args(&args).unwrap();
        assert_eq!(parsed.relay.as_deref(), Some("/ip4/1.2.3.4/tcp/4001"));
        assert_eq!(parsed.sandbox_id.as_deref(), Some("default--sync-oc"));
        assert_eq!(parsed.root.as_deref(), Some("/sandbox"));
        assert!(parsed.master_key_file.is_none());
    }

    #[test]
    fn p2p_args_rejects_unknown_flag_and_missing_value() {
        let err = parse_p2p_args(&["--bogus".to_string(), "x".to_string()]).unwrap_err();
        assert!(err.contains("--bogus"), "got: {err}");
        let err = parse_p2p_args(&["--relay".to_string()]).unwrap_err();
        assert!(err.contains("requires a value"), "got: {err}");
    }

    #[test]
    fn master_key_file_wins_over_env_and_accepts_trailing_newline() {
        let hex = "ab".repeat(32);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key");
        std::fs::write(&path, format!("{hex}\n")).unwrap();

        // Env set AND file given → file wins.
        std::env::set_var("SYNC_AGENT_MASTER_KEY", "11".repeat(32));
        let from_file = load_master_key(Some(&path)).unwrap();
        assert_eq!(from_file, sync_proto::p2p::parse_master_key(&hex).unwrap());

        // Env only.
        let from_env = load_master_key(None).unwrap();
        assert_eq!(
            from_env,
            sync_proto::p2p::parse_master_key(&"11".repeat(32)).unwrap()
        );

        // Garbage env → error mentioning the source.
        std::env::set_var("SYNC_AGENT_MASTER_KEY", "nothex");
        assert!(load_master_key(None).is_err());
        std::env::remove_var("SYNC_AGENT_MASTER_KEY");
    }

    #[test]
    fn sandbox_id_flag_wins_over_env() {
        std::env::set_var("SYNC_AGENT_SANDBOX_ID", "from-env");
        assert_eq!(resolve_sandbox_id(Some("from-flag")).unwrap(), "from-flag");
        assert_eq!(resolve_sandbox_id(None).unwrap(), "from-env");
        std::env::remove_var("SYNC_AGENT_SANDBOX_ID");
        assert!(resolve_sandbox_id(None).is_err());
    }

    // ----- the M3 buildability proof -----

    /// Relay node stand-in (crates/relay is built in parallel): relay-v2 SERVER
    /// over the memory transport.
    #[derive(NetworkBehaviour)]
    struct TestRelayBehaviour {
        relay: relay::Behaviour,
    }

    /// Mini daemon stand-in (crates/cli is built in parallel): relay client +
    /// identify + stream behaviour. Deliberately NO dcutr, so the connection to
    /// the agent stays relayed — the test asserts the fallback path deterministically.
    #[derive(NetworkBehaviour)]
    struct TestClientBehaviour {
        relay_client: relay::client::Behaviour,
        identify: identify::Behaviour,
        stream: libp2p_stream::Behaviour,
    }

    fn build_relay_swarm(keypair: identity::Keypair) -> libp2p::Swarm<TestRelayBehaviour> {
        libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|kp| {
                MemoryTransport::default()
                    .upgrade(libp2p::core::upgrade::Version::V1)
                    .authenticate(noise::Config::new(kp).expect("noise config"))
                    .multiplex(yamux::Config::default())
            })
            .expect("memory transport")
            .with_behaviour(|kp| TestRelayBehaviour {
                relay: relay::Behaviour::new(kp.public().to_peer_id(), Default::default()),
            })
            .expect("relay behaviour")
            .build()
    }
    // NOTE for the real relay (crates/relay): with `Config::default()` a relay
    // server starts at `Status::Disable` and auto-enables HOP advertisement only
    // once it has a CONFIRMED external address; the RESERVE response also needs
    // that address (else the client fails with NoAddressesInReservation). On the
    // VPS this comes from identify: on `identify::Event::Received` call
    // `swarm.add_external_address(observed_addr)` (relay-server example pattern).

    fn build_client_swarm(keypair: identity::Keypair) -> libp2p::Swarm<TestClientBehaviour> {
        libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|kp| {
                MemoryTransport::default()
                    .upgrade(libp2p::core::upgrade::Version::V1)
                    .authenticate(noise::Config::new(kp).expect("noise config"))
                    .multiplex(yamux::Config::default())
            })
            .expect("memory transport")
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .expect("relay client transport")
            .with_behaviour(|kp, relay_client| TestClientBehaviour {
                relay_client,
                identify: identify::Behaviour::new(identify::Config::new(
                    IDENTIFY_PROTOCOL.to_string(),
                    kp.public(),
                )),
                stream: libp2p_stream::Behaviour::new(),
            })
            .expect("client behaviour")
            .build()
    }

    /// The mini daemon: dial the agent through the relay circuit (retrying until
    /// the agent's reservation is up), open the sync stream, then speak the M2
    /// protocol client-side over a bridged std duplex — TWICE, proving the accept
    /// loop serves sequential sessions.
    async fn mini_daemon_flow(
        mut control: libp2p_stream::Control,
        mut swarm: libp2p::Swarm<TestClientBehaviour>,
        agent_peer: PeerId,
        agent_circuit: Multiaddr,
    ) -> std::io::Result<()> {
        // 1. Relayed dial with retries (the agent may still be securing its
        //    reservation when we start). One dial in flight at a time — re-dialing
        //    while pending would burn the relay's per-peer circuit rate limit.
        let mut connected = false;
        let mut dial_in_flight = false;
        for attempt in 0..60 {
            if !dial_in_flight {
                let _ = swarm.dial(agent_circuit.clone()); // failure retried below
                dial_in_flight = true;
            }
            match tokio::time::timeout(Duration::from_millis(500), swarm.next()).await {
                Ok(Some(SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                })) if peer_id == agent_peer => {
                    eprintln!(
                        "test: client connected to agent (relayed={}) on attempt {attempt}",
                        endpoint.is_relayed()
                    );
                    connected = true;
                    break;
                }
                Ok(Some(SwarmEvent::OutgoingConnectionError {
                    peer_id: Some(p), ..
                })) if p == agent_peer => {
                    dial_in_flight = false;
                }
                Ok(Some(_)) => {}
                Ok(None) => return Err(std::io::Error::other("client swarm ended")),
                Err(_elapsed) => continue,
            }
        }
        if !connected {
            return Err(std::io::Error::other(
                "relayed connection to the agent was never established",
            ));
        }

        // 2. Open the sync stream on the established relayed connection.
        let stream = tokio::time::timeout(
            Duration::from_secs(15),
            control.open_stream(agent_peer, StreamProtocol::new(P2P_STREAM_PROTOCOL)),
        )
        .await
        .map_err(|_| std::io::Error::other("open_stream timed out"))?
        .map_err(|e| std::io::Error::other(format!("open_stream: {e}")))?;

        // 3. Full M2 protocol session over the bridged stream (daemon side).
        speak_m2_as_client(stream).await?;

        // 4. Sequential session #2: the agent's accept loop must keep serving.
        let stream2 = tokio::time::timeout(
            Duration::from_secs(15),
            control.open_stream(agent_peer, StreamProtocol::new(P2P_STREAM_PROTOCOL)),
        )
        .await
        .map_err(|_| std::io::Error::other("second open_stream timed out"))?
        .map_err(|e| std::io::Error::other(format!("second open_stream: {e}")))?;
        speak_m2_as_client(stream2).await
    }

    /// Handshake → Hello → Ping/Pong → Shutdown/Bye over one bridged stream,
    /// running the blocking protocol side on spawn_blocking (daemon shape).
    async fn speak_m2_as_client(stream: Stream) -> std::io::Result<()> {
        let task = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let mut s = SyncIoBridge::new(stream.compat());
            client_handshake(&mut s).map_err(|e| std::io::Error::other(e.to_string()))?;
            exchange_versions_client(&mut s).map_err(|e| std::io::Error::other(e.to_string()))?;
            match read_response(&mut s)? {
                Response::Hello(h) => eprintln!(
                    "test: Hello(agent_version {}, root {}, writable {})",
                    h.agent_version, h.root, h.root_writable
                ),
                other => {
                    return Err(std::io::Error::other(format!(
                        "expected Hello, got {other:?}"
                    )))
                }
            }
            send_request(&mut s, &Request::Ping)?;
            match read_response(&mut s)? {
                Response::Pong => {}
                other => {
                    return Err(std::io::Error::other(format!(
                        "expected Pong, got {other:?}"
                    )))
                }
            }
            send_request(&mut s, &Request::Shutdown)?;
            match read_response(&mut s)? {
                Response::Bye => {}
                other => {
                    return Err(std::io::Error::other(format!(
                        "expected Bye, got {other:?}"
                    )))
                }
            }
            // SyncIoBridge has no Drop shutdown — close cleanly like the daemon will.
            let _ = s.shutdown();
            Ok(())
        });
        task.await
            .map_err(|e| std::io::Error::other(format!("protocol task join: {e}")))?
    }

    /// THREE swarms on the memory transport: relay (server), the agent under test
    /// (production build + drive code), and a mini daemon client dialing the agent
    /// VIA the relay circuit. Asserts: reservation → relayed dial → stream →
    /// protocol — twice (sequential sessions).
    #[tokio::test]
    async fn in_process_loopback_reservation_relayed_dial_stream_protocol() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("libp2p_relay=debug,libp2p_swarm=debug")
                }),
            )
            .with_test_writer()
            .try_init();
        let master = [7u8; 32];

        // ---- relay node (the VPS stand-in) ----
        let relay_kp = identity::Keypair::generate_ed25519();
        let relay_peer = relay_kp.public().to_peer_id();
        let mut relay_swarm = build_relay_swarm(relay_kp);
        relay_swarm
            .listen_on("/memory/0".parse::<Multiaddr>().unwrap())
            .expect("relay listen on memory");
        // Capture the listen addr HERE (before the driver task owns the swarm) so
        // the relay can be given its confirmed external address first — the same
        // thing identify's observed-addr flow provides on the real VPS relay.
        let relay_listen = loop {
            match tokio::time::timeout(Duration::from_secs(10), relay_swarm.next()).await {
                Ok(Some(SwarmEvent::NewListenAddr { address, .. })) => break address,
                Ok(Some(_)) => continue,
                Ok(None) => panic!("relay swarm ended"),
                Err(_) => panic!("relay did not start listening in time"),
            }
        };
        relay_swarm.add_external_address(relay_listen.clone());
        tokio::spawn(async move {
            while let Some(event) = relay_swarm.next().await {
                if let SwarmEvent::Behaviour(TestRelayBehaviourEvent::Relay(_)) = event {
                    eprintln!("test: relay event: {event:?}");
                }
            }
        });
        eprintln!("test: relay {relay_peer} listening on {relay_listen}");
        // The contract the agent is configured with (--relay) and the daemon dials:
        let relay_with_peer = relay_listen.clone().with(Protocol::P2p(relay_peer));

        // ---- agent under test: the REAL p2p-mode build + drive code ----
        let root = tempfile::tempdir().unwrap();
        let agent_keypair = derive_keypair(&master, "test");
        let agent_peer = agent_keypair.public().to_peer_id();
        // The daemon computes the agent's PeerId from the same derivation:
        assert_eq!(
            derive_keypair(&master, "test").public().to_peer_id(),
            agent_peer,
            "rendezvous: identity derivation is position-independent"
        );

        let agent_swarm = build_agent_swarm(agent_keypair).expect("agent swarm");
        let mut agent_control = agent_swarm.behaviour().stream.new_control();
        let incoming = agent_control
            .accept(StreamProtocol::new(P2P_STREAM_PROTOCOL))
            .expect("accept on fresh control");
        let driver = AgentDriver::new(
            root.path().to_path_buf(),
            StreamProtocol::new(P2P_STREAM_PROTOCOL),
            &relay_with_peer,
            None,
            Arc::new(AtomicBool::new(false)),
        );
        let agent_task = tokio::spawn(drive_agent(agent_swarm, incoming, driver));

        // ---- mini daemon client ----
        let client_kp = identity::Keypair::generate_ed25519();
        let client_swarm = build_client_swarm(client_kp);
        let client_control = client_swarm.behaviour().stream.new_control();
        // Daemon dial target per the contract: <relay>/p2p-circuit/p2p/<agent>.
        let agent_circuit = relay_with_peer
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(agent_peer));
        let flow = tokio::spawn(mini_daemon_flow(
            client_control,
            client_swarm,
            agent_peer,
            agent_circuit,
        ));

        let result = tokio::time::timeout(Duration::from_secs(60), flow)
            .await
            .expect("client flow finished in time")
            .expect("client flow task alive");
        result.expect("full path works: reservation → relayed dial → stream → protocol");

        // The agent driver must still be running (sessions don't kill the swarm).
        assert!(
            !agent_task.is_finished(),
            "agent swarm died during sessions"
        );
        agent_task.abort();
        drop(root);
    }
}
