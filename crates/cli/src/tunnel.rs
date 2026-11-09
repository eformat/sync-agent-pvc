//! M5 memory access broker — the laptop-side TUNNEL SERVICE (plan §5).
//!
//! The sandbox agents dial OUT to us on `sync_proto::p2p::TUNNEL_STREAM_PROTOCOL`
//! (opposite direction of the sync protocol: the agent's loopback listener
//! bridges here). For every tunnel stream we:
//!
//! 1. read the handshake (magic | version | service name),
//! 2. AUTHORIZE the peer — it must be a derived agent peer of a p2p target
//!    (the agent's identity is deterministic from (master, sandbox_id), so the
//!    expected set is computed from the target config; nothing is TOFU'd here),
//! 3. enforce the SERVICE ALLOWLIST — **default deny** (the owner rule: the
//!    agent cannot opt itself in; only services listed under
//!    `[[tunnel.services]]` in config.toml exist at all),
//! 4. dial the upstream (`http://HOST:PORT` — the HTTP path rides from the
//!    client's request line; this side is a raw byte pipe) and
//!    `tokio::io::copy_bidirectional` the two duplexes until both end.
//!
//! Refusals are one clean status byte (`TUNNEL_STATUS_*`) and a close — never a
//! hang. The daemon's tunnel identity is DETERMINISTICALLY derived from the
//! master key (`derive_daemon_identity_seed`), so agents compute our PeerId and
//! circuit address with no rendezvous. The relay reservation is held forever
//! (1s→2s→5s→30s-cap backoff on loss), DCUtR upgrades to direct best-effort.
//!
//! Config shape (config.toml):
//!
//! ```toml
//! [tunnel]
//! enabled = true
//!
//! [[tunnel.services]]
//! name = "memory"
//! upstream = "http://127.0.0.1:7999"
//! ```
//!
//! The tunnel is STATIC for the daemon's lifetime (services/expected peers are
//! resolved at startup; config hot-reload keeps steering targets only) — a
//! tunnel change is a daemon restart, which is also the honest scope boundary
//! for v1.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::core::multiaddr::Protocol;
use libp2p::core::transport::MemoryTransport;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    dcutr, identify, identity, noise, relay, tcp, yamux, Multiaddr, PeerId, StreamProtocol,
    Transport,
};
use serde::{Deserialize, Serialize};

use sync_proto::p2p::{
    derive_daemon_identity_seed, parse_tunnel_request, tunnel_status_name, TUNNEL_MAX_SERVICE_NAME,
    TUNNEL_STATUS_BAD_HANDSHAKE, TUNNEL_STATUS_OK, TUNNEL_STATUS_UNAUTHORIZED_PEER,
    TUNNEL_STATUS_UNKNOWN_SERVICE, TUNNEL_STATUS_UPSTREAM_UNAVAILABLE, TUNNEL_STREAM_PROTOCOL,
};

use crate::transport::agent_peer_id;

// ---------------------------------------------------------------------------
// Configuration (the [[tunnel.services]] allowlist — default deny)
// ---------------------------------------------------------------------------

/// The `[tunnel]` section of config.toml. `enabled: false` (the default) means
/// the tunnel service never starts — zero behavior change until opted in.
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
pub struct TunnelConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The allowlist. An empty list with `enabled = true` is a LOUD startup
    /// refusal, not an empty allow-all: the tunnel exists to expose specific
    /// opted-in services and nothing else.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<TunnelServiceConfig>,
}

impl TunnelConfig {
    /// `skip_serializing_if` predicate: keep disabled tunnels out of rewritten
    /// config.toml files entirely (the disabled state is the zero-value).
    pub(crate) fn is_default(v: &TunnelConfig) -> bool {
        !v.enabled && v.services.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TunnelServiceConfig {
    /// The service name agents use in their tunnel handshake.
    pub name: String,
    /// `http://HOST[:PORT][/path]` — only host:port is dialed; the HTTP path
    /// (e.g. `/mcp`) rides from the sandbox client's request line untouched.
    pub upstream: String,
    /// The loopback port the SANDBOX agent binds for this service
    /// (`127.0.0.1:<agent_port>` — OpenCode's MCP URL points here). The daemon
    /// pushes the full spec to provisioned agents as
    /// `--tunnel <name>@<agent_port>:<spool_tools>`.
    pub agent_port: u16,
    /// MCP tool names the agent SPOOLS for this service while the tunnel is
    /// down (writes). Everything else fails fast to a clean miss.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spool_tools: Vec<String>,
}

/// A resolved upstream dial target.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamAddr {
    pub host: String,
    pub port: u16,
}

/// Parse `http://HOST[:PORT][/path]`. Only `http` — loopback laptop services;
/// TLS termination on localhost is a problem the tunnel does not need.
pub fn parse_upstream(url: &str) -> io::Result<UpstreamAddr> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tunnel upstream {url:?}: only http:// is supported (loopback services)"),
        )
    })?;
    let hostport = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("tunnel upstream {url:?}: bad port {p:?}: {e}"),
                )
            })?,
        ),
        None => (hostport.to_string(), 80),
    };
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tunnel upstream {url:?}: empty host"),
        ));
    }
    Ok(UpstreamAddr { host, port })
}

// ---------------------------------------------------------------------------
// Startup resolution (master keys, relay, expected peers, services)
// ---------------------------------------------------------------------------

/// Everything [`run_service`] needs, resolved once at daemon startup.
#[derive(Debug)]
pub struct TunnelRun {
    /// The DEFAULTS master key — the daemon's tunnel identity derives from it,
    /// and every agent must derive the same daemon PeerId (i.e. tunneling
    /// assumes the shared master key; see the warning in [`prepare`]).
    pub master: [u8; 32],
    pub relay: Multiaddr,
    pub services: HashMap<String, UpstreamAddr>,
    /// Agent peers allowed to open tunnel streams: the derived p2p-target
    /// agent peers (same derivation the sync transport dials).
    pub expected_peers: HashSet<PeerId>,
    /// Live counters shared with the daemon API (the UI's tunnel view).
    pub status: TunnelStatusHandle,
}

/// Resolve the `[tunnel]` config into a [`TunnelRun`]. `Ok(None)` = tunnel
/// disabled (the default). Errors are LOUD startup refusals.
pub fn prepare(cfg: &crate::daemon::DaemonConfig) -> io::Result<Option<TunnelRun>> {
    if !cfg.tunnel.enabled {
        return Ok(None);
    }
    if cfg.tunnel.services.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tunnel.enabled = true but no [[tunnel.services]] — refusing to run an empty allowlist",
        ));
    }
    let relay_str = cfg.defaults.relay.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "tunnel.enabled = true but defaults.relay is not set",
        )
    })?;
    let relay: Multiaddr = relay_str.parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tunnel: bad defaults.relay {relay_str:?}: {e}"),
        )
    })?;
    let master = load_defaults_master(&cfg.defaults)?;

    let mut services = HashMap::new();
    for s in &cfg.tunnel.services {
        let upstream = parse_upstream(&s.upstream)?;
        if s.name.is_empty() || s.name.len() > TUNNEL_MAX_SERVICE_NAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "tunnel service name {:?} must be 1..={TUNNEL_MAX_SERVICE_NAME} chars",
                    s.name
                ),
            ));
        }
        if services.insert(s.name.clone(), upstream).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("duplicate tunnel service name {:?}", s.name),
            ));
        }
    }

    // Expected tunnel peers: the derived agent peer of every p2p target. A
    // target on a DIFFERENT master key than the defaults still authorizes
    // (its agent identity derives from its own key) but its agent cannot FIND
    // this daemon (it derives the daemon PeerId from its own key) — warn.
    let mut expected_peers = HashSet::new();
    for t in &cfg.targets {
        if t.relay.is_none() {
            continue; // exec-transport targets have no tunnel path
        }
        let args = t.to_target_args();
        match crate::load_master_key(&args) {
            Ok(m) => {
                if m != master {
                    eprintln!(
                        "daemon tunnel: WARNING target {:?} uses a different master key than defaults — \
                         its agent will not be able to locate this daemon's tunnel listener",
                        t.name
                    );
                }
                match agent_peer_id(&m, &t.sandbox) {
                    Ok(p) => {
                        expected_peers.insert(p);
                    }
                    Err(e) => eprintln!("daemon tunnel: WARNING target {:?}: {e} (skipped)", t.name),
                }
            }
            Err(e) => eprintln!(
                "daemon tunnel: WARNING target {:?}: master key unavailable ({e}) — its agent cannot tunnel (skipped)",
                t.name
            ),
        }
    }
    if expected_peers.is_empty() {
        eprintln!("daemon tunnel: WARNING no p2p targets — every tunnel stream will be refused as unauthorized");
    }

    Ok(Some(TunnelRun {
        master,
        relay,
        services,
        expected_peers,
        status: TunnelStatusHandle::new(&cfg.tunnel),
    }))
}

/// The defaults-level master key (env or 0600-style file), mirroring
/// main.rs's per-target resolution.
fn load_defaults_master(d: &crate::daemon::Defaults) -> io::Result<[u8; 32]> {
    let raw = if d.master_key_env {
        std::env::var("SYNC_AGENT_MASTER_KEY").map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tunnel: defaults.master_key_env set but $SYNC_AGENT_MASTER_KEY is missing",
            )
        })?
    } else if let Some(path) = &d.master_key_file {
        std::fs::read_to_string(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "tunnel: cannot read defaults.master_key_file {}: {e}",
                    path.display()
                ),
            )
        })?
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tunnel: no defaults master key (master_key_file / master_key_env)",
        ));
    };
    sync_proto::p2p::parse_master_key(&raw).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tunnel master key: {e}"),
        )
    })
}

// ---------------------------------------------------------------------------
// Swarm + relay link (the daemon holds the reservation agents dial through)
// ---------------------------------------------------------------------------

/// Overall timeout for the handshake exchange on a fresh tunnel stream.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for dialing the upstream laptop service.
const UPSTREAM_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Reconnect backoff steps (mirrors the agent: 1s, 2s, 5s, 30s cap).
const BACKOFF_STEPS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
];
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// The daemon's tunnel behaviours — same shape as the sync transport's
/// (relay CLIENT for the reservation agents dial through, identify for the
/// observed address (DCUtR punch candidate), DCUtR, raw streams).
#[derive(NetworkBehaviour)]
struct TunnelBehaviours {
    relay: relay::client::Behaviour,
    identify: identify::Behaviour,
    dcutr: dcutr::Behaviour,
    stream: libp2p_stream::Behaviour,
}

/// Identify protocol version — MUST match the relay's (`crates/relay`).
const IDENTIFY_PROTOCOL_VERSION: &str = "sync-agent-pvc/relay/1";
/// The 0.57 default (10 s) would drop the relay connection between agents.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(600);

/// Production swarm: tcp (direct transport, the DCUtR punch endpoint) + memory
/// (in-process, used by the loopback test against the SAME code path).
fn build_tunnel_swarm(
    keypair: identity::Keypair,
) -> Result<libp2p::Swarm<TunnelBehaviours>, String> {
    let daemon_peer = keypair.public().to_peer_id();
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
                .authenticate(noise::Config::new(kp).expect("noise config"))
                .multiplex(yamux::Config::default())
        })
        .map_err(|e| format!("memory transport: {e}"))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| format!("relay client transport: {e}"))?
        .with_behaviour(|key, relay_client| TunnelBehaviours {
            relay: relay_client,
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL_VERSION.to_string(),
                key.public(),
            )),
            // Responds to agent-initiated punches (the agent side initiates;
            // this side only ever answers). Needs the direct listener that
            // run_service adds to matter.
            dcutr: dcutr::Behaviour::new(daemon_peer),
            stream: libp2p_stream::Behaviour::new(),
        })
        .map_err(|e| format!("behaviour: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build())
}

/// Backoff over the fixed step table (1s → 2s → 5s → 30s cap, reset on health).
struct Backoff {
    step: usize,
}

impl Backoff {
    fn new() -> Self {
        Backoff { step: 0 }
    }
    fn next(&mut self) -> Duration {
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

/// The relay link state machine — a compact mirror of the agent's
/// (`crates/agent/src/p2p.rs` AgentDriver): hold a reservation forever so
/// agents can dial this daemon whenever they need a tunnel.
struct RelayLink {
    relay_base: Multiaddr,
    relay_peer: Option<PeerId>,
    learning: bool,
    connected: bool,
    reserved: bool,
    circuit_listener: Option<libp2p::core::transport::ListenerId>,
    backoff: Backoff,
    retry_at: Option<Instant>,
}

impl RelayLink {
    fn new(relay: &Multiaddr) -> Self {
        let mut base = Multiaddr::empty();
        let mut peer = None;
        for proto in relay.iter() {
            match proto {
                Protocol::P2p(id) => peer = Some(id),
                other => base.push(other),
            }
        }
        RelayLink {
            learning: peer.is_none(),
            relay_base: base,
            relay_peer: peer,
            connected: false,
            reserved: false,
            circuit_listener: None,
            backoff: Backoff::new(),
            retry_at: None,
        }
    }

    fn start(&mut self, swarm: &mut libp2p::Swarm<TunnelBehaviours>) {
        // Direct-transport listener: DCUtR punches from agents need a dialable
        // local endpoint. Ephemeral port; unreachable from outside except
        // through the punch itself.
        match swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>().expect("static addr")) {
            Ok(_) => {}
            Err(e) => eprintln!("daemon tunnel: WARNING no direct transport listener ({e}); hole-punching unavailable, relayed only"),
        }
        match self.relay_peer {
            Some(peer) => self.listen_on_circuit(swarm, peer),
            None => {
                eprintln!(
                    "daemon tunnel: relay peer id unknown from {}, dialing to learn it",
                    self.relay_base
                );
                self.dial_relay(swarm);
            }
        }
    }

    fn dial_relay(&mut self, swarm: &mut libp2p::Swarm<TunnelBehaviours>) {
        let addr = match self.relay_peer {
            Some(p) => self.relay_base.clone().with(Protocol::P2p(p)),
            None => self.relay_base.clone(),
        };
        match swarm.dial(addr.clone()) {
            Ok(()) => eprintln!("daemon tunnel: dialing relay {addr}"),
            Err(e) => {
                eprintln!("daemon tunnel: dialing relay {addr} failed: {e}");
                self.schedule_retry();
            }
        }
    }

    fn listen_on_circuit(
        &mut self,
        swarm: &mut libp2p::Swarm<TunnelBehaviours>,
        relay_peer: PeerId,
    ) {
        let addr = self
            .relay_base
            .clone()
            .with(Protocol::P2p(relay_peer))
            .with(Protocol::P2pCircuit);
        match swarm.listen_on(addr.clone()) {
            Ok(listener) => {
                eprintln!("daemon tunnel: requesting relay reservation at {addr}");
                self.circuit_listener = Some(listener);
            }
            Err(e) => {
                eprintln!("daemon tunnel: listen_on {addr} failed: {e}");
                self.schedule_retry();
            }
        }
    }

    fn schedule_retry(&mut self) {
        let delay = self.backoff.next();
        self.retry_at = Some(Instant::now() + delay);
        eprintln!("daemon tunnel: next relay attempt in {delay:?}");
    }

    fn tick(&mut self, swarm: &mut libp2p::Swarm<TunnelBehaviours>) {
        self.retry_at = None;
        if !self.connected {
            self.dial_relay(swarm);
        } else if !self.reserved {
            match self.relay_peer {
                Some(peer) if self.circuit_listener.is_none() => {
                    self.listen_on_circuit(swarm, peer)
                }
                _ => {}
            }
        }
    }

    fn handle_event(
        &mut self,
        swarm: &mut libp2p::Swarm<TunnelBehaviours>,
        event: SwarmEvent<TunnelBehavioursEvent>,
    ) {
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if self.learning {
                    eprintln!("daemon tunnel: learned relay peer id {peer_id}");
                    self.learning = false;
                    self.relay_peer = Some(peer_id);
                }
                if Some(peer_id) == self.relay_peer {
                    self.connected = true;
                    let via = if endpoint.is_relayed() {
                        "relayed"
                    } else {
                        "direct"
                    };
                    eprintln!("daemon tunnel: relay {peer_id} connected ({via})");
                    if self.circuit_listener.is_none() && !self.reserved {
                        self.listen_on_circuit(swarm, peer_id);
                    }
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
                        "daemon tunnel: relay {peer_id} disconnected (cause: {}); will reconnect",
                        cause
                            .as_ref()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "n/a".into())
                    );
                    self.connected = false;
                    self.reserved = false;
                    self.circuit_listener = None;
                    self.schedule_retry();
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let relay_failure = match (peer_id, self.relay_peer) {
                    (Some(p), Some(relay)) => p == relay,
                    (None, None) => self.learning,
                    _ => false,
                };
                if relay_failure {
                    eprintln!("daemon tunnel: relay dial failed: {error}");
                    self.connected = false;
                    self.schedule_retry();
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
                            eprintln!("daemon tunnel: relay reservation listener failed: {e}");
                            self.schedule_retry();
                        }
                        Ok(()) => {
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
                    eprintln!("daemon tunnel: relay listener error: {error}");
                }
            }
            SwarmEvent::Behaviour(TunnelBehavioursEvent::Relay(
                relay::client::Event::ReservationReqAccepted { renewal, .. },
            )) => {
                eprintln!(
                    "daemon tunnel: relay reservation {} — agents can now dial this daemon",
                    if renewal { "renewed" } else { "established" }
                );
                self.reserved = true;
                self.backoff.reset();
                self.retry_at = None;
            }
            SwarmEvent::Behaviour(TunnelBehavioursEvent::Identify(identify::Event::Received {
                info: identify::Info { observed_addr, .. },
                ..
            })) => {
                swarm.add_external_address(observed_addr);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Live status (the daemon UI/API's tunnel view — M5 step 6)
// ---------------------------------------------------------------------------

/// Per-service live counters, updated by the accept path.
#[derive(Debug, Default, Clone)]
struct ServiceStat {
    upstream: String,
    agent_port: u16,
    /// Distinct agent peers seen, each with its live connection path
    /// ("direct" | "relayed" | "unknown") — one agent, many streams.
    peers: HashMap<String, String>,
    active_streams: i64,
    refusals: u64,
    last_activity_unix: Option<u64>,
}

/// What the API serializes.
#[derive(Debug, Clone, Serialize, Default)]
pub struct TunnelServiceStatus {
    pub name: String,
    pub upstream: String,
    pub agent_port: u16,
    pub connected_agents: usize,
    /// Of the connected agents: how many ride a DCUtR-punched direct
    /// connection vs a relayed circuit. The tunnel connection is independent
    /// of the sync transport's, so this is its own direct/relayed badge.
    pub direct_agents: usize,
    pub relayed_agents: usize,
    pub active_streams: i64,
    pub refusals: u64,
    pub last_activity_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TunnelLinkStatus {
    /// Live agent ↔ daemon tunnel connections (held open by the agent's
    /// driver, independent of stream traffic).
    pub agents: usize,
    pub direct: usize,
    pub relayed: usize,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TunnelStatusSnapshot {
    pub enabled: bool,
    pub link: TunnelLinkStatus,
    pub services: Vec<TunnelServiceStatus>,
}

/// Shared handle: the tunnel service updates it, the daemon API reads it.
/// Clones share one mutex-protected map.
#[derive(Clone)]
pub struct TunnelStatusHandle {
    enabled: bool,
    /// Live agent connections: peer id -> "direct" | "relayed" (from the
    /// swarm's ConnectionEstablished endpoint).
    links: Arc<std::sync::Mutex<HashMap<String, String>>>,
    inner: Arc<std::sync::Mutex<HashMap<String, ServiceStat>>>,
}

impl std::fmt::Debug for TunnelStatusHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelStatusHandle")
            .field("enabled", &self.enabled)
            .field("services", &self.snapshot().services)
            .finish()
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl TunnelStatusHandle {
    pub fn new(cfg: &TunnelConfig) -> Self {
        let mut inner = HashMap::new();
        for s in &cfg.services {
            inner.insert(
                s.name.clone(),
                ServiceStat {
                    upstream: s.upstream.clone(),
                    agent_port: s.agent_port,
                    ..Default::default()
                },
            );
        }
        TunnelStatusHandle {
            enabled: cfg.enabled,
            links: Arc::new(std::sync::Mutex::new(HashMap::new())),
            inner: Arc::new(std::sync::Mutex::new(inner)),
        }
    }

    fn with<F: FnOnce(&mut HashMap<String, ServiceStat>)>(&self, f: F) {
        let mut m = self.inner.lock().expect("tunnel status lock");
        f(&mut m);
    }

    pub(crate) fn note_connected(&self, service: &str, peer: &PeerId, path: &str) {
        let now = now_unix();
        self.with(|m| {
            if let Some(s) = m.get_mut(service) {
                s.peers.insert(peer.to_string(), path.to_string());
                s.active_streams += 1;
                s.last_activity_unix = Some(now);
            }
        });
    }

    pub(crate) fn note_stream_closed(&self, service: &str) {
        let now = now_unix();
        self.with(|m| {
            if let Some(s) = m.get_mut(service) {
                s.active_streams -= 1;
                s.last_activity_unix = Some(now);
            }
        });
    }

    pub(crate) fn note_refusal(&self, service: Option<&str>) {
        let now = now_unix();
        self.with(|m| {
            match service {
                // A known-service refusal (upstream down); unknown services
                // have no row — count them under a synthetic row so the UI
                // sees the refusal attempts against the allowlist.
                Some(name) => {
                    if let Some(s) = m.get_mut(name) {
                        s.refusals += 1;
                        s.last_activity_unix = Some(now);
                    }
                }
                None => {
                    let s = m.entry(String::from("(unauthorized/unknown)")).or_default();
                    s.refusals += 1;
                    s.last_activity_unix = Some(now);
                }
            }
        });
    }

    /// A live agent connection appeared (swarm event); record its path.
    pub(crate) fn note_link_established(&self, peer: &PeerId, path: &str) {
        self.links
            .lock()
            .expect("tunnel link lock")
            .insert(peer.to_string(), path.to_string());
    }

    /// The peer's last live connection closed.
    pub(crate) fn note_link_closed(&self, peer: &PeerId) {
        self.links
            .lock()
            .expect("tunnel link lock")
            .remove(&peer.to_string());
    }

    /// The live path for a peer, for stamping its streams ("unknown" if the
    /// stream somehow arrived before the connection event was processed).
    pub(crate) fn link_path(&self, peer: &PeerId) -> String {
        self.links
            .lock()
            .expect("tunnel link lock")
            .get(&peer.to_string())
            .cloned()
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn snapshot(&self) -> TunnelStatusSnapshot {
        let link_counts = {
            let links = self.links.lock().expect("tunnel link lock");
            TunnelLinkStatus {
                agents: links.len(),
                direct: links.values().filter(|p| p.as_str() == "direct").count(),
                relayed: links.values().filter(|p| p.as_str() == "relayed").count(),
            }
        };
        let mut services: Vec<TunnelServiceStatus> = {
            let m = self.inner.lock().expect("tunnel status lock");
            m.iter()
                .map(|(name, s)| TunnelServiceStatus {
                    name: name.clone(),
                    upstream: s.upstream.clone(),
                    agent_port: s.agent_port,
                    connected_agents: s.peers.len(),
                    direct_agents: s.peers.values().filter(|p| p.as_str() == "direct").count(),
                    relayed_agents: s.peers.values().filter(|p| p.as_str() == "relayed").count(),
                    active_streams: s.active_streams,
                    refusals: s.refusals,
                    last_activity_unix: s.last_activity_unix,
                })
                .collect()
        };
        services.sort_by(|a, b| a.name.cmp(&b.name));
        TunnelStatusSnapshot {
            enabled: self.enabled,
            link: link_counts,
            services,
        }
    }
}

// ---------------------------------------------------------------------------
// The service loop
// ---------------------------------------------------------------------------

/// Run the tunnel service forever (spawned onto the daemon's runtime). Errors
/// here are startup failures only; connection-level failures are logged and
/// never kill the loop.
pub async fn run_service(run: TunnelRun) -> Result<(), String> {
    let seed = derive_daemon_identity_seed(&run.master);
    let keypair = identity::Keypair::ed25519_from_bytes(seed)
        .map_err(|e| format!("daemon identity seed: {e}"))?;
    let daemon_peer = keypair.public().to_peer_id();
    eprintln!(
        "daemon tunnel: identity {daemon_peer} (derived from the defaults master key) — {} service(s) allowlisted: {:?}",
        run.services.len(),
        {
            let mut names: Vec<&String> = run.services.keys().collect();
            names.sort();
            names
        }
    );

    let mut swarm = build_tunnel_swarm(keypair)?;
    let services = std::sync::Arc::new(run.services);
    let expected = std::sync::Arc::new(run.expected_peers);

    let mut control = swarm.behaviour().stream.new_control();
    let mut incoming = control
        .accept(StreamProtocol::new(TUNNEL_STREAM_PROTOCOL))
        .map_err(|_| "tunnel protocol already registered on a fresh control")?;

    let mut link = RelayLink::new(&run.relay);
    link.start(&mut swarm);
    let status = run.status.clone();

    loop {
        let retry_at = link.retry_at;
        tokio::select! {
            event = swarm.next() => match event {
                Some(event) => {
                    // Track each AGENT peer's live connection path for the
                    // status surface (the relay's own connection is skipped —
                    // a relayed endpoint there just means the DIAL to the
                    // relay rode a circuit). Agents dial the daemon's circuit
                    // listener; DCUtR punches upgrade them to direct.
                    match &event {
                        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }
                            if Some(peer_id) != link.relay_peer.as_ref() =>
                        {
                            status.note_link_established(
                                peer_id,
                                if endpoint.is_relayed() { "relayed" } else { "direct" },
                            );
                        }
                        SwarmEvent::ConnectionClosed { peer_id, num_established, .. }
                            if Some(peer_id) != link.relay_peer.as_ref() && *num_established == 0 =>
                        {
                            status.note_link_closed(peer_id);
                        }
                        _ => {}
                    }
                    link.handle_event(&mut swarm, event);
                }
                None => return Err("tunnel swarm ended".into()),
            },
            maybe_stream = incoming.next() => match maybe_stream {
                Some((peer, stream)) => {
                    let services = services.clone();
                    let expected = expected.clone();
                    let status = status.clone();
                    let path = status.link_path(&peer);
                    tokio::spawn(async move {
                        handle_conn(stream, peer, services, expected, path, status).await;
                    });
                }
                None => return Err("tunnel accept stream ended".into()),
            },
            _ = async {
                match retry_at {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from(at)).await,
                    None => std::future::pending::<()>().await,
                }
            } => link.tick(&mut swarm),
        }
    }
}

/// One tunnel stream: handshake → authorize → allowlist → raw pipe to upstream.
/// Every refusal is a single status byte + close; every failure logs and
/// returns (never panics — a sandbox must not be able to disrupt the daemon).
async fn handle_conn(
    stream: libp2p::Stream,
    peer: PeerId,
    services: std::sync::Arc<HashMap<String, UpstreamAddr>>,
    expected: std::sync::Arc<HashSet<PeerId>>,
    // The agent's live connection path ("direct"|"relayed"|"unknown") for the
    // status surface, captured from the swarm's ConnectionEstablished.
    path: String,
    status: TunnelStatusHandle,
) {
    let mut pinned: std::pin::Pin<Box<libp2p::Stream>> = Box::pin(stream);

    // --- handshake (bounded) ---
    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut header = [0u8; 10];
        futures::AsyncReadExt::read_exact(&mut pinned, &mut header)
            .await
            .map_err(|_| TUNNEL_STATUS_BAD_HANDSHAKE)?;
        let mut name = vec![0u8; header[9] as usize];
        futures::AsyncReadExt::read_exact(&mut pinned, &mut name)
            .await
            .map_err(|_| TUNNEL_STATUS_BAD_HANDSHAKE)?;
        let mut buf = header.to_vec();
        buf.extend_from_slice(&name);
        match parse_tunnel_request(&buf) {
            Ok(service) => Ok(service.to_string()),
            Err(status) => Err(status),
        }
    })
    .await;
    let service = match handshake {
        Ok(Ok(service)) => service,
        Ok(Err(status)) => {
            eprintln!(
                "daemon tunnel: {peer} bad handshake ({})",
                tunnel_status_name(status)
            );
            let _ = refuse(&mut pinned, status).await;
            return;
        }
        Err(_) => {
            eprintln!("daemon tunnel: {peer} handshake timed out");
            return; // nothing sane to reply to
        }
    };

    // --- authorize (derived agent peer of a p2p target?) ---
    if !expected.contains(&peer) {
        eprintln!(
            "daemon tunnel: REFUSED {peer} (service {service:?}): peer is not a known sync agent"
        );
        status.note_refusal(None);
        let _ = refuse(&mut pinned, TUNNEL_STATUS_UNAUTHORIZED_PEER).await;
        return;
    }

    // --- allowlist (default deny — the owner rule) ---
    let Some(upstream) = services.get(&service) else {
        eprintln!(
            "daemon tunnel: REFUSED {peer} (service {service:?}): not in the [[tunnel.services]] allowlist"
        );
        status.note_refusal(None);
        let _ = refuse(&mut pinned, TUNNEL_STATUS_UNKNOWN_SERVICE).await;
        return;
    };

    // --- upstream dial ---
    let dial = tokio::time::timeout(
        UPSTREAM_DIAL_TIMEOUT,
        tokio::net::TcpStream::connect((upstream.host.as_str(), upstream.port)),
    )
    .await;
    let tcp = match dial {
        Ok(Ok(tcp)) => tcp,
        Ok(Err(e)) => {
            eprintln!(
                "daemon tunnel: {peer} (service {service:?}): upstream {} unreachable: {e}",
                upstream.host
            );
            status.note_refusal(Some(&service));
            let _ = refuse(&mut pinned, TUNNEL_STATUS_UPSTREAM_UNAVAILABLE).await;
            return;
        }
        Err(_) => {
            eprintln!(
                "daemon tunnel: {peer} (service {service:?}): upstream {} dial timed out",
                upstream.host
            );
            status.note_refusal(Some(&service));
            let _ = refuse(&mut pinned, TUNNEL_STATUS_UPSTREAM_UNAVAILABLE).await;
            return;
        }
    };

    // --- accept: status byte, then a raw pipe in both directions ---
    if refuse(&mut pinned, TUNNEL_STATUS_OK).await.is_err() {
        return; // the peer vanished before the accept — nothing was counted
    }
    status.note_connected(&service, &peer, &path);
    eprintln!(
        "daemon tunnel: {peer} tunneled to {}:{} (service {service:?})",
        upstream.host, upstream.port
    );
    let mut pipe = Box::pin(tokio_util::compat::FuturesAsyncReadCompatExt::compat(
        pinned,
    ));
    let (tcp_read, tcp_write) = tcp.into_split();
    let mut tcp_stream = tokio::io::join(tcp_read, tcp_write);
    match tokio::io::copy_bidirectional(&mut pipe, &mut tcp_stream).await {
        Ok((up, down)) => {
            eprintln!(
                "daemon tunnel: {peer} (service {service:?}) pipe ended (up {up}B, down {down}B)"
            );
        }
        Err(e) => {
            eprintln!("daemon tunnel: {peer} (service {service:?}) pipe error: {e}");
        }
    }
    status.note_stream_closed(&service);
}

/// Best-effort status byte + close. `TUNNEL_STATUS_OK` here means "accepted".
async fn refuse(stream: &mut std::pin::Pin<Box<libp2p::Stream>>, status: u8) -> io::Result<()> {
    let write = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        futures::AsyncWriteExt::write_all(stream, &[status]).await?;
        futures::AsyncWriteExt::flush(stream).await
    })
    .await;
    match write {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "status byte write timed out",
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests — config shapes, upstream parsing, expected-peer derivation. The
// full relay→tunnel→upstream proof is crates/cli/tests/tunnel_loopback.rs.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sync_proto::p2p::{derive_sandbox_identity_seed, tunnel_request_bytes};

    #[test]
    fn tunnel_config_parses_from_toml_and_defaults_to_disabled() {
        let cfg: TunnelConfig = toml::from_str("").unwrap();
        assert!(!cfg.enabled, "default deny: tunnel off unless enabled");
        assert!(cfg.services.is_empty());

        let cfg: TunnelConfig = toml::from_str(
            r#"
enabled = true

[[services]]
name = "memory"
upstream = "http://127.0.0.1:7999"
agent_port = 7402
spool_tools = ["memory_store", "memory_delete"]
"#,
        )
        .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.services.len(), 1);
        assert_eq!(cfg.services[0].name, "memory");
        assert_eq!(cfg.services[0].upstream, "http://127.0.0.1:7999");
        assert_eq!(cfg.services[0].agent_port, 7402);
        assert_eq!(
            cfg.services[0].spool_tools,
            vec!["memory_store", "memory_delete"]
        );
    }

    #[test]
    fn parse_upstream_host_port_and_path_ignoring() {
        let u = parse_upstream("http://127.0.0.1:7999").unwrap();
        assert_eq!(
            u,
            UpstreamAddr {
                host: "127.0.0.1".into(),
                port: 7999
            }
        );
        // A path component is IGNORED: the client's request line carries the
        // real path through the raw pipe.
        let u = parse_upstream("http://127.0.0.1:7999/mcp").unwrap();
        assert_eq!(u.port, 7999);
        let u = parse_upstream("http://localhost").unwrap();
        assert_eq!(
            u,
            UpstreamAddr {
                host: "localhost".into(),
                port: 80
            }
        );
        assert!(
            parse_upstream("https://127.0.0.1:7999").is_err(),
            "https rejected loudly"
        );
        assert!(parse_upstream("ftp://x").is_err());
        assert!(
            parse_upstream("http://:7999").is_err(),
            "empty host rejected"
        );
        assert!(parse_upstream("http://127.0.0.1:notaport").is_err());
    }

    #[test]
    fn prepare_disabled_is_none_and_enabled_requires_the_pieces() {
        let mut cfg = crate::daemon::DaemonConfig {
            server: Default::default(),
            defaults: Default::default(),
            targets: Vec::new(),
            tunnel: TunnelConfig::default(),
        };
        cfg.tunnel = TunnelConfig::default();
        assert!(
            matches!(prepare(&cfg), Ok(None)),
            "disabled → no tunnel run"
        );

        cfg.tunnel.enabled = true;
        let err = prepare(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("no [[tunnel.services]]"),
            "empty allowlist refused loudly: {err}"
        );

        cfg.tunnel.services.push(TunnelServiceConfig {
            name: "memory".into(),
            upstream: "http://127.0.0.1:7999".into(),
            agent_port: 7402,
            spool_tools: vec!["memory_store".into(), "memory_delete".into()],
        });
        let err = prepare(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("defaults.relay"),
            "relay required: {err}"
        );

        cfg.defaults.relay = Some("/ip4/203.0.113.7/tcp/4001".into());
        let err = prepare(&cfg).unwrap_err();
        assert!(
            err.to_string().contains("master key"),
            "master key required: {err}"
        );

        cfg.defaults.master_key_file = Some(std::path::PathBuf::from("/nonexistent/key"));
        let err = prepare(&cfg).unwrap_err();
        assert!(err.to_string().contains("master_key_file"), "{err}");

        // Full happy path (with a temp key file): services resolved, no peers.
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master.key");
        std::fs::write(&key, "ab".repeat(32) + "\n").unwrap();
        cfg.defaults.master_key_file = Some(key);
        let run = prepare(&cfg).unwrap().expect("tunnel run");
        assert_eq!(run.services.get("memory").unwrap().port, 7999);
        assert!(
            run.expected_peers.is_empty(),
            "no p2p targets → no expected peers (all refused)"
        );
    }

    #[test]
    fn prepare_expected_peers_match_the_agent_derivation() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master.key");
        std::fs::write(&key, "ab".repeat(32)).unwrap();

        let mk_target = |name: &str, sandbox: &str| {
            crate::daemon::TargetConfig {
            name: name.into(),
            root: std::path::PathBuf::from("/tmp/x"),
            sandbox: sandbox.into(),
            workspace: None,
            relay: Some("/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWQqWcYxCifgqAsynZL2uJUd132gbG3XhZbCQZMs6Dq9Qc".into()),
            excludes: vec![],
            interval_secs: None,
            debounce_ms: None,
            master_key_file: Some(key.clone()),
            master_key_env: false,
            kubeconfig: None,
            root_remote: "/sandbox".into(),
            auto_provision: false,
            first_run_dry_run: None,
            hole_punch: true,
            tunnel_services: Vec::new(),
            tunnel_args: Vec::new(),
        }
        };
        let mut cfg = crate::daemon::DaemonConfig {
            server: Default::default(),
            defaults: Default::default(),
            targets: Vec::new(),
            tunnel: TunnelConfig {
                enabled: true,
                services: vec![TunnelServiceConfig {
                    name: "memory".into(),
                    upstream: "http://127.0.0.1:7999".into(),
                    agent_port: 7402,
                    spool_tools: vec!["memory_store".into(), "memory_delete".into()],
                }],
            },
        };
        cfg.defaults.relay = Some("/ip4/203.0.113.7/tcp/4001".into());
        cfg.defaults.master_key_file = Some(key.clone());
        cfg.targets = vec![
            mk_target("plan", "sync-oc+plan"),
            mk_target("slides", "sync-oc+slides"),
        ];
        let run = prepare(&cfg).unwrap().expect("tunnel run");

        // The expected set is EXACTLY what the agents derive from their own
        // (master, sandbox_id) — the same identity the sync transport dials.
        let master = sync_proto::p2p::parse_master_key(&"ab".repeat(32)).unwrap();
        let a = agent_peer_id(&master, "sync-oc+plan").unwrap();
        let b = agent_peer_id(&master, "sync-oc+slides").unwrap();
        assert_eq!(run.expected_peers.len(), 2);
        assert!(run.expected_peers.contains(&a) && run.expected_peers.contains(&b));
        let stranger = agent_peer_id(&[9u8; 32], "sync-oc+plan").unwrap();
        assert!(
            !run.expected_peers.contains(&stranger),
            "a different master → unauthorized"
        );
    }

    // ----- the M5 buildability proof: relay → REAL tunnel service → upstream -----

    /// Relay node stand-in (crates/relay): relay-v2 SERVER over memory transport.
    #[derive(NetworkBehaviour)]
    struct TestRelayBehaviour {
        relay: relay::Behaviour,
    }

    /// Mini agent client (mimics crates/agent/src/tunnel.rs): relay client +
    /// identify + stream control; open_stream AUTO-DIALS the daemon from the
    /// address book — the exact seam the real agent relies on.
    #[derive(NetworkBehaviour)]
    struct TestAgentBehaviour {
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

    fn build_agent_swarm(keypair: identity::Keypair) -> libp2p::Swarm<TestAgentBehaviour> {
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
            .with_behaviour(|kp, relay_client| TestAgentBehaviour {
                relay_client,
                identify: identify::Behaviour::new(identify::Config::new(
                    IDENTIFY_PROTOCOL_VERSION.to_string(),
                    kp.public(),
                )),
                stream: libp2p_stream::Behaviour::new(),
            })
            .expect("agent behaviour")
            .build()
    }

    /// Handshake one tunnel stream: `open_stream` rides an ESTABLISHED
    /// connection (peer-id auto-dial has no address book in libp2p-stream —
    /// the real agent's DRIVER dials explicitly, exactly like this test).
    /// Retries until the explicit dial lands.
    async fn handshake(
        control: &mut libp2p_stream::Control,
        daemon_peer: PeerId,
        service: &str,
    ) -> (std::pin::Pin<Box<libp2p::Stream>>, u8) {
        let mut opened = None;
        for _ in 0..120 {
            match tokio::time::timeout(
                Duration::from_millis(500),
                control.open_stream(daemon_peer, StreamProtocol::new(TUNNEL_STREAM_PROTOCOL)),
            )
            .await
            {
                Ok(Ok(s)) => {
                    opened = Some(s);
                    break;
                }
                _ => tokio::time::sleep(Duration::from_millis(250)).await, // the explicit dial is still landing
            }
        }
        let stream = opened.expect("open_stream succeeded once the dial landed");
        let mut pinned: std::pin::Pin<Box<libp2p::Stream>> = Box::pin(stream);
        use futures::{AsyncReadExt as _, AsyncWriteExt as _};
        pinned
            .as_mut()
            .write_all(&tunnel_request_bytes(service).expect("valid name"))
            .await
            .expect("handshake write");
        pinned.as_mut().flush().await.expect("handshake flush");
        let mut status = [0u8; 1];
        tokio::time::timeout(
            Duration::from_secs(15),
            pinned.as_mut().read_exact(&mut status),
        )
        .await
        .expect("status byte arrived in time")
        .expect("status byte readable");
        (pinned, status[0])
    }

    /// THREE swarms on the memory transport: a relay (the VPS stand-in), the
    /// REAL daemon tunnel service under test (`run_service`), and mini agent
    /// clients that dial the daemon EXPLICITLY (the AgentDriver shape).
    /// Asserts the whole M5 daemon chain:
    /// reservation → explicit circuit dial → open_stream → handshake →
    /// ALLOWLIST (allowed = raw pipe to the upstream; unknown = refused;
    /// stranger = unauthorized) → bidirectional pump.
    #[tokio::test]
    async fn in_process_loopback_tunnel_service_end_to_end() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    tracing_subscriber::EnvFilter::new("libp2p_relay=debug,libp2p_swarm=debug")
                }),
            )
            .with_test_writer()
            .try_init();
        let master = [7u8; 32];

        // ---- fake upstream (the stand-in for mcp-memory.service) ----
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    // Read ONE chunk, answer with a marker, close. (Reading to
                    // EOF would deadlock: the tunnel pipe stays open until the
                    // client closes, but the client is waiting for OUR reply.)
                    let mut buf = vec![0u8; 4096];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let _ = sock
                        .write_all(format!("UPSTREAM-SAW-{n}-BYTES").as_bytes())
                        .await;
                    let _ = sock.shutdown().await;
                });
            }
        });

        // ---- relay node (the VPS stand-in) ----
        let relay_kp = identity::Keypair::generate_ed25519();
        let relay_peer = relay_kp.public().to_peer_id();
        let mut relay_swarm = build_relay_swarm(relay_kp);
        relay_swarm
            .listen_on("/memory/0".parse::<Multiaddr>().unwrap())
            .expect("relay listen");
        let relay_listen = loop {
            match tokio::time::timeout(Duration::from_secs(10), relay_swarm.next()).await {
                Ok(Some(SwarmEvent::NewListenAddr { address, .. })) => break address,
                Ok(Some(_)) => continue,
                Ok(None) => panic!("relay swarm ended"),
                Err(_) => panic!("relay did not start listening in time"),
            }
        };
        relay_swarm.add_external_address(relay_listen.clone());
        tokio::spawn(async move { while relay_swarm.next().await.is_some() {} });
        let relay_with_peer = relay_listen.with(Protocol::P2p(relay_peer));

        // ---- the REAL daemon tunnel service under test ----
        let agent_peer = agent_peer_id(&master, "test").expect("derived agent peer");
        let run = TunnelRun {
            master,
            relay: relay_with_peer.clone(),
            services: HashMap::from([(
                "memory".to_string(),
                UpstreamAddr {
                    host: upstream_addr.ip().to_string(),
                    port: upstream_addr.port(),
                },
            )]),
            expected_peers: HashSet::from([agent_peer]),
            status: TunnelStatusHandle::new(&TunnelConfig {
                enabled: true,
                services: vec![TunnelServiceConfig {
                    name: "memory".into(),
                    upstream: "http://127.0.0.1:0".into(),
                    agent_port: 0,
                    spool_tools: Vec::new(),
                }],
            }),
        };
        let daemon_task = tokio::spawn(run_service(run));

        // ---- authorized client (the shape of crates/agent tunnel.rs: the
        //      driver DIALS the daemon circuit explicitly; open_stream rides
        //      the established connection) ----
        let client_kp = {
            let seed = derive_sandbox_identity_seed(&master, "test");
            identity::Keypair::ed25519_from_bytes(seed).expect("identity seed")
        };
        assert_eq!(
            client_kp.public().to_peer_id(),
            agent_peer,
            "same derivation on both ends"
        );
        let mut client_swarm = build_agent_swarm(client_kp);
        let mut control = client_swarm.behaviour().stream.new_control();
        let daemon_peer = {
            let seed = derive_daemon_identity_seed(&master);
            identity::Keypair::ed25519_from_bytes(seed)
                .expect("daemon seed")
                .public()
                .to_peer_id()
        };
        let circuit = relay_with_peer
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(daemon_peer));
        client_swarm.dial(circuit.clone()).expect("dial accepted");
        // Drive the client swarm forever (the pump) — Control works alongside.
        // The DIAL is retried on a timer exactly like the real AgentDriver:
        // the daemon's reservation may not exist yet when we first dial.
        let client_circuit = circuit.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut connected = false;
            let mut redial = tokio::time::interval(Duration::from_millis(500));
            redial.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    ev = client_swarm.next() => match ev {
                        Some(SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }) => {
                            eprintln!("test client: connected {peer_id} (relayed={})", endpoint.is_relayed());
                            if peer_id == daemon_peer { connected = true; }
                        }
                        Some(SwarmEvent::ConnectionClosed { peer_id, num_established, .. }) => {
                            if peer_id == daemon_peer && num_established == 0 { connected = false; }
                        }
                        Some(SwarmEvent::OutgoingConnectionError { peer_id, error, .. }) => {
                            eprintln!("test client: dial error to {peer_id:?}: {error}");
                        }
                        _ => {}
                    },
                    _ = redial.tick() => {
                        if !connected {
                            let _ = client_swarm.dial(client_circuit.clone());
                        }
                    }
                }
            }
        });

        // 1. allowed service: handshake OK, then a RAW PIPE to the upstream.
        let (mut pinned, status) = handshake(&mut control, daemon_peer, "memory").await;
        assert_eq!(status, TUNNEL_STATUS_OK, "allowlisted service accepted");
        {
            use futures::{AsyncReadExt as _, AsyncWriteExt as _};
            pinned
                .as_mut()
                .write_all(b"hello-upstream")
                .await
                .expect("pipe write");
            pinned.as_mut().flush().await.expect("pipe flush");
            let mut resp = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(15),
                pinned.as_mut().read_to_end(&mut resp),
            )
            .await
            .expect("upstream reply in time")
            .expect("upstream reply read");
            let text = String::from_utf8_lossy(&resp);
            assert!(
                text.contains("UPSTREAM-SAW-14-BYTES"),
                "raw bytes must reach the upstream untouched: {text:?}"
            );
        }

        // 2. UNKNOWN service: refused cleanly (default deny), stream stays framed.
        let (_pinned, status) = handshake(&mut control, daemon_peer, "nosuch").await;
        assert_eq!(status, TUNNEL_STATUS_UNKNOWN_SERVICE, "default deny");

        // 3. unauthorized peer: a client whose identity is NOT a derived agent
        //    peer gets the unauthorized refusal.
        let stranger_kp = identity::Keypair::generate_ed25519();
        let mut stranger_swarm = build_agent_swarm(stranger_kp);
        let mut stranger_control = stranger_swarm.behaviour().stream.new_control();
        stranger_swarm.dial(circuit.clone()).expect("dial accepted");
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut connected = false;
            let mut redial = tokio::time::interval(Duration::from_millis(500));
            redial.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    ev = stranger_swarm.next() => match ev {
                        Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                            if peer_id == daemon_peer { connected = true; }
                        }
                        Some(SwarmEvent::ConnectionClosed { peer_id, num_established, .. }) => {
                            if peer_id == daemon_peer && num_established == 0 { connected = false; }
                        }
                        _ => {}
                    },
                    _ = redial.tick() => {
                        if !connected {
                            let _ = stranger_swarm.dial(circuit.clone());
                        }
                    }
                }
            }
        });
        let (_pinned, status) = handshake(&mut stranger_control, daemon_peer, "memory").await;
        assert_eq!(status, TUNNEL_STATUS_UNAUTHORIZED_PEER, "stranger refused");

        daemon_task.abort();
    }
}
