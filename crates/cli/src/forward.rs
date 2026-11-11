//! M9 reverse-forward runtime (daemon side).
//!
//! One loopback TCP listener per serve-enabled target, bridged over libp2p to
//! the pod's `opencode serve` — the laptop `opencode --server` attach path
//! with NO openshell/OIDC in the loop (M8's `openshell forward` died hourly
//! on gateway-JWT expiry; this rides our own relay/direct link).
//!
//! Shape (mirrors the M5 tunnel listener in [`crate::tunnel`], flipped):
//! - Identity: the DERIVED daemon identity (`derive_daemon_identity_seed`) —
//!   the agent's forward accept loop authorizes exactly this peer.
//! - Dial-out only: the swarm dials the agent's relay circuit (the agent
//!   holds the reservation); no own circuit listener, so the M5 tunnel
//!   listener and this runtime never fight over duplicate reservations.
//! - The local listener exists IFF the agent link is up: bound on
//!   ConnectionEstablished(agent), dropped on ConnectionClosed — a dead p2p
//!   path fails fast (ECONNREFUSED) and leaves the port free for the
//!   openshell-forward fallback.
//! - Per accepted TCP connection: open_stream(FORWARD_STREAM_PROTOCOL) →
//!   MAGIC|VERSION → the agent's one status byte → RAW PIPE.
use futures::StreamExt as _;
use libp2p::swarm::SwarmEvent;
use libp2p::{
    identify, noise, relay, tcp, yamux, Multiaddr, StreamProtocol, Transport as _,
};
use sync_proto::p2p::{
    derive_daemon_identity_seed, forward_request_bytes, forward_status_name,
    FORWARD_STREAM_PROTOCOL, FORWARD_STATUS_OK,
};

/// How long one open_stream may take (cold relay dials take seconds).
const OPEN_STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// The 0.57 default (10 s) would drop the relay connection between attaches.
const IDLE_CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
/// Re-dial backoff after the agent link drops (tunnel.rs's ladder).
const BACKOFF_STEPS: [std::time::Duration; 3] = [
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(5),
];
const BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(30);

/// Identify protocol version — MUST match the relay's (`crates/relay`).
const IDENTIFY_PROTOCOL_VERSION: &str = "sync-agent-pvc/relay/1";

#[derive(libp2p::swarm::NetworkBehaviour)]
struct ForwardBehaviours {
    relay: relay::client::Behaviour,
    identify: identify::Behaviour,
    stream: libp2p_stream::Behaviour,
}

/// Production swarm: tcp transport (the dial-out path) + memory (the loopback
/// test against the SAME code path).
fn build_forward_swarm(
    keypair: libp2p::identity::Keypair,
) -> Result<libp2p::Swarm<ForwardBehaviours>, String> {
    Ok(libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| format!("tcp transport: {e}"))?
        .with_other_transport(|kp| {
            libp2p::core::transport::MemoryTransport::default()
                .upgrade(libp2p::core::upgrade::Version::V1)
                .authenticate(noise::Config::new(kp).expect("noise config"))
                .multiplex(yamux::Config::default())
        })
        .map_err(|e| format!("memory transport: {e}"))?
        .with_relay_client(noise::Config::new, yamux::Config::default)
        .map_err(|e| format!("relay client transport: {e}"))?
        .with_behaviour(|key, relay_client| ForwardBehaviours {
            relay: relay_client,
            identify: identify::Behaviour::new(identify::Config::new(
                IDENTIFY_PROTOCOL_VERSION.to_string(),
                key.public(),
            )),
            stream: libp2p_stream::Behaviour::new(),
        })
        .map_err(|e| format!("behaviour: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build())
}

pub(crate) struct ForwardRun {
    /// The target's relay multiaddr (with the /p2p/PEER suffix — required to
    /// build the agent's circuit address).
    pub relay: String,
    /// The qualified sandbox id — pins the agent peer + the serve port.
    pub qualified: String,
    /// Master key material (the daemon identity derives from it).
    pub master: [u8; 32],
    /// Laptop loopback listener port (== the derived serve port).
    pub local_port: u16,
    /// Live status for the UI/API (the tunnel banner's attach row).
    pub status: std::sync::Arc<ForwardStatus>,
}

/// The forward runtime's live state, shared with the API (rendered in the
/// tunnel banner's attach row). All fields are daemon-side truth: the
/// listener exists IFF the agent link is up, and `active_conns` counts the
/// bridged attach connections right now. `path` is how the agent link
/// actually came up (relayed circuit vs direct punch) — tracked from the
/// dial's endpoint, not assumed.
#[derive(Debug, Default)]
pub(crate) struct ForwardStatus {
    pub target: String,
    pub local_port: u16,
    /// "dialing" | "up" | "down" — the agent link, not the listener.
    pub agent_link: std::sync::Mutex<String>,
    /// "relayed" | "direct" — how the link came up (endpoint truth).
    pub path: std::sync::Mutex<String>,
    pub listening: std::sync::atomic::AtomicBool,
    pub active_conns: std::sync::atomic::AtomicU64,
}

impl ForwardStatus {
    pub(crate) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "target": self.target,
            "local_port": self.local_port,
            "agent_link": self.agent_link.lock().unwrap().clone(),
            "path": self.path.lock().unwrap().clone(),
            "listening": self.listening.load(std::sync::atomic::Ordering::Relaxed),
            "active_conns": self.active_conns.load(std::sync::atomic::Ordering::Relaxed),
        })
    }
}

/// Run the forward service forever (spawned onto the daemon's runtime).
/// Errors here are startup failures only; connection-level failures are
/// logged and never kill the loop.
pub(crate) async fn run_service(run: ForwardRun) -> Result<(), String> {
    let st = run.status.clone();
    let seed = derive_daemon_identity_seed(&run.master);
    let keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed)
        .map_err(|e| format!("daemon identity seed: {e}"))?;
    let daemon_peer = keypair.public().to_peer_id();
    eprintln!(
        "daemon forward: {} — identity {daemon_peer}, dialing the agent circuit (local 127.0.0.1:{})",
        run.qualified, run.local_port
    );
    *st.agent_link.lock().unwrap() = "dialing".to_string();

    let mut swarm = build_forward_swarm(keypair)?;
    let control = swarm.behaviour().stream.new_control();

    // The agent's relay circuit address: <relay>/p2p-circuit/p2p/<agent-peer>.
    let agent_peer = crate::transport::agent_peer_id(&run.master, &run.qualified)
        .map_err(|e| format!("agent peer derivation: {e}"))?;
    let relay: Multiaddr = run
        .relay
        .parse()
        .map_err(|e| format!("relay multiaddr {:?}: {e}", run.relay))?;
    if extract_relay_peer(&relay).is_none() {
        return Err("relay multiaddr needs a /p2p/PEER suffix for the circuit dial".to_string());
    }
    let agent_circuit = relay
        .clone()
        .with(libp2p::multiaddr::Protocol::P2pCircuit)
        .with(libp2p::multiaddr::Protocol::P2p(agent_peer));

    // Dial state: one in-flight dial at a time; backoff after failures/drops.
    let mut dial_queued = false;
    let mut backoff_idx = 0usize;
    let mut retry_at: Option<tokio::time::Instant> = None;
    // The local listener — bound only while the agent link is up.
    let mut listener: Option<tokio::net::TcpListener> = None;
    // Accepted connections the accept loop hands over before the listener is
    // dropped (drained by the next loop iteration).
    let mut pending: Vec<tokio::net::TcpStream> = Vec::new();

    // First dial straight away.
    match swarm.dial(agent_circuit.clone()) {
        Ok(()) => dial_queued = true,
        Err(e) => eprintln!("daemon forward: agent dial failed: {e}"),
    }

    loop {
        let retry_at_now = retry_at;
        tokio::select! {
            event = swarm.next() => match event {
                Some(event) => match &event {
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }
                        if *peer_id == agent_peer =>
                    {
                        backoff_idx = 0;
                        retry_at = None;
                        *st.agent_link.lock().unwrap() = "up".to_string();
                        *st.path.lock().unwrap() = if endpoint.is_relayed() {
                            "relayed".to_string()
                        } else {
                            "direct".to_string()
                        };
                        if listener.is_none() {
                            match tokio::net::TcpListener::bind(("127.0.0.1", run.local_port)).await {
                                Ok(l) => {
                                    eprintln!(
                                        "daemon forward: agent link UP — listening on 127.0.0.1:{} (p2p → pod serve)",
                                        run.local_port
                                    );
                                    st.listening
                                        .store(true, std::sync::atomic::Ordering::Relaxed);
                                    listener = Some(l);
                                }
                                Err(e) => eprintln!(
                                    "daemon forward: bind 127.0.0.1:{} failed ({e}) — is the openshell forward holding the port?",
                                    run.local_port
                                ),
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, num_established, .. }
                        if *peer_id == agent_peer && *num_established == 0 =>
                    {
                        // The queued dial CONSUMED itself into the connection
                        // that just died — clear it or the retry tick never
                        // re-dials (hit live 2026-11-10: the drift cycle's
                        // agent respawn left the forward silent forever).
                        dial_queued = false;
                        *st.agent_link.lock().unwrap() = "down".to_string();
                        if listener.take().is_some() {
                            eprintln!(
                                "daemon forward: agent link DOWN — listener on 127.0.0.1:{} released",
                                run.local_port
                            );
                            st.listening
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                        }
                        let wait = backoff_wait(backoff_idx);
                        backoff_idx += 1;
                        retry_at = Some(tokio::time::Instant::now() + wait);
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. }
                        if peer_id.map(|p| p == agent_peer).unwrap_or(false) =>
                    {
                        dial_queued = false;
                        let wait = backoff_wait(backoff_idx);
                        backoff_idx += 1;
                        retry_at = Some(tokio::time::Instant::now() + wait);
                        eprintln!("daemon forward: agent dial failed ({error}) — retrying");
                    }
                    _ => {}
                },
                None => return Ok(()),
            },
            accept = async {
                match listener.as_ref() {
                    Some(l) => l.accept().await,
                    None => std::future::pending().await,
                }
            } => match accept {
                Ok((conn, _)) => pending.push(conn),
                Err(e) => eprintln!("daemon forward: accept failed: {e}"),
            },
            _ = async {
                match retry_at_now {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                if !dial_queued {
                    match swarm.dial(agent_circuit.clone()) {
                        Ok(()) => dial_queued = true,
                        Err(e) => eprintln!("daemon forward: re-dial failed: {e}"),
                    }
                }
            }
        }

        // Bridge any handed-over connections while the link is up.
        if listener.is_some() {
            for mut conn in pending.drain(..) {
                let _ = conn.set_nodelay(true);
                let mut control = control.clone();
                let port = run.local_port;
                let st = st.clone();
                st.active_conns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tokio::spawn(async move {
                    let result = bridge_conn(&mut control, agent_peer, &mut conn).await;
                    st.active_conns.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    if let Err(e) = result {
                        eprintln!("daemon forward: 127.0.0.1:{port} conn failed: {e}");
                    }
                });
            }
        } else {
            pending.clear();
        }
    }
}

/// One bridged connection: open the forward stream, handshake, RAW PIPE.
async fn bridge_conn(
    control: &mut libp2p_stream::Control,
    agent_peer: libp2p::PeerId,
    conn: &mut tokio::net::TcpStream,
) -> Result<(), String> {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    let open = tokio::time::timeout(
        OPEN_STREAM_TIMEOUT,
        control.open_stream(agent_peer, StreamProtocol::new(FORWARD_STREAM_PROTOCOL)),
    )
    .await
    .map_err(|_| "forward dial timed out".to_string())?
    .map_err(|e| format!("forward dial failed: {e}"))?;
    let mut pinned: std::pin::Pin<Box<libp2p::Stream>> = Box::pin(open);
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        pinned.as_mut().write_all(&forward_request_bytes()).await?;
        pinned.as_mut().flush().await?;
        let mut status = [0u8; 1];
        pinned.as_mut().read_exact(&mut status).await?;
        Ok::<u8, std::io::Error>(status[0])
    })
    .await
    .map_err(|_| "forward handshake timed out".to_string())?
    .map_err(|e| format!("forward handshake failed: {e}"))?;
    if status != FORWARD_STATUS_OK {
        return Err(format!(
            "forward refused: {}",
            forward_status_name(status)
        ));
    }
    let mut pipe = Box::pin(tokio_util::compat::FuturesAsyncReadCompatExt::compat(pinned));
    match tokio::io::copy_bidirectional(conn, &mut pipe).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("pipe ended: {e}")),
    }
}

/// The re-dial wait for attempt `idx`: the ladder steps, then the cap (a
/// dead agent must not burn dial attempts into the shared relay budget).
fn backoff_wait(idx: usize) -> std::time::Duration {
    BACKOFF_STEPS.get(idx).copied().unwrap_or(BACKOFF_CAP)
}

/// Pull the relay's peer id out of a `/p2p/PEER`-suffixed multiaddr.
fn extract_relay_peer(addr: &Multiaddr) -> Option<libp2p::PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}
