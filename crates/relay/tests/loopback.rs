//! In-process loopback proof for the relay (M3 buildability gate, plan M0(h) shape).
//!
//! Three full libp2p swarms on the tokio runtime, MemoryTransport standing in for
//! TCP (same noise + yamux upgrades as production, so only the socket differs):
//!
//!   relay swarm  — the SERVER exactly as `src/main.rs` composes it:
//!                  relay(SERVER) + dcutr + identify
//!   agent swarm  — relay::client: obtains a RESERVATION (listens on
//!                  `<relay>/p2p-circuit`), then serves inbound circuit connections
//!   daemon swarm — relay::client: DIALS `/p2p-circuit/p2p/<agent-peer>`
//!
//! The daemon then opens a raw stream on `sync_proto::p2p::P2P_STREAM_PROTOCOL`
//! and exchanges fixed-length frames BOTH directions through the hop. This is
//! the exact shape the real agent/cli run over tcp — the only unproven piece
//! left for M3 is the real socket.
//!
//! Wire shape of the proof exchange (one hop relay):
//!   daemon ─ noise/yamux over /memory circuit substream ─ agent
//!   (the end-to-end noise runs INSIDE the relayed channel, on top of the
//!    daemon↔relay noise — standard relay-v2 double encryption)

use std::time::Duration;

use futures::StreamExt;
use libp2p::core::transport::{MemoryTransport, OrTransport};
use libp2p::core::upgrade::{ReadyUpgrade, Version};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::handler::{
    ConnectionEvent, ConnectionHandler, ConnectionHandlerEvent, FullyNegotiatedInbound,
    FullyNegotiatedOutbound, SubstreamProtocol,
};
use libp2p::swarm::{ConnectionDenied, ConnectionId, NetworkBehaviour, NotifyHandler, SwarmEvent};
use libp2p::{
    dcutr, identify, noise, relay, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, Transport,
};
use sync_proto::p2p::P2P_STREAM_PROTOCOL;
use tokio::sync::mpsc;

/// "A few bytes" in both directions — the payload the daemon sends and expects
/// echoed byte-identical by the agent.
const PAYLOAD: &[u8] = b"sync-agent-pvc/relay-loopback/1 ping through the hop";

// ---------------------------------------------------------------------------
// Raw stream protocol (test stand-in for the real sync protocol session):
// the daemon opens a stream on P2P_STREAM_PROTOCOL, sends one length-prefixed
// frame; the agent reads it and echoes it back. Fixed-length framing, no
// half-close reliance, deterministic end condition.
// ---------------------------------------------------------------------------

/// Behaviour → handler: open one outbound stream.
#[derive(Debug)]
enum RawCommand {
    OpenStream,
}

/// Handler → behaviour: the exchange finished (Ok = echoed payload, agent side
/// Ok = echo completed).
#[derive(Debug)]
enum RawEvent {
    Done(Result<Vec<u8>, String>),
}

type RoundtripResult = Result<Vec<u8>, String>;

const MAX_FRAME: u32 = 64 * 1024;

async fn write_frame<S: futures::io::AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
) -> Result<(), String> {
    use futures::io::AsyncWriteExt;
    let len = u32::try_from(payload.len()).map_err(|_| "frame too large".to_string())?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| format!("write len: {e}"))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| format!("write body: {e}"))?;
    stream.flush().await.map_err(|e| format!("flush: {e}"))
}

async fn read_frame<S: futures::io::AsyncRead + Unpin>(
    stream: &mut S,
    what: &str,
) -> Result<Vec<u8>, String> {
    use futures::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("{what}: read len: {e}"))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(format!("{what}: frame {len} > {MAX_FRAME}"));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("{what}: read body: {e}"))?;
    Ok(buf)
}

/// Per-connection handler. Inbound streams are echoed; an explicitly opened
/// outbound stream sends the payload and waits for the echo.
struct RawHandler {
    want_open: bool,
    opened: bool,
    payload: Vec<u8>,
    result_tx: mpsc::UnboundedSender<RoundtripResult>,
}

impl ConnectionHandler for RawHandler {
    type FromBehaviour = RawCommand;
    type ToBehaviour = RawEvent;
    type InboundProtocol = ReadyUpgrade<StreamProtocol>;
    type OutboundProtocol = ReadyUpgrade<StreamProtocol>;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(
            ReadyUpgrade::new(StreamProtocol::new(P2P_STREAM_PROTOCOL)),
            (),
        )
    }

    fn on_behaviour_event(&mut self, event: RawCommand) {
        if matches!(event, RawCommand::OpenStream) {
            self.want_open = true;
        }
    }

    fn poll(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<
        ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, RawEvent>,
    > {
        if self.want_open && !self.opened {
            self.opened = true;
            return std::task::Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                protocol: SubstreamProtocol::new(
                    ReadyUpgrade::new(StreamProtocol::new(P2P_STREAM_PROTOCOL)),
                    (),
                ),
            });
        }
        std::task::Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol: mut stream,
                info: (),
            }) => {
                // Agent side: read one frame, echo it back.
                let tx = self.result_tx.clone();
                tokio::spawn(async move {
                    let res = async {
                        let msg = read_frame(&mut stream, "agent").await?;
                        write_frame(&mut stream, &msg).await?;
                        Ok(msg)
                    }
                    .await;
                    let _ = tx.send(res);
                });
            }
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol: mut stream,
                info: (),
            }) => {
                // Daemon side: send the payload, expect the identical echo.
                let tx = self.result_tx.clone();
                let payload = self.payload.clone();
                tokio::spawn(async move {
                    let res = async {
                        write_frame(&mut stream, &payload).await?;
                        let echoed = read_frame(&mut stream, "daemon").await?;
                        if echoed != payload {
                            return Err(format!(
                                "echo mismatch: sent {} bytes, got {} different bytes",
                                payload.len(),
                                echoed.len()
                            ));
                        }
                        Ok(echoed)
                    }
                    .await;
                    let _ = tx.send(res);
                });
            }
            _ => {}
        }
    }
}

/// Minimal NetworkBehaviour exposing the raw handler to the swarm. Connections
/// are tracked so `open_stream(peer)` can be routed to the right handler.
struct RawBehaviour {
    payload: Vec<u8>,
    connections: Vec<(PeerId, ConnectionId)>,
    open_requested: Option<PeerId>,
    results: mpsc::UnboundedReceiver<RoundtripResult>,
    result_tx: mpsc::UnboundedSender<RoundtripResult>,
}

impl RawBehaviour {
    fn new(payload: Vec<u8>) -> Self {
        let (result_tx, results) = mpsc::unbounded_channel();
        Self {
            payload,
            connections: Vec::new(),
            open_requested: None,
            results,
            result_tx,
        }
    }

    fn open_stream(&mut self, peer: PeerId) {
        self.open_requested = Some(peer);
    }
}

impl NetworkBehaviour for RawBehaviour {
    type ConnectionHandler = RawHandler;
    type ToSwarm = RawEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        Ok(())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        Ok(RawHandler {
            want_open: false,
            opened: false,
            payload: Vec::new(),
            result_tx: self.result_tx.clone(),
        })
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: Option<PeerId>,
        _: &[Multiaddr],
        _: libp2p::core::Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        Ok(vec![])
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: libp2p::core::Endpoint,
        _: libp2p::core::transport::PortUse,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.connections.push((peer, connection_id));
        Ok(RawHandler {
            want_open: false,
            opened: false,
            payload: self.payload.clone(),
            result_tx: self.result_tx.clone(),
        })
    }

    fn on_swarm_event(&mut self, _event: libp2p::swarm::derive_prelude::FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        _event: libp2p::swarm::THandlerOutEvent<Self>,
    ) {
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<libp2p::swarm::ToSwarm<RawEvent, RawCommand>> {
        use libp2p::swarm::ToSwarm;

        // Surface completed exchanges. poll_recv(cx) registers the swarm's
        // waker with the channel — without it the behaviour is never re-polled
        // once the connection goes idle and the result is silently stranded.
        match self.results.poll_recv(cx) {
            std::task::Poll::Ready(Some(res)) => {
                return std::task::Poll::Ready(ToSwarm::GenerateEvent(RawEvent::Done(res)));
            }
            std::task::Poll::Ready(None) | std::task::Poll::Pending => {}
        }
        if let Some(peer) = self.open_requested {
            if let Some(&(_, cid)) = self.connections.iter().find(|(p, _)| *p == peer) {
                self.open_requested = None;
                return std::task::Poll::Ready(ToSwarm::NotifyHandler {
                    peer_id: peer,
                    handler: NotifyHandler::One(cid),
                    event: RawCommand::OpenStream,
                });
            }
        }
        std::task::Poll::Pending
    }
}

// ---------------------------------------------------------------------------
// Swarm construction — mirrors production compositions.
// ---------------------------------------------------------------------------

/// Same behaviour composition as the relay binary.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct RelayServerBehaviour {
    relay: relay::Behaviour,
    dcutr: dcutr::Behaviour,
    identify: identify::Behaviour,
}

/// Agent/daemon swarms: relay CLIENT (reservation + circuit dials) + the raw
/// protocol behaviour. The relay-client transport is OR-ed under the base
/// transport exactly as rust-libp2p's relay tests do: /p2p-circuit addresses
/// are claimed by the client transport, everything else passes through.
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct ClientBehaviour {
    relay: relay::client::Behaviour,
    raw: RawBehaviour,
}

fn relay_swarm() -> (Swarm<RelayServerBehaviour>, PeerId) {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let transport = MemoryTransport::default()
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(&keypair).expect("noise config"))
        .multiplex(yamux::Config::default())
        .boxed();
    // Production-shaped hop limits (the binary's defaults, not libp2p's
    // signaling-oriented 2 min / 128 KiB — a sync session must survive both).
    let relay_config = relay::Config {
        max_circuit_duration: Duration::from_secs(24 * 60 * 60),
        max_circuit_bytes: 10 * (1 << 30),
        ..relay::Config::default()
    };
    let behaviour = RelayServerBehaviour {
        relay: relay::Behaviour::new(peer_id, relay_config),
        dcutr: dcutr::Behaviour::new(peer_id),
        identify: identify::Behaviour::new(identify::Config::new(
            "sync-agent-pvc/relay-test/1".to_string(),
            keypair.public(),
        )),
    };
    (
        libp2p::Swarm::new(
            transport,
            behaviour,
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        ),
        peer_id,
    )
}

fn client_swarm(payload: Vec<u8>) -> (Swarm<ClientBehaviour>, PeerId) {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let peer_id = keypair.public().to_peer_id();
    let (relay_transport, relay_client) = relay::client::new(peer_id);
    let transport = OrTransport::new(relay_transport, MemoryTransport::default())
        .upgrade(Version::V1)
        .authenticate(noise::Config::new(&keypair).expect("noise config"))
        .multiplex(yamux::Config::default())
        .boxed();
    (
        libp2p::Swarm::new(
            transport,
            ClientBehaviour {
                relay: relay_client,
                raw: RawBehaviour::new(payload),
            },
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        ),
        peer_id,
    )
}

// ---------------------------------------------------------------------------
// Event loops — each swarm runs on its own task and reports milestones.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum RelaySignal {
    Listening(Multiaddr),
    ReservationGranted {
        src: PeerId,
    },
    CircuitOpened {
        src: PeerId,
        dst: PeerId,
    },
    CircuitDenied {
        src: PeerId,
        dst: PeerId,
        status: String,
    },
    /// Any other relay event (including the deprecated failure variants) —
    /// forwarded so a stuck test shows WHAT the hop actually did.
    OtherRelayEvent(String),
}

async fn relay_loop(
    mut swarm: Swarm<RelayServerBehaviour>,
    tx: mpsc::UnboundedSender<RelaySignal>,
) {
    while let Some(event) = swarm.next().await {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                swarm.add_external_address(address.clone());
                let _ = tx.send(RelaySignal::Listening(address));
            }
            SwarmEvent::Behaviour(RelayServerBehaviourEvent::Relay(ev)) => {
                let signal = match ev {
                    relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                        Some(RelaySignal::ReservationGranted { src: src_peer_id })
                    }
                    relay::Event::CircuitReqAccepted {
                        src_peer_id,
                        dst_peer_id,
                    } => Some(RelaySignal::CircuitOpened {
                        src: src_peer_id,
                        dst: dst_peer_id,
                    }),
                    relay::Event::CircuitReqDenied {
                        src_peer_id,
                        dst_peer_id,
                        status,
                    } => Some(RelaySignal::CircuitDenied {
                        src: src_peer_id,
                        dst: dst_peer_id,
                        status: format!("{status:?}"),
                    }),
                    // Deprecated failure variants included: surface everything.
                    other => Some(RelaySignal::OtherRelayEvent(format!("{other:?}"))),
                };
                if let Some(s) = signal {
                    if tx.send(s).is_err() {
                        return; // test body gone
                    }
                }
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
enum AgentSignal {
    Reserved {
        relay: PeerId,
    },
    InboundCircuit {
        src: PeerId,
    },
    /// The agent saw an end-to-end connection arriving on its relayed listener.
    RelayedConnection {
        peer: PeerId,
    },
    EchoResult(RoundtripResult),
}

async fn agent_loop(mut swarm: Swarm<ClientBehaviour>, tx: mpsc::UnboundedSender<AgentSignal>) {
    while let Some(event) = swarm.next().await {
        match event {
            SwarmEvent::Behaviour(ClientBehaviourEvent::Relay(
                relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
            )) => {
                let _ = tx.send(AgentSignal::Reserved {
                    relay: relay_peer_id,
                });
            }
            SwarmEvent::Behaviour(ClientBehaviourEvent::Relay(
                relay::client::Event::InboundCircuitEstablished { src_peer_id, .. },
            )) => {
                let _ = tx.send(AgentSignal::InboundCircuit { src: src_peer_id });
            }
            SwarmEvent::Behaviour(ClientBehaviourEvent::Raw(RawEvent::Done(res))) => {
                if tx.send(AgentSignal::EchoResult(res)).is_err() {
                    return;
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint: libp2p::core::ConnectedPoint::Listener { ref local_addr, .. },
                ..
            } => {
                // The daemon's end-to-end connection must be a RELAYED one: the
                // listener side of a /p2p-circuit dial has the circuit in its
                // local address. (Direct inbound connections — e.g. the relay's
                // identify probe — are legitimate here and must NOT trip this.)
                if local_addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                    let _ = tx.send(AgentSignal::RelayedConnection { peer: peer_id });
                }
            }
            _ => {}
        }
    }
}

async fn daemon_loop(
    mut swarm: Swarm<ClientBehaviour>,
    agent_peer: PeerId,
    tx: mpsc::UnboundedSender<RoundtripResult>,
) {
    while let Some(event) = swarm.next().await {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == agent_peer => {
                // End-to-end connection over the circuit is up → open the sync
                // protocol stream, exactly what the real daemon will do.
                swarm.behaviour_mut().raw.open_stream(agent_peer);
            }
            SwarmEvent::Behaviour(ClientBehaviourEvent::Raw(RawEvent::Done(res))) => {
                let _ = tx.send(res);
                return;
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                let _ = tx.send(Err(format!(
                    "dial failed ({}): {error}",
                    peer_id.map(|p| p.to_string()).unwrap_or_default()
                )));
                return;
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------------

async fn recv<T>(rx: &mut mpsc::UnboundedReceiver<T>, what: &str) -> T {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
        .expect("event loop dropped before sending {what}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reservation_then_relayed_stream_end_to_end() {
    let memory_port = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .subsec_nanos() as u64
        | 1;
    let relay_addr: Multiaddr = format!("/memory/{memory_port}").parse().expect("multiaddr");

    // 1. Relay server: listen + advertise (mirrors the binary's listen phase).
    let (mut relay_swarm, relay_peer_id) = relay_swarm();
    relay_swarm
        .listen_on(relay_addr.clone())
        .expect("relay listen");
    let (relay_tx, mut relay_rx) = mpsc::unbounded_channel();
    tokio::spawn(relay_loop(relay_swarm, relay_tx));

    let RelaySignal::Listening(listen_addr) = recv(&mut relay_rx, "relay listening").await else {
        panic!("first relay signal must be Listening");
    };
    assert_eq!(listen_addr, relay_addr);

    // 2. Agent (relay CLIENT): obtain a reservation by listening on the circuit
    //    address — the form printed by the relay's startup announce.
    let (mut agent_swarm, agent_peer_id) = client_swarm(Vec::new());
    let agent_circuit_addr = relay_addr
        .clone()
        .with(Protocol::P2p(relay_peer_id))
        .with(Protocol::P2pCircuit);
    agent_swarm
        .listen_on(agent_circuit_addr.clone())
        .expect("agent reservation listen");
    let (agent_tx, mut agent_rx) = mpsc::unbounded_channel();
    tokio::spawn(agent_loop(agent_swarm, agent_tx));

    let AgentSignal::Reserved { relay } = recv(&mut agent_rx, "agent reservation").await else {
        panic!("first agent signal must be Reserved");
    };
    assert_eq!(relay, relay_peer_id, "reservation is on OUR relay");
    let granted = loop {
        match recv(&mut relay_rx, "relay saw reservation").await {
            RelaySignal::ReservationGranted { src } => break src,
            // Benign interleaved events: external-address status flips after
            // add_external_address, late listening reports.
            RelaySignal::OtherRelayEvent(ev) if ev.contains("StatusChanged") => continue,
            RelaySignal::Listening(_) => continue,
            other => panic!("expected ReservationGranted, got {other:?}"),
        }
    };
    assert_eq!(granted, agent_peer_id, "reservation granted to the agent");

    // 3. Daemon: dial the agent THROUGH the relay — the exact multiaddr the
    //    daemon computes from the relay bootstrap + the agent PeerId it pins.
    let daemon_dial_addr = agent_circuit_addr
        .clone()
        .with(Protocol::P2p(agent_peer_id));
    let (mut daemon_swarm, _daemon_peer_id) = client_swarm(PAYLOAD.to_vec());
    daemon_swarm
        .dial(daemon_dial_addr.clone())
        .expect("daemon dial");
    let (daemon_tx, mut daemon_rx) = mpsc::unbounded_channel();
    tokio::spawn(daemon_loop(daemon_swarm, agent_peer_id, daemon_tx));

    // 4. The hop relays: circuit opens between daemon and agent.
    let (circuit_src, circuit_dst) = loop {
        match recv(&mut relay_rx, "relay circuit accepted").await {
            RelaySignal::CircuitOpened { src, dst } => break (src, dst),
            RelaySignal::CircuitDenied { src, dst, status } => {
                panic!("relay DENIED the circuit {src} → {dst}: {status} (hop config regression)")
            }
            RelaySignal::OtherRelayEvent(ev) => {
                panic!("unexpected relay event instead of CircuitOpened: {ev}")
            }
            // Reservation renewals / status flips / stray listening reports are benign.
            _ => continue,
        }
    };
    assert_eq!(circuit_src, _daemon_peer_id, "circuit source is the daemon");
    assert_eq!(
        circuit_dst, agent_peer_id,
        "circuit destination is the agent"
    );

    let inbound_src = loop {
        match recv(&mut agent_rx, "agent inbound circuit").await {
            AgentSignal::InboundCircuit { src } => break src,
            AgentSignal::RelayedConnection { .. } => continue, // ordering, checked below
            other => panic!("expected InboundCircuit, got {other:?}"),
        }
    };
    assert_eq!(
        inbound_src, _daemon_peer_id,
        "inbound circuit is from the daemon"
    );

    // 4b. The agent's end-to-end connection really arrived ON the relayed
    //     listener (circuit shape proven at the connection level, not just the
    //     relay-client event level).
    let relayed_peer = loop {
        match recv(&mut agent_rx, "agent relayed connection").await {
            AgentSignal::RelayedConnection { peer } => break peer,
            AgentSignal::InboundCircuit { .. } => continue, // ordering, checked above
            other => panic!("expected RelayedConnection, got {other:?}"),
        }
    };
    assert_eq!(relayed_peer, _daemon_peer_id);

    // 5. Bytes flow BOTH directions on P2P_STREAM_PROTOCOL through the hop:
    //    daemon → agent (payload), agent → daemon (echo).
    let echoed = tokio::time::timeout(Duration::from_secs(10), async {
        match recv(&mut daemon_rx, "daemon echo").await {
            Ok(bytes) => bytes,
            Err(e) => panic!("daemon exchange failed: {e}"),
        }
    })
    .await
    .expect("echo exchange timed out");
    assert_eq!(echoed, PAYLOAD, "byte-identical roundtrip over the relay");

    // 6. The agent's echo completed cleanly as well (both directions proven).
    let agent_echo = loop {
        match recv(&mut agent_rx, "agent echo completion").await {
            AgentSignal::EchoResult(res) => break res,
            _ => continue, // connection-level signals already asserted above
        }
    };
    match agent_echo {
        Ok(bytes) => assert_eq!(bytes, PAYLOAD),
        Err(e) => panic!("agent echo failed: {e}"),
    }
}
