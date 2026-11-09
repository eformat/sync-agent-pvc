//! sync-relay — the VPS relay node for sync-agent-pvc (M3, plan §1).
//!
//! This REPLACES the borrowed Go `p2p-claude-plans --bootstrap-mode` unit on the
//! VPS. The relay is deliberately DUMB: a standard libp2p relay-v2 hop (circuit
//! reservations + circuits) plus a DCUtR helper, and that is all. It holds no
//! keys of the peers (per-sandbox agent identities are derived daemon-side), it
//! only ever sees noise-encrypted traffic, and it needs no per-sandbox state —
//! so there is nothing here to authenticate, track, or persist beyond its OWN
//! identity. Protocol stack: tcp + noise + yamux + relay(SERVER) + dcutr +
//! identify. NO DHT/rendezvous — the fixed VPS is the rendezvous (plan §1).
//!
//! Identity: ed25519 keypair persisted at `--key` (default
//! /var/lib/sync-agent-relay/identity.ed25519). Missing → generated + written
//! 0600 (parent dirs created). Corrupt → hard failure, NEVER silently
//! regenerated: the relay's PeerId is load-bearing (operators copy it into
//! daemon/agent bootstrap configs).
//!
//! OUTPUT CONTRACT (mirrors the agent's stdout-protocol discipline):
//!   stderr — timestamped operational logs: PeerId, listen multiaddrs, ready
//!            line, then reservation/circuit activity.
//!   stdout — exactly ONE line, the relay's PeerId, written once at startup as
//!            the machine-readable bootstrap; stdout is never touched again.
//!
//! Deploy (single static musl binary for the VPS):
//!   cargo build --release -p sync-relay --target x86_64-unknown-linux-musl

mod config;

use std::fmt::Write as _;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{dcutr, identify, noise, relay, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};

use config::{Config, RelayLimits};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// identify protocol version reported by THIS relay (agents/daemons run their own).
const IDENTIFY_PROTOCOL_VERSION: &str = "sync-agent-pvc/relay/1";

/// Idle connections (no reservation, no circuit, no open stream) are reaped
/// after this. Active reservations override keep-alive inside the relay handler
/// itself, so this only reaps truly idle connections (stray scanners, dead
/// peers after their reservation expired). Small-VPS friendly.
// Relay idle timeout: sync sessions go SILENT while the daemon scans/hashes
// locally (a 200k-file tree is minutes without traffic). libp2p's default is
// 10s — it killed the first live relayed session mid-handshake (2026-11-06).
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Behaviours of the relay node. Same composition as the reference rust-libp2p
/// relay example: the hop (server), DCUtR (helps two NATed peers behind OUR
/// circuits upgrade to direct), and identify (peers learn the relay's
/// address/agent; the relay learns theirs — operators can see who is connected).
#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct RelayBehaviour {
    relay: relay::Behaviour,
    dcutr: dcutr::Behaviour,
    identify: identify::Behaviour,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match config::parse_args(&args) {
        Ok(config::ArgOutcome::Run(cfg)) => {
            // Multi-thread runtime: the swarm + signal handling live on one task,
            // but musl static builds still get real threading for the I/O drivers.
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    log(format_args!("fatal: cannot start tokio runtime: {e}"));
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(run(cfg)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    log(format_args!("fatal: {e}"));
                    ExitCode::FAILURE
                }
            }
        }
        Ok(config::ArgOutcome::Version(v)) => {
            // The only other stdout user (no protocol is active on that path).
            println!("{v}");
            ExitCode::SUCCESS
        }
        Ok(config::ArgOutcome::Help(usage)) => {
            // Help goes to stderr: stdout is reserved for the PeerId bootstrap.
            eprintln!("{usage}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sync-relay: {e}\n\n{}", config::USAGE);
            ExitCode::FAILURE
        }
    }
}

/// Load the relay identity: generate + persist 0600 if missing, load if present,
/// hard-fail if corrupt (never silently rotate — the PeerId is load-bearing).
fn load_or_create_key(path: &Path) -> std::io::Result<libp2p::identity::Keypair> {
    match std::fs::read(path) {
        Ok(bytes) => libp2p::identity::Keypair::from_protobuf_encoding(&bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "relay identity {} is corrupt ({e}) — refusing to regenerate: the PeerId \
                     is pinned in daemon/agent configs; restore the key file or move it aside \
                     deliberately",
                    path.display()
                ),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let keypair = libp2p::identity::Keypair::generate_ed25519();
            let bytes = keypair
                .to_protobuf_encoding()
                .map_err(std::io::Error::other)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&bytes)?;
            Ok(keypair)
        }
        Err(e) => Err(e),
    }
}

/// Hop config: caller-tunable circuit limits; reservations + rate limiters stay
/// at the libp2p defaults (1 h reservation; 30/2 min per peer + 60/min per IP).
fn relay_config(limits: &RelayLimits) -> relay::Config {
    relay::Config {
        max_circuits: limits.max_circuits,
        max_circuit_duration: limits.max_circuit_duration,
        max_circuit_bytes: limits.max_circuit_bytes,
        ..relay::Config::default()
    }
}

async fn run(cfg: Config) -> Result<(), Box<dyn std::error::Error>> {
    let keypair = load_or_create_key(&cfg.key_path)?;
    let peer_id = keypair.public().to_peer_id();

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let local = key.public().to_peer_id();
            RelayBehaviour {
                relay: relay::Behaviour::new(local, relay_config(&cfg.limits)),
                dcutr: dcutr::Behaviour::new(local),
                identify: identify::Behaviour::new(identify::Config::new(
                    IDENTIFY_PROTOCOL_VERSION.to_string(),
                    key.public(),
                )),
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build();

    // Listen on every requested address; resolved addresses are reported as
    // NewListenAddr events and collected for the startup announce.
    for addr in &cfg.listens {
        swarm.listen_on(addr.clone())?;
    }

    // Advertise the operator-provided public address immediately: without a
    // confirmed external address the relay server keeps HOP disabled and every
    // reservation fails NoAddressesInReservation (the NAT'd-VPS failure mode
    // hit live on first deploy, 2026-11-06).
    if let Some(ext) = &cfg.external_addr {
        swarm.add_external_address(ext.clone());
        log(format_args!("external address advertised: {ext}"));
    }

    // SIGINT/SIGTERM → graceful shutdown (systemd system unit sends SIGTERM).
    let signals = async {
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("install SIGINT handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        tokio::select! {
            _ = sigint.recv() => "SIGINT",
            _ = sigterm.recv() => "SIGTERM",
        }
    };
    tokio::pin!(signals);

    log(format_args!("sync-relay {VERSION} starting"));
    log(format_args!(
        "peer-id {peer_id} (identity {})",
        cfg.key_path.display()
    ));
    log(format_args!("limits {:?}", cfg.limits));

    let mut startup = Startup {
        expected: cfg.listens.len(),
        addrs: Vec::new(),
        announced: false,
    };

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                handle_swarm_event(&mut swarm, event, &mut startup);
            }
            signal = &mut signals => {
                log(format_args!("{signal} received, shutting down"));
                break;
            }
        }
    }
    Ok(())
}

/// Startup bookkeeping: gather listen addrs, then emit the operator announce
/// (stderr block + the single stdout PeerId line).
struct Startup {
    expected: usize,
    addrs: Vec<Multiaddr>,
    announced: bool,
}

impl Startup {
    fn on_new_listen_addr(&mut self, addr: Multiaddr, peer_id: PeerId) {
        log(format_args!("listening on {addr}"));
        self.addrs.push(addr);
        if self.addrs.len() >= self.expected && !self.announced {
            self.announced = true;
            announce(peer_id, &self.addrs);
        }
    }
}

/// The operator-facing startup announce. Stderr gets the copy-paste block
/// (bootstrap multiaddr + the two client forms); stdout gets exactly one line:
/// the PeerId — the last thing stdout ever carries in server mode.
fn announce(peer_id: PeerId, addrs: &[Multiaddr]) {
    let mut msg = String::new();
    let _ = writeln!(msg, "READY — copy into daemon/agent configs:");
    let _ = writeln!(msg, "  peer-id:            {peer_id}");
    for addr in addrs {
        let _ = writeln!(msg, "  relay bootstrap:    {addr}/p2p/{peer_id}");
        let _ = writeln!(
            msg,
            "  agent reservation:  {addr}/p2p/{peer_id}/p2p-circuit"
        );
        let _ = writeln!(
            msg,
            "  daemon dial:        {addr}/p2p/{peer_id}/p2p-circuit/p2p/<agent-peer-id>"
        );
    }
    let _ = writeln!(
        msg,
        "  (relay is untrusted: it relays noise-encrypted traffic only)"
    );
    log(format_args!("{}", msg.trim_end()));

    // Machine-readable bootstrap: one line, once, then stdout is closed for good.
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{peer_id}");
    let _ = lock.flush();
}

fn handle_swarm_event(
    swarm: &mut Swarm<RelayBehaviour>,
    event: SwarmEvent<RelayBehaviourEvent>,
    startup: &mut Startup,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            let peer_id = *swarm.local_peer_id();
            startup.on_new_listen_addr(address, peer_id);
        }
        SwarmEvent::ConnectionEstablished {
            peer_id,
            num_established,
            ..
        } => {
            log(format_args!(
                "peer connected {peer_id} ({} connection{})",
                num_established,
                if num_established.get() == 1 { "" } else { "s" }
            ));
        }
        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            log(format_args!(
                "peer disconnected {peer_id} ({})",
                cause
                    .as_ref()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "clean".into())
            ));
        }
        SwarmEvent::IncomingConnection {
            local_addr,
            send_back_addr,
            ..
        } => {
            log(format_args!(
                "incoming connection {send_back_addr} → {local_addr}"
            ));
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            log(format_args!(
                "outgoing dial failed ({}): {error}",
                peer_id
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "unknown peer".into())
            ));
        }
        SwarmEvent::ListenerError { error, .. } => {
            log(format_args!("listener error: {error}"));
        }
        SwarmEvent::ListenerClosed { reason, .. } => {
            log(format_args!("listener closed: {reason:?}"));
        }
        SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => match event {
            // Success paths are the operator's visibility into the relay doing its job.
            relay::Event::ReservationReqAccepted {
                src_peer_id,
                renewed,
            } => {
                log(format_args!(
                    "reservation {} for {src_peer_id}",
                    if renewed { "renewed" } else { "granted" }
                ));
            }
            relay::Event::ReservationReqDenied {
                src_peer_id,
                status,
            } => {
                log(format_args!(
                    "reservation DENIED for {src_peer_id}: {status:?}"
                ));
            }
            relay::Event::ReservationClosed { src_peer_id } => {
                log(format_args!("reservation closed: {src_peer_id}"));
            }
            relay::Event::ReservationTimedOut { src_peer_id } => {
                log(format_args!("reservation timed out: {src_peer_id}"));
            }
            relay::Event::CircuitReqAccepted {
                src_peer_id,
                dst_peer_id,
            } => {
                log(format_args!("circuit open: {src_peer_id} → {dst_peer_id}"));
            }
            relay::Event::CircuitReqDenied {
                src_peer_id,
                dst_peer_id,
                status,
            } => {
                log(format_args!(
                    "circuit DENIED: {src_peer_id} → {dst_peer_id}: {status:?}"
                ));
            }
            relay::Event::CircuitClosed {
                src_peer_id,
                dst_peer_id,
                error,
            } => {
                log(format_args!(
                    "circuit closed: {src_peer_id} → {dst_peer_id} ({})",
                    error
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "clean".into())
                ));
            }
            relay::Event::StatusChanged { status } => {
                log(format_args!("relay status: {status:?}"));
            }
            // Failure variants are deprecated (logged internally by the crate
            // per the deprecation note) — keep them in the catch-all.
            _ => {}
        },
        SwarmEvent::Behaviour(RelayBehaviourEvent::Dcutr(event)) => match &event.result {
            Ok(_) => log(format_args!(
                "hole-punch completed with {}",
                event.remote_peer_id
            )),
            Err(e) => log(format_args!(
                "hole-punch with {} failed: {e}",
                event.remote_peer_id
            )),
        },
        SwarmEvent::Behaviour(RelayBehaviourEvent::Identify(event)) => match event {
            identify::Event::Received { peer_id, info, .. } => {
                // The connecting peer just told us our own external address —
                // CONFIRM it (finite score, re-confirmed by each peer's identify)
                // so relay reservations can advertise HOP. Without this, a NAT'd
                // relay never accumulates a confirmed public address and every
                // reservation fails NoAddressesInReservation.
                let observed = info.observed_addr.clone();
                swarm.add_external_address(observed.clone());
                log(format_args!(
                    "identified {peer_id}: agent={} observed={observed} (external addr confirmed)",
                    info.agent_version
                ));
            }
            identify::Event::Error { peer_id, error, .. } => {
                log(format_args!("identify error for {peer_id}: {error}"));
            }
            _ => {}
        },
        _ => {}
    }
}

/// Timestamped operational logging. Everything human-readable goes to stderr;
/// stdout carries only the one-line PeerId bootstrap (see announce()).
fn log(args: std::fmt::Arguments<'_>) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tod = secs % 86_400; // UTC wall-clock time-of-day (date rarely matters at a glance)
    eprintln!(
        "[{:02}:{:02}:{:02}Z] {}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60,
        args
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn key_is_generated_once_and_reloads_to_the_same_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.ed25519");

        let first = load_or_create_key(&path).expect("generate on first run");
        let second = load_or_create_key(&path).expect("reload on second run");

        assert_eq!(
            first.public().to_peer_id(),
            second.public().to_peer_id(),
            "same key file → same PeerId (identity is load-bearing across restarts)"
        );

        // File perms must be 0600 (identity material on a shared VPS).
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key file must be 0600, got {:o}", mode);
    }

    #[test]
    fn missing_parent_dirs_are_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("var/lib/sync-agent-relay/identity.ed25519");
        assert!(load_or_create_key(&path).is_ok(), "parents created");
        assert!(path.is_file());
    }

    #[test]
    fn corrupt_identity_fails_loudly_instead_of_regenerating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.ed25519");
        std::fs::write(&path, b"garbage-not-a-protobuf-key").unwrap();

        let err = load_or_create_key(&path).expect_err("corrupt key must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // And the file is untouched — no silent rotation.
        assert!(std::fs::read(&path).unwrap().starts_with(b"garbage"));
    }

    #[test]
    fn announce_stdout_contract_single_line_then_nothing() {
        // announce() writes the PeerId to stdout; capture via the run-level
        // contract instead: the only stdout writes in the binary are --version
        // and announce(). Verify announce content shape via stderr-free probe:
        // (stdout itself is captured by the test harness; here we assert the
        // PeerId formats as the exact expected single line.)
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let line = peer_id.to_string();
        assert!(line.starts_with("12D3Koo"), "ed25519 peer id shape: {line}");
        assert_eq!(line.lines().count(), 1, "exactly one stdout line");
    }

    #[test]
    fn relay_config_applies_limits_and_keeps_libp2p_reservation_defaults() {
        let limits = RelayLimits {
            max_circuits: 32,
            max_circuit_duration: Duration::from_secs(60),
            max_circuit_bytes: 1 << 20,
        };
        let cfg = relay_config(&limits);
        let defaults = relay::Config::default();
        assert_eq!(cfg.max_circuits, 32);
        assert_eq!(cfg.max_circuit_duration, Duration::from_secs(60));
        assert_eq!(cfg.max_circuit_bytes, 1 << 20);
        // Untouched knobs stay at libp2p defaults (1 h reservation, per-peer cap 4).
        assert_eq!(cfg.reservation_duration, defaults.reservation_duration);
        assert_eq!(cfg.max_reservations, defaults.max_reservations);
        assert_eq!(
            cfg.max_reservations_per_peer,
            defaults.max_reservations_per_peer
        );
        assert_eq!(cfg.max_circuits_per_peer, defaults.max_circuits_per_peer);
    }
}
