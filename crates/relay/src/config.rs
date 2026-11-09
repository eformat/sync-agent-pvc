//! CLI parsing for `sync-relay` — manual, no clap.
//!
//! The relay runs headless on a fixed VPS with a five-flag surface; a dependency
//! for this would be dead weight. Keep this file small and total: every arg is
//! either accepted with a value or rejected with a usage hint.

use std::path::PathBuf;
use std::time::Duration;

use libp2p::Multiaddr;

/// Default listener. Port 4001 (project-owner decision, 2026-11-06): the VPS
/// firewall + the chart's egress NetworkPolicy already allow the relay
/// node's IP (203.0.113.42 here — see deploy/chart values.yaml vps.cidr)
/// tcp/4001 end-to-end, and the borrowed Go bootstrap node that held the port
/// is retired at deploy time. Overridable per `--listen`.
pub const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/4001";

/// Default identity file. System location (systemd system unit on the VPS);
/// parent dirs are created and the file is written 0600.
pub const DEFAULT_KEY_PATH: &str = "/var/lib/sync-agent-relay/identity.ed25519";

// Resource limits for the relay-v2 hop.
//
// `max_circuits` follows the libp2p default. The other two DEVIATE from libp2p
// defaults on purpose (documented for the final report):
//   * max_circuit_duration: libp2p's 2 minutes is signaling-shaped; a sync
//     session rides ONE circuit for the whole transfer (M2: 1 GB in 5.6 s, so
//     an hour-scale session is normal).
//   * max_circuit_bytes: libp2p's 128 KiB would silently kill every real sync
//     mid-flight. 10 GiB covers v1 $HOME syncs; operator-tunable.
pub const DEFAULT_MAX_CIRCUITS: usize = 16; // libp2p relay-v2 default
pub const DEFAULT_MAX_CIRCUIT_DURATION_SECS: u64 = 24 * 60 * 60; // 24 h
pub const DEFAULT_MAX_CIRCUIT_BYTES: u64 = 10 * (1 << 30); // 10 GiB

/// Hop resource limits (see module docs for default provenance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLimits {
    pub max_circuits: usize,
    pub max_circuit_duration: Duration,
    pub max_circuit_bytes: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_circuits: DEFAULT_MAX_CIRCUITS,
            max_circuit_duration: Duration::from_secs(DEFAULT_MAX_CIRCUIT_DURATION_SECS),
            max_circuit_bytes: DEFAULT_MAX_CIRCUIT_BYTES,
        }
    }
}

/// Parsed runtime configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// One or more listeners (repeatable `--listen`).
    pub listens: Vec<Multiaddr>,
    /// Publicly-reachable address to advertise (e.g. `/ip4/VPS/tcp/4001`) — added as
    /// an EXTERNAL address so relay reservations can advertise HOP immediately.
    /// Without a confirmed external address, reservations fail
    /// `NoAddressesInReservation` on a NAT'd host (identify-observed confirmations
    /// also accumulate at runtime — this flag makes the fixed-IP VPS deterministic).
    pub external_addr: Option<Multiaddr>,
    /// Identity file: load if present, else generate + write 0600.
    pub key_path: PathBuf,
    /// Hop resource limits.
    pub limits: RelayLimits,
}

/// What `parse_args` decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgOutcome {
    Run(Config),
    Version(String),
    Help(String),
}

pub const USAGE: &str = "\
sync-relay — VPS relay node for sync-agent-pvc (dumb libp2p relay-v2 hop + DCUtR, no DHT)

USAGE:
  sync-relay [--listen <multiaddr>]... [--key <path>] [--max-circuits <N>]
             [--max-circuit-duration-secs <S>] [--max-circuit-bytes <B>] [--version]

FLAGS:
  --listen <multiaddr>            Listen address, repeatable.
                                  (default /ip4/0.0.0.0/tcp/4001)
  --key <path>                    ed25519 identity, protobuf-encoded; generated
                                  0600 if missing, FAILS LOUDLY if corrupt (the
                                  PeerId is load-bearing for peer pinning).
                                  (default /var/lib/sync-agent-relay/identity.ed25519)
  --max-circuits <N>              Concurrent relay circuits. (default 16)
  --max-circuit-duration-secs <S> Max lifetime of one circuit. (default 86400)
  --max-circuit-bytes <B>         Max bytes relayed per circuit. (default 10737418240)
  --version                       Print \"sync-relay <version>\" to stdout and exit.
  --help                          This text (stderr).

OUTPUT CONTRACT
  stderr: timestamped operational logs (peer id, listen addrs, ready line,
          reservations/circuits). No config files, no state beyond the key.
  stdout: exactly ONE line — the relay's PeerId, written once at startup.
          Machine-readable bootstrap; nothing else ever touches stdout.

MULTIADDR FORMS FOR THE OPERATOR (printed at startup)
  relay bootstrap:  <listen-addr>/p2p/<relay-peer-id>
  agent (client):   <listen-addr>/p2p/<relay-peer-id>/p2p-circuit
  daemon dial:      <listen-addr>/p2p/<relay-peer-id>/p2p-circuit/p2p/<agent-peer-id>

DEPLOY (single static binary)
  cargo build --release -p sync-relay --target x86_64-unknown-linux-musl";

/// Parse CLI args. Unknown flags and missing/invalid values are hard errors.
pub fn parse_args(args: &[String]) -> Result<ArgOutcome, String> {
    let mut listens: Vec<Multiaddr> = Vec::new();
    let mut key_path = PathBuf::from(DEFAULT_KEY_PATH);
    let mut external_addr: Option<Multiaddr> = None;
    let mut limits = RelayLimits::default();

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        // Value-taking flag → fetch + parse the next token.
        macro_rules! value {
            () => {{
                i += 1;
                args.get(i)
                    .ok_or_else(|| format!("missing value for {arg}"))?
            }};
        }
        match arg {
            "--version" | "-V" => {
                return Ok(ArgOutcome::Version(format!(
                    "sync-relay {}",
                    env!("CARGO_PKG_VERSION")
                )));
            }
            "--help" | "-h" => return Ok(ArgOutcome::Help(USAGE.to_string())),
            "--listen" => {
                let value = value!();
                let addr: Multiaddr = value
                    .parse()
                    .map_err(|e| format!("invalid --listen {value:?}: {e}"))?;
                listens.push(addr);
            }
            "--key" => {
                let value = value!();
                key_path = PathBuf::from(value);
            }
            "--external-addr" => {
                let value = value!();
                let addr: Multiaddr = value
                    .parse()
                    .map_err(|e| format!("invalid --external-addr {value:?}: {e}"))?;
                external_addr = Some(addr);
            }
            "--max-circuits" => {
                let value = value!();
                limits.max_circuits = value
                    .parse()
                    .map_err(|_| format!("invalid --max-circuits {value:?}: want usize > 0"))?;
                if limits.max_circuits == 0 {
                    return Err("--max-circuits must be > 0".to_string());
                }
            }
            "--max-circuit-duration-secs" => {
                let value = value!();
                let secs: u64 = value.parse().map_err(|_| {
                    format!("invalid --max-circuit-duration-secs {value:?}: want u64")
                })?;
                if secs == 0 {
                    return Err("--max-circuit-duration-secs must be > 0".to_string());
                }
                limits.max_circuit_duration = Duration::from_secs(secs);
            }
            "--max-circuit-bytes" => {
                let value = value!();
                limits.max_circuit_bytes = value
                    .parse()
                    .map_err(|_| format!("invalid --max-circuit-bytes {value:?}: want u64"))?;
                if limits.max_circuit_bytes == 0 {
                    return Err("--max-circuit-bytes must be > 0".to_string());
                }
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
        i += 1;
    }

    if listens.is_empty() {
        listens.push(
            DEFAULT_LISTEN_ADDR
                .parse()
                .expect("DEFAULT_LISTEN_ADDR is a valid multiaddr"),
        );
    }

    Ok(ArgOutcome::Run(Config {
        listens,
        external_addr,
        key_path,
        limits,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults_are_port_4001_and_libp2p_shapes() {
        let ArgOutcome::Run(cfg) = parse_args(&[]).unwrap() else {
            panic!("no args → Run");
        };
        assert_eq!(
            cfg.listens,
            vec!["/ip4/0.0.0.0/tcp/4001".parse::<Multiaddr>().unwrap()],
            "default listen is tcp/4001 (owner decision: VPS firewall + chart egress NP already open)"
        );
        assert_eq!(cfg.key_path, PathBuf::from(DEFAULT_KEY_PATH));
        assert_eq!(cfg.limits, RelayLimits::default());
        assert_eq!(cfg.limits.max_circuits, 16);
        assert_eq!(cfg.limits.max_circuit_duration, Duration::from_secs(86_400));
        assert_eq!(cfg.limits.max_circuit_bytes, 10 * (1 << 30));
    }

    #[test]
    fn listen_is_repeatable_and_everything_is_overridable() {
        let ArgOutcome::Run(cfg) = parse_args(&args(&[
            "--listen",
            "/ip4/127.0.0.1/tcp/4001",
            "--listen",
            "/ip6/::1/tcp/4001",
            "--key",
            "/tmp/relay-test-key",
            "--max-circuits",
            "64",
            "--max-circuit-duration-secs",
            "3600",
            "--max-circuit-bytes",
            "1000",
        ]))
        .unwrap() else {
            panic!("flags → Run");
        };
        assert_eq!(cfg.listens.len(), 2, "--listen is repeatable");
        assert_eq!(
            cfg.listens[1],
            "/ip6/::1/tcp/4001".parse::<Multiaddr>().unwrap()
        );
        assert_eq!(cfg.key_path, PathBuf::from("/tmp/relay-test-key"));
        assert_eq!(cfg.limits.max_circuits, 64);
        assert_eq!(cfg.limits.max_circuit_duration, Duration::from_secs(3600));
        assert_eq!(cfg.limits.max_circuit_bytes, 1000);
    }

    #[test]
    fn version_and_help_are_not_run() {
        assert!(matches!(
            parse_args(&args(&["--version"])).unwrap(),
            ArgOutcome::Version(_)
        ));
        assert!(matches!(
            parse_args(&args(&["--help"])).unwrap(),
            ArgOutcome::Help(_)
        ));
    }

    #[test]
    fn rejects_unknown_and_invalid() {
        assert!(parse_args(&args(&["--bogus"])).is_err());
        assert!(parse_args(&args(&["--listen"])).is_err(), "missing value");
        assert!(parse_args(&args(&["--listen", "not-a-multiaddr"])).is_err());
        assert!(parse_args(&args(&["--max-circuits", "0"])).is_err());
        assert!(parse_args(&args(&["--max-circuits", "-1"])).is_err());
        assert!(
            parse_args(&args(&["--max-circuit-duration-secs", "0"])).is_err(),
            "a zero-duration circuit limit would drop every circuit instantly"
        );
    }
}
