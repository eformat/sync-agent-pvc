//! P2P transport constants + identity derivation (M3).
//!
//! Topology (plan §1): laptop daemon and in-pod sync sidecar BOTH dial OUT to our
//! fixed VPS relay (`sync-agent-relay`, crates/relay). No DHT — the rendezvous is
//! cryptographic: the agent's libp2p identity is DETERMINISTICALLY derived from
//! (master secret, sandbox_id), so the daemon computes the agent's PeerId and dials
//! it via the relay directly (`.../p2p-circuit/p2p/<agent-peer>`). TOFU: the daemon
//! pins the first observed agent PeerId per sandbox; strict pin afterwards.
//!
//! Master secret sources: env `SYNC_AGENT_MASTER_KEY` (64 hex chars) or a 0600 file.
//! NEVER in git; k8s Secret + env in-cluster (§9 project-local exception).

/// libp2p application protocol the sync protocol rides (one duplex stream per session).
pub const P2P_STREAM_PROTOCOL: &str = "/sync-agent-pvc/sync/1";

// ---------------------------------------------------------------------------
// Tunnel protocol (M5 memory access broker) — plan §5.
//
// The AGENT dials the DAEMON (opposite direction of the sync protocol): the
// sandbox-side loopback listener bridges to a stream on TUNNEL_STREAM_PROTOCOL,
// the daemon authorizes + enforces its service allowlist, then pipes the rest
// raw to the opted-in laptop service (e.g. mcp-memory.service). A SEPARATE
// protocol from the sync one on purpose: the M3.5 lesson (wire-index algebra)
// is that touching a shared enum's variants silently shifts every later index;
// a distinct StreamProtocol can never collide.
// ---------------------------------------------------------------------------

/// libp2p application protocol the service tunnel rides.
pub const TUNNEL_STREAM_PROTOCOL: &str = "/sync-agent-pvc/tunnel/1";

/// Tunnel handshake magic (agent → daemon, first bytes of every tunnel stream).
pub const TUNNEL_MAGIC: &[u8; 8] = b"SAPVTUN1";
/// Tunnel handshake version.
pub const TUNNEL_VERSION: u8 = 1;
/// Service-name cap (bytes) — names are config identifiers, not data.
pub const TUNNEL_MAX_SERVICE_NAME: usize = 64;

/// Daemon → agent status byte, sent right after the handshake request.
pub const TUNNEL_STATUS_OK: u8 = 0;
pub const TUNNEL_STATUS_UNKNOWN_SERVICE: u8 = 1;
pub const TUNNEL_STATUS_UNAUTHORIZED_PEER: u8 = 2;
pub const TUNNEL_STATUS_UPSTREAM_UNAVAILABLE: u8 = 3;
pub const TUNNEL_STATUS_BAD_HANDSHAKE: u8 = 4;

/// Human name for a status byte (agent-side error messages + logs).
pub fn tunnel_status_name(status: u8) -> &'static str {
    match status {
        TUNNEL_STATUS_OK => "ok",
        TUNNEL_STATUS_UNKNOWN_SERVICE => "unknown service (laptop allowlist)",
        TUNNEL_STATUS_UNAUTHORIZED_PEER => "unauthorized peer",
        TUNNEL_STATUS_UPSTREAM_UNAVAILABLE => "upstream unavailable",
        TUNNEL_STATUS_BAD_HANDSHAKE => "bad handshake",
        _ => "unknown status",
    }
}

/// Domain-separated DAEMON identity seed (32 bytes → ed25519 secret key).
///
/// The daemon's tunnel swarm identity is derived from the master key alone, so
/// every agent computes the SAME daemon PeerId and dials
/// `<relay>/p2p-circuit/p2p/<daemon-peer>` with no rendezvous and no pin state
/// for the daemon direction. (The daemon's per-pass sync DIALS keep their
/// ephemeral identity — this derivation is only for the tunnel listener.)
pub fn derive_daemon_identity_seed(master: &[u8]) -> [u8; 32] {
    blake3::derive_key("sync-agent-pvc/v1/daemon", master)
}

/// The daemon's TUNNEL swarm identity — a SEPARATE derivation from the sync
/// identity. The tunnel listener is the one peer OTHERS dial through the relay
/// (its reservation must be unambiguous), and the daemon otherwise holds
/// SEVERAL same-identity relay connections (sync per-pass dials + the M9
/// forward client); relays intermittently mis-resolve reservations for a peer
/// with multiple connections (hit live 2026-11-11: the agent's tunnel dials
/// flapped "Relay has no reservation for destination" while the daemon's
/// reservation was continuously renewed). A dedicated tunnel peer gives the
/// reservation exactly one connection.
pub fn derive_tunnel_identity_seed(master: &[u8]) -> [u8; 32] {
    blake3::derive_key("sync-agent-pvc/v1/tunnel", master)
}

/// The exact bytes an agent sends to open a tunnel for `service`:
/// MAGIC(8) | VERSION(1) | name_len(1) | name.
pub fn tunnel_request_bytes(service: &str) -> Result<Vec<u8>, String> {
    let name = service.as_bytes();
    if name.is_empty() || name.len() > TUNNEL_MAX_SERVICE_NAME {
        return Err(format!(
            "tunnel service name must be 1..={} bytes, got {}",
            TUNNEL_MAX_SERVICE_NAME,
            name.len()
        ));
    }
    let mut out = Vec::with_capacity(10 + name.len());
    out.extend_from_slice(TUNNEL_MAGIC);
    out.push(TUNNEL_VERSION);
    out.push(name.len() as u8);
    out.extend_from_slice(name);
    Ok(out)
}

/// Parse a tunnel request from the exact bytes [`tunnel_request_bytes`] produced
/// (the daemon reads 10 header bytes, then the name). `Ok(name)` on success;
/// `Err(status)` is the status byte the daemon must reply with before closing.
pub fn parse_tunnel_request(buf: &[u8]) -> Result<&str, u8> {
    if buf.len() < 10 {
        return Err(TUNNEL_STATUS_BAD_HANDSHAKE);
    }
    if &buf[..8] != TUNNEL_MAGIC {
        return Err(TUNNEL_STATUS_BAD_HANDSHAKE);
    }
    if buf[8] != TUNNEL_VERSION {
        return Err(TUNNEL_STATUS_BAD_HANDSHAKE);
    }
    let len = buf[9] as usize;
    if buf.len() < 10 + len {
        return Err(TUNNEL_STATUS_BAD_HANDSHAKE);
    }
    std::str::from_utf8(&buf[10..10 + len]).map_err(|_| TUNNEL_STATUS_BAD_HANDSHAKE)
}

/// Domain-separated per-sandbox identity seed (32 bytes → ed25519 secret key).
/// blake3's derive_key is a purpose-built KDF for exactly this shape (context +
/// keyed material) — keeps the dependency set at blake3 alone.
pub fn derive_sandbox_identity_seed(master: &[u8], sandbox_id: &str) -> [u8; 32] {
    blake3::derive_key(
        &format!("sync-agent-pvc/v1/sandbox/{sandbox_id}"),
        master,
    )
}

// ---------------------------------------------------------------------------
// M9 reverse-forward (the DAEMON dials the agent; the agent bridges the stream
// to the pod-local `opencode serve` — the laptop `opencode --server` attach
// path with NO openshell/OIDC in the loop). Separate protocol id from the
// tunnel per the M3.5 wire-index lesson: touching a shared enum's variants
// silently shifts every later index; a distinct StreamProtocol can never
// collide.
// ---------------------------------------------------------------------------

/// libp2p application protocol the reverse-forward rides.
pub const FORWARD_STREAM_PROTOCOL: &str = "/sync-agent-pvc/forward/1";

/// Forward handshake magic (daemon → agent, first bytes of every forward stream).
pub const FORWARD_MAGIC: &[u8; 8] = b"SAPVFWD1";
/// Forward handshake version.
pub const FORWARD_VERSION: u8 = 1;

/// Agent → daemon status byte, the agent's entire reply to the handshake.
pub const FORWARD_STATUS_OK: u8 = 0;
pub const FORWARD_STATUS_UNAUTHORIZED_PEER: u8 = 1;
pub const FORWARD_STATUS_UPSTREAM_UNAVAILABLE: u8 = 2;
pub const FORWARD_STATUS_BAD_HANDSHAKE: u8 = 3;

/// Human name for a forward status byte (agent-side refusals + daemon logs).
pub fn forward_status_name(status: u8) -> &'static str {
    match status {
        FORWARD_STATUS_OK => "ok",
        FORWARD_STATUS_UNAUTHORIZED_PEER => "unauthorized peer (not the derived daemon identity)",
        FORWARD_STATUS_UPSTREAM_UNAVAILABLE => "pod-local serve unreachable",
        FORWARD_STATUS_BAD_HANDSHAKE => "bad handshake",
        _ => "unknown status",
    }
}

/// The deterministic per-target `opencode serve` port — SHARED by the daemon
/// (spawn scripts + laptop-side listener) and the agent (the TCP dial target).
/// blake3 hash of the qualified sandbox id → 4100 + n%400: stable across
/// restarts, distinct per target, clear of the sync agent's own listeners.
pub fn forward_serve_port(qualified: &str) -> u16 {
    let h = blake3::hash(qualified.as_bytes());
    let n = u32::from_le_bytes(h.as_bytes()[..4].try_into().expect("4 bytes"));
    4100 + (n % 400) as u16
}

/// The exact bytes the daemon sends to open a forward: MAGIC(8) | VERSION(1).
/// Deliberately port-less: the agent dials ITS OWN derived serve port
/// ([`forward_serve_port`] of its sandbox id) — the daemon never asserts a
/// port the agent must trust.
pub fn forward_request_bytes() -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.extend_from_slice(FORWARD_MAGIC);
    out.push(FORWARD_VERSION);
    out
}

/// Agent-side validation of a forward request (the first 9 stream bytes).
/// `Ok(())` on a valid daemon handshake; `Err(status)` is the status byte the
/// agent must reply with before closing.
pub fn parse_forward_request(buf: &[u8]) -> Result<(), u8> {
    if buf.len() < 9 {
        return Err(FORWARD_STATUS_BAD_HANDSHAKE);
    }
    if &buf[..8] != FORWARD_MAGIC {
        return Err(FORWARD_STATUS_BAD_HANDSHAKE);
    }
    if buf[8] != FORWARD_VERSION {
        return Err(FORWARD_STATUS_BAD_HANDSHAKE);
    }
    Ok(())
}

/// Parse a 64-hex-char master key from a string (env value or file content).
pub fn parse_master_key(s: &str) -> Result<[u8; 32], String> {
    let hex = s.trim();
    if hex.len() != 64 {
        return Err(format!(
            "master key must be 64 hex chars (32 bytes), got {} chars",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex at byte {i}: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_deterministic_and_domain_separated() {
        let master = [7u8; 32];
        let a1 = derive_sandbox_identity_seed(&master, "default--sync-oc");
        let a2 = derive_sandbox_identity_seed(&master, "default--sync-oc");
        let b = derive_sandbox_identity_seed(&master, "default--other");
        let m2 = [8u8; 32];
        let c = derive_sandbox_identity_seed(&m2, "default--sync-oc");
        assert_eq!(a1, a2, "same inputs → same seed (deterministic rendezvous)");
        assert_ne!(a1, b, "different sandbox → isolated identity");
        assert_ne!(a1, c, "different master → isolated identity");
    }

    #[test]
    fn master_key_parsing() {
        let hex = "00".repeat(32);
        assert!(parse_master_key(&hex).is_ok());
        assert!(parse_master_key(&"00".repeat(31)).is_err());
        assert!(parse_master_key(&"zz".repeat(32)).is_err());
        assert!(parse_master_key(&format!("{hex}\n")).is_ok(), "trailing newline ok (file content)");
    }

    // ----- tunnel handshake (M5) -----

    #[test]
    fn daemon_identity_is_deterministic_and_master_bound() {
        let a1 = derive_daemon_identity_seed(&[7u8; 32]);
        let a2 = derive_daemon_identity_seed(&[7u8; 32]);
        let b = derive_daemon_identity_seed(&[8u8; 32]);
        assert_eq!(a1, a2, "same master → same daemon identity (agents precompute it)");
        assert_ne!(a1, b, "different master → isolated daemon identity");
        assert_ne!(
            a1,
            derive_sandbox_identity_seed(&[7u8; 32], "x"),
            "domain-separated from the sandbox derivation"
        );
        // The tunnel identity is a DIFFERENT peer from the sync identity (the
        // relay must never see multiple roles on one peer's reservation).
        let t = derive_tunnel_identity_seed(&[7u8; 32]);
        assert_ne!(t, a1, "tunnel peer ≠ sync peer (domain-separated)");
        assert_ne!(t, derive_tunnel_identity_seed(&[8u8; 32]));
    }

    #[test]
    fn tunnel_request_roundtrip_and_rejections() {
        let bytes = tunnel_request_bytes("memory").expect("valid name");
        assert_eq!(parse_tunnel_request(&bytes).unwrap(), "memory");
        // Round trip through a reader that delivers the bytes in two chunks —
        // the wire does not preserve message boundaries.
        let (head, rest) = bytes.split_at(10);
        let mut joined = Vec::new();
        joined.extend_from_slice(head);
        assert_eq!(parse_tunnel_request(&joined), Err(TUNNEL_STATUS_BAD_HANDSHAKE), "header alone is incomplete, not malformed");
        joined.extend_from_slice(rest);
        assert_eq!(parse_tunnel_request(&joined).unwrap(), "memory");

        // Wrong magic / version → bad handshake.
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(parse_tunnel_request(&bad), Err(TUNNEL_STATUS_BAD_HANDSHAKE));
        let mut bad = bytes.clone();
        bad[8] = 99;
        assert_eq!(parse_tunnel_request(&bad), Err(TUNNEL_STATUS_BAD_HANDSHAKE));
        // Truncated name → bad handshake (not a panic).
        assert_eq!(parse_tunnel_request(&bytes[..10]), Err(TUNNEL_STATUS_BAD_HANDSHAKE));
        assert_eq!(parse_tunnel_request(&[]), Err(TUNNEL_STATUS_BAD_HANDSHAKE));
    }

    #[test]
    fn tunnel_service_name_caps() {
        assert!(tunnel_request_bytes("").is_err(), "empty name rejected");
        let long = "m".repeat(TUNNEL_MAX_SERVICE_NAME + 1);
        assert!(tunnel_request_bytes(&long).is_err(), "over-long name rejected");
        let ok = tunnel_request_bytes(&"m".repeat(TUNNEL_MAX_SERVICE_NAME)).expect("cap-sized name ok");
        assert_eq!(parse_tunnel_request(&ok).unwrap().len(), TUNNEL_MAX_SERVICE_NAME);
    }

    #[test]
    fn forward_handshake_round_trips_and_rejects() {
        let req = forward_request_bytes();
        assert_eq!(req.len(), 9);
        assert_eq!(parse_forward_request(&req), Ok(()));
        let mut bad = req.clone();
        bad[8] = 99;
        assert_eq!(parse_forward_request(&bad), Err(FORWARD_STATUS_BAD_HANDSHAKE));
        assert_eq!(parse_forward_request(&req[..8]), Err(FORWARD_STATUS_BAD_HANDSHAKE));
        assert_eq!(parse_forward_request(&[]), Err(FORWARD_STATUS_BAD_HANDSHAKE));
        // Domain separation: the tunnel magic must NEVER validate as forward.
        let mut mixed = forward_request_bytes();
        mixed[..8].copy_from_slice(TUNNEL_MAGIC);
        assert_eq!(parse_forward_request(&mixed), Err(FORWARD_STATUS_BAD_HANDSHAKE));
    }

    #[test]
    fn forward_serve_port_is_deterministic_in_range_and_distinct() {
        let a = forward_serve_port("sync-oc+plan");
        assert_eq!(a, forward_serve_port("sync-oc+plan"), "stable across processes");
        assert!((4100..4500).contains(&a), "inside the reserved range: {a}");
        // Distinctness across a realistic target set (hash collisions in a
        // 400-wide range would silently cross-wire two targets' forwards).
        let ports: Vec<u16> = ["sync-oc+plan", "sync-oc+demo-platform-investigate", "sync-oc+ph-rhaibu"]
            .iter()
            .map(|q| forward_serve_port(q))
            .collect();
        let unique: std::collections::HashSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), ports.len(), "no collisions: {ports:?}");
    }

    #[test]
    fn tunnel_status_names_cover_the_protocol() {        for s in [
            TUNNEL_STATUS_OK,
            TUNNEL_STATUS_UNKNOWN_SERVICE,
            TUNNEL_STATUS_UNAUTHORIZED_PEER,
            TUNNEL_STATUS_UPSTREAM_UNAVAILABLE,
            TUNNEL_STATUS_BAD_HANDSHAKE,
        ] {
            assert!(!tunnel_status_name(s).is_empty());
        }
        assert_eq!(tunnel_status_name(250), "unknown status");
    }
}
