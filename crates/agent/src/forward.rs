//! M9 reverse-forward accept loop (the daemon dials US).
//!
//! The laptop `opencode --server` attach path needs to reach the pod-local
//! `opencode serve` (127.0.0.1:<serve_port>). With M8 that ride was an
//! `openshell forward` TCP pipe — gated on the gateway's ~1 h auth tokens.
//! M9 rides OUR p2p link instead: the daemon opens a
//! `/sync-agent-pvc/forward/1` stream to this agent over the relay circuit
//! (or direct after a punch), and this loop bridges each such stream to the
//! pod-local serve with a raw `copy_bidirectional` pipe — zero protocol
//! understanding, exactly like the M5 tunnel's UP path, direction-flipped.
//!
//! Trust model:
//! - The dialing peer MUST be the derived daemon identity
//!   ([`derive_daemon_identity_seed`] of the shared master key) — anyone else
//!   gets one status byte (`UNAUTHORIZED_PEER`) and a LOUD log, then a close.
//! - The dial target is ALWAYS this agent's own derived serve port
//!   ([`forward_serve_port`] of the sandbox id) — the daemon never asserts a
//!   port we must trust, and the target is loopback-only inside the pod.
//! - The handshake is 9 bytes (MAGIC | VERSION); anything else is
//!   `BAD_HANDSHAKE` + close.
//!
//! The loop is always-on: without a dialer it is inert, and the daemon-side
//! listener only exists while the p2p link is up (see crates/cli/src/forward.rs).
use libp2p::StreamProtocol;
use sync_proto::p2p::{
    forward_serve_port, forward_status_name, parse_forward_request, derive_daemon_identity_seed,
    FORWARD_STREAM_PROTOCOL, FORWARD_STATUS_BAD_HANDSHAKE, FORWARD_STATUS_OK,
    FORWARD_STATUS_UNAUTHORIZED_PEER, FORWARD_STATUS_UPSTREAM_UNAVAILABLE,
};

/// How long the daemon may take to finish its 9-byte handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(crate) struct ForwardRuntime {
    /// A control on the agent's swarm (shares the reservation + identity).
    pub control: libp2p_stream::Control,
    /// The master key — the daemon's expected peer is DERIVED from it, so the
    /// authorization never depends on config or pin state.
    pub master: [u8; 32],
    /// This agent's sandbox id (qualified) — the serve port derives from it.
    pub sandbox_id: String,
}

/// Accept forward streams forever (spawned onto the agent's runtime).
/// Errors here are startup failures only; per-connection failures are logged
/// and never kill the loop.
pub(crate) async fn run(mut rt: ForwardRuntime) -> Result<(), String> {
    use futures::StreamExt as _;
    let seed = derive_daemon_identity_seed(&rt.master);
    let keypair = libp2p::identity::Keypair::ed25519_from_bytes(seed)
        .map_err(|e| format!("daemon identity seed: {e}"))?;
    let daemon_peer = keypair.public().to_peer_id();
    let serve_port = forward_serve_port(&rt.sandbox_id);

    let mut incoming = rt
        .control
        .accept(StreamProtocol::new(FORWARD_STREAM_PROTOCOL))
        .map_err(|_| "forward protocol already registered on a fresh control")?;
    eprintln!(
        "sync-agent forward: serving {} → 127.0.0.1:{} (authorized peer {daemon_peer})",
        FORWARD_STREAM_PROTOCOL, serve_port
    );
    loop {
        match incoming.next().await {
            Some((peer, stream)) => {
                tokio::spawn(bridge(stream, peer, daemon_peer, serve_port));
            }
            // Accept handle dropped — only possible if we dropped it ourselves.
            None => return Ok(()),
        }
    }
}

/// Bridge one forward stream: authorize the peer, validate the handshake,
/// dial the pod-local serve, then RAW PIPE both directions.
async fn bridge(
    mut stream: libp2p::Stream,
    peer: libp2p::PeerId,
    daemon_peer: libp2p::PeerId,
    serve_port: u16,
) {
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};

    // AUTH first — a stranger gets one status byte and nothing else.
    if peer != daemon_peer {
        eprintln!("sync-agent forward: REFUSED unauthorized peer {peer}");
        let _ = stream.write_all(&[FORWARD_STATUS_UNAUTHORIZED_PEER]).await;
        let _ = stream.flush().await;
        return;
    }

    // Handshake: exactly 9 bytes (MAGIC | VERSION).
    let mut req = [0u8; 9];
    let read = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut req)).await;
    let status = match read {
        Err(_) => FORWARD_STATUS_BAD_HANDSHAKE, // timeout
        Ok(Err(_)) => FORWARD_STATUS_BAD_HANDSHAKE,
        Ok(Ok(())) => match parse_forward_request(&req) {
            Ok(()) => FORWARD_STATUS_OK,
            Err(s) => s,
        },
    };
    if status != FORWARD_STATUS_OK {
        eprintln!(
            "sync-agent forward: refused daemon handshake ({})",
            forward_status_name(status)
        );
        let _ = stream.write_all(&[status]).await;
        let _ = stream.flush().await;
        return;
    }

    // Dial the pod-local serve BEFORE replying — a dial failure must reach
    // the daemon as a status byte, not a mid-pipe reset.
    let tcp = match tokio::net::TcpStream::connect(("127.0.0.1", serve_port)).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "sync-agent forward: serve dial 127.0.0.1:{serve_port} failed: {e}"
            );
            let _ = stream.write_all(&[FORWARD_STATUS_UPSTREAM_UNAVAILABLE]).await;
            let _ = stream.flush().await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    let _ = stream.write_all(&[FORWARD_STATUS_OK]).await;
    let _ = stream.flush().await;

    // RAW PIPE both directions — zero understanding of what flows.
    let mut pipe = Box::pin(tokio_util::compat::FuturesAsyncReadCompatExt::compat(stream));
    let mut tcp = tcp;
    if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut pipe).await {
        eprintln!("sync-agent forward: pipe to 127.0.0.1:{serve_port} ended: {e}");
    }
}
