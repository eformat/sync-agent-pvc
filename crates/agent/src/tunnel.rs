//! M5 tunnel client — the agent-side half of the memory access broker (plan §5).
//!
//! Runs INSIDE the `p2p` agent process alongside the sync accept loop, sharing
//! the agent's swarm, relay reservation and derived identity. One loopback
//! TCP listener PER SERVICE (`--tunnel name@port[:spool,tools]`); OpenCode's
//! MCP config points at `http://127.0.0.1:<port>/mcp`.
//!
//! Per connection:
//! - Tunnel UP (open_stream auto-dials the daemon through the relay circuit,
//!   handshake accepted) → the rest of the connection is a RAW byte pipe to
//!   the laptop service. Zero HTTP understanding on the happy path.
//! - Tunnel DOWN (dial failed / refused / cooldown) → the connection is read
//!   as an HTTP request and CLASSIFIED (this is the only place HTTP is ever
//!   parsed): spool-listed write tools (`tools/call` → `memory_store`…) are
//!   appended to `<root>/.sync-agent/tunnel-spool/<service>.jsonl` (a
//!   scanner-skipped state dir) and answered with an honest fabricated MCP
//!   result ("write spooled"); everything else gets a fabricated clean-miss
//!   tool error. Reads are never spooled.
//!
//! A flush loop replays the spool FIFO once the tunnel returns. Replay is
//! IDEMPOTENT end to end: the store is content-addressed (`content_hash`), so
//! a re-flushed store is a no-op server-side; `memory_delete` is keyed by the
//! same hash. Dial attempts are gated (30 s cooldown while down) — the relay's
//! per-peer circuit rate limit must never be burned by retry storms, because
//! the SYNC path shares the agent's relay budget.
//!
//! Trust note: the AGENT never decides what is reachable — the daemon's
//! default-deny allowlist is the enforcement point. A service name this agent
//! is configured with that the laptop has not opted in gets a clean refusal
//! (which degrades to the down path: reads miss, writes spool — harmless).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::StreamProtocol;
use serde_json::json;

use sync_proto::p2p::{
    tunnel_request_bytes, tunnel_status_name, TUNNEL_MAX_SERVICE_NAME, TUNNEL_STATUS_OK,
    TUNNEL_STREAM_PROTOCOL,
};

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Timeout for open_stream (auto-dial through the relay can take seconds).
const OPEN_STREAM_TIMEOUT: Duration = Duration::from_secs(20);
/// Timeout for the tunnel handshake exchange.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Flush sweep cadence.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// Timeout for one replayed request (write + response read).
const REPLAY_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a captured HTTP head (down path).
const HEAD_CAP: usize = 32 * 1024;
/// Cap on a captured HTTP body (down path).
const BODY_CAP: usize = 1024 * 1024;
/// Cap on a replayed response read.
const REPLAY_READ_CAP: usize = 1024 * 1024;
/// Spool depth cap — beyond this, writes are refused loudly (never silently
/// dropped); the laptop being away that long is an operational problem.
const SPOOL_MAX_ENTRIES: usize = 10_000;

// ---------------------------------------------------------------------------
// Service specs (--tunnel name@port[:tool,tool,...])
// ---------------------------------------------------------------------------

/// One tunneled laptop service, as configured on the agent.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelServiceSpec {
    /// The service name sent in the tunnel handshake (must match the laptop's
    /// `[[tunnel.services]]` name — enforcement happens THERE, not here).
    pub name: String,
    /// Loopback port this service's listener binds (127.0.0.1 only).
    pub port: u16,
    /// MCP tool names that SPOOL when the tunnel is down (writes). Everything
    /// else gets the clean-miss error. Empty = nothing spools for this service.
    pub spool_tools: Vec<String>,
}

/// Parse repeatable `--tunnel` specs: `name@port` or `name@port:tool,tool`.
pub fn parse_tunnel_specs(specs: &[String]) -> Result<Vec<TunnelServiceSpec>, String> {
    let mut out = Vec::new();
    for raw in specs {
        let bad = || format!("--tunnel {raw:?} (expected name@port[:tool,tool,...])");
        let (head, tools) = match raw.split_once(':') {
            Some((h, t)) => (h, t),
            None => (raw.as_str(), ""),
        };
        let (name, port) = head.split_once('@').ok_or_else(bad)?;
        if name.is_empty() || name.len() > TUNNEL_MAX_SERVICE_NAME {
            return Err(format!("--tunnel {raw:?}: service name must be 1..={TUNNEL_MAX_SERVICE_NAME} chars"));
        }
        let port: u16 = port.parse().map_err(|_| format!("--tunnel {raw:?}: bad port {port:?}"))?;
        if port == 0 {
            return Err(format!("--tunnel {raw:?}: port 0 is not a bindable service port"));
        }
        let spool_tools: Vec<String> = tools
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        if out.iter().any(|s: &TunnelServiceSpec| s.name == name) {
            return Err(format!("--tunnel {raw:?}: duplicate service name {name:?}"));
        }
        out.push(TunnelServiceSpec { name: name.to_string(), port, spool_tools });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Down path — parse the request, spool writes, fabricate honest responses
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Spool store — <root>/.sync-agent/tunnel-spool/<service>.jsonl (FIFO lines)
// ---------------------------------------------------------------------------

/// Append-only JSONL spool. The `.sync-agent` dir is scanner-skipped, so the
/// spool NEVER syncs to the laptop. Depth is cached (the file is the truth;
/// the cache is initialized lazily and adjusted on append/retain).
pub(crate) struct SpoolStore {
    path: PathBuf,
    max: usize,
    lock: Mutex<()>,
    depth: AtomicUsize,
    initialized: AtomicBool,
}

/// The result of a flush attempt per spool entry (FIFO order preserved).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ReplayOutcome {
    /// Replayed successfully — drop from the spool.
    Flushed,
    /// The upstream permanently rejected it (4xx) — drop + loud log; keeping a
    /// poison entry would block the FIFO forever.
    Dropped,
    /// Tunnel/upstream unavailable — keep for the next sweep.
    Retry,
}

impl SpoolStore {
    pub(crate) fn new(path: PathBuf, max: usize) -> Self {
        SpoolStore { path, max, lock: Mutex::new(()), depth: AtomicUsize::new(0), initialized: AtomicBool::new(false) }
    }

    fn read_lines(&self) -> Vec<String> {
        match std::fs::read_to_string(&self.path) {
            Ok(content) => content.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect(),
            Err(_) => Vec::new(), // missing file = empty spool
        }
    }

    fn ensure_depth(&self) {
        if !self.initialized.swap(true, Ordering::SeqCst) {
            self.depth.store(self.read_lines().len(), Ordering::SeqCst);
        }
    }

    /// Current depth (lines in the file).
    pub(crate) fn depth(&self) -> usize {
        let _g = self.lock.lock().expect("spool lock");
        self.ensure_depth();
        self.depth.load(Ordering::SeqCst)
    }

    /// Append one spool entry. `Err(())` = spool full (write REFUSED loudly,
    /// never silently dropped).
    fn append(&self, entry: &serde_json::Value) -> Result<usize, ()> {
        let _g = self.lock.lock().expect("spool lock");
        self.ensure_depth();
        let d = self.depth.load(Ordering::SeqCst);
        if d >= self.max {
            return Err(());
        }
        use std::io::Write as _;
        let mut f = match std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("sync-agent tunnel: spool append to {} failed: {e}", self.path.display());
                return Err(());
            }
        };
        if let Err(e) = writeln!(f, "{entry}") {
            eprintln!("sync-agent tunnel: spool write to {} failed: {e}", self.path.display());
            return Err(());
        }
        self.depth.store(d + 1, Ordering::SeqCst);
        Ok(d + 1)
    }

    /// Snapshot the entries (FIFO order).
    fn snapshot(&self) -> Vec<serde_json::Value> {
        let _g = self.lock.lock().expect("spool lock");
        self.read_lines()
            .iter()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Keep only the entries whose (aligned) flag is true; rewrite the file.
    fn retain(&self, keep: &[bool]) {
        let _g = self.lock.lock().expect("spool lock");
        let lines = self.read_lines();
        let mut kept = Vec::with_capacity(lines.len());
        for (i, line) in lines.iter().enumerate() {
            if keep.get(i).copied().unwrap_or(true) {
                kept.push(line.as_str());
            }
        }
        if kept.len() == lines.len() {
            return; // nothing to drop
        }
        let tmp = self.path.with_extension("jsonl.tmp");
        let write = (|| -> std::io::Result<()> {
            use std::io::Write as _;
            std::fs::create_dir_all(self.path.parent().unwrap_or(&PathBuf::from(".")))?;
            let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
            for l in &kept {
                writeln!(f, "{l}")?;
            }
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        })();
        match write {
            Ok(()) => self.depth.store(kept.len(), Ordering::SeqCst),
            Err(e) => eprintln!("sync-agent tunnel: spool rewrite of {} failed: {e} (entries kept)", self.path.display()),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Down path — parse the request, spool writes, fabricate honest responses
// ---------------------------------------------------------------------------

/// A parsed (enough) HTTP request for the down path.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub content_type: String,
    pub accept: String,
    pub body: Vec<u8>,
    /// The JSON-RPC id (echoed in the fabricated response).
    pub id: serde_json::Value,
    /// The parsed JSON-RPC body (method + params) when it is one.
    pub rpc: Option<(String, serde_json::Value)>,
}

/// Parse a captured head + body into a [`CapturedRequest`]. Pure (unit-tested).
pub(crate) fn parse_http_request(head: &[u8], body: &[u8]) -> Result<CapturedRequest, String> {
    let head = std::str::from_utf8(head).map_err(|_| "request head is not utf-8".to_string())?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or("empty request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method in request line")?.to_string();
    let path = parts.next().ok_or("no path in request line")?.to_string();
    let mut host = None;
    let mut content_type = String::from("application/json");
    let mut accept = String::from("application/json, text/event-stream");
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "host" => host = Some(v.to_string()),
            "content-type" => content_type = v.to_string(),
            "accept" => accept = v.to_string(),
            _ => {}
        }
    }
    // JSON-RPC: {"jsonrpc":"2.0","id":…,"method":…,"params":…}
    let rpc = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .filter(|v| v.get("method").and_then(|m| m.as_str()).is_some())
        .map(|v| {
            (
                v.get("method").and_then(|m| m.as_str()).unwrap_or_default().to_string(),
                v.clone(),
            )
        });
    let id = rpc
        .as_ref()
        .and_then(|(_, v)| v.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    Ok(CapturedRequest { method, path, host, content_type, accept, body: body.to_vec(), id, rpc })
}

/// Extract the MCP tool name from a `tools/call` JSON-RPC body, if any.
pub(crate) fn tool_name(rpc_value: &serde_json::Value) -> Option<&str> {
    rpc_value.get("params").and_then(|p| p.get("name")).and_then(|n| n.as_str())
}

/// Classify a down-path request and produce the fabricated HTTP response.
/// `Ok(Some(depth))` = a write was spooled at that depth; `Ok(None)` = answered
/// without spooling (read tool / non-POST / unparseable / spool full).
pub(crate) fn serve_down(req: &CapturedRequest, spec: &TunnelServiceSpec, spool: &SpoolStore) -> (Vec<u8>, Option<usize>) {
    // Only POSTs carry JSON-RPC calls worth spooling; GET (SSE) and anything
    // else is answered with the same clean-miss error.
    let mut spooled_depth = None;
    let text = if req.method == "POST" {
        let is_write = req
            .rpc
            .as_ref()
            .filter(|(m, _)| m == "tools/call")
            .and_then(|(_, v)| tool_name(v))
            .map(|t| spec.spool_tools.iter().any(|s| s == t))
            .unwrap_or(false);
        if is_write {
            let (_, rpc_value) = req.rpc.as_ref().expect("is_write implies rpc");
            let entry = json!({
                "ts": now_unix(),
                "path": req.path,
                "host": req.host,
                "content_type": req.content_type,
                "accept": req.accept,
                "method": "tools/call",
                "id": req.id,
                "params": rpc_value.get("params").cloned().unwrap_or(serde_json::Value::Null),
            });
            match spool.append(&entry) {
                Ok(depth) => {
                    spooled_depth = Some(depth);
                    format!(
                        "MEMORY OFFLINE — write spooled for replay when the laptop reconnects ({} queued). \
                         The real result (e.g. content_hash) arrives server-side at flush time.",
                        depth
                    )
                }
                Err(()) => {
                    format!(
                        "MEMORY OFFLINE — spool full ({} entries); write REFUSED (never silently dropped). \
                         Reconnect the laptop to drain the spool.",
                        SPOOL_MAX_ENTRIES
                    )
                }
            }
        } else {
            "MEMORY OFFLINE (laptop unreachable): this memory read was not served. \
             Writes spool and replay on reconnect; reads miss until then."
                .to_string()
        }
    } else {
        "MEMORY OFFLINE (laptop unreachable): service requests are not served while the tunnel is down.".to_string()
    };
    let is_error = spooled_depth.is_none();
    let result = json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    });
    let body = json!({"jsonrpc": "2.0", "id": req.id, "result": result});
    (render_http_response(&body), spooled_depth)
}

/// Render a minimal HTTP/1.1 200 response with `Connection: close`.
pub(crate) fn render_http_response(body: &serde_json::Value) -> Vec<u8> {
    let body = body.to_string();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// Read one full HTTP request off the connection (head + Content-Length body),
/// with caps. Only used on the down path.
async fn read_http_request(conn: &mut tokio::net::TcpStream) -> Result<CapturedRequest, String> {
    use tokio::io::AsyncReadExt as _;
    let mut head = Vec::new();
    let mut buf = [0u8; 2048];
    let head_end = loop {
        if head.len() > HEAD_CAP {
            return Err(format!("request head exceeds {HEAD_CAP} bytes"));
        }
        let n = conn.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before the request head ended".into());
        }
        head.extend_from_slice(&buf[..n]);
        if let Some(pos) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let (head_bytes, rest) = head.split_at(head_end);
    // Content-Length body.
    let content_length = std::str::from_utf8(head_bytes)
        .ok()
        .and_then(|h| {
            h.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                if k.trim().eq_ignore_ascii_case("content-length") {
                    v.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
        })
        .unwrap_or(0);
    if content_length > BODY_CAP {
        return Err(format!("request body exceeds {BODY_CAP} bytes"));
    }
    let mut body = rest.to_vec();
    if body.len() > content_length {
        body.truncate(content_length); // pipelined extra bytes are ignored
    }
    while body.len() < content_length {
        let n = conn.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed mid-body".into());
        }
        let need = content_length - body.len();
        body.extend_from_slice(&buf[..n.min(need)]);
    }
    let _ = rest;
    parse_http_request(head_bytes, &body)
}

/// The full down path: read → classify → fabricated response → close.
async fn serve_down_path(mut conn: tokio::net::TcpStream, spec: &TunnelServiceSpec, spool: &SpoolStore) {
    let req = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_http_request(&mut conn)).await {
        Ok(Ok(req)) => req,
        Ok(Err(e)) => {
            eprintln!("sync-agent tunnel: down-path request unreadable ({}): {e}", spec.name);
            return;
        }
        Err(_) => {
            eprintln!("sync-agent tunnel: down-path request timed out ({})", spec.name);
            return;
        }
    };
    let (resp, spooled) = serve_down(&req, spec, spool);
    use tokio::io::AsyncWriteExt as _;
    let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, conn.write_all(&resp)).await;
    let _ = conn.shutdown().await;
    if let Some(depth) = spooled {
        eprintln!("sync-agent tunnel: {} offline — write spooled (depth {depth})", spec.name);
    }
}

// ---------------------------------------------------------------------------
// Tunnel open + raw pipe (the happy path)
// ---------------------------------------------------------------------------

/// Open a tunnel stream to the daemon and complete the handshake. `Ok(stream)`
/// is ready for a raw pipe; `Err` means DOWN (caller decides). The daemon's
/// status byte is ENFORCED here — a refusal (unknown service / unauthorized /
/// upstream unavailable) is an error, never a silent fallthrough.
async fn open_tunnel(
    control: &mut libp2p_stream::Control,
    daemon_peer: libp2p::PeerId,
    spec: &TunnelServiceSpec,
) -> Result<std::pin::Pin<Box<libp2p::Stream>>, String> {
    let request = tunnel_request_bytes(&spec.name).map_err(|e| format!("service name: {e}"))?;
    let open = tokio::time::timeout(
        OPEN_STREAM_TIMEOUT,
        control.open_stream(daemon_peer, StreamProtocol::new(TUNNEL_STREAM_PROTOCOL)),
    )
    .await
    .map_err(|_| "tunnel dial timed out".to_string())?
    .map_err(|e| format!("tunnel dial failed: {e}"))?;
    let mut pinned: std::pin::Pin<Box<libp2p::Stream>> = Box::pin(open);
    let status = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        use futures::{AsyncReadExt as _, AsyncWriteExt as _};
        pinned.as_mut().write_all(&request).await?;
        pinned.as_mut().flush().await?;
        let mut status = [0u8; 1];
        pinned.as_mut().read_exact(&mut status).await?;
        Ok::<u8, std::io::Error>(status[0])
    })
    .await
    .map_err(|_| "tunnel handshake timed out".to_string())?
    .map_err(|e| format!("tunnel handshake failed: {e}"))?;
    if status != TUNNEL_STATUS_OK {
        return Err(format!("tunnel refused: {}", tunnel_status_name(status)));
    }
    Ok(pinned)
}

/// Per-connection entry point (spawned per accepted loopback connection).
async fn handle_client(
    mut conn: tokio::net::TcpStream,
    spec: TunnelServiceSpec,
    daemon_peer: libp2p::PeerId,
    mut control: libp2p_stream::Control,
    daemon_connected: Arc<AtomicBool>,
    wake: Arc<tokio::sync::Notify>,
    spool: Arc<SpoolStore>,
) {
    let _ = conn.set_nodelay(true);

    // While the driver's daemon link is down, don't even try: the down path
    // answers immediately (fail-fast for reads, spool for writes) and no
    // open_stream storms burn the relay's circuit budget (shared with sync).
    if !daemon_connected.load(Ordering::SeqCst) {
        return serve_down_path(conn, &spec, &spool).await;
    }
    let pinned = match open_tunnel(&mut control, daemon_peer, &spec).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sync-agent tunnel: {} DOWN ({e}) — serving the offline path", spec.name);
            // A stream-open failure while the driver believes the link is up
            // is the ZOMBIE signature: the daemon restarted (or its circuit
            // died) and the relay never delivered a ConnectionClosed, so the
            // driver would stay "connected" forever and every request would
            // quietly hit this offline path (hit live 2026-11-11 — ~10h of a
            // dead tunnel). Clear the flag and wake the driver's re-dial.
            daemon_connected.store(false, Ordering::SeqCst);
            wake.notify_one();
            return serve_down_path(conn, &spec, &spool).await;
        }
    };
    eprintln!("sync-agent tunnel: {} UP — piping 127.0.0.1:{} to the laptop", spec.name, spec.port);

    // RAW PIPE both directions — zero HTTP understanding on the happy path.
    let mut pipe = Box::pin(tokio_util::compat::FuturesAsyncReadCompatExt::compat(pinned));
    if let Err(e) = tokio::io::copy_bidirectional(&mut conn, &mut pipe).await {
        eprintln!("sync-agent tunnel: {} pipe ended with error: {e}", spec.name);
    }
}

// ---------------------------------------------------------------------------
// Flush — FIFO replay of the spool once the tunnel returns
// ---------------------------------------------------------------------------

/// Rebuild one spooled request as a fresh HTTP POST (`Connection: close` so
/// the response ends the stream cleanly). Pure (unit-tested).
pub(crate) fn build_replay_request(entry: &serde_json::Value) -> Result<String, String> {
    let path = entry.get("path").and_then(|v| v.as_str()).ok_or("spool entry missing path")?;
    let host = entry.get("host").and_then(|v| v.as_str()).unwrap_or("laptop-tunnel");
    let content_type = entry.get("content_type").and_then(|v| v.as_str()).unwrap_or("application/json");
    let accept = entry.get("accept").and_then(|v| v.as_str()).unwrap_or("application/json, text/event-stream");
    let id = entry.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let params = entry.get("params").cloned().unwrap_or(serde_json::Value::Null);
    let body = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params}).to_string();
    Ok(format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\nAccept: {accept}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ))
}

/// HTTP statuses that mean the upstream PERMANENTLY rejected the replay
/// (keeping the entry would poison the FIFO). Everything else retries.
pub(crate) fn is_permanent_replay_failure(status_line: &str) -> bool {
    status_line.starts_with("HTTP/1.1 400 ")
        || status_line.starts_with("HTTP/1.0 400 ")
        || status_line.starts_with("HTTP/1.1 404 ")
        || status_line.starts_with("HTTP/1.0 404 ")
        || status_line.starts_with("HTTP/1.1 405 ")
        || status_line.starts_with("HTTP/1.0 405 ")
}

/// Replay one spooled entry through the tunnel. `Err` = tunnel-level failure
/// (transient, stop the batch). `Ok(outcome)` per [`ReplayOutcome`].
async fn replay_one(
    control: &mut libp2p_stream::Control,
    daemon_peer: libp2p::PeerId,
    spec: &TunnelServiceSpec,
    entry: &serde_json::Value,
) -> Result<ReplayOutcome, String> {
    let request = build_replay_request(entry)?;
    let mut pinned = open_tunnel(control, daemon_peer, spec).await?;
    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
    let resp = tokio::time::timeout(REPLAY_TIMEOUT, async {
        pinned
            .as_mut()
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        pinned.as_mut().flush().await.map_err(|e| e.to_string())?;
        // Read the response to EOF (Connection: close ends it) with a cap.
        let mut resp = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            if resp.len() > REPLAY_READ_CAP {
                return Err("replay response exceeds cap".to_string());
            }
            let n = pinned.as_mut().read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            resp.extend_from_slice(&buf[..n]);
        }
        Ok::<Vec<u8>, String>(resp)
    })
    .await
    .map_err(|_| "replay timed out".to_string())??;
    let head = String::from_utf8_lossy(&resp);
    let status_line = head.lines().next().unwrap_or("");
    if status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200") {
        // A JSON-RPC error body rides a 200 — treat it as a retry-able failure
        // unless the body parses cleanly without "error".
        let body = head.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        match serde_json::from_str::<serde_json::Value>(body) {
            Ok(v) if v.get("error").is_some() => {
                eprintln!("sync-agent tunnel: replay for {} got a JSON-RPC error — keeping the entry", spec.name);
                Ok(ReplayOutcome::Retry)
            }
            Ok(_) => Ok(ReplayOutcome::Flushed),
            Err(_) => {
                eprintln!("sync-agent tunnel: replay for {} got an unparseable response — keeping the entry", spec.name);
                Ok(ReplayOutcome::Retry)
            }
        }
    } else if is_permanent_replay_failure(status_line) {
        eprintln!(
            "sync-agent tunnel: replay for {} PERMANENTLY rejected ({status_line}) — dropping the entry",
            spec.name
        );
        Ok(ReplayOutcome::Dropped)
    } else {
        eprintln!("sync-agent tunnel: replay for {} failed ({status_line}) — keeping the entry", spec.name);
        Ok(ReplayOutcome::Retry)
    }
}

/// Sweep all service spools FIFO. Runs forever (flush cadence [`FLUSH_INTERVAL`]).
/// Only sweeps when the driver reports the daemon link up — otherwise the
/// spool simply waits (and connection handlers keep spooling into it).
async fn flush_loop(
    services: Vec<TunnelServiceSpec>,
    daemon_peer: libp2p::PeerId,
    control: libp2p_stream::Control,
    spools: Arc<std::collections::HashMap<String, Arc<SpoolStore>>>,
    daemon_connected: Arc<AtomicBool>,
) {
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if !daemon_connected.load(Ordering::SeqCst) {
            continue;
        }
        for spec in &services {
            let Some(spool) = spools.get(&spec.name) else { continue };
            if spool.depth() == 0 {
                continue;
            }
            let entries = spool.snapshot();
            if entries.is_empty() {
                continue;
            }
            let mut control = control.clone();
            let mut keep: Vec<bool> = Vec::with_capacity(entries.len());
            let mut flushed = 0usize;
            for entry in &entries {
                match replay_one(&mut control, daemon_peer, spec, entry).await {
                    Ok(ReplayOutcome::Flushed) => {
                        keep.push(false);
                        flushed += 1;
                    }
                    Ok(ReplayOutcome::Dropped) => {
                        keep.push(false);
                    }
                    Ok(ReplayOutcome::Retry) => {
                        keep.push(true);
                        break; // FIFO: a blocked entry blocks the rest
                    }
                    Err(e) => {
                        keep.push(true);
                        eprintln!("sync-agent tunnel: flush for {} stopped: {e}", spec.name);
                        break;
                    }
                }
            }
            if flushed > 0 {
                eprintln!("sync-agent tunnel: flushed {flushed} spooled write(s) for {} ({} left)", spec.name, spool.depth());
            }
            spool.retain(&keep);
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime entry point
// ---------------------------------------------------------------------------

/// Everything the tunnel client needs — built in `p2p.rs::run_agent` from the
/// p2p config (services parsed from `--tunnel`, the shared master key, root).
pub struct TunnelRuntime {
    pub services: Vec<TunnelServiceSpec>,
    /// The sync root — the spool lives under `<root>/.sync-agent/tunnel-spool/`
    /// (scanner-skipped, so spool state never syncs to the laptop).
    pub root: PathBuf,
    /// The daemon's tunnel PeerId, derived from the shared master key (the
    /// SAME derivation the daemon runs — no rendezvous, no pin state).
    pub daemon_peer: libp2p::PeerId,
    /// Liveness of the driver-held daemon connection: the driver dials and
    /// re-dials the daemon (backoff), and flips this flag on up/down. While
    /// false the offline path answers immediately (no open_stream storms).
    pub daemon_connected: Arc<AtomicBool>,
    /// A clone of the p2p swarm's stream control.
    pub control: libp2p_stream::Control,
    /// Wakes the driver's re-dial tick when a REQUEST discovers the daemon
    /// link is dead (the zombie case: the relay never delivers a
    /// ConnectionClosed for a circuit whose far end restarted).
    pub wake: Arc<tokio::sync::Notify>,
}

/// Run the tunnel client forever: one loopback listener per service + the
/// flush loop. Listener bind failures SKIP that service loudly (the sync path
/// must survive tunnel misconfig); a total failure (no listeners) returns.
pub async fn run(rt: TunnelRuntime) -> Result<(), String> {
    if rt.services.is_empty() {
        return Ok(());
    }
    let spool_dir = rt.root.join(".sync-agent").join("tunnel-spool");
    std::fs::create_dir_all(&spool_dir)
        .map_err(|e| format!("cannot create tunnel spool dir {}: {e}", spool_dir.display()))?;

    let mut spools = std::collections::HashMap::new();
    let mut bound = 0usize;
    for spec in &rt.services {
        spools.insert(spec.name.clone(), Arc::new(SpoolStore::new(spool_dir.join(format!("{}.jsonl", spec.name)), SPOOL_MAX_ENTRIES)));
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", spec.port)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "sync-agent tunnel: WARNING service {:?} bind 127.0.0.1:{} failed ({e}) — SKIPPED (sync continues)",
                    spec.name, spec.port
                );
                continue;
            }
        };
        bound += 1;
        eprintln!(
            "sync-agent tunnel: service {:?} on 127.0.0.1:{} → daemon peer {} (spools {:?})",
            spec.name, spec.port, rt.daemon_peer, spec.spool_tools
        );
        let spec2 = spec.clone();
        let control = rt.control.clone();
        let daemon_peer = rt.daemon_peer;
        let connected2 = rt.daemon_connected.clone();
        let wake2 = rt.wake.clone();
        let spool2 = spools.get(&spec.name).expect("just inserted").clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((conn, _)) => {
                        tokio::spawn(handle_client(
                            conn,
                            spec2.clone(),
                            daemon_peer,
                            control.clone(),
                            connected2.clone(),
                            wake2.clone(),
                            spool2.clone(),
                        ));
                    }
                    Err(e) => {
                        eprintln!("sync-agent tunnel: accept failed ({}): {e}", spec2.name);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }
    if bound == 0 {
        return Err("no tunnel service could bind its loopback port".into());
    }
    flush_loop(rt.services, rt.daemon_peer, rt.control, Arc::new(spools), rt.daemon_connected).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests — spec parsing, HTTP parsing/classification, spool semantics, replay
// construction. The live loopback proof (relay → daemon → upstream) is
// crates/cli/tests/tunnel_loopback.rs; the sandbox e2e is the M5 gate.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, port: u16, tools: &[&str]) -> TunnelServiceSpec {
        TunnelServiceSpec {
            name: name.into(),
            port,
            spool_tools: tools.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn spool_entry_body(tool: &str, args: serde_json::Value) -> Vec<u8> {
        json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": tool, "arguments": args}
        })
        .to_string()
        .into_bytes()
    }

    fn captured(body: &[u8]) -> CapturedRequest {
        let head = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:7402\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        parse_http_request(head.as_bytes(), body).unwrap()
    }

    // ----- spec parsing -----

    #[test]
    fn tunnel_specs_parse_all_shapes() {
        let specs = parse_tunnel_specs(&["memory@7402".to_string()]).unwrap();
        assert_eq!(specs, vec![spec("memory", 7402, &[])]);

        let specs = parse_tunnel_specs(&["memory@7402:memory_store,memory_delete".to_string()]).unwrap();
        assert_eq!(specs, vec![spec("memory", 7402, &["memory_store", "memory_delete"])]);

        // Spacing in the tool list is tolerated; duplicates rejected.
        assert!(parse_tunnel_specs(&["a@1:x".into(), "a@2".into()]).is_err());
        assert!(parse_tunnel_specs(&["@7402".into()]).is_err());
        assert!(parse_tunnel_specs(&["memory@0".into()]).is_err(), "port 0 rejected");
        assert!(parse_tunnel_specs(&["memory".into()]).is_err(), "missing @port");
        assert!(parse_tunnel_specs(&["memory@abc".into()]).is_err());
        let long = "m".repeat(TUNNEL_MAX_SERVICE_NAME + 1);
        assert!(parse_tunnel_specs(&[format!("{long}@1")]).is_err(), "over-long name rejected");
    }

    // ----- HTTP capture / classification -----

    #[test]
    fn parse_http_request_extracts_the_pieces() {
        let body = spool_entry_body("memory_store", json!({"content": "hello"}));
        let req = captured(&body);
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/mcp");
        assert_eq!(req.host.as_deref(), Some("127.0.0.1:7402"));
        assert_eq!(req.id, serde_json::json!(7));
        let (m, _) = req.rpc.as_ref().unwrap();
        assert_eq!(m, "tools/call");
        assert_eq!(tool_name(&req.rpc.as_ref().unwrap().1), Some("memory_store"));
    }

    #[test]
    fn down_path_spools_listed_writes_and_answers_honestly() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpoolStore::new(dir.path().join("memory.jsonl"), 10);
        let s = spec("memory", 7402, &["memory_store", "memory_delete"]);

        let req = captured(&spool_entry_body("memory_store", json!({"content": "hello"})));
        let (resp, depth) = serve_down(&req, &s, &store);
        assert_eq!(depth, Some(1), "listed write tool spooled");
        let text = String::from_utf8(resp).unwrap();
        assert!(text.contains("200 OK"), "{text}");
        assert!(text.contains("write spooled"), "{text}");
        assert!(text.contains("\"isError\":false"), "a spooled write is NOT a tool error: {text}");
        assert_eq!(store.depth(), 1);

        // A second write deepens the spool; FIFO order in the file.
        let (resp, depth) = serve_down(&captured(&spool_entry_body("memory_delete", json!({"content_hash": "abc"}))), &s, &store);
        assert_eq!(depth, Some(2));
        assert!(String::from_utf8(resp).unwrap().contains("2 queued"));

        let entries = store.snapshot();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["params"]["name"], "memory_store");
        assert_eq!(entries[1]["params"]["name"], "memory_delete");
        assert_eq!(entries[0]["path"], "/mcp", "the replay must reuse the captured path");
    }

    #[test]
    fn down_path_reads_miss_cleanly_and_never_spool() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpoolStore::new(dir.path().join("memory.jsonl"), 10);
        let s = spec("memory", 7402, &["memory_store"]);

        let req = captured(&spool_entry_body("memory_search", json!({"query": "tunnel"})));
        let (resp, depth) = serve_down(&req, &s, &store);
        assert_eq!(depth, None, "reads are never spooled");
        let text = String::from_utf8(resp).unwrap();
        assert!(text.contains("was not served"), "{text}");
        assert!(text.contains("\"isError\":true"), "an unserved read IS a tool error: {text}");
        assert_eq!(store.depth(), 0);

        // An unlisted write tool is treated like a read (config decides).
        let (resp, depth) = serve_down(&captured(&spool_entry_body("memory_store", json!({}))), &spec("memory", 7402, &[]), &store);
        assert_eq!(depth, None);
        assert!(String::from_utf8(resp).unwrap().contains("was not served"));
        assert_eq!(store.depth(), 0);

        // GETs (SSE) are answered, never spooled.
        let head = b"GET /mcp HTTP/1.1\r\nHost: x\r\n\r\n";
        let req = parse_http_request(head, b"").unwrap();
        let (resp, depth) = serve_down(&req, &s, &store);
        assert_eq!(depth, None);
        assert!(String::from_utf8(resp).unwrap().contains("tunnel is down"));
    }

    #[test]
    fn spool_full_refuses_loudly_and_depth_caps() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpoolStore::new(dir.path().join("memory.jsonl"), 3);
        let s = spec("memory", 7402, &["memory_store"]);
        for i in 0..3 {
            let body = spool_entry_body("memory_store", json!({"n": i}));
            let (_, depth) = serve_down(&captured(&body), &s, &store);
            assert_eq!(depth, Some(i + 1));
        }
        let (resp, depth) = serve_down(&captured(&spool_entry_body("memory_store", json!({"n": 4}))), &s, &store);
        assert_eq!(depth, None, "cap reached — nothing spooled");
        let text = String::from_utf8(resp).unwrap();
        assert!(text.contains("spool full"), "{text}");
        assert!(text.contains("\"isError\":true"), "a refused write is a tool error: {text}");
        assert_eq!(store.depth(), 3);
    }

    #[test]
    fn spool_retain_drops_only_flagged_entries_and_keeps_order() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpoolStore::new(dir.path().join("memory.jsonl"), 10);
        let s = spec("memory", 7402, &["memory_store"]);
        for i in 0..4 {
            let body = spool_entry_body("memory_store", json!({"n": i}));
            serve_down(&captured(&body), &s, &store);
        }
        // Flush the first two, keep the rest (a mid-batch retry shape).
        store.retain(&[false, false, true, true]);
        let entries = store.snapshot();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["params"]["arguments"]["n"], 2);
        assert_eq!(entries[1]["params"]["arguments"]["n"], 3);
        // Depth cache tracks the rewrite.
        assert_eq!(store.depth(), 2);
    }

    // ----- replay construction + classification -----

    #[test]
    fn replay_request_rebuilds_the_original_post() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpoolStore::new(dir.path().join("memory.jsonl"), 10);
        let s = spec("memory", 7402, &["memory_store"]);
        serve_down(&captured(&spool_entry_body("memory_store", json!({"content": "hello"}))), &s, &store);
        let entry = &store.snapshot()[0];
        let req = build_replay_request(entry).unwrap();
        assert!(req.starts_with("POST /mcp HTTP/1.1\r\n"), "{req}");
        assert!(req.contains("Host: 127.0.0.1:7402\r\n"), "{req}");
        assert!(req.contains("Connection: close\r\n"), "{req}");
        let body = req.split_once("\r\n\r\n").unwrap().1;
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["method"], "tools/call");
        assert_eq!(v["params"]["name"], "memory_store");
        assert_eq!(v["params"]["arguments"]["content"], "hello");
        // The declared Content-Length matches the body exactly.
        let cl: usize = req
            .lines()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-length")).map(|(_, v)| v.trim().parse().unwrap()))
            .unwrap();
        assert_eq!(cl, body.len());
    }

    #[test]
    fn replay_outcome_classification() {
        assert!(is_permanent_replay_failure("HTTP/1.1 404 Not Found"));
        assert!(is_permanent_replay_failure("HTTP/1.1 400 Bad Request"));
        assert!(is_permanent_replay_failure("HTTP/1.1 405 Method Not Allowed"));
        assert!(!is_permanent_replay_failure("HTTP/1.1 500 Internal Server Error"));
        assert!(!is_permanent_replay_failure("HTTP/1.1 200 OK"));
        assert!(!is_permanent_replay_failure(""));
    }

    // ----- dial gate -----

    #[test]
    fn down_path_works_without_the_daemon_flag() {
        // The offline path never consults the connection flag — the CALLER
        // (handle_client) does. Sanity: serve_down is pure w.r.t. spool+spec.
        let dir = tempfile::tempdir().unwrap();
        let store = SpoolStore::new(dir.path().join("memory.jsonl"), 10);
        let s = spec("memory", 7402, &["memory_store"]);
        let (resp, depth) = serve_down(&captured(&spool_entry_body("memory_store", json!({}))), &s, &store);
        assert_eq!(depth, Some(1));
        assert!(String::from_utf8(resp).unwrap().contains("write spooled"));
    }

    // ----- the M5 agent-side e2e: REAL run_agent + spool + flush cycle -----

    use futures::StreamExt as TestStreamExt;
    use libp2p::core::multiaddr::Protocol;
    use libp2p::core::transport::{MemoryTransport, Transport as TestTransport};
    use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
    use libp2p::{identity, identify, noise, relay, yamux, Multiaddr};
    use std::sync::atomic::AtomicUsize;

    /// Relay node stand-in (crates/relay) + a mini DAEMON stand-in that holds
    /// the reservation the agent's driver dials, speaks the SERVER side of the
    /// tunnel handshake, refuses the first N streams, and records accepted
    /// request bytes.
    #[derive(NetworkBehaviour)]
    struct TestNodeBehaviour {
        relay_client: relay::client::Behaviour,
        identify: identify::Behaviour,
        stream: libp2p_stream::Behaviour,
    }

    fn build_node_swarm(keypair: identity::Keypair) -> libp2p::Swarm<TestNodeBehaviour> {
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
            .with_behaviour(|kp, relay_client| TestNodeBehaviour {
                relay_client,
                identify: identify::Behaviour::new(identify::Config::new(
                    "sync-agent-pvc/relay/1".to_string(),
                    kp.public(),
                )),
                stream: libp2p_stream::Behaviour::new(),
            })
            .expect("node behaviour")
            .build()
    }

    /// The full agent e2e over a relay: the REAL `run_agent` (driver dials the
    /// daemon target, tunnel client serves the loopback port) against a mini
    /// daemon that REFUSES the first tunnel stream. Asserts the complete
    /// offline cycle: loopback write → refused handshake → SPOOL → flush loop
    /// replay → the daemon receives the memory_store call.
    #[tokio::test]
    async fn run_agent_spools_offline_write_and_flushes_through_the_tunnel() {
        let master = [7u8; 32];

        // ---- relay (the VPS stand-in) ----
        let relay_kp = identity::Keypair::generate_ed25519();
        let relay_peer = relay_kp.public().to_peer_id();
        let relay_swarm = build_node_swarm(relay_kp.clone());
        // (the relay stand-in needs the relay SERVER behaviour, not the client)
        // — reuse the p2p.rs test relay via a dedicated builder below.
        drop(relay_swarm);
        let mut relay_swarm = {
            #[derive(NetworkBehaviour)]
            struct TestRelayBehaviour {
                relay: relay::Behaviour,
            }
            libp2p::SwarmBuilder::with_existing_identity(relay_kp)
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
        };
        relay_swarm.listen_on("/memory/0".parse::<Multiaddr>().unwrap()).expect("relay listen");
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
            while relay_swarm.next().await.is_some() {}
        });
        let relay_with_peer = relay_listen.with(Protocol::P2p(relay_peer));

        // ---- mini daemon stand-in (the derived TUNNEL identity — the agent
        // dials the tunnel peer, not the sync peer) ----
        let daemon_seed = sync_proto::p2p::derive_tunnel_identity_seed(&master);
        let daemon_kp = identity::Keypair::ed25519_from_bytes(daemon_seed).expect("daemon seed");
        let daemon_peer = daemon_kp.public().to_peer_id();
        let mut daemon_swarm = build_node_swarm(daemon_kp);
        // Reservation (the agent dials this circuit). (No direct listener —
        // the test swarm is memory-transport only.)
        let circuit_listen = relay_with_peer
            .clone()
            .with(Protocol::P2pCircuit);
        daemon_swarm.listen_on(circuit_listen).expect("daemon reservation listen");
        let mut daemon_control = daemon_swarm.behaviour().stream.new_control();
        let mut daemon_incoming = daemon_control
            .accept(StreamProtocol::new(TUNNEL_STREAM_PROTOCOL))
            .expect("accept tunnel protocol");
        let refuse_first = Arc::new(AtomicUsize::new(1)); // the FIRST stream is refused
        let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let refuse2 = refuse_first.clone();
        let seen2 = seen.clone();
        tokio::spawn(async move {
            while let Some((_peer, stream)) = daemon_incoming.next().await {
                let refuse2 = refuse2.clone();
                let seen2 = seen2.clone();
                tokio::spawn(async move {
                    use futures::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut pinned: std::pin::Pin<Box<libp2p::Stream>> = Box::pin(stream);
                    // handshake: 10-byte header + name
                    let mut header = [0u8; 10];
                    pinned.as_mut().read_exact(&mut header).await.expect("daemon handshake read");
                    let mut name = vec![0u8; header[9] as usize];
                    pinned.as_mut().read_exact(&mut name).await.expect("daemon name read");
                    if refuse2.fetch_sub(1, Ordering::SeqCst) >= 1 {
                        let _ = pinned.as_mut().write_all(&[sync_proto::p2p::TUNNEL_STATUS_UNKNOWN_SERVICE]).await;
                        eprintln!("test daemon: refused stream (service {:?})", String::from_utf8_lossy(&name));
                        return;
                    }
                    let _ = pinned.as_mut().write_all(&[sync_proto::p2p::TUNNEL_STATUS_OK]).await;
                    // read the request head + body (content-length aware, small caps)
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 2048];
                    let head_end = loop {
                        let n = pinned.as_mut().read(&mut chunk).await.expect("daemon request read");
                        assert!(n > 0, "daemon: stream ended before a request");
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                        assert!(buf.len() < 64 * 1024, "daemon: head cap");
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let clen: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse().ok())?
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + clen {
                        let n = pinned.as_mut().read(&mut chunk).await.expect("daemon body read");
                        assert!(n > 0, "daemon: stream ended mid-body");
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    seen2.lock().unwrap().push(buf);
                    let _ = pinned
                        .as_mut()
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                        .await;
                    eprintln!("test daemon: served one request");
                });
            }
        });
        tokio::spawn(async move {
            while daemon_swarm.next().await.is_some() {}
        });
        // (kept for readability: the exact circuit address the agent dials)
        let _daemon_circuit = relay_with_peer
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(daemon_peer));

        // ---- a free loopback port for the agent's tunnel listener ----
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let service_port = probe.local_addr().unwrap().port();
        drop(probe);

        // ---- the REAL agent (run_agent: driver + tunnel client) ----
        let root = tempfile::tempdir().unwrap();
        let cfg = crate::p2p::P2pConfig {
            master,
            sandbox_id: "test".into(),
            relay: relay_with_peer,
            root: root.path().to_path_buf(),
            protocol: crate::p2p::P2pConfig::stream_protocol(),
            tunnel: vec![TunnelServiceSpec {
                name: "memory".into(),
                port: service_port,
                spool_tools: vec!["memory_store".into()],
            }],
        };
        let agent_task = tokio::spawn(crate::p2p::run_agent(cfg));

        // ---- drive the loopback port: an OpenCode-shaped POST while the
        //      daemon REFUSES the first stream → the write must SPOOL ----
        let body = json!({
            "jsonrpc": "2.0", "id": 42, "method": "tools/call",
            "params": {"name": "memory_store", "arguments": {"content": "spooled through the tunnel"}}
        })
        .to_string();
        let request = format!(
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{service_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        // (retry connects: the listener comes up early, but be tidy)
        let mut conn = None;
        for _ in 0..50 {
            match tokio::net::TcpStream::connect(("127.0.0.1", service_port)).await {
                Ok(c) => {
                    conn = Some(c);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
        let mut conn = conn.expect("agent tunnel listener reachable");
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        conn.write_all(request.as_bytes()).await.expect("loopback write");
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(20), conn.read_to_end(&mut resp))
            .await
            .expect("spooled response in time")
            .expect("spooled response read");
        let resp_text = String::from_utf8_lossy(&resp);
        assert!(
            resp_text.contains("write spooled") && resp_text.contains("200 OK"),
            "the offline write must be spooled honestly: {resp_text:?}"
        );
        let spool_file = root.path().join(".sync-agent").join("tunnel-spool").join("memory.jsonl");
        assert!(spool_file.exists(), "spool file exists under the scanner-skipped state dir");

        // ---- the flush loop must replay it through the (now-accepting) daemon ----
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let flushed = loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "flush did not reach the daemon in time"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
            let got = seen.lock().unwrap();
            if !got.is_empty() {
                break got[0].clone();
            }
        };
        let text = String::from_utf8_lossy(&flushed);
        assert!(text.starts_with("POST /mcp HTTP/1.1"), "replayed as a POST: {text}");
        assert!(text.contains("memory_store"), "replayed the spooled tool call: {text}");
        assert!(text.contains("Connection: close"), "replay uses Connection: close: {text}");
        // The spool drained.
        assert_eq!(SpoolStore::new(spool_file.clone(), 10).depth(), 0, "spool empty after the flush");

        agent_task.abort();
        drop(root);
    }
}
