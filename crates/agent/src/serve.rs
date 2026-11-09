//! The M2 serve loop: request dispatch over any duplex `Read + Write` stream.
//!
//! Flow (per `sync_proto::messages` docs): magic handshake → exact version exchange →
//! `Hello` identity → request/response loop until `Shutdown` (`Bye`) or the connection
//! ends (clean EOF and torn frames both exit `Ok` — the documented cancellation idiom).
//!
//! Dispatch contract:
//! - Per-request failures answer `Response::Error` and keep the session framed; the
//!   loop never panics and never goes silent.
//! - `Scan` streams `ScanBegin` → `ScanChunk*` (≤ `SCAN_CHUNK_ENTRIES`) → `CacheChunk*`
//!   (≤ `CHUNK_BYTES`) → `ScanDone`, and leaves the fresh cache as session state.
//! - `ReadFile` sends `FileHeader` then EXACTLY `size` raw bytes (regular files only).
//! - `StageFile` consumes EXACTLY `size` raw bytes after its frame — ALWAYS, even on
//!   early failure (the protocol has no mid-payload resync; undrained bytes would
//!   desync the session). Verified content lands in `<root>/.sync-agent/stage/<hex>`.
//! - `TransitionChunk` accumulates a plan; `TransitionRun` safety-checks it (defense
//!   in depth — the daemon's driver check is authoritative) and executes it through
//!   sync-core `apply.rs` primitives ONLY: removals first (child-first), then
//!   materializations (parent-first) — driver.rs's two-phase order, which is what
//!   makes type flips land.
//!
//! Path safety: every client-supplied path is validated lexically (no absolute paths,
//! no `..`, no empty/`./` components, no `.sync-agent`/`.sync-agent-tmp-*` internal
//! names) before any filesystem access. KNOWN v1 BOUND (plan scope): an intermediate
//! symlink component could still redirect a join — the daemon is a trusted authority
//! and the M0-b Landlock policy bounds the agent process to the sync root.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sync_core::apply::{
    atomic_write, check_safety, create_symlink, guard_empty_overwrite, remove_tree_verified,
    remove_verified, ApplyError, ApplyReport, Operation, PlannedAction, SafetyContext, SafetyLimits,
};
use sync_core::cache::{self, CacheMap};
use sync_core::scan::{scan_with_cache, to_flat, IgnoreRules};
use sync_core::types::{Digest, Entry, EntryKind, RelPath};
use sync_proto::convert::{action_from_wire, chunk_bytes, chunk_flat_tree, report_to_wire};
use sync_proto::messages::{send_response, Hello, Request, Response, StageResult, CHUNK_BYTES};
use sync_proto::{control, exchange_versions_server, read_frame, server_handshake};

/// Streaming hash/echo buffer (same 64 KiB convention as sync-core scan.rs).
const READ_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Path safety
// ---------------------------------------------------------------------------

/// Local mirror of `sync_core::scan::is_internal_name` (crate-private there, so not
/// importable from outside sync-core). KEEP IN SYNC: `.sync-agent` (agent state dir)
/// and `.sync-agent-tmp-*` (in-flight artifacts) are never client-addressable.
fn is_internal_name(leaf: &str) -> bool {
    leaf.starts_with(".sync-agent-tmp-") || leaf == ".sync-agent"
}

/// Validate a client-supplied root-relative path. `allow_root` permits the empty
/// path (the root itself — legal in transition plans so `check_safety` can see and
/// halt a root deletion); leaf addressing (ReadFile/StageFile) rejects it.
fn validate_rel(rel: &str, allow_root: bool) -> Result<(), String> {
    if rel.is_empty() {
        return if allow_root {
            Ok(())
        } else {
            Err("empty path (paths are root-relative)".to_string())
        };
    }
    if rel.starts_with('/') {
        return Err(format!(
            "absolute path {rel:?} rejected — paths are root-relative"
        ));
    }
    for seg in rel.split('/') {
        if seg.is_empty() {
            return Err(format!("path {rel:?} contains an empty component"));
        }
        if seg == "." || seg == ".." {
            return Err(format!("path {rel:?} contains a '.'/'..' component"));
        }
        if is_internal_name(seg) {
            return Err(format!("path {rel:?} targets an agent-internal name"));
        }
    }
    Ok(())
}

/// Resolve a client-supplied LEAF path (ReadFile/StageFile) under `root`.
fn resolve_leaf(root: &Path, client_path: &str) -> Result<PathBuf, String> {
    validate_rel(client_path, false)?;
    Ok(root.join(client_path))
}

// ---------------------------------------------------------------------------
// Staging-area paths
// ---------------------------------------------------------------------------

/// Agent-internal transient state (staging). Lives OUTSIDE the sync root
/// when the root follows the OpenShell /sandbox convention (2026-11-06:
/// "move them to a global top level — else we will pollute a lot of folders"): `/sandbox/.sync-agent/agent/<root-hash>/` — same filesystem
/// as the root (atomic renames still work), scanner-invisible (outside every
/// root), and per-root via a path hash. Elsewhere (tests, non-/sandbox
/// roots) it stays in-root exactly as before.
fn agent_state_dir(root: &Path) -> PathBuf {
    if root.starts_with("/sandbox/") {
        let hash = blake3::hash(root.to_string_lossy().as_bytes());
        let short: String = hash.to_hex().to_string()[..16].to_string();
        PathBuf::from("/sandbox/.sync-agent/agent").join(short)
    } else {
        root.join(".sync-agent")
    }
}

fn stage_dir(root: &Path) -> PathBuf {
    agent_state_dir(root).join("stage")
}

fn stage_path(root: &Path, digest: &Digest) -> PathBuf {
    stage_dir(root).join(hex(digest))
}

fn hex(digest: &Digest) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

static STAGE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `.sync-agent-tmp-<pid>-<uniq>` — same convention as apply.rs `temp_name` (that
/// helper is crate-private), so our in-flight stage temp is scanner-skipped (plan §2).
fn stage_temp_name() -> String {
    let n = STAGE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".sync-agent-tmp-{}-{n:x}", unsafe { libc::getpid() })
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// Per-connection state. v1 assumes ONE session per root at a time (the daemon
/// drives a single sync per endpoint pair, mutagen model) — the staging area and
/// cache are therefore per-root, not per-session-keyed.
struct Session {
    /// Accumulated `CacheChunk` bytes — the PRIOR cache for the next `Scan`.
    pending_cache: Vec<u8>,
    /// The LAST completed scan's fresh cache: the delete-time verification basis.
    last_scan_cache: CacheMap,
    /// The root Directory entry from the LAST completed scan (safety context).
    last_root_entry: Option<Entry>,
    /// Digests currently staged under `<root>/.sync-agent/stage/`.
    staged: HashSet<Digest>,
    /// The accumulated transition plan (cleared on conversion errors and runs).
    pending_plan: Vec<PlannedAction>,
}

impl Session {
    fn new(root: &Path) -> Self {
        // Torn-session leftovers: a previous session may have died mid-stage. The
        // staging dir is agent-internal (scanner-skipped); clear it so this session
        // starts from a known-empty state. Best-effort; failures log to stderr only.
        cleanup_stage(root);
        Session {
            pending_cache: Vec::new(),
            last_scan_cache: CacheMap::new(),
            last_root_entry: None,
            staged: HashSet::new(),
            pending_plan: Vec::new(),
        }
    }

    /// Clean-shutdown GC point for unconsumed staged content. The daemon drives GC
    /// by ending sessions cleanly; a torn session leaves content that the NEXT
    /// session's startup cleanup removes.
    fn shutdown_cleanup(&self, root: &Path) {
        cleanup_stage(root);
    }
}

fn cleanup_stage(root: &Path) {
    let dir = stage_dir(root);
    if let Err(e) = fs::remove_dir_all(&dir) {
        if e.kind() != io::ErrorKind::NotFound {
            eprintln!(
                "sync-agent: could not clear staging area {}: {e}",
                dir.display()
            );
        }
    }
    // Legacy in-root state (pre-0.1.2): remove only the abandoned STAGING
    // subdir, NEVER the whole `<root>/.sync-agent` — for /sandbox roots that
    // dir still hosts the agent install (exec transports) and, until 0.1.4,
    // the control files + the tunnel spool; deleting it at session start
    // destroyed spooled offline writes (M6 "engine state outside the sync
    // roots": the casual-deletion hazard). In-root `.sync-agent-tmp-*` temps
    // are scanner-skipped and removed by their own guards.
    let legacy_stage = root.join(".sync-agent").join("stage");
    if legacy_stage != stage_dir(root) {
        if let Err(e) = fs::remove_dir_all(&legacy_stage) {
            if e.kind() != io::ErrorKind::NotFound {
                eprintln!(
                    "sync-agent: could not remove legacy staging {}: {e}",
                    legacy_stage.display()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Serve loop
// ---------------------------------------------------------------------------

/// Serve one protocol session against `root`. Returns `Ok` on clean session end
/// (Shutdown or connection gone), `Err` on fatal stream errors (broken pipe,
/// oversized frame — the body was not consumed, so the session cannot resync).
pub fn serve<S: Read + Write>(stream: S, root: &Path) -> io::Result<()> {
    let mut stream = stream;

    // 1. Magic handshake + exact version exchange (banner noise fails loudly;
    //    version mismatch is the daemon's cue to re-inject the agent).
    server_handshake(&mut stream).map_err(io::Error::other)?;
    exchange_versions_server(&mut stream).map_err(io::Error::other)?;

    // 2. Hello identity (§8: reports uid/gid + root facts to status/UI).
    send_response(&mut stream, &Response::Hello(build_hello(root)))?;

    // 3. Request/response loop.
    let mut session = Session::new(root);
    loop {
        let req = match read_request_or_eof(&mut stream)? {
            // Clean EOF or torn frame: connection gone (cancellation idiom) — exit
            // without corrupting anything; leftovers are cleaned by the next session.
            None => return Ok(()),
            Some(Ok(req)) => req,
            // Framed but undecodable: the frame body was fully consumed, so the
            // session stays framed — answer Error and continue.
            Some(Err(msg)) => {
                send_response(&mut stream, &Response::Error(msg))?;
                continue;
            }
        };

        if let Request::Shutdown = req {
            session.shutdown_cleanup(root);
            send_response(&mut stream, &Response::Bye)?;
            return Ok(());
        }
        dispatch(&mut stream, root, &mut session, req)?;
    }
}

/// Read one framed request, classifying the three outcomes:
/// - `Ok(None)` — connection ended (clean EOF or torn frame; both are "gone").
/// - `Ok(Some(Err(msg)))` — decodable frame, undecodable request (session framed).
/// - `Err(e)` — fatal: oversized/invalid frame header (body NOT consumed → desync)
///   or a real I/O error. The caller must exit.
///
/// (Uses `read_frame` + bincode directly — `messages::read_request` collapses the
/// fatal and undecodable cases into one error, which would lose the distinction.)
fn read_request_or_eof<S: Read>(stream: &mut S) -> io::Result<Option<Result<Request, String>>> {
    let body = match read_frame(stream) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    match bincode::deserialize::<Request>(&body) {
        Ok(req) => Ok(Some(Ok(req))),
        Err(e) => Ok(Some(Err(format!("undecodable request: {e}")))),
    }
}

/// `Hello` identity: agent version, pod uid/gid, sync root, writability probe.
fn build_hello(root: &Path) -> Hello {
    // Writability probe: create + remove a temp file in the root. The name follows
    // the `.sync-agent-tmp-` convention (scanner-skipped) so a concurrent scan
    // never sees it. Unwritable roots surface here AND as loud scan errors (§8).
    let probe = root.join(format!(".sync-agent-tmp-probe-{}", unsafe {
        libc::getpid()
    }));
    let root_writable = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    };
    Hello {
        agent_version: env!("CARGO_PKG_VERSION").into(),
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        root: root.display().to_string(),
        root_writable,
        // TODO(M4/daemon, §8): a real executability probe lands with the daemon's
        // filesystem checks (plan §8 probe is M4/daemon scope). v1 assumes the
        // PVC preserves the exec bit — same assumption as sync-core's
        // PRESERVES_EXECUTABILITY_V1.
        preserves_executability: true,
    }
}

fn dispatch<S: Read + Write>(
    stream: &mut S,
    root: &Path,
    session: &mut Session,
    req: Request,
) -> io::Result<()> {
    match req {
        Request::Ping => send_response(stream, &Response::Pong),
        Request::CacheChunk(bytes) => {
            // Prior-cache fragment for the NEXT Scan (≥0 frames may precede it).
            session.pending_cache.extend_from_slice(&bytes);
            Ok(())
        }
        Request::Scan { rules } => do_scan(stream, root, session, rules),
        Request::ReadFile { path } => do_read_file(stream, root, &path),
        Request::StageFile {
            path,
            size,
            mode,
            executable,
            digest,
        } => do_stage_file(stream, root, session, &path, size, mode, executable, digest),
        Request::TransitionChunk(actions) => do_transition_chunk(stream, session, actions),
        Request::TransitionRun { force } => do_transition_run(stream, root, session, force),
        // M3.5 control plane: the daemon persists its post-run state for the
        // sandbox-side MCP server, and fetches the MCP server's control requests
        // (both files live in the scanner-skipped `.sync-agent/` dir — control
        // plane only, never bulk file data).
        Request::SyncReport { state } => do_sync_report(stream, root, &state),
        Request::ControlFetch { consume } => do_control_fetch(stream, root, consume),
        // Shutdown is handled in the serve loop (it ends the session).
        Request::Shutdown => unreachable!("Shutdown handled in serve loop"),
    }
}

/// M3.5: persist the daemon's post-pass [`control::SyncState`] at
/// `<root>/.sync-agent/sync-state.json` — the `sync_status` source of the
/// sandbox-side MCP server. `Pong` on success, `Error` when the state dir is
/// unwritable (the session stays framed either way).
fn do_sync_report<S: Read + Write>(
    stream: &mut S,
    root: &Path,
    state: &control::SyncState,
) -> io::Result<()> {
    match control::write_sync_state(root, state) {
        Ok(()) => send_response(stream, &Response::Pong),
        Err(e) => send_response(stream, &Response::Error(format!("sync report: {e}"))),
    }
}

/// M3.5: hand the daemon the MCP server's pending control requests. `consume`
/// is fetch-and-CLEAR (honored requests never re-fire); a non-consuming read
/// leaves the file intact. `None` = nothing pending.
fn do_control_fetch<S: Read + Write>(stream: &mut S, root: &Path, consume: bool) -> io::Result<()> {
    let requests = if consume {
        control::take_control_requests(root)
    } else {
        control::read_control_requests(root)
    };
    match requests {
        Ok(requests) => send_response(stream, &Response::ControlPayload { requests }),
        Err(e) => send_response(stream, &Response::Error(format!("control fetch: {e}"))),
    }
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

fn do_scan<S: Read + Write>(
    stream: &mut S,
    root: &Path,
    session: &mut Session,
    rules: Vec<String>,
) -> io::Result<()> {
    // The agent takes the daemon's patterns AS-IS: the daemon is the merge point for
    // config excludes (and any root .syncignore content it chooses to fold in) — the
    // agent adds no rules of its own.
    let rules = IgnoreRules::new(rules);
    // Rejected patterns are surfaced loudly (silently dropping one would sync data
    // the user believed excluded). stderr only — stdout is the protocol channel.
    for r in rules.rejected() {
        eprintln!("sync-agent: rejected ignore pattern: {r}");
    }

    // Corrupt/undecodable prior cache = cold scan (safe, never unsafe): garbage is
    // never treated as truth about the tree.
    let prior = match cache::from_bytes(&session.pending_cache) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sync-agent: prior cache unusable ({e}); scanning cold");
            CacheMap::new()
        }
    };
    // The accumulated fragments belonged to THIS scan attempt — consumed either way.
    session.pending_cache.clear();

    let (snapshot, fresh) = match scan_with_cache(root, &prior, &rules) {
        Ok(x) => x,
        Err(e) => {
            // Last scan's session state stays intact (it describes the last
            // successful scan).
            send_response(stream, &Response::Error(format!("scan failed: {e}")))?;
            return Ok(());
        }
    };

    send_response(
        stream,
        &Response::ScanBegin {
            file_count: snapshot.file_count,
            dir_count: snapshot.dir_count,
            total_size: snapshot.total_size,
            preserves_executability: snapshot.preserves_executability,
        },
    )?;

    // Build the flat form + the root entry for the safety context, then drop the
    // nested snapshot before streaming (bounds peak memory to flat + root entry).
    let (flat, root_entry) = {
        let root_entry = Entry::directory(snapshot.root.clone());
        (to_flat(&snapshot), root_entry)
    };
    drop(snapshot);

    // Flat entries via proto's chunking helper: ≤ SCAN_CHUNK_ENTRIES per frame, in
    // to_flat (BTreeMap) order — the copia "single big frame dies >15-20k files"
    // defect is exactly what this avoids (plan §2).
    for batch in chunk_flat_tree(&flat) {
        send_response(stream, &Response::ScanChunk(batch))?;
    }

    // Fresh cache via the byte chunking helper: ≤ CHUNK_BYTES fragments (≥0 frames
    // — an empty cache sends none).
    let cache_bytes = cache::to_bytes(&fresh);
    for chunk in chunk_bytes(&cache_bytes) {
        send_response(stream, &Response::CacheChunk(chunk))?;
    }
    send_response(stream, &Response::ScanDone)?;

    // Session state: fresh cache (delete verification) + root entry (safety
    // context). MEMORY NOTE (v1): root_entry clones the whole tree — the flat form
    // needs it gone anyway; bounded by the tree size like the snapshot itself.
    session.last_scan_cache = fresh;
    session.last_root_entry = Some(root_entry);
    Ok(())
}

// ---------------------------------------------------------------------------
// ReadFile
// ---------------------------------------------------------------------------

fn do_read_file<S: Read + Write>(stream: &mut S, root: &Path, client_path: &str) -> io::Result<()> {
    // Path safety first — client-supplied, never trusted.
    let fs_path = match resolve_leaf(root, client_path) {
        Ok(p) => p,
        Err(msg) => {
            send_response(stream, &Response::Error(msg))?;
            return Ok(());
        }
    };
    // Regular files only, and NEVER through a symlink (symlink_metadata does not
    // follow): the daemon syncs the LINK itself, not its target. Directories,
    // symlinks (even to files), FIFOs/sockets/devices → Error.
    let meta = match fs::symlink_metadata(&fs_path) {
        Ok(m) => m,
        Err(e) => {
            send_response(stream, &Response::Error(format!("{client_path}: {e}")))?;
            return Ok(());
        }
    };
    if !meta.file_type().is_file() {
        send_response(
            stream,
            &Response::Error(format!(
                "{client_path}: not a regular file (directories, symlinks and special files are not served)"
            )),
        )?;
        return Ok(());
    }
    let size = meta.len();
    let mode = meta.mode() & 0o7777;
    let executable = mode & 0o111 != 0;
    let mut file = match fs::File::open(&fs_path) {
        Ok(f) => f,
        Err(e) => {
            send_response(stream, &Response::Error(format!("{client_path}: {e}")))?;
            return Ok(());
        }
    };

    // Pass 1 — stream the content through blake3 to learn the digest. The header
    // (which carries the digest) must precede the payload, so "hash-while-sending"
    // cannot produce a truthful header; the content is read twice WITHOUT ever
    // being held in memory (a 1 GB file costs two sequential streaming passes and
    // O(READ_CHUNK) resident — the rejected alternative was a 1 GB buffer).
    let mut hasher = blake3::Hasher::new();
    {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
    }
    let digest: Digest = hasher.finalize().into();

    // Re-stat before anything is sent: if the file changed shape while hashing,
    // fail the request CLEANLY (no header yet — the session stays framed). The
    // digest is still point-in-time: same-size content changes are caught by the
    // daemon's payload-hash check below, never silently accepted.
    // RACE (documented, inherent to streaming reads): a file changing mid-read
    // means the digest describes neither the on-disk file nor the payload exactly.
    // The DAEMON owns the verdict — it compares the header digest against its
    // expectation (its own scan) and hashes the received payload against the
    // header digest, so any mid-read change surfaces as a verification failure
    // and a re-sync, never as silent corruption.
    match fs::symlink_metadata(&fs_path) {
        Ok(m2) => {
            let mtime = |m: &fs::Metadata| m.mtime() * 1_000_000_000 + m.mtime_nsec();
            if m2.len() != size || m2.ino() != meta.ino() || mtime(&m2) != mtime(&meta) {
                send_response(
                    stream,
                    &Response::Error(format!("{client_path}: changed while reading; retry")),
                )?;
                return Ok(());
            }
        }
        Err(e) => {
            send_response(stream, &Response::Error(format!("{client_path}: {e}")))?;
            return Ok(());
        }
    }

    send_response(
        stream,
        &Response::FileHeader {
            path: client_path.to_string(),
            size,
            mode,
            executable,
            digest,
        },
    )?;

    // Pass 2 — stream EXACTLY `size` bytes (a file growing mid-stream must not leak
    // extra bytes into the framed session), re-hashing defensively as we go.
    file.seek(SeekFrom::Start(0))?;
    let mut echoed = blake3::Hasher::new();
    let mut buf = vec![0u8; READ_CHUNK];
    let mut remaining = size;
    while remaining > 0 {
        let want = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want])?;
        if n == 0 {
            // Shrank mid-stream: the header cannot be unsent. Log loudly; the
            // daemon hits EOF waiting for the payload (torn-session idiom) and
            // the next sync re-reads. Never fabricate padding bytes.
            eprintln!(
                "sync-agent: {client_path} shrank during read (sent {} of {size} bytes)",
                size - remaining
            );
            break;
        }
        stream.write_all(&buf[..n])?;
        echoed.update(&buf[..n]);
        remaining -= n as u64;
    }
    stream.flush()?;
    if remaining == 0 {
        let sent: Digest = echoed.finalize().into();
        if sent != digest {
            // Payload already sent — nothing to retract. The daemon's hash check
            // will reject it; this log makes the cause visible server-side.
            eprintln!("sync-agent: {client_path} changed between digest pass and payload stream");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// StageFile
// ---------------------------------------------------------------------------

/// Receive a staged upload: EXACTLY `size` raw bytes follow the request frame.
/// Hash-verified content lands at `<root>/.sync-agent/stage/<hex digest>`.
// (Argument list mirrors `Request::StageFile` 1:1 by design.)
#[allow(clippy::too_many_arguments)]
fn do_stage_file<S: Read + Write>(
    stream: &mut S,
    root: &Path,
    session: &mut Session,
    client_path: &str,
    size: u64,
    mode: u32,
    executable: bool,
    digest: Digest,
) -> io::Result<()> {
    let mut hasher = blake3::Hasher::new();
    // Some while healthy: (temp file, temp path). Deactivated on any write error
    // (the drain CONTINUES — the payload must be fully consumed either way).
    let mut sink: Option<(fs::File, PathBuf)> = None;
    let mut sink_err: Option<String> = None;

    // Path safety FIRST; the payload is drained regardless (stream discipline) and
    // the request rejected with Error — a bad path is caller misuse, not a staging
    // outcome.
    if let Err(msg) = validate_rel(client_path, false) {
        let _ = drain_payload(stream, &mut hasher, &mut sink, &mut sink_err, size);
        send_response(
            stream,
            &Response::Error(format!("stage path rejected: {msg}")),
        )?;
        return Ok(());
    }

    // Prepare the staging area (dir + temp file). Any failure → drain everything,
    // report Stage(Io) — the session stays framed either way.
    let dir = stage_dir(root);
    match fs::create_dir_all(&dir) {
        Ok(()) => {
            let temp = dir.join(stage_temp_name());
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                // mutagen stages content 0600; the FINAL mode comes from the
                // transition's WireEntry at Materialize time via atomic_write
                // (mode bits ONLY, never chown — §8).
                .mode(0o600)
                .open(&temp)
            {
                Ok(f) => sink = Some((f, temp)),
                Err(e) => sink_err = Some(format!("stage temp: {e}")),
            }
        }
        Err(e) => sink_err = Some(format!("stage dir: {e}")),
    }

    // Drain EXACTLY `size` raw bytes (hash + write while healthy, hash-only into
    // the void otherwise). Stream read errors propagate — framing is lost anyway.
    // (mode, executable) are informational in M2: they label the upload for the
    // daemon's bookkeeping; the stage file stays 0600.
    let _ = (mode, executable);
    let total = drain_payload(stream, &mut hasher, &mut sink, &mut sink_err, size)?;

    if total != size {
        // The daemon promised `size` bytes and under-sent: protocol framing is
        // already broken on the peer side. Clean up and report; the next read
        // will surface the desync and end the session.
        if let Some((_, temp)) = sink.take() {
            let _ = fs::remove_file(&temp);
        }
        send_response(
            stream,
            &Response::Error(format!("stage payload short: got {total} of {size} bytes")),
        )?;
        return Ok(());
    }

    if let Some(msg) = sink_err {
        if let Some((_, temp)) = sink.take() {
            let _ = fs::remove_file(&temp);
        }
        send_response(stream, &Response::Stage(StageResult::Io(msg)))?;
        return Ok(());
    }

    let got: Digest = hasher.finalize().into();
    let Some((file, temp)) = sink.take() else {
        unreachable!("sink active whenever the digest check is reached");
    };

    if got != digest {
        // Mid-transfer source change (THE M2 gate): the bytes are not what was
        // asked for — stage nothing, never a silently corrupt file.
        drop(file);
        let _ = fs::remove_file(&temp);
        send_response(
            stream,
            &Response::Stage(StageResult::DigestMismatch { got }),
        )?;
        return Ok(());
    }

    // Verified: fsync (bytes durable before the name exists), then atomic rename
    // into the digest-keyed stage path (the temp lives in the same dir → same-
    // device rename by construction; mirrors apply.rs atomic_write).
    if let Err(e) = file.sync_all() {
        let _ = fs::remove_file(&temp);
        send_response(
            stream,
            &Response::Stage(StageResult::Io(format!("stage fsync: {e}"))),
        )?;
        return Ok(());
    }
    drop(file);
    let stage_file = stage_path(root, &digest);
    match fs::rename(&temp, &stage_file) {
        Ok(()) => {
            session.staged.insert(digest);
            send_response(stream, &Response::Stage(StageResult::Staged))
        }
        Err(e) => {
            let _ = fs::remove_file(&temp);
            send_response(
                stream,
                &Response::Stage(StageResult::Io(format!("stage rename: {e}"))),
            )
        }
    }
}

/// Read exactly `size` bytes from the stream, hashing every byte received. While
/// `sink` is Some, each chunk is appended to the temp file; a write failure records
/// `sink_err`, deactivates the sink, and the drain CONTINUES — the payload is always
/// fully consumed so the session stays framed (no mid-payload resync exists).
/// Returns the number of bytes actually read (< size ⇒ under-sent payload).
fn drain_payload<S: Read>(
    stream: &mut S,
    hasher: &mut blake3::Hasher,
    sink: &mut Option<(fs::File, PathBuf)>,
    sink_err: &mut Option<String>,
    size: u64,
) -> io::Result<u64> {
    let mut buf = vec![0u8; CHUNK_BYTES];
    let mut total: u64 = 0;
    while total < size {
        let want = std::cmp::min(size - total, buf.len() as u64) as usize;
        let n = stream.read(&mut buf[..want])?;
        if n == 0 {
            break; // under-sent payload — the caller handles the short count
        }
        hasher.update(&buf[..n]);
        let mut write_failure: Option<String> = None;
        if let Some((file, _)) = sink.as_mut() {
            if let Err(e) = file.write_all(&buf[..n]) {
                write_failure = Some(format!("stage write: {e}"));
            }
        }
        if let Some(msg) = write_failure {
            *sink = None;
            if sink_err.is_none() {
                *sink_err = Some(msg);
            }
        }
        total += n as u64;
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Transition
// ---------------------------------------------------------------------------

fn do_transition_chunk<S: Read + Write>(
    stream: &mut S,
    session: &mut Session,
    wire_actions: Vec<sync_proto::messages::WirePlannedAction>,
) -> io::Result<()> {
    let mut converted = Vec::with_capacity(wire_actions.len());
    for wa in &wire_actions {
        match action_from_wire(wa) {
            Ok(a) => converted.push(a),
            Err(msg) => {
                // A malformed action poisons the whole accumulated plan: clear it so
                // a later TransitionRun can never execute a half-converted plan. The
                // daemon re-sends the transition from scratch.
                session.pending_plan.clear();
                send_response(stream, &Response::Error(format!("invalid action: {msg}")))?;
                return Ok(());
            }
        }
    }
    session.pending_plan.extend(converted);
    Ok(())
}

fn do_transition_run<S: Read + Write>(
    stream: &mut S,
    root: &Path,
    session: &mut Session,
    force: bool,
) -> io::Result<()> {
    let actions = std::mem::take(&mut session.pending_plan);

    // Defense-in-depth safety re-check BEFORE any mutation (the daemon's driver
    // check is authoritative; this one uses the agent's own knowledge). NO ancestor
    // baseline exists agent-side (the archive lives daemon-side), so: root deletion
    // and large-deletion guards are live; the root-type-change check cannot fire
    // without an ancestor and one-sided-root-emptied cannot fire without a beta
    // root — both remain the daemon's responsibility.
    let sctx = SafetyContext {
        ancestor_root: None,
        alpha_root: session.last_root_entry.as_ref(),
        beta_root: None,
    };
    match check_safety(&sctx, &actions, &SafetyLimits::default(), force) {
        Err(ApplyError::Halted(h)) => {
            // NOTHING mutated — check_safety ran before any mutation. Mirror
            // apply_plan's halt-report shape (halted set, zero counts, loud problem).
            let report = ApplyReport {
                applied: 0,
                deleted: 0,
                failed: 0,
                halted: Some(h.clone()),
                problems: vec![(RelPath::root(), format!("halted before any mutation: {h}"))],
            };
            send_response(stream, &Response::TransitionDone(report_to_wire(&report)))?;
            return Ok(());
        }
        Err(other) => {
            send_response(
                stream,
                &Response::Error(format!("safety check failed: {other}")),
            )?;
            return Ok(());
        }
        Ok(()) => {}
    }

    let report = {
        // Disjoint field borrows: the cache is read, the staging map is updated.
        let cache = &session.last_scan_cache;
        let staged = &mut session.staged;
        execute_plan(root, &actions, cache, staged)
    };
    send_response(stream, &Response::TransitionDone(report_to_wire(&report)))?;
    Ok(())
}

/// Execute the plan against `root` — the wire analog of the driver's two apply_plan
/// phases: ALL removals first (child-first), then materializations (parent-first).
/// (driver.rs: "removals first (type flips), then materializations" — the split
/// phase order is the semantics that makes type flips land; apply_plan's in-call
/// order is the bisync-oriented variant.) Uses ONLY apply.rs primitives; per-action
/// failures are recorded in the report and the run continues (best-effort, never
/// silent). On a halt NOTHING is mutated — checked by the caller before this runs.
fn execute_plan(
    root: &Path,
    actions: &[PlannedAction],
    cache: &CacheMap,
    staged: &mut HashSet<Digest>,
) -> ApplyReport {
    let mut report = ApplyReport::default();

    // Phase 1 — removals, child-first (directories empty out before their parents).
    let mut removals: Vec<&PlannedAction> = actions
        .iter()
        .filter(|a| matches!(a.op, Operation::Remove(_)))
        .collect();
    removals.sort_by(|a, b| b.path.as_str().cmp(a.path.as_str()));
    for action in removals {
        let Operation::Remove(expected) = &action.op else {
            unreachable!("filtered above");
        };
        if let Err(msg) = validate_rel(action.path.as_str(), true) {
            report.failed += 1;
            report
                .problems
                .push((action.path.clone(), format!("unsafe path rejected: {msg}")));
            continue;
        }
        if action.path.as_str().is_empty() {
            // Unreachable in practice (check_safety halts root deletions first) —
            // kept as a belt-and-suspenders refusal to ever delete the root.
            report.failed += 1;
            report
                .problems
                .push((action.path.clone(), "refusing to remove the root".into()));
            continue;
        }
        let fs_path = root.join(action.path.as_str());
        let result = if expected.kind == EntryKind::Directory {
            remove_tree_verified(&fs_path, &action.path, expected, cache)
        } else {
            remove_verified(&fs_path, &action.path, expected, cache)
        };
        match result {
            Ok(()) => report.deleted += 1,
            Err(e) => {
                report.failed += 1;
                report.problems.push((action.path.clone(), e.to_string()));
            }
        }
    }

    // Phase 2 — materializations, parent-first (lexicographic puts "a/b" before
    // "a/b/c").
    let mut materials: Vec<&PlannedAction> = actions
        .iter()
        .filter(|a| matches!(a.op, Operation::Materialize(_)))
        .collect();
    materials.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    let mut used_digests: Vec<Digest> = Vec::new();
    for action in materials {
        let Operation::Materialize(entry) = &action.op else {
            unreachable!("filtered above");
        };
        if let Err(msg) = validate_rel(action.path.as_str(), true) {
            report.failed += 1;
            report
                .problems
                .push((action.path.clone(), format!("unsafe path rejected: {msg}")));
            continue;
        }
        if let EntryKind::File = entry.kind {
            if let Some(d) = entry.digest {
                used_digests.push(d);
            }
        }
        match materialize_staged(root, &action.path, entry, staged) {
            Ok(()) => report.applied += 1,
            Err(msg) => {
                report.failed += 1;
                report.problems.push((action.path.clone(), msg));
            }
        }
    }

    // Consume staged content AFTER the run: every digest this run referenced is
    // now spent. Consuming only after the WHOLE run (not per action) keeps
    // identical-content files working — they all read the same stage file while
    // it still exists. The daemon re-stages content for any later transition in
    // the session; leftovers are GC'd at Shutdown / next session start.
    for d in used_digests {
        let _ = fs::remove_file(stage_path(root, &d));
        staged.remove(&d);
    }

    report
}

/// Materialize one entry at `rel` under `root` — apply.rs materialize semantics
/// with the STAGING AREA as the file-content source (there is no peer root here).
fn materialize_staged(
    root: &Path,
    rel: &RelPath,
    entry: &Entry,
    staged: &HashSet<Digest>,
) -> Result<(), String> {
    if rel.as_str().is_empty() {
        return Err("refusing to materialize the root entry itself".to_string());
    }
    let fs_path = root.join(rel.as_str());
    match entry.kind {
        EntryKind::Directory => {
            // Dirs are created normally — default mode + umask; setgid inheritance
            // on the PVC handles group ownership (plan §8, never chown). Already-
            // exists + is-dir is idempotent; a type conflict is a problem (the
            // removal phase runs first, so this is a mid-plan inconsistency).
            match fs::create_dir(&fs_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if fs_path.is_dir() {
                        Ok(())
                    } else {
                        Err(format!(
                            "{rel}: type conflict — directory planned over non-directory"
                        ))
                    }
                }
                Err(e) => Err(format!("{rel}: {e}")),
            }
        }
        EntryKind::SymbolicLink => {
            let Some(target) = entry.target.as_deref() else {
                return Err(format!("{rel}: symlink entry without a target"));
            };
            create_symlink(target, &fs_path).map_err(|e| format!("{rel}: {e}"))
        }
        EntryKind::File => {
            // Content comes from the staging area keyed by digest. atomic_write
            // does temp-in-target-dir + fsync + rename and sets the final mode
            // from (mode, executable) — mode bits ONLY, never chown (§8).
            let Some(digest) = entry.digest else {
                return Err(format!("content not staged for {rel}"));
            };
            if !staged.contains(&digest) {
                // Failed, never a guess: no content, no materialization.
                return Err(format!("content not staged for {rel}"));
            }
            let stage_file = stage_path(root, &digest);
            let mut reader = fs::File::open(&stage_file)
                .map_err(|e| format!("{rel}: staged content unavailable: {e}"))?;
            // M6 empty-overwrite guard: staged content IS the incoming size —
            // an empty stage must never rename over a non-empty target.
            let staged_len = reader.metadata().map(|m| m.len()).unwrap_or(0);
            guard_empty_overwrite(&fs_path, rel, staged_len)?;
            atomic_write(&fs_path, &mut reader, entry.mode, entry.executable)
                .map_err(|e| format!("{rel}: {e}"))
        }
        // Never transitioned (plan §2): opaque entries are markers, not content.
        EntryKind::Untracked | EntryKind::Problematic => {
            Err(format!("{rel}: refusing to materialize opaque entry"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — session-level, over a UnixStream socketpair (server threaded, client
// drives sync_proto::messages directly).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;
    use std::thread::JoinHandle;

    use sync_core::cache;
    use sync_proto::messages::{
        read_response, send_request, WireApplyReport, WireEntry, WireHaltReason, WireOperation,
        WirePlannedAction, WireSide,
    };
    use sync_proto::{client_handshake, exchange_versions_client};

    // ----- harness -----

    fn blake3_of(bytes: &[u8]) -> Digest {
        blake3::hash(bytes).into()
    }

    /// Spawn the serve loop on one half of a socketpair; handshake + read the Hello
    /// on the other half. Returns the client half + the server thread handle.
    fn connect(root: &Path) -> (UnixStream, JoinHandle<io::Result<()>>) {
        let (mut client, server) = UnixStream::pair().unwrap();
        let root_buf = root.to_path_buf();
        let root_display = root.display().to_string();
        let handle = std::thread::spawn(move || serve(server, &root_buf));
        client_handshake(&mut client).unwrap();
        exchange_versions_client(&mut client).unwrap();
        match read_response(&mut client).unwrap() {
            Response::Hello(h) => {
                assert_eq!(h.agent_version, env!("CARGO_PKG_VERSION"));
                assert_eq!(h.root, root_display);
                assert!(h.uid != u32::MAX);
            }
            other => panic!("expected Hello, got {other:?}"),
        }
        (client, handle)
    }

    /// Send one request (owned — mirrors every other call site's ergonomics).
    fn send(client: &mut UnixStream, req: Request) {
        send_request(client, &req).unwrap();
    }

    fn mkfifo(path: &Path) {
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o7777
    }

    fn expect_error(client: &mut UnixStream, needle: &str) {
        match read_response(client).unwrap() {
            Response::Error(msg) => assert!(
                msg.contains(needle),
                "Error message {msg:?} should contain {needle:?}"
            ),
            other => panic!("expected Error({needle}), got {other:?}"),
        }
    }

    fn wire_file(content: &[u8], mode: u32, executable: bool) -> WireEntry {
        WireEntry {
            kind: 1,
            digest: Some(blake3_of(content)),
            executable,
            target: None,
            mode,
            size: content.len() as u64,
            problem: None,
        }
    }

    fn wire_dir() -> WireEntry {
        WireEntry {
            kind: 0,
            digest: None,
            executable: false,
            target: None,
            mode: 0o755,
            size: 0,
            problem: None,
        }
    }

    fn mat(path: &str, e: WireEntry) -> Request {
        Request::TransitionChunk(vec![WirePlannedAction {
            side: WireSide::A,
            path: path.into(),
            op: WireOperation::Materialize(e),
        }])
    }

    fn rem(path: &str, e: WireEntry) -> Request {
        Request::TransitionChunk(vec![WirePlannedAction {
            side: WireSide::A,
            path: path.into(),
            op: WireOperation::Remove(e),
        }])
    }

    fn run_transition(client: &mut UnixStream, force: bool) -> WireApplyReport {
        send_request(client, &Request::TransitionRun { force }).unwrap();
        match read_response(client).unwrap() {
            Response::TransitionDone(r) => r,
            other => panic!("expected TransitionDone, got {other:?}"),
        }
    }

    fn stage(
        client: &mut UnixStream,
        path: &str,
        content: &[u8],
        mode: u32,
        executable: bool,
        digest: Digest,
    ) -> Response {
        send_request(
            client,
            &Request::StageFile {
                path: path.into(),
                size: content.len() as u64,
                mode,
                executable,
                digest,
            },
        )
        .unwrap();
        client.write_all(content).unwrap();
        read_response(client).unwrap()
    }

    struct ScanOut {
        file_count: u64,
        dir_count: u64,
        total_size: u64,
        preserves_executability: bool,
        entries: Vec<(String, WireEntry)>,
        cache: Vec<u8>,
        chunk_count: usize,
    }

    fn collect_scan(client: &mut UnixStream, rules: Vec<String>) -> ScanOut {
        send_request(client, &Request::Scan { rules }).unwrap();
        let mut out = ScanOut {
            file_count: 0,
            dir_count: 0,
            total_size: 0,
            preserves_executability: false,
            entries: Vec::new(),
            cache: Vec::new(),
            chunk_count: 0,
        };
        loop {
            match read_response(client).unwrap() {
                Response::ScanBegin {
                    file_count,
                    dir_count,
                    total_size,
                    preserves_executability,
                } => {
                    out.file_count = file_count;
                    out.dir_count = dir_count;
                    out.total_size = total_size;
                    out.preserves_executability = preserves_executability;
                }
                Response::ScanChunk(v) => {
                    out.chunk_count += 1;
                    out.entries.extend(v);
                }
                Response::CacheChunk(b) => out.cache.extend_from_slice(&b),
                Response::ScanDone => break,
                other => panic!("unexpected response during scan: {other:?}"),
            }
        }
        out
    }

    /// files+symlink+FIFO+ignored dir; returns big.bin's content (5 MB).
    fn build_tree(root: &Path) -> Vec<u8> {
        fs::write(root.join("a.txt"), b"alpha").unwrap();
        fs::write(root.join("exec.sh"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(root.join("exec.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        let big: Vec<u8> = (0..5_000_000u64).map(|i| (i % 251) as u8).collect();
        fs::write(root.join("big.bin"), &big).unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/nested.txt"), b"nested").unwrap();
        std::os::unix::fs::symlink("a.txt", root.join("link")).unwrap();
        mkfifo(&root.join("fifo"));
        fs::create_dir(root.join("ignored")).unwrap();
        fs::write(root.join("ignored/x.txt"), b"x").unwrap();
        big
    }

    // ----- session basics -----

    #[test]
    fn hello_ping_pong_and_shutdown() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        send_request(&mut client, &Request::Ping).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Pong);

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn clean_eof_exits_ok() {
        let root = tempfile::tempdir().unwrap();
        let (client, handle) = connect(root.path());
        drop(client); // connection gone without Shutdown
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn garbage_frame_gets_error_then_session_continues() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        // An empty frame is decodable framing with an undecodable body.
        client.write_all(&0u32.to_be_bytes()).unwrap();
        expect_error(&mut client, "undecodable request");

        // The session survives: Ping still works.
        send_request(&mut client, &Request::Ping).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Pong);

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn oversized_frame_is_fatal() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());
        client.write_all(&u32::MAX.to_be_bytes()).unwrap();
        drop(client);
        let err = handle.join().unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ----- scan -----

    #[test]
    fn scan_roundtrip_stats_entries_and_cache() {
        let root = tempfile::tempdir().unwrap();
        let big = build_tree(root.path());
        let (mut client, handle) = connect(root.path());

        let out = collect_scan(&mut client, vec!["ignored".to_string()]);
        assert_eq!(out.file_count, 4, "a.txt, exec.sh, big.bin, sub/nested.txt");
        assert_eq!(
            out.dir_count, 1,
            "sub only — root and ignored dirs are not counted"
        );
        assert_eq!(out.total_size, (5 + 10 + 6) as u64 + big.len() as u64);
        assert!(out.preserves_executability);

        // Flat entries reconstruct the expected tree, in to_flat (BTreeMap) order.
        let expected: Vec<(&str, u8)> = vec![
            ("", 0),               // root Directory (children stripped in flat form)
            ("a.txt", 1),          // File
            ("big.bin", 1),        // File
            ("exec.sh", 1),        // File
            ("fifo", 3),           // Untracked
            ("ignored", 3),        // Untracked (ignored dir collapses to a leaf)
            ("link", 2),           // SymbolicLink
            ("sub", 0),            // Directory
            ("sub/nested.txt", 1), // File
        ];
        assert_eq!(out.entries.len(), expected.len());
        for ((path, entry), (want_path, want_kind)) in out.entries.iter().zip(&expected) {
            assert_eq!(path, want_path);
            assert_eq!(entry.kind, *want_kind, "kind mismatch at {path}");
        }
        let by_path: std::collections::HashMap<&str, &WireEntry> =
            out.entries.iter().map(|(p, e)| (p.as_str(), e)).collect();
        assert_eq!(by_path["link"].target.as_deref(), Some("a.txt"));
        assert!(by_path["exec.sh"].executable);
        assert!(!by_path["a.txt"].executable);
        assert_eq!(by_path["sub/nested.txt"].size, 6);

        // CacheChunk fragments reassemble to a parseable cache with real digests.
        let cache = cache::from_bytes(&out.cache).unwrap();
        assert_eq!(cache.len(), 4, "only regular files enter the cache");
        assert_eq!(
            cache
                .get(&sync_core::types::RelPath("a.txt".into()))
                .unwrap()
                .digest,
            blake3_of(b"alpha")
        );

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn scan_chunks_over_2000_entries() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("many")).unwrap();
        for i in 0..2100 {
            fs::write(root.path().join(format!("many/f{i:05}.txt")), b"x").unwrap();
        }
        let (mut client, handle) = connect(root.path());

        let out = collect_scan(&mut client, vec![]);
        // 2100 files + "many" + root = 2102 entries in 2000 + 102 chunks.
        assert_eq!(out.entries.len(), 2102);
        assert_eq!(out.chunk_count, 2);
        assert_eq!(out.file_count, 2100);
        assert_eq!(out.dir_count, 1);

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn warm_scan_reuses_the_prior_cache() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("one.txt"), b"1").unwrap();
        fs::write(root.path().join("two.txt"), b"22").unwrap();
        let (mut client, handle) = connect(root.path());

        let first = collect_scan(&mut client, vec![]);
        assert!(!first.cache.is_empty());

        // Feed the fresh cache back as the prior cache: an unchanged tree must
        // reproduce an identical cache (digests reused, nothing re-hashed).
        send_request(&mut client, &Request::CacheChunk(first.cache.clone())).unwrap();
        let second = collect_scan(&mut client, vec![]);
        assert_eq!(
            second.cache, first.cache,
            "warm scan must reuse the prior cache"
        );

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn corrupt_prior_cache_scans_cold() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("one.txt"), b"1").unwrap();
        let (mut client, handle) = connect(root.path());

        send_request(
            &mut client,
            &Request::CacheChunk(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        )
        .unwrap();
        let out = collect_scan(&mut client, vec![]);
        assert_eq!(
            out.file_count, 1,
            "corrupt cache = cold scan, never a failure"
        );

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    // ----- ReadFile -----

    #[test]
    fn read_file_streaming_digest_size_and_content() {
        let root = tempfile::tempdir().unwrap();
        let big = build_tree(root.path());
        let (mut client, handle) = connect(root.path());

        for (path, content, want_exec) in [
            ("big.bin", big.as_slice(), false),
            ("exec.sh", b"#!/bin/sh\n".as_slice(), true),
        ] {
            send_request(&mut client, &Request::ReadFile { path: path.into() }).unwrap();
            let (size, digest, mode, executable) = match read_response(&mut client).unwrap() {
                Response::FileHeader {
                    path: p,
                    size,
                    mode,
                    executable,
                    digest,
                } => {
                    assert_eq!(p, path);
                    (size, digest, mode, executable)
                }
                other => panic!("expected FileHeader, got {other:?}"),
            };
            assert_eq!(size, content.len() as u64);
            assert_eq!(digest, blake3_of(content));
            assert_eq!(executable, want_exec);
            assert_eq!(executable, mode & 0o111 != 0);
            let mut raw = vec![0u8; size as usize];
            client.read_exact(&mut raw).unwrap();
            assert_eq!(raw, content, "payload must match the file byte-for-byte");
        }

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn read_file_rejects_directories_and_specials() {
        let root = tempfile::tempdir().unwrap();
        build_tree(root.path());
        let (mut client, handle) = connect(root.path());

        send_request(&mut client, &Request::ReadFile { path: "sub".into() }).unwrap();
        expect_error(&mut client, "not a regular file");
        send_request(
            &mut client,
            &Request::ReadFile {
                path: "fifo".into(),
            },
        )
        .unwrap();
        expect_error(&mut client, "not a regular file");
        // Even a symlink TO a regular file is not served (the link is the entry).
        send_request(
            &mut client,
            &Request::ReadFile {
                path: "link".into(),
            },
        )
        .unwrap();
        expect_error(&mut client, "not a regular file");
        send_request(
            &mut client,
            &Request::ReadFile {
                path: "missing.txt".into(),
            },
        )
        .unwrap();
        expect_error(&mut client, "missing.txt");

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn path_traversal_absolute_and_internal_paths_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        build_tree(root.path());
        let (mut client, handle) = connect(root.path());

        // Every rejection message names the path ("empty path", "absolute path …
        // rejected", "path … contains a '.'/'..' component", "path … targets an
        // agent-internal name").
        for bad in [
            "../escape",
            "/etc/passwd",
            "a/../../escape",
            ".",
            ".sync-agent",
            ".sync-agent-tmp-1",
            "sub/../x",
            "",
        ] {
            send_request(&mut client, &Request::ReadFile { path: bad.into() }).unwrap();
            expect_error(&mut client, "path");
        }

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    // ----- StageFile -----

    #[test]
    fn stage_file_with_matching_digest_stages() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        let content = b"staged-bytes-0123456789";
        let digest = blake3_of(content);
        match stage(&mut client, "made/inner.txt", content, 0o644, false, digest) {
            Response::Stage(StageResult::Staged) => {}
            other => panic!("expected Staged, got {other:?}"),
        }
        let on_disk = fs::read(stage_path(root.path(), &digest)).unwrap();
        assert_eq!(on_disk, content);

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
        // Clean shutdown GCs the staging area.
        assert!(
            !stage_dir(root.path()).exists(),
            "shutdown must clear the stage"
        );
    }

    #[test]
    fn stage_file_with_wrong_digest_stages_nothing() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        let content = b"actual-bytes";
        let claimed = blake3_of(b"expected-but-never-sent");
        match stage(&mut client, "f.txt", content, 0o644, false, claimed) {
            Response::Stage(StageResult::DigestMismatch { got }) => {
                assert_eq!(got, blake3_of(content));
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
        assert!(!stage_path(root.path(), &claimed).exists());
        assert!(
            !stage_path(root.path(), &blake3_of(content)).exists(),
            "nothing may be staged on a digest mismatch"
        );

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn stage_file_rejects_unsafe_paths_but_stays_framed() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        let content = b"payload that must still be drained";
        send_request(
            &mut client,
            &Request::StageFile {
                path: "../escape".into(),
                size: content.len() as u64,
                mode: 0o644,
                executable: false,
                digest: blake3_of(content),
            },
        )
        .unwrap();
        client.write_all(content).unwrap(); // payload sent even though path was rejected
        expect_error(&mut client, "stage path rejected");

        // Session still framed.
        send_request(&mut client, &Request::Ping).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Pong);

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    // ----- Transition -----

    #[test]
    fn transition_materializes_dirs_files_modes_and_exec_bits() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        let script = b"#!/bin/sh\necho hi\n";
        let text = b"plain text";
        match stage(
            &mut client,
            "run.sh",
            script,
            0o755,
            true,
            blake3_of(script),
        ) {
            Response::Stage(StageResult::Staged) => {}
            other => panic!("expected Staged, got {other:?}"),
        }
        match stage(&mut client, "note.txt", text, 0o640, false, blake3_of(text)) {
            Response::Stage(StageResult::Staged) => {}
            other => panic!("expected Staged, got {other:?}"),
        }

        send(&mut client, mat("made", wire_dir()));
        send(
            &mut client,
            mat("made/inner.txt", wire_file(text, 0o600, false)),
        );
        send(&mut client, mat("run.sh", wire_file(script, 0o755, true)));
        let report = run_transition(&mut client, false);

        assert_eq!(report.applied, 3, "dir + 2 files");
        assert_eq!(report.failed, 0);
        assert!(report.halted.is_none());
        assert_eq!(fs::read(root.path().join("made/inner.txt")).unwrap(), text);
        assert_eq!(fs::read(root.path().join("run.sh")).unwrap(), script);
        assert_eq!(mode_of(&root.path().join("made/inner.txt")), 0o600);
        assert_eq!(
            mode_of(&root.path().join("run.sh")),
            0o755,
            "exec bit propagated"
        );

        // Consumed staged content is gone after the run.
        assert!(!stage_path(root.path(), &blake3_of(script)).exists());
        assert!(!stage_path(root.path(), &blake3_of(text)).exists());

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn transition_materialize_without_staged_content_fails_never_guesses() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        let phantom = b"never staged";
        send(
            &mut client,
            mat("ghost.txt", wire_file(phantom, 0o644, false)),
        );
        let report = run_transition(&mut client, false);
        assert_eq!(report.applied, 0);
        assert_eq!(report.failed, 1);
        assert!(
            report
                .problems
                .iter()
                .any(|(p, m)| p == "ghost.txt" && m.contains("content not staged")),
            "problems must name the path and the missing stage: {:?}",
            report.problems
        );
        assert!(!root.path().join("ghost.txt").exists());

        // Opaque entries are never transitioned (plan §2).
        let opaque = WireEntry {
            kind: 3,
            digest: None,
            executable: false,
            target: None,
            mode: 0,
            size: 0,
            problem: None,
        };
        send(&mut client, mat("pipe", opaque));
        let report = run_transition(&mut client, false);
        assert_eq!(report.failed, 1);
        assert!(report.problems[0]
            .1
            .contains("refusing to materialize opaque entry"));

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn remove_with_stale_on_disk_content_is_refused() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("stale.txt"), b"v1").unwrap();
        let (mut client, handle) = connect(root.path());

        // Scan to arm delete-time verification (session cache + safety root).
        let out = collect_scan(&mut client, vec![]);
        let entry = out
            .entries
            .iter()
            .find(|(p, _)| p == "stale.txt")
            .expect("stale.txt in the scan")
            .1
            .clone();

        // Drift the on-disk content after the scan.
        fs::write(root.path().join("stale.txt"), b"v1-drift").unwrap();

        send(&mut client, rem("stale.txt", entry));
        let report = run_transition(&mut client, false);
        assert_eq!(report.deleted, 0, "verification refusal — never deletes");
        assert_eq!(report.failed, 1);
        assert!(
            report.problems[0].1.contains("verification failed"),
            "got {:?}",
            report.problems
        );
        assert_eq!(
            fs::read(root.path().join("stale.txt")).unwrap(),
            b"v1-drift"
        );

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn large_deletion_halts_then_force_bypasses() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..40 {
            fs::write(
                root.path().join(format!("f{i:02}.txt")),
                format!("content-{i}"),
            )
            .unwrap();
        }
        let (mut client, handle) = connect(root.path());

        let out = collect_scan(&mut client, vec![]);
        let victim = |i: usize| {
            out.entries
                .iter()
                .find(|(p, _)| *p == format!("f{i:02}.txt"))
                .expect("file in scan")
                .1
                .clone()
        };

        // Removing 30 of 41 tree nodes (73% > 50% default ratio) halts BEFORE any
        // mutation.
        for i in 0..30 {
            send(&mut client, rem(&format!("f{i:02}.txt"), victim(i)));
        }
        let report = run_transition(&mut client, false);
        assert_eq!(report.applied, 0);
        assert_eq!(report.deleted, 0, "halted plans mutate nothing");
        assert_eq!(
            report.halted,
            Some(WireHaltReason::LargeDeletion {
                count: 30,
                ratio: 30.0 / 41.0
            })
        );
        for i in 0..40 {
            assert!(root.path().join(format!("f{i:02}.txt")).exists());
        }

        // The plan is cleared by a run (even a halted one) — the daemon re-sends.
        // force=true bypasses the deletion guard; verification still passes (the
        // files were untouched since the scan).
        for i in 0..30 {
            send(&mut client, rem(&format!("f{i:02}.txt"), victim(i)));
        }
        let report = run_transition(&mut client, true);
        assert_eq!(report.halted, None);
        assert_eq!(report.deleted, 30);
        assert_eq!(report.applied, 0);
        for i in 0..30 {
            assert!(!root.path().join(format!("f{i:02}.txt")).exists());
        }
        for i in 30..40 {
            assert!(root.path().join(format!("f{i:02}.txt")).exists());
        }

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn invalid_transition_action_is_rejected_and_clears_the_plan() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        // A valid chunk, then a chunk with an unknown kind (5) — the whole plan
        // must be dropped so nothing half-valid can ever run.
        send(&mut client, mat("ok.txt", wire_file(b"x", 0o644, false)));
        send(
            &mut client,
            Request::TransitionChunk(vec![WirePlannedAction {
                side: WireSide::A,
                path: "bad.txt".into(),
                op: WireOperation::Materialize(WireEntry {
                    kind: 9,
                    digest: None,
                    executable: false,
                    target: None,
                    mode: 0,
                    size: 0,
                    problem: None,
                }),
            }]),
        );
        expect_error(&mut client, "invalid action");

        // The cleared plan makes the run a no-op.
        let report = run_transition(&mut client, false);
        assert_eq!(report.applied, 0);
        assert_eq!(report.failed, 0);

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    // ----- M3.5 control plane (SyncReport / ControlFetch) -----

    #[test]
    fn sync_report_persists_state_the_mcp_server_can_read() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        let state = control::SyncState {
            last_sync_unix: 42,
            conflicts: vec![control::ConflictInfo {
                path: "dir".into(),
                kind: "dir-conflict".into(),
                description: "both sides changed the dir".into(),
            }],
            applied: 3,
            daemon_version: "0.1.0".into(),
            ..Default::default()
        };
        send_request(&mut client, &Request::SyncReport { state }).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Pong);

        // The persisted state is exactly what the MCP server's read_sync_state
        // would see (this is the sync_status source of truth).
        let read_back = control::read_sync_state(root.path()).unwrap().unwrap();
        assert_eq!(read_back.last_sync_unix, 42);
        assert_eq!(read_back.conflicts.len(), 1);
        assert_eq!(read_back.conflicts[0].path, "dir");

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn sync_report_write_failure_is_an_error_not_a_crash() {
        let root = tempfile::tempdir().unwrap();
        // Make the state path unwritable: sync-state.json exists as a DIRECTORY,
        // so the atomic rename in write_json fails.
        fs::create_dir_all(
            root.path()
                .join(".sync-agent")
                .join(control::SYNC_STATE_FILE),
        )
        .unwrap();
        let (mut client, handle) = connect(root.path());

        send_request(
            &mut client,
            &Request::SyncReport {
                state: control::SyncState::default(),
            },
        )
        .unwrap();
        expect_error(&mut client, "sync report");

        // Session still framed.
        send_request(&mut client, &Request::Ping).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Pong);

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn control_fetch_consume_clears_and_non_consume_preserves() {
        let root = tempfile::tempdir().unwrap();
        let (mut client, handle) = connect(root.path());

        // Nothing pending yet → a fetch over an absent file answers None.
        send_request(&mut client, &Request::ControlFetch { consume: false }).unwrap();
        match read_response(&mut client).unwrap() {
            Response::ControlPayload { requests } => assert!(requests.is_none()),
            other => panic!("expected ControlPayload, got {other:?}"),
        }

        control::merge_control_requests(
            root.path(),
            control::ControlRequests {
                paused: true,
                ..Default::default()
            },
        )
        .unwrap();

        // Peek: a non-consuming fetch returns the pending pause and PRESERVES
        // the file (the daemon can inspect without honoring).
        send_request(&mut client, &Request::ControlFetch { consume: false }).unwrap();
        match read_response(&mut client).unwrap() {
            Response::ControlPayload { requests } => {
                let r = requests.expect("merged pause is pending");
                assert!(r.paused);
            }
            other => panic!("expected ControlPayload, got {other:?}"),
        }
        assert!(
            control::read_control_requests(root.path())
                .unwrap()
                .is_some(),
            "non-consuming fetch must preserve the requests"
        );

        // Consume: fetch-and-clear; the next fetch finds nothing.
        send_request(&mut client, &Request::ControlFetch { consume: true }).unwrap();
        match read_response(&mut client).unwrap() {
            Response::ControlPayload { requests } => {
                assert!(
                    requests
                        .expect("consume returns the pending requests")
                        .paused
                );
            }
            other => panic!("expected ControlPayload, got {other:?}"),
        }
        send_request(&mut client, &Request::ControlFetch { consume: true }).unwrap();
        match read_response(&mut client).unwrap() {
            Response::ControlPayload { requests } => {
                assert!(requests.is_none(), "consumed requests never re-fire");
            }
            other => panic!("expected ControlPayload, got {other:?}"),
        }

        send_request(&mut client, &Request::Shutdown).unwrap();
        assert_eq!(read_response(&mut client).unwrap(), Response::Bye);
        drop(client);
        handle.join().unwrap().unwrap();
    }
}
