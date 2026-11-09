//! Wire messages for the sync-agent-pvc protocol (M2). bincode-coded into the
//! bounded frames from `lib.rs`.
//!
//! ## Message flow (one session)
//! 1. Magic handshake + exact version exchange (`lib.rs`; mismatch ⇒ re-inject agent).
//! 2. Agent → client: `Response::Hello` (identity: agent version, uid/gid, sync root,
//!    writability — §8 handshake reports, surfaced in status/UI).
//! 3. Loop, client → agent requests, agent → client responses:
//!    - **Scan**: `CacheChunk*` (prior cache, ≥0 frames) → `Scan{rules}` →
//!      `ScanBegin` → `ScanChunk*` (FlatTree entries, ≤ `SCAN_CHUNK_ENTRIES` per
//!      frame) → `CacheChunk*` (fresh cache, ≥0 frames) → `ScanDone`.
//!      WHY CHUNKED: a 200k-entry tree encodes to tens of MB — the copia defect
//!      "L3 List single 1 MiB frame dies >~15-20k files" is exactly what this
//!      avoids (plan §2 "chunked listings").
//!    - **Read**: `ReadFile{path}` → `FileHeader{size,digest,mode,executable}` then
//!      EXACTLY `size` RAW bytes (not framed — the header is the length contract).
//!    - **Stage**: `StageFile{path,size,mode,executable,digest}` then EXACTLY `size`
//!      RAW bytes → `Stage{result}`. The agent hashes while streaming and verifies
//!      the digest: a mid-transfer file change on the daemon side is caught as
//!      `StageResult::DigestMismatch`, never a silently corrupt file (M2 gate).
//!    - **Transition**: `TransitionChunk*` (PlannedActions, ≤1 MiB per frame) →
//!      `TransitionRun` → `TransitionDone{report}`. Materialize(File) actions
//!      consume STAGED content (the staging area, keyed by digest) — there is no
//!      "peer root" on the remote side.
//!    - `Ping` → `Pong`; `Shutdown` → `Bye` then the agent exits.
//!
//! ## Cancellation idiom (v1)
//! A client that abandons a session just stops reading / kills the transport
//! (exec: kill the subprocess; p2p: close the stream, M3). Torn frames surface as
//! UnexpectedEof and the serve loop exits without corrupting anything: staged
//! content lives under `.sync-agent/` (scanner-skipped), in-flight writes use the
//! `.sync-agent-tmp-` temp convention (scanner-skipped, apply.rs), and the archive
//! is only ever written on proven convergence (driver). A later session
//! re-detects any un-applied divergence from the untouched ancestor.
//!
//! Everything here is std-only and generic over Read/Write (rides exec stdio now,
//! libp2p streams in M3, in-memory duplex in tests).

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

use crate::read_frame;
use crate::write_frame;

/// Upper bound on entries per `ScanChunk` frame (kept well under MAX_FRAME —
/// paths and entries are small; ~2000 entries ≈ a few hundred KB worst case).
pub const SCAN_CHUNK_ENTRIES: usize = 2000;

/// Upper bound on bytes per cache/raw-content frame chunk.
pub const CHUNK_BYTES: usize = 256 * 1024;

/// Who an action targets (mirror of `sync_core::apply::Side`, wire-stable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireSide {
    A,
    B,
}

/// One tree entry on the wire — mirror of `sync_core::types::Entry` WITHOUT the
/// nested `children` (the wire carries the FLAT form: path → entry; descendants
/// are their own paths). Keeps types.rs serde-free (M1 design).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEntry {
    /// 0=Directory, 1=File, 2=SymbolicLink, 3=Untracked, 4=Problematic.
    pub kind: u8,
    pub digest: Option<[u8; 32]>,
    pub executable: bool,
    pub target: Option<String>,
    pub mode: u32,
    pub size: u64,
    pub problem: Option<String>,
}

/// `Operation` mirror: materialize this entry, or remove after verifying the
/// on-disk content matches the expected (baseline) entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireOperation {
    Materialize(WireEntry),
    Remove(WireEntry),
}

/// `PlannedAction` mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePlannedAction {
    pub side: WireSide,
    pub path: String,
    pub op: WireOperation,
}

/// `HaltReason` mirror (safety halts + large-deletion guard).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WireHaltReason {
    OneSideRootEmptied,
    RootDeletionProposed,
    RootTypeChanged,
    LargeDeletion { count: usize, ratio: f64 },
}

/// `ApplyReport` mirror — never silent: failures carry paths + reasons.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireApplyReport {
    pub applied: u64,
    pub deleted: u64,
    pub failed: u64,
    pub halted: Option<WireHaltReason>,
    pub problems: Vec<(String, String)>,
}

/// Agent identity + root facts, sent once after the version exchange (§8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The agent binary's own version (semver string, CARGO_PKG_VERSION).
    pub agent_version: String,
    pub uid: u32,
    pub gid: u32,
    /// The sync root the agent serves.
    pub root: String,
    /// Quick writability probe of the root (create+remove a temp file).
    pub root_writable: bool,
    /// Whether the root filesystem preserves the executable bit (§8 probe).
    pub preserves_executability: bool,
}

/// Outcome of a stage (upload) — digest verification is the mid-transfer-change gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StageResult {
    /// Content verified (blake3 == request digest) and atomically staged.
    Staged,
    /// The source changed while streaming (hash ≠ requested digest). Nothing staged.
    DigestMismatch { got: [u8; 32] },
    /// I/O failure (root unwritable, disk full…). Nothing staged.
    Io(String),
}

/// Client → agent. Every variant elicits either its documented response sequence
/// or `Response::Error` (never a panic, never silence).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Request {
    /// Prior-cache fragment (≥0 frames may precede `Scan`).
    CacheChunk(Vec<u8>),
    /// Run a scan with these merged ignore patterns (mutagen-syntax globs).
    Scan {
        rules: Vec<String>,
    },
    /// Stream the file's content after the response header.
    ReadFile {
        path: String,
    },
    /// Upload content for a later Materialize: EXACTLY `size` RAW bytes follow the
    /// request frame; the agent verifies blake3(content) == `digest` before staging.
    StageFile {
        path: String,
        size: u64,
        mode: u32,
        executable: bool,
        digest: [u8; 32],
    },
    /// Accumulate a transition plan (≥1 frames precede `TransitionRun`).
    TransitionChunk(Vec<WirePlannedAction>),
    /// Execute the accumulated transition (safety-checked first). `force` bypasses
    /// the agent's large-deletion guard; the daemon's driver check is authoritative
    /// (the agent re-checks with its own knowledge as defense-in-depth).
    TransitionRun {
        force: bool,
    },
    /// Daemon → agent, after every sync pass: persist this state for the
    /// sandbox-side MCP server (`sync-agent mcp` reads it for sync_status).
    /// Responds `Pong` on success, `Error` if the state dir is unwritable.
    SyncReport {
        state: crate::control::SyncState,
    },
    /// Daemon → agent, at the START of a sync pass: fetch the MCP server's
    /// control requests. `consume=true` is fetch-and-CLEAR (honored requests
    /// never re-fire). Responds `ControlPayload`.
    ControlFetch {
        consume: bool,
    },
    Ping,
    /// Graceful end: agent responds `Bye` and exits.
    Shutdown,
}

/// Agent → client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    Hello(Hello),
    /// Scan started; stats from the agent's scan.
    ScanBegin {
        file_count: u64,
        dir_count: u64,
        total_size: u64,
        preserves_executability: bool,
    },
    /// Flat-tree fragment: (root-relative path, entry), sorted.
    ScanChunk(Vec<(String, WireEntry)>),
    /// Fresh-cache fragment (opaque bincode fragments of `CacheMap::to_bytes`).
    CacheChunk(Vec<u8>),
    /// Terminal marker of a scan response sequence.
    ScanDone,
    /// ReadFile header; EXACTLY `size` RAW bytes follow this frame.
    FileHeader {
        path: String,
        size: u64,
        mode: u32,
        executable: bool,
        digest: [u8; 32],
    },
    Stage(StageResult),
    TransitionDone(WireApplyReport),
    /// The pending control requests at fetch time (None = none pending).
    ControlPayload {
        requests: Option<crate::control::ControlRequests>,
    },
    Pong,
    Bye,
    /// Any dispatch/IO failure that aborts the current request (session may continue).
    Error(String),
}

/// Send one request frame (bincode body, bounded by MAX_FRAME).
pub fn send_request<W: Write>(w: &mut W, req: &Request) -> io::Result<()> {
    let body = bincode::serialize(req)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode request: {e}")))?;
    write_frame(w, &body)
}

/// Read one request frame and decode.
pub fn read_request<R: Read>(r: &mut R) -> io::Result<Request> {
    let body = read_frame(r)?;
    bincode::deserialize(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decode request: {e}")))
}

/// Send one response frame.
pub fn send_response<W: Write>(w: &mut W, resp: &Response) -> io::Result<()> {
    let body = bincode::serialize(resp)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode response: {e}")))?;
    write_frame(w, &body)
}

/// Read one response frame and decode.
pub fn read_response<R: Read>(r: &mut R) -> io::Result<Response> {
    let body = read_frame(r)?;
    bincode::deserialize(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decode response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_frame;

    #[test]
    fn request_response_roundtrip() {
        let req = Request::StageFile {
            path: "a/b.txt".into(),
            size: 7,
            mode: 0o644,
            executable: false,
            digest: [9u8; 32],
        };
        let mut buf = Vec::new();
        send_request(&mut buf, &req).unwrap();
        let mut cur = io::Cursor::new(buf);
        assert_eq!(read_request(&mut cur).unwrap(), req);

        let resp = Response::TransitionDone(WireApplyReport {
            applied: 3,
            deleted: 1,
            failed: 0,
            halted: Some(WireHaltReason::LargeDeletion {
                count: 42,
                ratio: 0.7,
            }),
            problems: vec![("x".into(), "boom".into())],
        });
        let mut buf = Vec::new();
        send_response(&mut buf, &resp).unwrap();
        let mut cur = io::Cursor::new(buf);
        assert_eq!(read_response(&mut cur).unwrap(), resp);
    }

    #[test]
    fn wire_entry_mirror_roundtrip() {
        let e = WireEntry {
            kind: 2,
            digest: Some([1; 32]),
            executable: false,
            target: Some("../link".into()),
            mode: 0o777,
            size: 0,
            problem: None,
        };
        let mut buf = Vec::new();
        send_response(
            &mut buf,
            &Response::ScanChunk(vec![("p".into(), e.clone())]),
        )
        .unwrap();
        let mut cur = io::Cursor::new(buf);
        match read_response(&mut cur).unwrap() {
            Response::ScanChunk(v) => assert_eq!(v[0].1, e),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn oversized_body_is_rejected_by_the_frame_layer() {
        let big = vec![0u8; (crate::MAX_FRAME as usize) + 1];
        let mut buf = Vec::new();
        assert!(write_frame(&mut buf, &big).is_err());
    }
}
