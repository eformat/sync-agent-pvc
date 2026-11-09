//! M3.5 control plane: how the in-sandbox OpenCode agent sees and steers its sync.
//!
//! Architecture (plan §3 — MCP is the CONTROL plane only, never bulk data):
//! - The laptop daemon drives syncs (one-shot in v1; looped in M4). After every run
//!   it pushes a [`SyncState`] to the remote agent (`Request::SyncReport`), which the
//!   agent persists at `<root>/.sync-agent/sync-state.json`.
//! - The sandbox-side MCP server (`sync-agent mcp`, spawned by OpenCode via the
//!   `mcp` config) READS that state for `sync_status` and WRITES
//!   `<root>/.sync-agent/control-requests.json` for pause / resolve / ignore-add /
//!   sync-now.
//! - The daemon's next run FETCHES the requests (`Request::ControlFetch{consume}` —
//!   fetch-and-clear is atomic on the agent side), honors them, and reports what it
//!   did. Unhonorable requests (e.g. a resolve for a path that no longer conflicts)
//!   are consumed + reported as stale — no silent loops, no restore churn.
//!
//! Both files live in the scanner-skipped `.sync-agent` dir: control state never
//! enters the sync set. All writes are temp+fsync+rename (the archive discipline).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File names inside `<root>/.sync-agent/`.
pub const SYNC_STATE_FILE: &str = "sync-state.json";
pub const CONTROL_REQUESTS_FILE: &str = "control-requests.json";

/// One conflict the daemon left for manual resolution (dir/symlink/opaque
/// conflicts — file conflicts auto-resolve newest-wins per the v1 policy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictInfo {
    /// Root-relative path of the conflict root.
    pub path: String,
    /// Why it was left: "dir-conflict" | "symlink-conflict" | "opaque-conflict".
    pub kind: String,
    /// Human-readable detail for the agent/user.
    pub description: String,
}

/// Daemon-written per-sandbox sync state (the MCP server's `sync_status` source).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SyncState {
    /// Unix seconds when the last sync pass finished (0 = never ran).
    pub last_sync_unix: u64,
    /// Whether the sync is paused (control request honored by the daemon).
    pub paused: bool,
    /// Conflicts left for manual resolution.
    pub conflicts: Vec<ConflictInfo>,
    /// Last run's counters (0 on first run).
    pub applied: u64,
    pub deleted: u64,
    pub failed: u64,
    /// Free-form problems from the last run (path, message).
    pub problems: Vec<(String, String)>,
    /// The daemon's version that wrote this state.
    pub daemon_version: String,
}

/// One resolution decision: how the next sync must settle `path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictResolution {
    pub path: String,
    /// "keep-local" (laptop wins) or "keep-remote" (sandbox wins). The WINNING
    /// side's content propagates; the loser's divergent content is dropped —
    /// an explicit human/agent decision, surfaced in the run report.
    pub choice: String,
}

/// Agent-written control requests, consumed by the daemon's next sync pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlRequests {
    /// Stop syncing entirely until resume (the daemon skips the pass).
    pub paused: bool,
    /// Conflict resolutions to honor on the next pass.
    pub resolutions: Vec<ConflictResolution>,
    /// Ignore patterns to append to the laptop's `.syncignore` (persistent).
    pub ignore_add: Vec<String>,
    /// A "sync now" nudge (v1: honored by the M4 daemon loop; the one-shot
    /// driver reports it as queued-then-run).
    pub sync_now: bool,
}

impl ControlRequests {
    /// Whether anything in here would change daemon behavior.
    pub fn is_empty(&self) -> bool {
        !self.paused
            && self.resolutions.is_empty()
            && self.ignore_add.is_empty()
            && !self.sync_now
    }
}

/// Validate a resolution choice (the MCP tool rejects anything else loudly).
pub fn is_valid_choice(choice: &str) -> bool {
    matches!(choice, "keep-local" | "keep-remote")
}

// ---------------------------------------------------------------------------
// File IO (atomic). For OpenShell `/sandbox/...` roots the files live in the
// agent's global state area — the SAME location serve.rs `agent_state_dir`
// picks (KEEP THE TWO RULES IN SYNC) — so synced trees stay clean and an
// agent restart cannot wipe pending control requests or the last reported
// state (M6: engine state outside the sync roots). Elsewhere: in-root as
// always. The pre-0.1.4 in-root location is still READ (fallback) so an
// upgrade never loses a pending request; writes always go to the new path.
// ---------------------------------------------------------------------------

fn state_dir(root: &Path) -> PathBuf {
    if root.starts_with("/sandbox/") {
        let hash = blake3::hash(root.to_string_lossy().as_bytes());
        let short: String = hash.to_hex().to_string()[..16].to_string();
        PathBuf::from("/sandbox/.sync-agent/agent").join(short)
    } else {
        root.join(".sync-agent")
    }
}

/// The pre-0.1.4 in-root location, when it differs from the current one.
fn legacy_state_dir(root: &Path) -> Option<PathBuf> {
    let legacy = root.join(".sync-agent");
    if legacy == state_dir(root) {
        None
    } else {
        Some(legacy)
    }
}

/// Atomically persist a JSON file under the control state dir (tmp + fsync + rename).
fn write_json<T: Serialize>(root: &Path, file: &str, value: &T) -> io::Result<()> {
    let dir = state_dir(root);
    std::fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!("{file}.tmp"));
    let json = serde_json::to_vec_pretty(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode {file}: {e}")))?;
    {
        let mut f = std::fs::File::create(&tmp)?;
        use std::io::Write;
        f.write_all(&json)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(file))
}

/// Read a JSON file; MISSING file → Ok(None) (first run); corrupt → Ok(None)
/// (control state we cannot parse must never block a sync — the daemon simply
/// runs with defaults, and the next SyncReport overwrites the file). A missing
/// file is ALSO looked up in the legacy in-root dir (pre-0.1.4 /sandbox
/// layout) so an upgrade reads pending requests written there; the next write
/// relocates them.
fn read_json<T: for<'de> Deserialize<'de>>(root: &Path, file: &str) -> io::Result<Option<T>> {
    let bytes = match std::fs::read(state_dir(root).join(file)) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => match
            legacy_state_dir(root).map(|d| std::fs::read(d.join(file)))
        {
            Some(Ok(b)) => b,
            _ => return Ok(None),
        },
        Err(e) => return Err(e),
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

pub fn write_sync_state(root: &Path, state: &SyncState) -> io::Result<()> {
    write_json(root, SYNC_STATE_FILE, state)
}

pub fn read_sync_state(root: &Path) -> io::Result<Option<SyncState>> {
    read_json(root, SYNC_STATE_FILE)
}

/// Persist control requests — MERGE semantics: the MCP server may be called
/// multiple times between daemon passes; later calls accumulate on top of what
/// is already pending (pause wins over resume; resolutions append, later
/// duplicates for the same path win; ignore patterns dedup; sync_now sticks).
pub fn merge_control_requests(root: &Path, update: ControlRequests) -> io::Result<ControlRequests> {
    let mut current = read_control_requests(root)?.unwrap_or_default();
    if update.paused {
        current.paused = true;
    } else if current.paused && update_has_resume_hint(&update) {
        // An explicit resume arrives as a full ControlRequests with paused=false
        // AND at least one other field set OR a bare pause=false write; the MCP
        // resume tool sends ControlRequests{paused:false, ..} with a marker.
        current.paused = false;
    }
    for r in update.resolutions {
        current.resolutions.retain(|x| x.path != r.path);
        current.resolutions.push(r);
    }
    for p in update.ignore_add {
        if !current.ignore_add.contains(&p) {
            current.ignore_add.push(p);
        }
    }
    if update.sync_now {
        current.sync_now = true;
    }
    write_json(root, CONTROL_REQUESTS_FILE, &current)?;
    Ok(current)
}

/// The MCP resume tool writes paused=false; distinguish "explicit resume" from
/// "a write that simply did not touch pause" via a dedicated field on the tool
/// layer — here we treat a ControlRequests that is ENTIRELY default except
/// paused=false as a resume marker.
fn update_has_resume_hint(update: &ControlRequests) -> bool {
    update.resolutions.is_empty() && update.ignore_add.is_empty() && !update.sync_now
}

pub fn read_control_requests(root: &Path) -> io::Result<Option<ControlRequests>> {
    read_json(root, CONTROL_REQUESTS_FILE)
}

/// Fetch-and-clear (the daemon's `ControlFetch{consume:true}`): atomically return
/// the pending requests and remove the file so honored requests never re-fire.
pub fn take_control_requests(root: &Path) -> io::Result<Option<ControlRequests>> {
    // RACE WINDOW (M6, documented): a concurrent MCP `merge_control_requests`
    // is a read-modify-write of the same file — a merge that lands between the
    // read above and the rename below is LOST (its request never reaches a
    // pass). Bounded in practice: the sandbox MCP writes are human-scale and
    // the daemon fetches once per pass; the atomic rename means the loser
    // sees either "already consumed" (empty take, retried next tool call) or
    // a clean file — never a torn one. A seqlock/watch would close it
    // properly if control-plane traffic ever grows beyond human scale.
    let pending = read_control_requests(root)?;
    if pending.is_some() {
        let path = state_dir(root).join(CONTROL_REQUESTS_FILE);
        // Rename to a dead name first (atomic consume), then remove.
        let consumed = state_dir(root).join(format!("{CONTROL_REQUESTS_FILE}.consumed"));
        let _ = std::fs::rename(&path, &consumed);
        let _ = std::fs::remove_file(&consumed);
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root() -> (tempfile::TempDir, PathBuf) {
        let td = tempfile::tempdir().unwrap();
        let root = td.path().to_path_buf();
        std::fs::create_dir_all(root.join(".sync-agent")).unwrap();
        (td, root)
    }

    #[test]
    fn sync_state_roundtrip_and_missing_is_none() {
        let (_td, root) = tmp_root();
        assert!(read_sync_state(&root).unwrap().is_none(), "first run: no state");
        let st = SyncState {
            last_sync_unix: 123,
            conflicts: vec![ConflictInfo {
                path: "dir".into(),
                kind: "dir-conflict".into(),
                description: "both sides changed the dir".into(),
            }],
            applied: 3,
            daemon_version: "0.1.0".into(),
            ..Default::default()
        };
        write_sync_state(&root, &st).unwrap();
        assert_eq!(read_sync_state(&root).unwrap().unwrap(), st);
    }

    #[test]
    fn corrupt_state_file_reads_as_none() {
        let (_td, root) = tmp_root();
        std::fs::write(root.join(".sync-agent").join(SYNC_STATE_FILE), b"garbage{").unwrap();
        assert!(read_sync_state(&root).unwrap().is_none(), "corrupt control state must never block a sync");
    }

    #[test]
    fn control_requests_merge_accumulates() {
        let (_td, root) = tmp_root();
        merge_control_requests(
            &root,
            ControlRequests {
                resolutions: vec![ConflictResolution { path: "d".into(), choice: "keep-remote".into() }],
                ..Default::default()
            },
        )
        .unwrap();
        let merged = merge_control_requests(
            &root,
            ControlRequests {
                paused: true,
                ignore_add: vec!["node_modules".into()],
                resolutions: vec![ConflictResolution { path: "d".into(), choice: "keep-local".into() }],
                ..Default::default()
            },
        )
        .unwrap();
        assert!(merged.paused);
        assert_eq!(merged.ignore_add, vec!["node_modules".to_string()]);
        assert_eq!(merged.resolutions.len(), 1, "later resolution for same path wins");
        assert_eq!(merged.resolutions[0].choice, "keep-local");
    }

    #[test]
    fn take_is_fetch_and_clear() {
        let (_td, root) = tmp_root();
        merge_control_requests(&root, ControlRequests { sync_now: true, ..Default::default() }).unwrap();
        let taken = take_control_requests(&root).unwrap().unwrap();
        assert!(taken.sync_now);
        assert!(take_control_requests(&root).unwrap().is_none(), "consumed — never re-fires");
    }

    #[test]
    fn resume_clears_pause_only_via_marker() {
        let (_td, root) = tmp_root();
        merge_control_requests(&root, ControlRequests { paused: true, ..Default::default() }).unwrap();
        // A bare resume (all-default except paused=false) clears the pause.
        let merged = merge_control_requests(&root, ControlRequests::default()).unwrap();
        assert!(!merged.paused, "explicit resume marker clears pause");
        // A write that touches other fields without pausing does NOT un-pause.
        merge_control_requests(&root, ControlRequests { paused: true, ..Default::default() }).unwrap();
        let merged = merge_control_requests(
            &root,
            ControlRequests { ignore_add: vec!["x".into()], ..Default::default() },
        )
        .unwrap();
        assert!(merged.paused, "unrelated update leaves the pause in place");
    }

    #[test]
    fn choice_validation() {
        assert!(is_valid_choice("keep-local"));
        assert!(is_valid_choice("keep-remote"));
        assert!(!is_valid_choice("keep-mine"));
        assert!(!is_valid_choice(""));
    }
}
