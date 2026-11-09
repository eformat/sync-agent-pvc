//! Apply side: atomic write primitives, symlink-aware lifecycle, delete-time
//! verification, and the three safety halts + large-deletion guard.
//!
//! Semantics ported from mutagen (design source, Go — ported ideas, not code):
//! - `pkg/synchronization/core/transition.go`:
//!   - `findAndMoveStagedFileIntoPlace` — permissions set before rename; a defensive
//!     copy-into-target-dir-then-rename fallback for cross-device quirks.
//!   - `ensureExpectedFile` / `removeFile` / `removeSymbolicLink` — before deleting,
//!     verify the on-disk content still matches the expectation; refuse otherwise.
//!   - `removeDirectory` — iterate the ON-DISK listing (never the entry map) so
//!     untracked stragglers abort the removal instead of being silently nuked.
//! - `pkg/synchronization/safety.go` — the three halts (`oneEndpointEmptiedRoot`,
//!   root deletion, root type change), all evaluated BEFORE any mutation.
//!
//! Plan §8 (load-bearing): mode bits ONLY — never chown, never uid/gid. New dirs
//! inherit setgid group ownership automatically on the PVC; we never force group.
//! Plan §2: unreadable ≠ absent — verification failures are loud errors.

use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cache::CacheMap;
use crate::scan::{hash_file, is_internal_name};
use crate::types::{Entry, EntryKind, RelPath};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which endpoint an action targets (copia's alpha/beta).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

/// One reconciler decision for one path, in executable form. The reconciler produces
/// these from its 3-way table; `apply_plan` executes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    /// Materialize this entry at the path (mkdir / write file / create symlink).
    Materialize(Entry),
    /// Remove the existing entry after verifying it still matches this expected
    /// (baseline) entry. Directories recurse via `remove_tree_verified`.
    Remove(Entry),
}

/// `&[(side, path, operation)]` from the plan — the concrete action tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    pub side: Side,
    pub path: RelPath,
    pub op: Operation,
}

/// Deletion-threshold configuration (plan M1: ">N/>X% requires --force").
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SafetyLimits {
    /// More planned deletions than this halts the plan (unless forced).
    pub max_deletes: usize,
    /// A planned deletion fraction above this (of the baseline tree) halts.
    pub max_delete_ratio: f64,
}

impl Default for SafetyLimits {
    fn default() -> Self {
        SafetyLimits {
            max_deletes: 10_000,
            max_delete_ratio: 0.5,
        }
    }
}

/// Baseline/current snapshots the safety checks need (mutagen's algorithm has these
/// in scope; a bare `SafetyLimits` cannot express `oneEndpointEmptiedRoot`).
#[derive(Debug, Clone, Copy)]
pub struct SafetyContext<'a> {
    /// Baseline (archive) root Directory entry, if a baseline exists.
    pub ancestor_root: Option<&'a Entry>,
    /// Current scan of side A's root, if available.
    pub alpha_root: Option<&'a Entry>,
    /// Current scan of side B's root, if available.
    pub beta_root: Option<&'a Entry>,
}

impl<'a> SafetyContext<'a> {
    pub fn none() -> Self {
        SafetyContext {
            ancestor_root: None,
            alpha_root: None,
            beta_root: None,
        }
    }
}

/// Everything `apply_plan` needs beyond the two roots and the action list.
pub struct ApplyCtx<'a> {
    /// Prior-scan cache for delete-time verification (an empty map is safe: the
    /// verifier falls back to a full re-hash).
    pub cache: &'a CacheMap,
    /// Bypass the large-deletion guard (`--force`).
    pub force: bool,
    pub limits: SafetyLimits,
    pub safety: SafetyContext<'a>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HaltReason {
    /// safety.go `oneEndpointEmptiedRoot`: baseline root had ≥2 immediate children
    /// and exactly one side now has none.
    OneSideRootEmptied,
    /// The plan deletes the sync root itself.
    RootDeletionProposed,
    /// The root's entry kind flips (directory → file/symlink or vice versa).
    RootTypeChanged,
    /// Large-deletion guard tripped (plan M1).
    LargeDeletion { count: usize, ratio: f64 },
}

impl std::fmt::Display for HaltReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HaltReason::OneSideRootEmptied => write!(
                f,
                "one side emptied the sync root while the other did not (mutagen safety halt)"
            ),
            HaltReason::RootDeletionProposed => write!(f, "plan deletes the sync root itself"),
            HaltReason::RootTypeChanged => write!(f, "sync root type changed"),
            HaltReason::LargeDeletion { count, ratio } => write!(
                f,
                "plan deletes {count} items ({ratio:.1}% of the tree) — rerun with force to proceed"
            ),
        }
    }
}

#[derive(Debug)]
pub enum ApplyError {
    /// A safety halt fired BEFORE any mutation (mutagen safety.go discipline).
    Halted(HaltReason),
    /// The on-disk content no longer matches the expectation — the operation was
    /// REFUSED (nothing deleted/overwritten).
    VerificationMismatch { path: RelPath, reason: String },
    /// Unwrapped I/O failure at a specific path.
    Io { path: RelPath, source: io::Error },
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::Halted(h) => write!(f, "halted: {h}"),
            ApplyError::VerificationMismatch { path, reason } => {
                write!(f, "{path}: verification failed, refusing: {reason}")
            }
            ApplyError::Io { path, source } => write!(f, "{path}: {source}"),
        }
    }
}

/// Outcome of an apply run — never silent: failures land in `problems` with their
/// paths, and halts are recorded even though nothing was mutated.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ApplyReport {
    pub applied: u64,
    pub deleted: u64,
    pub failed: u64,
    pub halted: Option<HaltReason>,
    pub problems: Vec<(RelPath, String)>,
}

// ---------------------------------------------------------------------------
// Temp-name machinery
// ---------------------------------------------------------------------------

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `<dir>/.sync-agent-tmp-<pid>-<uniq>` — the same prefix the scanner skips
/// (`scan::is_internal_name`), so our own in-flight artifacts never enter the tree
/// (plan §2 stale-scan self-inversion guard).
fn temp_name() -> String {
    let pid = unsafe { libc::getpid() } as u64;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".sync-agent-tmp-{pid:x}-{nanos:x}{n:x}")
}

fn verification_mismatch(path: &RelPath, reason: impl Into<String>) -> ApplyError {
    ApplyError::VerificationMismatch {
        path: path.clone(),
        reason: reason.into(),
    }
}

fn io_err(path: &RelPath, source: io::Error) -> ApplyError {
    ApplyError::Io { path: path.clone(), source }
}

fn is_cross_device(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::EXDEV)
}

// ---------------------------------------------------------------------------
// Mode helpers (§8: mode bits ONLY — nothing in this module ever chowns)
// ---------------------------------------------------------------------------

/// mutagen transition.go `markExecutableForReaders` port: set the exec bit wherever
/// a read bit is set.
fn mark_executable_for_readers(mut mode: u32) -> u32 {
    for (r, x) in [(0o400, 0o100), (0o040, 0o010), (0o004, 0o001)] {
        if mode & r != 0 {
            mode |= x;
        }
    }
    mode
}

/// Final file mode from an entry's mode bits + executability flag: executable adds
/// exec-where-readable; non-executable strips all exec bits (mutagen's propagation
/// model for filesystems where executability may not be preserved).
fn effective_file_mode(mode: u32, executable: bool) -> u32 {
    let m = mode & 0o7777;
    if executable {
        mark_executable_for_readers(m)
    } else {
        m & !0o111
    }
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

/// Create missing parent directories with default permissions (umask applies →
/// typically 0755). Plan §8: setgid inheritance on the PVC handles group ownership
/// automatically — we never force group or owner.
pub fn ensure_parents(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

/// Write `reader` to `path` atomically:
/// temp file in the TARGET directory (`.sync-agent-tmp-<pid>-<uniq>`, 0600 while in
/// flight) → fsync → set permissions (mode bits ONLY — never chown; exec propagation
/// per mutagen) → rename over the target.
///
/// The temp file living in the target's directory makes the final rename same-device
/// by construction (mutagen transition.go `findAndMoveStagedFileIntoPlace`); the
/// EXDEV copy-into-place fallback is kept defensively for filesystem quirks.
///
/// RACE: concurrent writers last-ride the rename; the winner is one complete file —
/// never a partial one.
pub fn atomic_write(path: &Path, reader: &mut impl Read, mode: u32, executable: bool) -> io::Result<()> {
    ensure_parents(path)?;
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "target path has no parent directory")
    })?;
    let perms = fs::Permissions::from_mode(effective_file_mode(mode, executable));
    for _ in 0..3 {
        let temp = dir.join(temp_name());
        // 0600 while in flight (mutagen stages content 0600); final mode is set
        // explicitly below — chmod is exact and not umask-masked.
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
        {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let result = (|| -> io::Result<()> {
            io::copy(reader, &mut file)?;
            // fsync before rename: the bytes are durable before the name exists.
            file.sync_all()?;
            file.set_permissions(perms)?;
            drop(file);
            match fs::rename(&temp, path) {
                Ok(()) => Ok(()),
                Err(e) if is_cross_device(&e) => {
                    // Defensive parity with mutagen's cross-device staging path. The
                    // temp already lives in the target directory, so this is
                    // practically unreachable; kept for odd overlay/fuse setups.
                    let temp2 = dir.join(temp_name());
                    fs::copy(&temp, &temp2)?;
                    match fs::rename(&temp2, path) {
                        Ok(()) => {
                            let _ = fs::remove_file(&temp);
                            Ok(())
                        }
                        Err(e2) => {
                            let _ = fs::remove_file(&temp2);
                            let _ = fs::remove_file(&temp);
                            Err(e2)
                        }
                    }
                }
                Err(e) => Err(e),
            }
        })();
        return match result {
            Ok(()) => Ok(()),
            Err(e) => {
                // Best-effort temp cleanup on any failure path (mutagen removes its
                // intermediates too).
                let _ = fs::remove_file(&temp);
                Err(e)
            }
        };
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temporary file",
    ))
}

/// M6 hardening (the "plan.md went 0-byte on both sides" incident class): a
/// pass must never materialize an EMPTY file over an existing NON-EMPTY one.
/// A 0-byte incoming state is almost always a peer-side mid-write scan
/// artifact (the scanner hashed the file inside its `> file` truncation
/// window), and silently renaming empty content over real content destroyed
/// data with `applied: 1` and no problem record. Refuse instead: the caller
/// records a per-file problem, the pass continues, nothing is destroyed, and
/// the peer's next STABLE scan re-plans the path — either the file's real
/// content arrives, or, for a genuinely intentional truncation, the operator
/// empties/removes this side's copy too so the states agree.
///
/// Creating an empty file (target absent) and empty-over-empty destroy
/// nothing and pass.
pub fn guard_empty_overwrite(
    fs_path: &Path,
    rel: &RelPath,
    incoming_size: u64,
) -> Result<(), String> {
    if incoming_size > 0 {
        return Ok(());
    }
    let existing = match fs::metadata(fs_path) {
        Ok(m) if m.is_file() => m.len(),
        _ => return Ok(()), // absent / dir / symlink: nothing to destroy
    };
    if existing == 0 {
        return Ok(());
    }
    Err(format!(
        "{rel}: refusing to materialize an EMPTY file over the non-empty local copy \
         ({existing} bytes) — probable mid-write scan on the peer (empty-overwrite guard). \
         The peer's next stable scan re-plans this path; to accept an intentional truncation, \
         empty or remove this side's copy too."
    ))
}

/// Propagate the executable bit on an existing FILE — chmod of mode bits ONLY
/// (§8: never uid/gid; no chown anywhere in this crate). Does not change
/// mtime/inode, so the scan cache stays valid.
pub fn set_mode(path: &Path, executable: bool) -> io::Result<()> {
    // Real files only; following is intended here (the reconciler materializes
    // symlinks via create_symlink, never via set_mode).
    let meta = fs::metadata(path)?;
    let mode = {
        use std::os::unix::fs::MetadataExt;
        meta.mode()
    };
    let next = effective_file_mode(mode, executable);
    fs::set_permissions(path, fs::Permissions::from_mode(next))
}

/// Create (or atomically replace) a symlink with a posix-raw target string.
/// Replacement goes through a temp symlink + rename in the target directory, so the
/// swap is atomic and never dereferences the old link. If the target path currently
/// holds a real directory, the rename fails loudly — the reconciler removes
/// directories before type changes.
pub fn create_symlink(target: &str, path: &Path) -> io::Result<()> {
    ensure_parents(path)?;
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Fast path: nothing to replace.
            std::os::unix::fs::symlink(target, path)
        }
        Err(e) => Err(e),
        Ok(_) => {
            // Atomic replace: new link in the same dir, rename over the old entry.
            let dir = path.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "target path has no parent directory")
            })?;
            for _ in 0..3 {
                let temp = dir.join(temp_name());
                match std::os::unix::fs::symlink(target, &temp) {
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e),
                    Ok(()) => match fs::rename(&temp, path) {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            let _ = fs::remove_file(&temp);
                            return Err(e);
                        }
                    },
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not create a unique temporary symlink",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Delete-time verification (mutagen ensureExpectedFile / removeFile / removeDirectory)
// ---------------------------------------------------------------------------

/// Verify that a regular file on disk still matches the expected entry BEFORE it is
/// deleted. With a cache entry present this is mutagen's exact comparison: current
/// stat == cached stat (mode+mtime+size+inode) and cached digest == expected digest.
/// Without a cache entry we fall back to a full re-hash (stronger than mutagen, which
/// refuses; deletions are rare so the cost is fine).
fn verify_file(path: &Path, rel: &RelPath, expected: &Entry, cache: &CacheMap) -> Result<(), String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err("content missing at delete time".to_string())
        }
        Err(e) => return Err(format!("stat failed: {e}")),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err("on-disk type changed (expected regular file)".to_string());
    }
    let cur = FileMetaNow {
        mode: meta.mode() & 0o7777,
        // Full-precision mtime in nanoseconds (see scan.rs::classify — tv_nsec alone
        // is only the subsecond component).
        mtime_nanos: meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
        size: meta.len(),
        inode: meta.ino(),
    };
    let Some(want_digest) = expected.digest else {
        return Err("expected entry carries no digest to verify".to_string());
    };
    match cache.get(rel) {
        Some(ce) => {
            // mutagen ensureExpectedFile: current metadata must equal the cached
            // metadata (permission changes included), and the cached digest must
            // equal the expected entry's digest.
            if ce.meta.mode != cur.mode
                || ce.meta.mtime_nanos != cur.mtime_nanos
                || ce.meta.size != cur.size
                || ce.meta.inode != cur.inode
            {
                return Err("modification detected (metadata differs from cache)".to_string());
            }
            if ce.digest != want_digest {
                return Err("modification detected (digest differs from expected)".to_string());
            }
            Ok(())
        }
        None => {
            // No cache entry: verify by size + full re-hash.
            if cur.size != expected.size {
                return Err("modification detected (size differs from expected)".to_string());
            }
            match hash_file(path, cur.size) {
                Ok(d) if d == want_digest => Ok(()),
                Ok(_) => Err("modification detected (re-hash differs from expected)".to_string()),
                Err(e) => Err(format!("re-hash failed: {e}")),
            }
        }
    }
}

/// Local mirror of the four stat fields we compare (kept local so the cache
/// comparison reads field-by-field against the prior CacheEntry).
struct FileMetaNow {
    mode: u32,
    mtime_nanos: i64,
    size: u64,
    inode: u64,
}

/// Remove one on-disk entry, but ONLY after verifying it still matches `expected`
/// (mutagen removeFile / removeSymbolicLink semantics). On any mismatch the entry is
/// left untouched and `VerificationMismatch` is returned.
///
/// Symlinks: the LINK is removed, never its target. Untracked/Problematic entries
/// are never transitioned, so removing them is refused by construction.
pub fn remove_verified(
    path: &Path,
    rel: &RelPath,
    expected: &Entry,
    cache: &CacheMap,
) -> Result<(), ApplyError> {
    match expected.kind {
        EntryKind::File => {
            verify_file(path, rel, expected, cache).map_err(|r| verification_mismatch(rel, r))?;
            // RACE: between verification and removal the content could change —
            // inherent to filesystem APIs (mutagen removeFile carries the same
            // comment); worst case is removing content modified inside this window.
            fs::remove_file(path).map_err(|e| io_err(rel, e))
        }
        EntryKind::SymbolicLink => {
            // Re-read the raw target and compare (mutagen ensureExpectedSymbolicLink).
            match fs::read_link(path) {
                Ok(cur) => {
                    let same = cur
                        .to_str()
                        .map(|t| Some(t) == expected.target.as_deref())
                        .unwrap_or(false);
                    if !same {
                        return Err(verification_mismatch(
                            rel,
                            "symlink target changed since the baseline scan",
                        ));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(verification_mismatch(rel, "content missing at delete time"))
                }
                Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                    return Err(verification_mismatch(
                        rel,
                        "on-disk type changed (expected symbolic link)",
                    ))
                }
                Err(e) => return Err(io_err(rel, e)),
            }
            // RACE: same verify-vs-remove window as files. remove_file unlinks the
            // LINK itself — it never follows to the target.
            fs::remove_file(path).map_err(|e| io_err(rel, e))
        }
        EntryKind::Directory => {
            // A bare directory removal (children already gone). Whole-tree removal
            // goes through remove_tree_verified.
            match fs::symlink_metadata(path) {
                Ok(m) if m.file_type().is_dir() => {
                    let _ = m.mode(); // mode of directories is not enforced (§8: umask/setgid model)
                }
                Ok(_) => {
                    return Err(verification_mismatch(
                        rel,
                        "on-disk type changed (expected directory)",
                    ))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(verification_mismatch(rel, "content missing at delete time"))
                }
                Err(e) => return Err(io_err(rel, e)),
            }
            fs::remove_dir(path).map_err(|e| io_err(rel, e))
        }
        // Never transitioned (plan §2): the reconciler must not plan their removal.
        EntryKind::Untracked | EntryKind::Problematic => Err(verification_mismatch(
            rel,
            format!("refusing to delete a {:?} entry — untracked content is never transitioned", expected.kind),
        )),
    }
}

/// Recursively remove a directory tree, verifying every removal (mutagen
/// removeDirectory). Two passes over the ON-DISK listing:
///
/// 1. validate: every on-disk name (minus our own `.sync-agent-tmp-*` artifacts)
///    must exist in `expected_dir.children` — any straggler ABORTS the whole
///    removal before anything is deleted (never silently nuked);
/// 2. remove: children first (directories recurse), each through
///    `remove_verified`; finally the (now empty) directory itself.
///
/// `rel` is the tree-relative path of `root_path` (cache keys are RelPaths).
pub fn remove_tree_verified(
    root_path: &Path,
    rel: &RelPath,
    expected_dir: &Entry,
    cache: &CacheMap,
) -> Result<(), ApplyError> {
    // The tree root itself must still be a real directory.
    match fs::symlink_metadata(root_path) {
        Ok(m) if m.file_type().is_dir() => {
            let _ = m.mode();
        }
        Ok(_) => {
            return Err(verification_mismatch(
                rel,
                "on-disk type changed (expected directory)",
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(verification_mismatch(rel, "content missing at delete time"))
        }
        Err(e) => return Err(io_err(rel, e)),
    }

    // PASS 1 — read the on-disk listing and validate names. Deliberately NOT the
    // entry map (mutagen: "we use the on-disk content listing"). Non-UTF-8 names
    // become stragglers via lossy conversion — they can never match an expected
    // key, so they block the removal loudly instead of being skipped. Our own
    // transient artifacts (`.sync-agent-tmp-*`, a leftover `.sync-agent` dir) are
    // collected separately: they are garbage we own, not user data.
    let mut listing: Vec<(String, PathBuf)> = Vec::new();
    let mut our_artifacts: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(root_path).map_err(|e| io_err(rel, e))? {
        let entry = entry.map_err(|e| io_err(rel, e))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_internal_name(&name) {
            our_artifacts.push(entry.path());
            continue;
        }
        listing.push((name, entry.path()));
    }
    for (name, _) in &listing {
        if !expected_dir.children.contains_key(name.as_str()) {
            return Err(verification_mismatch(
                &rel.join(name),
                "untracked straggler blocks tree removal (plan §2: never nuke unknown content)",
            ));
        }
    }

    // Best-effort cleanup of our own artifacts so a crashed apply can never wedge a
    // tree removal. Errors ignored here — if something survives, the final
    // remove_dir fails ENOTEMPTY and the problem surfaces loudly.
    for artifact in &our_artifacts {
        let name = artifact.file_name().unwrap().to_string_lossy().into_owned();
        if name == ".sync-agent" {
            let _ = fs::remove_dir_all(artifact);
        } else {
            let _ = fs::remove_file(artifact);
        }
    }

    // PASS 2 — remove children (directories recurse child-first).
    for (name, child_path) in &listing {
        let child_expected = &expected_dir.children[name.as_str()];
        let child_rel = rel.join(name);
        match child_expected.kind {
            EntryKind::Directory => {
                remove_tree_verified(child_path, &child_rel, child_expected, cache)?
            }
            _ => remove_verified(child_path, &child_rel, child_expected, cache)?,
        }
    }

    // RACE: content created between the listing and this point makes remove_dir fail
    // ENOTEMPTY — surfaced as a problem, never force-removed.
    fs::remove_dir(root_path).map_err(|e| io_err(rel, e))
}

// ---------------------------------------------------------------------------
// Safety halts (mutagen safety.go ports + large-deletion guard)
// ---------------------------------------------------------------------------

/// safety.go `oneEndpointEmptiedRoot` port: exactly one side transitioned from a
/// root with ≥2 immediate children (baseline) to an empty root.
pub fn one_side_root_emptied(
    ancestor: Option<&Entry>,
    alpha: Option<&Entry>,
    beta: Option<&Entry>,
) -> bool {
    let (Some(ancestor), Some(alpha), Some(beta)) = (ancestor, alpha, beta) else {
        return false;
    };
    if ancestor.kind != EntryKind::Directory
        || alpha.kind != EntryKind::Directory
        || beta.kind != EntryKind::Directory
    {
        return false;
    }
    if ancestor.children.len() < 2 {
        return false;
    }
    let alpha_emptied = alpha.children.is_empty();
    let beta_emptied = beta.children.is_empty();
    (alpha_emptied || beta_emptied) && !(alpha_emptied && beta_emptied)
}

/// safety.go `containsRootDeletion` over the planned actions.
pub fn root_deletion_proposed(actions: &[PlannedAction]) -> bool {
    actions
        .iter()
        .any(|a| a.path == RelPath::root() && matches!(a.op, Operation::Remove(_)))
}

/// safety.go `containsRootTypeChange` over a reconciler Change list (integration
/// helper; `types::Change` only — no reconcile dependency).
pub fn root_type_change_in_changes(
    changes: &[crate::types::Change],
) -> bool {
    changes.iter().any(|c| {
        c.path == RelPath::root()
            && matches!(
                (c.old.as_ref().map(|e| e.kind), c.new.as_ref().map(|e| e.kind)),
                (Some(k1), Some(k2)) if k1 != k2
            )
    })
}

/// Root type change in plan form: a root materialization whose kind differs from the
/// baseline root's kind (mutagen compares change.old vs change.new at the root).
fn root_type_changed_in_actions(actions: &[PlannedAction], ancestor_root: Option<&Entry>) -> bool {
    let Some(ancestor) = ancestor_root else {
        return false; // no baseline → the check cannot apply (no-base disables deletes upstream)
    };
    actions.iter().any(|a| {
        a.path == RelPath::root()
            && match &a.op {
                Operation::Materialize(e) => e.kind != ancestor.kind,
                Operation::Remove(_) => false, // covered by RootDeletionProposed
            }
    })
}

/// Total node count of a subtree, including the entry itself.
fn count_tree(entry: &Entry) -> usize {
    let mut n = 1;
    for child in entry.children.values() {
        n += count_tree(child);
    }
    n
}

/// Deletions the plan performs, counted as DISTINCT removed paths: a directory
/// removal weights its whole subtree, and a separate `Remove(d/child)` in the
/// same plan (the driver's type-flip translation emits both) must not
/// double-count what the parent already covers.
fn count_removals(actions: &[PlannedAction]) -> usize {
    let mut rems: Vec<(&RelPath, usize)> = actions
        .iter()
        .filter_map(|a| match &a.op {
            Operation::Remove(e) => Some((&a.path, count_tree(e))),
            _ => None,
        })
        .collect();
    rems.sort_by(|x, y| x.0.as_str().cmp(y.0.as_str()));
    let mut n = 0;
    for (i, (path, weight)) in rems.iter().enumerate() {
        let subsumed = rems[..i].iter().any(|(anc, _)| {
            anc.as_str().is_empty()
                || (path.as_str().len() > anc.as_str().len()
                    && path.as_str().starts_with(&format!("{}/", anc.as_str())))
        });
        if !subsumed {
            n += weight;
        }
    }
    n
}

/// Below this ancestor size the ratio check is skipped: on a 3-entry tree a
/// two-path dir flip IS 67%, and halting every small-tree edit makes the engine
/// unusable. The absolute-count check still protects small trees; the ratio
/// exists for real mass deletion (mutagen has no %-of-tree guard at all — ours
/// is an extra heuristic, plan M1 ">N/>X% requires --force").
const RATIO_MIN_TREE: usize = 32;

/// Large-deletion guard (plan M1): more than `max_deletes` deletions, or a deletion
/// fraction above `max_delete_ratio` of the baseline tree, halts unless forced.
fn deletion_guard(
    actions: &[PlannedAction],
    ctx: &SafetyContext<'_>,
    limits: &SafetyLimits,
) -> Option<HaltReason> {
    let count = count_removals(actions);
    if count == 0 {
        return None;
    }
    let total = match ctx.ancestor_root {
        Some(a) => count_tree(a),
        None => ctx
            .alpha_root
            .map(count_tree)
            .unwrap_or(0)
            .max(ctx.beta_root.map(count_tree).unwrap_or(0)),
    };
    let ratio = if total > 0 {
        count as f64 / total as f64
    } else {
        0.0
    };
    if count > limits.max_deletes
        || (total >= RATIO_MIN_TREE && ratio > limits.max_delete_ratio)
    {
        Some(HaltReason::LargeDeletion { count, ratio })
    } else {
        None
    }
}

/// The safety wrapper — evaluates every halt BEFORE any mutation, in mutagen's
/// order (root deletion → root type change → root emptied), then the large-deletion
/// guard unless `force`.
pub fn check_safety(
    ctx: &SafetyContext<'_>,
    actions: &[PlannedAction],
    limits: &SafetyLimits,
    force: bool,
) -> Result<(), ApplyError> {
    if root_deletion_proposed(actions) {
        return Err(ApplyError::Halted(HaltReason::RootDeletionProposed));
    }
    if root_type_changed_in_actions(actions, ctx.ancestor_root) {
        return Err(ApplyError::Halted(HaltReason::RootTypeChanged));
    }
    if one_side_root_emptied(ctx.ancestor_root, ctx.alpha_root, ctx.beta_root) {
        return Err(ApplyError::Halted(HaltReason::OneSideRootEmptied));
    }
    if !force {
        if let Some(h) = deletion_guard(actions, ctx, limits) {
            return Err(ApplyError::Halted(h));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// apply_plan — provisional executor (integration wires the reconciler here)
// ---------------------------------------------------------------------------

fn side_root<'a>(ctx_path_a: &'a Path, ctx_path_b: &'a Path, side: Side) -> &'a Path {
    match side {
        Side::A => ctx_path_a,
        Side::B => ctx_path_b,
    }
}

/// Execute a reconciler plan against two local roots (v1 bisync: content for a file
/// materialization is read from the peer root; the M2 protocol layer will hand the
/// same primitives a staged-file reader instead). All safety halts run first; on a
/// halt NOTHING is mutated. Per-action failures are recorded in the report and the
/// run continues (best-effort, never silent).
pub fn apply_plan(
    root_a: &Path,
    root_b: &Path,
    actions: &[PlannedAction],
    ctx: &ApplyCtx<'_>,
) -> ApplyReport {
    if let Err(ApplyError::Halted(h)) = check_safety(&ctx.safety, actions, &ctx.limits, ctx.force) {
        return ApplyReport {
            applied: 0,
            deleted: 0,
            failed: 0,
            halted: Some(h.clone()),
            problems: vec![(RelPath::root(), format!("halted before any mutation: {h}"))],
        };
    }

    let mut report = ApplyReport::default();

    // Materializations parent-first (lexicographic puts "a/b" before "a/b/c");
    // removals child-first so directories empty out before their parents.
    let mut materializations: Vec<&PlannedAction> = actions
        .iter()
        .filter(|a| matches!(a.op, Operation::Materialize(_)))
        .collect();
    materializations.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    let mut removals: Vec<&PlannedAction> = actions
        .iter()
        .filter(|a| matches!(a.op, Operation::Remove(_)))
        .collect();
    removals.sort_by(|a, b| b.path.as_str().cmp(a.path.as_str()));

    for action in materializations {
        let Operation::Materialize(entry) = &action.op else {
            unreachable!("filtered above");
        };
        match materialize(root_a, root_b, action.side, &action.path, entry) {
            Ok(()) => report.applied += 1,
            Err(msg) => {
                report.failed += 1;
                report.problems.push((action.path.clone(), msg));
            }
        }
    }
    for action in removals {
        let Operation::Remove(expected) = &action.op else {
            unreachable!("filtered above");
        };
        let base = side_root(root_a, root_b, action.side);
        let fs_path = base.join(action.path.as_str());
        let result = if expected.kind == EntryKind::Directory {
            remove_tree_verified(&fs_path, &action.path, expected, ctx.cache)
        } else {
            remove_verified(&fs_path, &action.path, expected, ctx.cache)
        };
        match result {
            Ok(()) => report.deleted += 1,
            Err(e) => {
                report.failed += 1;
                report.problems.push((action.path.clone(), e.to_string()));
            }
        }
    }

    report
}

fn materialize(
    root_a: &Path,
    root_b: &Path,
    side: Side,
    rel: &RelPath,
    entry: &Entry,
) -> Result<(), String> {
    if rel.as_str().is_empty() {
        return Err("refusing to materialize the root entry itself".to_string());
    }
    let base = side_root(root_a, root_b, side);
    let fs_path = base.join(rel.as_str());
    match entry.kind {
        EntryKind::Directory => {
            // Dirs are created normally — default mode + umask; setgid inheritance
            // on the PVC handles group ownership (plan §8, never chown).
            match fs::create_dir(&fs_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    // Idempotent when it is already the right kind; a type conflict
                    // (file/link where a dir belongs) must be resolved by the
                    // reconciler's removal step first.
                    if fs_path.is_dir() {
                        Ok(())
                    } else {
                        Err(format!("{rel}: type conflict — directory planned over non-directory"))
                    }
                }
                Err(e) => Err(format!("{rel}: {e}")),
            }
        }
        EntryKind::File => {
            // v1 bisync content source: the peer root's live file. RACE: it may
            // change while we read — delete-time verification + the next scan bound
            // the damage; M2 staging removes the window entirely.
            let source = side_root(root_a, root_b, match side {
                Side::A => Side::B,
                Side::B => Side::A,
            })
            .join(rel.as_str());
            let mut file = match fs::File::open(&source) {
                Ok(f) => f,
                Err(e) => {
                    return Err(format!(
                        "{rel}: content source unavailable ({e}) — stage content before applying"
                    ))
                }
            };
            // M6: never rename empty content over a non-empty target (the v1
            // content source is the peer's live file — an empty source is the
            // mid-write scan shape this guard exists for).
            let source_len = file.metadata().map(|m| m.len()).unwrap_or(0);
            guard_empty_overwrite(&fs_path, rel, source_len)?;
            atomic_write(&fs_path, &mut file, entry.mode, entry.executable)
                .map_err(|e| format!("{rel}: {e}"))
        }
        EntryKind::SymbolicLink => {
            let Some(target) = entry.target.as_deref() else {
                return Err(format!("{rel}: symlink entry without a target"));
            };
            create_symlink(target, &fs_path).map_err(|e| format!("{rel}: {e}"))
        }
        // Never materialized (plan §2): these exist only as scan-side markers.
        EntryKind::Untracked | EntryKind::Problematic => Err(format!(
            "{rel}: refusing to materialize a {:?} entry — untracked content is never transitioned",
            entry.kind
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn guard_empty_overwrite_refuses_only_empty_over_nonempty() {
    // M6: the rule matrix — refuse exactly (incoming empty) × (target
    // non-empty file); everything else destroys nothing and passes.
    let td = tempfile::tempdir().unwrap();
    let rel = RelPath::join(&RelPath::root(), "f.txt");
    let target = td.path().join("f.txt");

    // Absent target: creating an empty file is fine.
    assert!(guard_empty_overwrite(&target, &rel, 0).is_ok());

    // Non-empty incoming content: always fine.
    fs::write(&target, b"real").unwrap();
    assert!(guard_empty_overwrite(&target, &rel, 4).is_ok());

    // THE case: empty incoming over a non-empty target.
    let err = guard_empty_overwrite(&target, &rel, 0).unwrap_err();
    assert!(err.contains("EMPTY file") && err.contains("f.txt"), "{err}");

    // Empty-over-empty: nothing to destroy.
    fs::write(&target, b"").unwrap();
    assert!(guard_empty_overwrite(&target, &rel, 0).is_ok());

    // A directory at the target path is not file content to destroy.
    let dir_target = td.path().join("d");
    fs::create_dir(&dir_target).unwrap();
    assert!(guard_empty_overwrite(&dir_target, &rel, 0).is_ok());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CacheEntry, Digest, FileMeta};
    use std::collections::BTreeMap;

    fn file_entry(digest: Option<Digest>, executable: bool, mode: u32, size: u64) -> Entry {
        Entry {
            kind: EntryKind::File,
            children: BTreeMap::new(),
            digest,
            executable,
            target: None,
            mode,
            size,
            problem: None,
        }
    }

    fn symlink_entry(target: &str) -> Entry {
        Entry {
            kind: EntryKind::SymbolicLink,
            children: BTreeMap::new(),
            digest: Some(blake3::hash(target.as_bytes()).into()),
            executable: false,
            target: Some(target.to_string()),
            mode: 0o777,
            size: 0,
            problem: None,
        }
    }

    fn dir_entry(children: BTreeMap<String, Entry>) -> Entry {
        Entry::directory(children)
    }

    fn digest_of(bytes: &[u8]) -> Digest {
        blake3::hash(bytes).into()
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o7777
    }

    fn mat(side: Side, path: &str, entry: Entry) -> PlannedAction {
        PlannedAction {
            side,
            path: RelPath(path.to_string()),
            op: Operation::Materialize(entry),
        }
    }

    fn rem(side: Side, path: &str, entry: Entry) -> PlannedAction {
        PlannedAction {
            side,
            path: RelPath(path.to_string()),
            op: Operation::Remove(entry),
        }
    }

    fn ctx(cache: &CacheMap) -> ApplyCtx<'_> {
        ApplyCtx {
            cache,
            force: false,
            limits: SafetyLimits::default(),
            safety: SafetyContext::none(),
        }
    }

    // ----- atomic_write -----

    #[test]
    fn atomic_write_round_trip_overwrite_and_modes() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("nested/out.bin");

        // Round-trip with parents auto-created.
        let payload = b"hello sync".repeat(1000);
        atomic_write(&target, &mut payload.as_slice(), 0o640, false).unwrap();
        assert_eq!(fs::read(&target).unwrap(), payload);
        assert_eq!(mode_of(&target), 0o640);

        // Executable propagation: x-where-r (0o640 → 0o750).
        atomic_write(&target, &mut b"v2".as_slice(), 0o640, true).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"v2");
        assert_eq!(mode_of(&target), 0o750);

        // Non-executable strips exec bits (0o755 → 0o644).
        atomic_write(&target, &mut b"v3".as_slice(), 0o755, false).unwrap();
        assert_eq!(mode_of(&target), 0o644);

        // Overwrite keeps the atomic path: exactly one file in the directory tree.
        atomic_write(&target, &mut b"final".as_slice(), 0o600, false).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"final");
        let mut on_disk: Vec<String> = Vec::new();
        for e in walk_all(dir.path()) {
            on_disk.push(e.file_name().unwrap().to_string_lossy().into_owned());
        }
        on_disk.sort();
        assert_eq!(on_disk, vec!["nested".to_string(), "out.bin".to_string()]);
    }

    /// Tiny recursive listing helper for tests (no ignore-crate dependency needed).
    fn walk_all(root: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        fn rec(dir: &Path, out: &mut Vec<PathBuf>) {
            if let Ok(rd) = fs::read_dir(dir) {
                for e in rd.flatten() {
                    out.push(e.path());
                    if e.path().is_dir() {
                        rec(&e.path(), out);
                    }
                }
            }
        }
        rec(root, &mut out);
        out
    }

    #[test]
    fn atomic_write_replaces_symlink_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data.txt");
        fs::write(&data, b"original").unwrap();
        let link = dir.path().join("alias");
        std::os::unix::fs::symlink("data.txt", &link).unwrap();

        // Writing over a symlink replaces the LINK, leaving the target untouched.
        atomic_write(&link, &mut b"new".as_slice(), 0o644, false).unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_file());
        assert_eq!(fs::read(&data).unwrap(), b"original");
    }

    // ----- set_mode -----

    #[test]
    fn set_mode_propagates_and_strips_exec_only() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("script.sh");
        fs::write(&f, b"#!/bin/sh").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();

        set_mode(&f, true).unwrap();
        assert_eq!(mode_of(&f), 0o755);

        set_mode(&f, false).unwrap();
        assert_eq!(mode_of(&f), 0o644);

        // Read-only group: exec-where-r only (0o440 → 0o550).
        fs::set_permissions(&f, fs::Permissions::from_mode(0o440)).unwrap();
        set_mode(&f, true).unwrap();
        assert_eq!(mode_of(&f), 0o550);
    }

    // ----- symlinks -----

    #[test]
    fn symlink_create_replace_delete_link_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target_file = dir.path().join("target.txt");
        fs::write(&target_file, b"payload").unwrap();
        let link = dir.path().join("link");

        // Create.
        create_symlink("target.txt", &link).unwrap();
        assert_eq!(
            fs::read_link(&link).unwrap().to_str().unwrap(),
            "target.txt"
        );

        // Replace (retarget) atomically.
        create_symlink("elsewhere", &link).unwrap();
        assert_eq!(fs::read_link(&link).unwrap().to_str().unwrap(), "elsewhere");

        // Delete via remove_verified: the LINK disappears, the target is untouched —
        // and a retargeted link no longer matches the baseline, so it refuses first.
        fs::remove_file(&link).unwrap();
        create_symlink("target.txt", &link).unwrap();
        let stale = rem(
            Side::A,
            "link",
            symlink_entry("elsewhere"), // baseline says the link pointed elsewhere
        );
        let err = remove_verified(&link, &RelPath("link".into()), stale.op_expected(), &CacheMap::new())
            .unwrap_err();
        assert!(matches!(err, ApplyError::VerificationMismatch { .. }));
        assert!(fs::symlink_metadata(&link).is_ok());

        // Matching baseline → deletes the link, never the target file.
        let ok = rem(Side::A, "link", symlink_entry("target.txt"));
        remove_verified(&link, &RelPath("link".into()), ok.op_expected(), &CacheMap::new())
            .unwrap();
        assert!(fs::symlink_metadata(&link).is_err());
        assert_eq!(fs::read(&target_file).unwrap(), b"payload");
    }

    impl PlannedAction {
        /// Test convenience: pull the expected entry out of a Remove action.
        fn op_expected(&self) -> &Entry {
            match &self.op {
                Operation::Remove(e) => e,
                Operation::Materialize(e) => e,
            }
        }
    }

    // ----- remove_verified -----

    fn cache_with(rel: &str, path: &Path) -> CacheMap {
        let meta = fs::symlink_metadata(path).unwrap();
        let mut cache = CacheMap::new();
        cache.insert(
            RelPath(rel.to_string()),
            CacheEntry {
                meta: FileMeta {
                    mode: meta.mode() & 0o7777,
                    mtime_nanos: meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
                    size: meta.len(),
                    inode: meta.ino(),
                },
                digest: digest_of(&fs::read(path).unwrap()),
            },
        );
        cache
    }

    fn expected_file(path: &Path) -> Entry {
        let meta = fs::symlink_metadata(path).unwrap();
        file_entry(
            Some(digest_of(&fs::read(path).unwrap())),
            meta.mode() & 0o111 != 0,
            meta.mode() & 0o7777,
            meta.len(),
        )
    }

    #[test]
    fn remove_verified_cache_hit_and_rehash_paths() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("gone.txt");
        fs::write(&f, b"delete me").unwrap();

        // Cache-hit path: untouched file, cache matches → removed.
        let cache = cache_with("gone.txt", &f);
        remove_verified(
            &f,
            &RelPath("gone.txt".into()),
            &expected_file(&f),
            &cache,
        )
        .unwrap();
        assert!(!f.exists());

        // Re-hash path (empty cache): still verifies content before removing.
        fs::write(&f, b"delete me too").unwrap();
        remove_verified(
            &f,
            &RelPath("gone.txt".into()),
            &expected_file(&f),
            &CacheMap::new(),
        )
        .unwrap();
        assert!(!f.exists());
    }

    #[test]
    fn remove_verified_refuses_on_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("precious.txt");
        fs::write(&f, b"original content").unwrap();

        // Cache-based verification: append changes size → refuse, file survives.
        let cache = cache_with("precious.txt", &f);
        let expected = expected_file(&f);
        {
            use std::io::Write;
            let mut fh = fs::OpenOptions::new().append(true).open(&f).unwrap();
            fh.write_all(b" plus drift").unwrap();
        }
        let err = remove_verified(&f, &RelPath("precious.txt".into()), &expected, &cache)
            .unwrap_err();
        assert!(matches!(err, ApplyError::VerificationMismatch { .. }));
        assert!(f.exists(), "mismatched file must NOT be deleted");
        assert_eq!(fs::read(&f).unwrap(), b"original content plus drift");

        // Re-hash-based verification (empty cache): content swap → refuse.
        fs::write(&f, b"totally different").unwrap();
        let err = remove_verified(&f, &RelPath("precious.txt".into()), &expected, &CacheMap::new())
            .unwrap_err();
        assert!(matches!(err, ApplyError::VerificationMismatch { .. }));
        assert!(f.exists());

        // Missing content at delete time is also a loud mismatch, not a silent Ok.
        let ghost = dir.path().join("vanished.txt");
        let ghost_entry = file_entry(Some(digest_of(b"x")), false, 0o644, 1);
        let err =
            remove_verified(&ghost, &RelPath("vanished.txt".into()), &ghost_entry, &cache)
                .unwrap_err();
        assert!(matches!(err, ApplyError::VerificationMismatch { .. }));
    }

    #[test]
    fn remove_verified_refuses_untracked_and_problematic() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("pipe");
        for kind in [EntryKind::Untracked, EntryKind::Problematic] {
            let e = Entry {
                kind,
                ..Entry::untracked()
            };
            let err = remove_verified(&f, &RelPath("pipe".into()), &e, &CacheMap::new()).unwrap_err();
            assert!(matches!(err, ApplyError::VerificationMismatch { .. }));
        }
    }

    // ----- remove_tree_verified -----

    #[test]
    fn remove_tree_straggler_aborts_before_any_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path().join("top");
        fs::create_dir_all(top.join("nested")).unwrap();
        fs::write(top.join("a.txt"), b"a").unwrap();
        fs::write(top.join("nested").join("b.txt"), b"b").unwrap();
        fs::write(top.join("surprise.txt"), b"not in the plan").unwrap();

        // Expected entry WITHOUT the straggler (the reconciler's view).
        let mut nested_children = BTreeMap::new();
        let b_entry = expected_file(&top.join("nested").join("b.txt"));
        nested_children.insert("b.txt".to_string(), b_entry);
        let mut children = BTreeMap::new();
        children.insert("a.txt".to_string(), expected_file(&top.join("a.txt")));
        children.insert("nested".to_string(), dir_entry(nested_children));
        let expected_top = dir_entry(children);

        let err = remove_tree_verified(&top, &RelPath("top".into()), &expected_top, &CacheMap::new())
            .unwrap_err();
        assert!(matches!(err, ApplyError::VerificationMismatch { .. }));

        // Two-pass discipline: NOTHING was deleted before the abort.
        assert!(top.join("a.txt").exists());
        assert!(top.join("nested").join("b.txt").exists());
        assert!(top.join("surprise.txt").exists());

        // After the straggler is acknowledged, the removal completes.
        fs::remove_file(top.join("surprise.txt")).unwrap();
        remove_tree_verified(&top, &RelPath("top".into()), &expected_top, &CacheMap::new())
            .unwrap();
        assert!(!top.exists());
    }

    #[test]
    fn remove_tree_nested_dirs_children_first() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path().join("top");
        fs::create_dir_all(top.join("x/y")).unwrap();
        fs::write(top.join("x/y/deep.txt"), b"d").unwrap();
        fs::write(top.join("x/mid.txt"), b"m").unwrap();

        let mut y_children = BTreeMap::new();
        y_children.insert("deep.txt".to_string(), expected_file(&top.join("x/y/deep.txt")));
        let mut x_children = BTreeMap::new();
        x_children.insert("y".to_string(), dir_entry(y_children));
        x_children.insert("mid.txt".to_string(), expected_file(&top.join("x/mid.txt")));
        let mut children = BTreeMap::new();
        children.insert("x".to_string(), dir_entry(x_children));
        let expected_top = dir_entry(children);

        remove_tree_verified(&top, &RelPath("top".into()), &expected_top, &CacheMap::new())
            .unwrap();
        assert!(!top.exists());
    }

    #[test]
    fn remove_tree_ignores_own_temp_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let top = dir.path().join("top");
        fs::create_dir_all(&top).unwrap();
        fs::write(top.join("a.txt"), b"a").unwrap();
        // A crashed apply left a temp file behind: it must not block the removal.
        fs::write(top.join(".sync-agent-tmp-99-deadbeef"), b"junk").unwrap();

        let mut children = BTreeMap::new();
        children.insert("a.txt".to_string(), expected_file(&top.join("a.txt")));
        let expected_top = dir_entry(children);

        remove_tree_verified(&top, &RelPath("top".into()), &expected_top, &CacheMap::new())
            .unwrap();
        assert!(!top.exists());
    }

    // ----- safety halts -----

    fn root_with_names(names: &[&str]) -> Entry {
        let mut children = BTreeMap::new();
        for n in names {
            children.insert(
                n.to_string(),
                file_entry(Some(digest_of(n.as_bytes())), false, 0o644, 1),
            );
        }
        dir_entry(children)
    }

    #[test]
    fn halt_one_side_root_emptied() {
        let ancestor = root_with_names(&["a", "b"]);
        let emptied = root_with_names(&[]);
        let intact = root_with_names(&["a", "b"]);

        // Exactly one side emptied a ≥2-child root → halt.
        let ctx = SafetyContext {
            ancestor_root: Some(&ancestor),
            alpha_root: Some(&emptied),
            beta_root: Some(&intact),
        };
        assert!(one_side_root_emptied(Some(&ancestor), Some(&emptied), Some(&intact)));

        // Both sides emptied (legitimate convergence) → no halt.
        assert!(!one_side_root_emptied(Some(&ancestor), Some(&emptied), Some(&emptied)));

        // Baseline with a single child → check does not apply (mutagen threshold).
        let one = root_with_names(&["a"]);
        assert!(!one_side_root_emptied(Some(&one), Some(&emptied), Some(&one)));

        // Missing snapshots → check does not apply.
        assert!(!one_side_root_emptied(None, Some(&emptied), Some(&intact)));

        // And through check_safety, the halt fires before anything else would run.
        let actions: Vec<PlannedAction> = Vec::new();
        let limits = SafetyLimits::default();
        let err = check_safety(&ctx, &actions, &limits, false).unwrap_err();
        assert!(matches!(err, ApplyError::Halted(HaltReason::OneSideRootEmptied)));
    }

    #[test]
    fn halt_root_deletion_and_type_change() {
        let ancestor = root_with_names(&["a", "b"]);
        let actions = vec![rem(Side::A, "", root_with_names(&[]))];
        let err =
            check_safety(&SafetyContext::none(), &actions, &SafetyLimits::default(), false)
                .unwrap_err();
        assert!(matches!(err, ApplyError::Halted(HaltReason::RootDeletionProposed)));

        // Root type change: materializing a FILE over the directory root.
        let actions = vec![mat(
            Side::A,
            "",
            file_entry(Some(digest_of(b"x")), false, 0o644, 1),
        )];
        let ctx = SafetyContext {
            ancestor_root: Some(&ancestor),
            alpha_root: None,
            beta_root: None,
        };
        let err = check_safety(&ctx, &actions, &SafetyLimits::default(), false).unwrap_err();
        assert!(matches!(err, ApplyError::Halted(HaltReason::RootTypeChanged)));

        // Same-kind root materialization is fine (content refresh at root is not a
        // type change — though apply_plan itself refuses to touch the root).
        let actions = vec![mat(Side::A, "", root_with_names(&["a", "b"]))];
        check_safety(&ctx, &actions, &SafetyLimits::default(), false).unwrap();
    }

    #[test]
    fn halt_root_type_change_in_changes_list() {
        use crate::types::Change;
        let changes = vec![Change {
            path: RelPath::root(),
            old: Some(root_with_names(&["a"])),
            new: Some(file_entry(Some(digest_of(b"x")), false, 0o644, 1)),
        }];
        assert!(root_type_change_in_changes(&changes));

        let same_kind = vec![Change {
            path: RelPath::root(),
            old: Some(root_with_names(&["a"])),
            new: Some(root_with_names(&["b"])),
        }];
        assert!(!root_type_change_in_changes(&same_kind));
    }

    #[test]
    fn halt_large_deletion_guard_and_force_bypass() {
        // 10-file tree; deleting all 10 trips both the count and ratio limits.
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let mut actions = Vec::new();
        let mut ancestor_children = BTreeMap::new();
        for i in 0..10 {
            let name = format!("f{i:02}.txt");
            let p = dir_a.path().join(&name);
            fs::write(&p, format!("content {i}")).unwrap();
            actions.push(rem(Side::A, &name, expected_file(&p)));
            ancestor_children.insert(
                name.clone(),
                file_entry(Some(digest_of(format!("content {i}").as_bytes())), false, 0o644, 0),
            );
        }
        // Baseline snapshot: root + 10 children → tree total 11 → ratio 10/11.
        let ancestor = dir_entry(ancestor_children);
        let limits = SafetyLimits {
            max_deletes: 5,
            max_delete_ratio: 0.4,
        };
        let mut cache = CacheMap::new();
        for i in 0..10 {
            let name = format!("f{i:02}.txt");
            let p = dir_a.path().join(&name);
            cache.extend(cache_with(&name, &p));
        }
        let apply_ctx = ApplyCtx {
            cache: &cache,
            force: false,
            limits,
            safety: SafetyContext {
                ancestor_root: Some(&ancestor),
                alpha_root: None,
                beta_root: None,
            },
        };

        // Halted BEFORE any mutation: nothing was deleted.
        let report = apply_plan(dir_a.path(), dir_b.path(), &actions, &apply_ctx);
        assert_eq!(
            report.halted,
            Some(HaltReason::LargeDeletion {
                count: 10,
                ratio: 10.0 / 11.0,
            })
        );
        assert_eq!(report.deleted, 0);
        for i in 0..10 {
            assert!(dir_a.path().join(format!("f{i:02}.txt")).exists());
        }

        // force bypasses the guard and the deletions run.
        let forced = ApplyCtx {
            cache: &cache,
            force: true,
            limits,
            safety: SafetyContext {
                ancestor_root: Some(&ancestor),
                alpha_root: None,
                beta_root: None,
            },
        };
        let report = apply_plan(dir_a.path(), dir_b.path(), &actions, &forced);
        assert_eq!(report.halted, None);
        assert_eq!(report.deleted, 10);
        assert_eq!(report.failed, 0);
        for i in 0..10 {
            assert!(!dir_a.path().join(format!("f{i:02}.txt")).exists());
        }
    }

    // ----- apply_plan end-to-end -----

    #[test]
    fn apply_plan_end_to_end_materialize_and_remove() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();

        fs::write(a.path().join("keep.txt"), b"keep me").unwrap();
        fs::write(a.path().join("old.txt"), b"old").unwrap();
        fs::create_dir_all(a.path().join("sub")).unwrap();
        fs::write(a.path().join("sub").join("note.txt"), b"note").unwrap();
        std::os::unix::fs::symlink("keep.txt", a.path().join("link")).unwrap();
        fs::set_permissions(a.path().join("keep.txt"), fs::Permissions::from_mode(0o750)).unwrap();

        let mut cache = CacheMap::new();
        cache.extend(cache_with("keep.txt", &a.path().join("keep.txt")));
        cache.extend(cache_with("old.txt", &a.path().join("old.txt")));

        let mut sub_children = BTreeMap::new();
        sub_children.insert(
            "note.txt".to_string(),
            file_entry(Some(digest_of(b"note")), false, 0o644, 4),
        );
        let actions = vec![
            mat(Side::B, "sub", dir_entry(sub_children.clone())),
            mat(
                Side::B,
                "keep.txt",
                file_entry(Some(digest_of(b"keep me")), true, 0o750, 7),
            ),
            mat(Side::B, "link", symlink_entry("keep.txt")),
            mat(
                Side::B,
                "sub/note.txt",
                file_entry(Some(digest_of(b"note")), false, 0o644, 4),
            ),
            rem(Side::A, "old.txt", expected_file(&a.path().join("old.txt"))),
        ];

        let apply_ctx = ApplyCtx {
            cache: &cache,
            force: false,
            limits: SafetyLimits::default(),
            safety: SafetyContext::none(),
        };
        let report = apply_plan(a.path(), b.path(), &actions, &apply_ctx);
        assert_eq!(report.halted, None);
        assert_eq!(report.applied, 4, "report: {report:?}");
        assert_eq!(report.deleted, 1);
        assert_eq!(report.failed, 0, "report: {report:?}");

        // Disk state on side B.
        assert_eq!(fs::read(b.path().join("keep.txt")).unwrap(), b"keep me");
        assert_eq!(mode_of(&b.path().join("keep.txt")), 0o750);
        assert!(b.path().join("sub").join("note.txt").is_file());
        assert_eq!(
            fs::read_link(b.path().join("link")).unwrap().to_str().unwrap(),
            "keep.txt"
        );
        // Disk state on side A.
        assert!(!a.path().join("old.txt").exists());
        assert!(a.path().join("keep.txt").exists());

        // Temp artifacts never linger.
        let leftovers: Vec<String> = walk_all(b.path())
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".sync-agent-tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temps: {leftovers:?}");
    }

    #[test]
    fn apply_plan_reports_per_path_failures_never_silent() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        // Materialize a file whose content source does not exist on the peer →
        // recorded as a failed action with its path, run continues.
        let actions = vec![
            mat(
                Side::B,
                "ghost.txt",
                file_entry(Some(digest_of(b"x")), false, 0o644, 1),
            ),
            mat(
                Side::B,
                "real.txt",
                file_entry(Some(digest_of(b"real")), false, 0o644, 4),
            ),
        ];
        fs::write(a.path().join("real.txt"), b"real").unwrap();
        let empty = CacheMap::new();
        let apply_ctx = ctx(&empty);
        let report = apply_plan(a.path(), b.path(), &actions, &apply_ctx);
        assert_eq!(report.applied, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].0, RelPath("ghost.txt".into()));
        assert!(b.path().join("real.txt").exists());
    }
}
