//! The M1 offline bisync driver: scan → 3-way reconcile → safety → apply → archive.
//!
//! Wires the six engine modules into one callable unit. v1 policy (plan §"v1
//! simplifications" #4): TwoWaySafe + newest-wins-with-conflict-copy, no config surface.
//!
//! ## Flow
//! 1. Merge ignore rules (`extra_ignores` + `.syncignore` from both roots).
//! 2. Load the pair archive (`archive::Archive::load`) — missing/corrupt/foreign ⇒
//!    **safe no-base** (`trust_base = false`, no deletes can be produced).
//! 3. Scan both roots with prior caches (quick-check warm path), flatten.
//! 4. `reconcile::reconcile` on the two live trees vs the ancestor.
//! 5. Translate `(path, Action)` into executable `PlannedAction`s. Type-flips get a
//!    remove-first pair, because `apply_plan` runs materializations before removals.
//! 6. Conflicts:
//!    - opaque content (Untracked/Problematic) on either side, or dir/symlink
//!      involvement ⇒ **left untouched and reported** (`conflicts_left`) — never a
//!      destructive auto-pick (the whole point of copia's arbitration);
//!    - file-vs-file ⇒ newest-wins by cached mtime (lstat fallback; deterministic
//!      side-A fallback when neither is available). The loser's content is copied to
//!      `<name>.sync-conflict-<epoch>-<side>` on BOTH roots before the winner
//!      propagates — conflict copies are data preservation, not metadata.
//! 7. `apply::check_safety` on the MERGED plan before anything mutates (a halt ⇒ zero
//!    mutation, zero conflict copies). Then two `apply_plan` phases: removals, then
//!    materializations.
//! 8. Archive is saved ONLY on full success (no halt, zero failures, no
//!    `conflicts_left`) AND after a post-apply re-scan proves both sides converged
//!    on all synchronizable content. Ancestor = that re-scan, so our own writes are
//!    never invisible to the next run (mutagen stale-scan self-inversion guard).
//!    Caches persist every non-dry-run regardless (a cache validates digests, never
//!    sync state).
//!
//! RACE (v1, documented): file content is read from the peer root at materialize
//! time and roots may change mid-apply. Delete-time verification plus the
//! next run's re-scan bound the damage; M2 staging removes the window.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::apply::{
    check_safety, apply_plan, ApplyCtx, ApplyError, HaltReason, Operation, PlannedAction,
    SafetyContext, SafetyLimits, Side,
};
use crate::archive::{Archive, ArchiveState};
use crate::cache::{from_bytes, to_bytes, CacheMap};
use crate::reconcile::{is_unsynchronizable, reconcile, same};
use crate::scan::{load_syncignore, scan_with_cache, to_flat, IgnoreRules};
use crate::types::{Entry, EntryKind, FlatTree, RelPath, Snapshot};

/// Driver knobs. Defaults match plan v1: no force, no dry-run, no extra ignores,
/// mutagen-scale deletion guard (10k files / 50% of the tree).
#[derive(Debug, Clone, Default)]
pub struct DriverConfig {
    /// State dir (archive + caches). Default: `<root_a>/.sync-agent` (skipped by
    /// the scanner at any depth — `scan::is_internal_name`).
    pub state_dir: Option<PathBuf>,
    /// Bypass the large-deletion guard (mutagen `--force` semantics).
    pub force: bool,
    /// Plan only: scan, reconcile, safety-check, classify conflicts — mutate nothing,
    /// write no state.
    pub dry_run: bool,
    /// Extra ignore patterns merged over both roots' `.syncignore` files.
    pub extra_ignores: Vec<String>,
    pub limits: SafetyLimits,
}

/// Outcome of one bisync run — never silent: every not-done thing is accounted for.
#[derive(Debug, Clone, PartialEq)]
pub struct BisyncReport {
    pub trust_base: bool,
    pub dry_run: bool,
    pub planned_removes: usize,
    pub planned_materializes: usize,
    pub applied: u64,
    pub deleted: u64,
    pub failed: u64,
    pub halted: Option<HaltReason>,
    /// File conflicts auto-resolved newest-wins (loser preserved as conflict copy).
    pub conflicts_resolved: Vec<RelPath>,
    /// Conflicts left for manual resolution (opaque content or dir/symlink
    /// involvement). While non-empty, the archive is NOT saved — the next run
    /// re-reports them instead of silently propagating one side.
    pub conflicts_left: Vec<RelPath>,
    pub archive_saved: bool,
    pub problems: Vec<(RelPath, String)>,
}

/// Run one bidirectional sync pass between two LOCAL roots (v1 offline engine; the
/// M2 transport layer calls this same unit per endpoint pair).
pub fn bisync(root_a: &Path, root_b: &Path, cfg: &DriverConfig) -> io::Result<BisyncReport> {
    let state_dir = cfg
        .state_dir
        .clone()
        .unwrap_or_else(|| root_a.join(".sync-agent"));

    // ---- rules -------------------------------------------------------------
    let mut patterns = cfg.extra_ignores.clone();
    patterns.extend(load_syncignore(root_a)?);
    patterns.extend(load_syncignore(root_b)?);
    let rules = IgnoreRules::new(patterns);

    // ---- state -------------------------------------------------------------
    let archive = Archive::load(root_a, root_b, &state_dir)?;
    let trust_base = archive.is_some();
    let base_flat: FlatTree = match &archive {
        Some(state) => to_flat(&state.ancestor),
        None => FlatTree::new(),
    };
    let prior_a = load_cache(&state_dir, "cache-a.bin");
    let prior_b = load_cache(&state_dir, "cache-b.bin");

    let mut report = BisyncReport {
        trust_base,
        dry_run: cfg.dry_run,
        planned_removes: 0,
        planned_materializes: 0,
        applied: 0,
        deleted: 0,
        failed: 0,
        halted: None,
        conflicts_resolved: Vec::new(),
        conflicts_left: Vec::new(),
        archive_saved: false,
        problems: Vec::new(),
    };
    for rejected in rules.rejected() {
        report
            .problems
            .push((RelPath::root(), format!("rejected ignore pattern: {rejected}")));
    }

    // ---- scan both sides ---------------------------------------------------
    let (snap_a, fresh_a) = scan_with_cache(root_a, &prior_a, &rules)?;
    let (snap_b, fresh_b) = scan_with_cache(root_b, &prior_b, &rules)?;
    let flat_a = to_flat(&snap_a);
    let flat_b = to_flat(&snap_b);

    // ---- reconcile ---------------------------------------------------------
    let raw = reconcile(&flat_a, &flat_b, &base_flat, trust_base);

    // ---- translate to executable actions -----------------------------------
    // Remove expectations come from the SNAPSHOT trees (full children): the flat
    // form strips directory children, and remove_tree_verified verifies on-disk
    // listing against expected.children — a stripped expectation would abort every
    // real tree removal as "stragglers" (integration contract with apply.rs).
    let ancestor_snap: Option<&Snapshot> = archive.as_ref().map(|s| &s.ancestor);
    let mut removes: Vec<PlannedAction> = Vec::new();
    let mut materials: Vec<PlannedAction> = Vec::new();
    // Conflict copies: (loser side, loser rel path, loser entry) — written after the
    // safety check passes, BEFORE the plan executes (the winner's propagation would
    // otherwise overwrite the loser's content irrecoverably).
    let mut conflict_copies: Vec<(Side, RelPath, Entry)> = Vec::new();

    for (path, action) in raw {
        match action {
            crate::types::Action::Noop | crate::types::Action::ConvergeIdentical => {}
            crate::types::Action::PropagateAtoB => {
                translate_propagate(
                    Side::B,
                    &path,
                    snapshot_entry(&snap_a, &path),
                    snapshot_entry(&snap_b, &path),
                    &mut removes,
                    &mut materials,
                    &mut report,
                );
            }
            crate::types::Action::PropagateBtoA => {
                translate_propagate(
                    Side::A,
                    &path,
                    snapshot_entry(&snap_b, &path),
                    snapshot_entry(&snap_a, &path),
                    &mut removes,
                    &mut materials,
                    &mut report,
                );
            }
            crate::types::Action::DeleteA => {
                push_verified_remove(
                    Side::A,
                    &path,
                    ancestor_snap.and_then(|s| snapshot_entry(s, &path)),
                    snapshot_entry(&snap_a, &path),
                    &mut removes,
                    &mut report,
                );
            }
            crate::types::Action::DeleteB => {
                push_verified_remove(
                    Side::B,
                    &path,
                    ancestor_snap.and_then(|s| snapshot_entry(s, &path)),
                    snapshot_entry(&snap_b, &path),
                    &mut removes,
                    &mut report,
                );
            }
            crate::types::Action::Conflict => {
                resolve_conflict(
                    root_a,
                    root_b,
                    &path,
                    &fresh_a,
                    &fresh_b,
                    &flat_a,
                    &flat_b,
                    &snap_a,
                    &snap_b,
                    &mut removes,
                    &mut materials,
                    &mut conflict_copies,
                    &mut report,
                );
            }
        }
    }
    report.planned_removes = removes.len();
    report.planned_materializes = materials.len();

    // ---- safety (BEFORE any mutation, including conflict copies) ------------
    let ancestor_root = archive.as_ref().map(|s| deep_root(&s.ancestor));
    let alpha_root = deep_root(&snap_a);
    let beta_root = deep_root(&snap_b);
    let sctx = SafetyContext {
        ancestor_root: ancestor_root.as_ref(),
        alpha_root: Some(&alpha_root),
        beta_root: Some(&beta_root),
    };
    let mut merged = removes.clone();
    merged.extend(materials.clone());
    if let Err(ApplyError::Halted(h)) = check_safety(&sctx, &merged, &cfg.limits, cfg.force) {
        report.halted = Some(h);
        return Ok(report); // zero mutation, zero state writes
    }

    if cfg.dry_run {
        return Ok(report);
    }

    // ---- conflict copies (loser preserved on both roots) --------------------
    for (loser, rel, entry) in &conflict_copies {
        if let Err(msg) = write_conflict_copies(root_a, root_b, loser, rel, entry) {
            report.failed += 1;
            report.problems.push((rel.clone(), msg));
        }
    }

    // ---- apply: removals first (type flips), then materializations ----------
    // Empty verification cache: forces remove_verified to re-hash the on-disk
    // content against the expected entry — a union map would risk validating a
    // path against the WRONG side's metadata. Cost is bounded by the deletion
    // guard (default 10k paths).
    let empty_cache = CacheMap::new();
    let ctx = ApplyCtx {
        cache: &empty_cache,
        force: cfg.force,
        limits: cfg.limits,
        safety: SafetyContext {
            ancestor_root: ancestor_root.as_ref(),
            alpha_root: None,
            beta_root: None,
        },
    };
    if !removes.is_empty() {
        let r = apply_plan(root_a, root_b, &removes, &ctx);
        accumulate(&mut report, &r);
    }
    if !materials.is_empty() {
        let r = apply_plan(root_a, root_b, &materials, &ctx);
        accumulate(&mut report, &r);
    }

    // ---- persist caches (valid regardless of sync success) ------------------
    save_cache(&state_dir, "cache-a.bin", &fresh_a);
    save_cache(&state_dir, "cache-b.bin", &fresh_b);

    // ---- archive (only on proven full convergence) --------------------------
    if report.failed == 0 && report.halted.is_none() && report.conflicts_left.is_empty() {
        let (snap_a2, fresh_a2) = scan_with_cache(root_a, &fresh_a, &rules)?;
        let (snap_b2, fresh_b2) = scan_with_cache(root_b, &fresh_b, &rules)?;
        let divergences = synchronizable_divergences(&to_flat(&snap_a2), &to_flat(&snap_b2));
        if divergences.is_empty() {
            let state = ArchiveState {
                format_version: crate::archive::FORMAT_VERSION,
                root_pair_hash: Archive::root_pair_hash(root_a, root_b),
                ancestor: snap_a2,
            };
            match state.save(&state_dir) {
                Ok(()) => report.archive_saved = true,
                Err(e) => report
                    .problems
                    .push((RelPath::root(), format!("archive save failed: {e}"))),
            }
            save_cache(&state_dir, "cache-a.bin", &fresh_a2);
            save_cache(&state_dir, "cache-b.bin", &fresh_b2);
        } else {
            report.problems.push((
                RelPath::root(),
                format!(
                    "post-apply verification found {} divergent path(s) — archive not updated",
                    divergences.len()
                ),
            ));
            for d in divergences.iter().take(10) {
                report.problems.push((d.clone(), "still divergent after apply".into()));
            }
        }
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn accumulate(report: &mut BisyncReport, r: &crate::apply::ApplyReport) {
    report.applied += r.applied;
    report.deleted += r.deleted;
    report.failed += r.failed;
    if report.halted.is_none() {
        report.halted = r.halted.clone();
    }
    report.problems.extend(r.problems.iter().cloned());
}

fn load_cache(state_dir: &Path, name: &str) -> CacheMap {
    std::fs::read(state_dir.join(name))
        .ok()
        .and_then(|bytes| from_bytes(&bytes).ok())
        .unwrap_or_default() // corrupt/missing cache = cold scan, never unsafe
}

/// Write `name` into the state dir via temp+rename (reconstructible data, but
/// keep the same atomic discipline as everything else).
fn save_cache(state_dir: &Path, name: &str, cache: &CacheMap) {
    if std::fs::create_dir_all(state_dir).is_err() {
        return;
    }
    let tmp = state_dir.join(format!("{name}.tmp"));
    if std::fs::write(&tmp, to_bytes(cache)).is_ok() {
        let _ = std::fs::rename(&tmp, state_dir.join(name));
    }
}

/// Root `Entry` for the safety halts AND the deletion-guard denominator:
/// FULL depth (deep clone). `count_tree` on a stripped/shallow root would
/// undercount the ancestor tree and inflate the deletion ratio — the guard is
/// only as good as this denominator. Cost: one deep clone per side per run
/// (the 200k bench measures scan, not the driver; acceptable in M1).
fn deep_root(snap: &Snapshot) -> Entry {
    Entry::directory(snap.root.clone())
}

/// Full-children entry lookup in a Snapshot by root-relative path (the flat form
/// strips directory children; delete-time tree verification needs them).
fn snapshot_entry<'a>(snap: &'a Snapshot, path: &RelPath) -> Option<&'a Entry> {
    let mut cur: &std::collections::BTreeMap<String, Entry> = &snap.root;
    let mut found: Option<&Entry> = None;
    for seg in path.as_str().split('/') {
        if seg.is_empty() {
            continue; // root path
        }
        found = cur.get(seg);
        match found {
            Some(e) if e.kind == EntryKind::Directory => cur = &e.children,
            Some(_) => cur = &EMPTY_CHILDREN,
            None => return None,
        }
    }
    found
}

static EMPTY_CHILDREN: std::collections::BTreeMap<String, Entry> = std::collections::BTreeMap::new();

/// Propagate `src` entry to `dst_side`: remove-first when the flip involves a
/// directory on either side (files/links replace each other atomically via
/// rename; a dir must be emptied and removed first).
fn translate_propagate(
    dst_side: Side,
    path: &RelPath,
    src: Option<&Entry>,
    dst_cur: Option<&Entry>,
    removes: &mut Vec<PlannedAction>,
    materials: &mut Vec<PlannedAction>,
    report: &mut BisyncReport,
) {
    let Some(entry) = src.cloned() else {
        report.problems.push((
            path.clone(),
            "internal: propagation source missing from live tree".into(),
        ));
        report.failed += 1;
        return;
    };
    if let Some(cur) = dst_cur {
        let dir_involved = cur.kind == EntryKind::Directory || entry.kind == EntryKind::Directory;
        // Remove-first only for a dir flip: files/links replace each other
        // atomically via rename; a dir must be emptied and removed first.
        if dir_involved && cur.kind != entry.kind {
            removes.push(PlannedAction {
                side: dst_side,
                path: path.clone(),
                op: Operation::Remove(cur.clone()),
            });
        }
    }
    materials.push(PlannedAction {
        side: dst_side,
        path: path.clone(),
        op: Operation::Materialize(entry),
    });
}

/// Delete with a verifiable expectation: prefer the ancestor entry (DeleteX means
/// the surviving side equals base), falling back to the live tree's entry. Both
/// candidates arrive from SNAPSHOT lookups (full directory children — see the
/// translation block above).
fn push_verified_remove(
    side: Side,
    path: &RelPath,
    base_expect: Option<&Entry>,
    live_expect: Option<&Entry>,
    removes: &mut Vec<PlannedAction>,
    report: &mut BisyncReport,
) {
    let expected = base_expect.or(live_expect).cloned();
    let Some(expected) = expected else {
        report.problems.push((
            path.clone(),
            "internal: deletion without base or live expectation — skipped".into(),
        ));
        report.failed += 1;
        return;
    };
    removes.push(PlannedAction {
        side,
        path: path.clone(),
        op: Operation::Remove(expected),
    });
}

/// v1 conflict policy (documented in the module docs): opaque content or
/// dir/symlink involvement ⇒ report and leave; file-vs-file ⇒ newest-wins with
/// conflict copy of the loser on both roots.
#[allow(clippy::too_many_arguments)]
fn resolve_conflict(
    root_a: &Path,
    root_b: &Path,
    path: &RelPath,
    fresh_a: &CacheMap,
    fresh_b: &CacheMap,
    flat_a: &FlatTree,
    flat_b: &FlatTree,
    snap_a: &Snapshot,
    snap_b: &Snapshot,
    removes: &mut Vec<PlannedAction>,
    materials: &mut Vec<PlannedAction>,
    conflict_copies: &mut Vec<(Side, RelPath, Entry)>,
    report: &mut BisyncReport,
) {
    let a = flat_a.get(path);
    let b = flat_b.get(path);
    let opaque = [a, b]
        .into_iter()
        .flatten()
        .any(is_unsynchronizable)
        || a.is_some_and(|e| e.kind == EntryKind::Directory)
        || b.is_some_and(|e| e.kind == EntryKind::Directory)
        || a.is_some_and(|e| e.kind == EntryKind::SymbolicLink)
        || b.is_some_and(|e| e.kind == EntryKind::SymbolicLink);
    if opaque {
        report.conflicts_left.push(path.clone());
        return;
    }
    // file-vs-file (both sides present — Conflict never fires on single presence)
    let (Some(ea), Some(eb)) = (a, b) else {
        report.conflicts_left.push(path.clone());
        return;
    };
    let ma = entry_mtime(root_a, path, fresh_a);
    let mb = entry_mtime(root_b, path, fresh_b);
    // newest wins; deterministic side-A fallback when neither mtime is known
    let winner = match (ma, mb) {
        (Some(x), Some(y)) if y > x => Side::B,
        (Some(x), Some(y)) if x > y => Side::A,
        _ => Side::A,
    };
    let (loser_side, loser_entry) = match winner {
        Side::A => (Side::B, eb),
        Side::B => (Side::A, ea),
    };
    // Loser content preserved BEFORE the winner's propagation overwrites it.
    conflict_copies.push((loser_side, path.clone(), loser_entry.clone()));
    // Winner propagates to the loser side (file-over-file: plain materialize;
    // winner entry from its full snapshot for consistency).
    let winner_entry = match winner {
        Side::A => snapshot_entry(snap_a, path),
        Side::B => snapshot_entry(snap_b, path),
    };
    translate_propagate(
        loser_side,
        path,
        winner_entry,
        Some(loser_entry),
        removes,
        materials,
        report,
    );
    report.conflicts_resolved.push(path.clone());
}

/// mtime for newest-wins: cache first (scan-fresh), then lstat, else None.
fn entry_mtime(root: &Path, path: &RelPath, cache: &CacheMap) -> Option<i64> {
    if let Some(c) = cache.get(path) {
        return Some(c.meta.mtime_nanos);
    }
    let md = std::fs::symlink_metadata(root.join(path.as_str())).ok()?;
    let st = md.modified().ok()?;
    st.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as i64)
}

/// Copy the loser's file to `<name>.sync-conflict-<epoch>-<side>` on BOTH roots.
/// Reads at execution time (post-safety-check), from the loser's root.
fn write_conflict_copies(
    root_a: &Path,
    root_b: &Path,
    loser: &Side,
    rel: &RelPath,
    entry: &Entry,
) -> Result<(), String> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tag = match loser {
        Side::A => "a",
        Side::B => "b",
    };
    let leaf = format!("{}.sync-conflict-{epoch}-{tag}", rel.leaf());
    let copy_rel = match rel.parent() {
        Some(p) => p.join(&leaf),
        None => RelPath(leaf),
    };
    let source = match loser {
        Side::A => root_a,
        Side::B => root_b,
    }
    .join(rel.as_str());
    for root in [root_a, root_b] {
        let dst = root.join(copy_rel.as_str());
        // FRESH handle per destination: a try_clone fd SHARES the file offset —
        // the second read would start at EOF and write an empty copy (caught by
        // the driver's conflict-copy integration test).
        let mut f = std::fs::File::open(&source)
            .map_err(|e| format!("conflict copy source {}: {e}", rel))?;
        crate::apply::atomic_write(&dst, &mut f, entry.mode, entry.executable)
            .map_err(|e| format!("conflict copy {}: {e}", copy_rel))?;
    }
    Ok(())
}

/// Cheap in-memory convergence proof: after a fully successful apply, both sides
/// must agree on every synchronizable entry (Untracked/Problematic content may
/// legitimately differ — it never transitions).
fn synchronizable_divergences(fa: &FlatTree, fb: &FlatTree) -> Vec<RelPath> {
    let keys: BTreeSet<&RelPath> = fa.keys().chain(fb.keys()).collect();
    let mut out = Vec::new();
    for k in keys {
        match (fa.get(k), fb.get(k)) {
            (Some(x), Some(y)) => {
                if !same(x, y) && !is_unsynchronizable(x) && !is_unsynchronizable(y) {
                    out.push(k.clone());
                }
            }
            (Some(e), None) | (None, Some(e)) => {
                if !is_unsynchronizable(e) && !k.as_str().is_empty() {
                    out.push(k.clone());
                }
            }
            (None, None) => {}
        }
    }
    out
}

// ---------------------------------------------------------------------------
// tests — the WIRING (modules are unit-tested in their own files)
// ---------------------------------------------------------------------------
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::apply::HaltReason;
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    fn mkfifo(path: &Path) {
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }

    /// Set an explicit mtime (newest-wins tests need controlled ordering).
    fn set_mtime(path: &Path, epoch_secs: u64) {
        let f = std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap();
        f.set_times(
            std::fs::FileTimes::new()
                .set_modified(UNIX_EPOCH + Duration::from_secs(epoch_secs)),
        )
        .unwrap();
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.retain(|n| n != ".sync-agent");
        v.sort();
        v
    }

    #[test]
    fn first_sync_propagates_and_converges() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("a.txt"), "alpha");
        write_file(&a.join("sub/inner.txt"), "inner");

        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert!(!r.trust_base, "first sync runs safe no-base");
        assert_eq!(r.applied, 3, "a.txt + sub + sub/inner.txt");
        assert_eq!(r.failed, 0);
        assert!(r.conflicts_left.is_empty());
        assert!(r.archive_saved);
        assert_eq!(read(&b.join("a.txt")), "alpha");
        assert_eq!(read(&b.join("sub/inner.txt")), "inner");

        // second run: full no-op, archive refreshed
        let r2 = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert!(r2.trust_base, "second run trusts the archive");
        assert_eq!(r2.applied, 0);
        assert_eq!(r2.deleted, 0);
        assert_eq!(r2.failed, 0);
        assert!(r2.archive_saved);
    }

    #[test]
    fn modify_propagates_next_run() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("f.txt"), "v1");
        bisync(&a, &b, &DriverConfig::default()).unwrap();

        write_file(&a.join("f.txt"), "v2");
        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert_eq!(r.applied, 1, "v1->v2 propagated a->b");
        assert_eq!(read(&b.join("f.txt")), "v2");
        assert!(r.archive_saved);
    }

    #[test]
    fn delete_propagates_with_base_evidence() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("keep.txt"), "k");
        write_file(&a.join("gone.txt"), "g");
        bisync(&a, &b, &DriverConfig::default()).unwrap();

        // B deletes gone.txt while A is unchanged -> delete propagates to A
        std::fs::remove_file(b.join("gone.txt")).unwrap();
        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert_eq!(r.deleted, 1, "delete B->A with base evidence");
        assert!(!a.join("gone.txt").exists(), "A's copy deleted");
        assert!(!b.join("gone.txt").exists());
        assert_eq!(read(&a.join("keep.txt")), "k");
        assert!(r.archive_saved);
    }

    #[test]
    fn file_conflict_newest_wins_with_conflict_copy() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("f.txt"), "base");
        bisync(&a, &b, &DriverConfig::default()).unwrap();

        // both sides diverge; B is NEWER (controlled mtimes, not sleep races)
        write_file(&a.join("f.txt"), "older edit");
        set_mtime(&a.join("f.txt"), 1_000);
        write_file(&b.join("f.txt"), "newer edit");
        set_mtime(&b.join("f.txt"), 2_000);

        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert_eq!(r.conflicts_resolved.len(), 1);
        assert!(r.conflicts_left.is_empty());
        assert!(r.archive_saved, "file conflicts resolve -> full convergence");
        // winner (B) converged on both sides
        assert_eq!(read(&a.join("f.txt")), "newer edit");
        assert_eq!(read(&b.join("f.txt")), "newer edit");
        // loser (A) preserved as a conflict copy on BOTH roots
        let copies = names(&a).into_iter().filter(|n| n.contains("f.txt.sync-conflict")).count();
        assert_eq!(copies, 1, "conflict copy next to winner on A");
        let copies_b = names(&b).into_iter().filter(|n| n.contains("f.txt.sync-conflict")).count();
        assert_eq!(copies_b, 1, "conflict copy next to winner on B");
        assert!(read(&a.join(names(&a).into_iter().find(|n| n.contains(".sync-conflict")).unwrap())).contains("older edit"));
    }

    #[test]
    fn opaque_conflict_left_untouched_blocks_archive() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        mkfifo(&a.join("x")); // opaque on A
        write_file(&b.join("x"), "a real file"); // synchronizable on B

        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert_eq!(r.conflicts_left, vec![RelPath("x".into())]);
        assert!(r.conflicts_resolved.is_empty());
        assert!(!r.archive_saved, "left conflicts must block the archive");
        assert_eq!(r.failed, 0, "left conflict is a report, not a failure");
        // nothing transitioned: fifo intact, file intact
        let md = a.join("x").symlink_metadata().unwrap();
        assert_eq!(
            md.mode() & libc::S_IFMT,
            libc::S_IFIFO,
            "fifo untouched by the run"
        );
        assert_eq!(read(&b.join("x")), "a real file");
    }

    #[test]
    fn one_side_root_emptied_halts_before_mutation() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("one.txt"), "1");
        write_file(&a.join("two.txt"), "2");
        bisync(&a, &b, &DriverConfig::default()).unwrap();

        // A wipes everything: one-sided root emptying (ancestor had >=2 children)
        std::fs::remove_file(a.join("one.txt")).unwrap();
        std::fs::remove_file(a.join("two.txt")).unwrap();
        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert_eq!(
            r.halted,
            Some(HaltReason::OneSideRootEmptied),
            "safety.go oneEndpointEmptiedRoot"
        );
        assert_eq!(r.applied + r.deleted, 0, "halt = zero mutation");
        assert!(!r.archive_saved);
        assert_eq!(read(&b.join("one.txt")), "1", "B untouched");
        assert_eq!(read(&b.join("two.txt")), "2");
    }

    #[test]
    fn large_deletion_guard_halts_and_force_bypasses() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        for n in ["one", "two", "three"] {
            write_file(&a.join(format!("{n}.txt")), n);
        }
        bisync(&a, &b, &DriverConfig::default()).unwrap();

        // B deletes two of three -> plan deletes 2 on A; guard allows only 1
        std::fs::remove_file(b.join("one.txt")).unwrap();
        std::fs::remove_file(b.join("two.txt")).unwrap();
        let cfg = DriverConfig {
            limits: SafetyLimits { max_deletes: 1, max_delete_ratio: 0.9 },
            ..DriverConfig::default()
        };
        let r = bisync(&a, &b, &cfg).unwrap();
        assert!(matches!(
            r.halted,
            Some(HaltReason::LargeDeletion { count: 2, .. })
        ));
        assert!(a.join("one.txt").exists(), "halt = nothing deleted");

        let r = bisync(&a, &b, &DriverConfig { force: true, ..cfg }).unwrap();
        assert_eq!(r.deleted, 2, "force bypasses the guard");
        assert!(!a.join("one.txt").exists());
        assert!(r.archive_saved);
    }

    #[test]
    fn dry_run_mutates_nothing() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("f.txt"), "content");

        let cfg = DriverConfig { dry_run: true, ..DriverConfig::default() };
        let r = bisync(&a, &b, &cfg).unwrap();
        assert!(r.dry_run);
        assert!(r.planned_materializes >= 1, "plan produced actions");
        assert!(!b.join("f.txt").exists(), "dry run wrote no data");
        assert!(!r.archive_saved);
        assert!(
            !a.join(".sync-agent/archive.bin").exists(),
            "dry run wrote no state"
        );
    }

    #[test]
    fn corrupt_archive_is_safe_no_base() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("a.txt"), "alpha");
        bisync(&a, &b, &DriverConfig::default()).unwrap();

        // corrupt the archive, then diverge: new file ONLY on B
        std::fs::write(a.join(".sync-agent/archive.bin"), b"garbage not bincode").unwrap();
        write_file(&b.join("only_b.txt"), "b side");

        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert!(!r.trust_base, "corrupt archive -> safe no-base");
        assert_eq!(r.deleted, 0, "NoBaseNeverDeletes through the whole driver");
        assert_eq!(read(&a.join("only_b.txt")), "b side", "absence = create");
        assert_eq!(read(&a.join("a.txt")), "alpha", "identical content untouched");
        assert!(r.archive_saved, "clean run re-seeds the archive");
    }

    #[test]
    fn dir_to_file_type_flip_applies() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("d/f1.txt"), "one");
        bisync(&a, &b, &DriverConfig::default()).unwrap();

        // A replaces the dir with a file (remove-first ordering + snapshot
        // expectations must let remove_tree_verified clear B's real children)
        std::fs::remove_dir_all(a.join("d")).unwrap();
        write_file(&a.join("d"), "now a file");

        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert_eq!(r.failed, 0, "type flip must apply cleanly: {:?}", r.problems);
        assert!(b.join("d").is_file(), "B's dir became a file");
        assert_eq!(read(&b.join("d")), "now a file");
        assert!(r.archive_saved);
    }

    #[test]
    fn file_to_dir_type_flip_applies() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("d"), "was a file");
        bisync(&a, &b, &DriverConfig::default()).unwrap();

        std::fs::remove_file(a.join("d")).unwrap();
        write_file(&a.join("d/inner.txt"), "now a dir");

        let r = bisync(&a, &b, &DriverConfig::default()).unwrap();
        assert_eq!(r.failed, 0, "flip must apply cleanly: {:?}", r.problems);
        assert!(b.join("d").is_dir());
        assert_eq!(read(&b.join("d/inner.txt")), "now a dir");
        assert!(r.archive_saved);
    }

    #[test]
    fn ignored_content_is_untracked_and_never_synced() {
        let td = tempfile::tempdir().unwrap();
        let (a, b) = (td.path().join("a"), td.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        write_file(&a.join("keep.txt"), "k");
        write_file(&a.join("node_modules/pkg.js"), "dep");
        write_file(&b.join("b_only.txt"), "b");

        let cfg = DriverConfig {
            extra_ignores: vec!["node_modules".into()],
            ..DriverConfig::default()
        };
        let r = bisync(&a, &b, &cfg).unwrap();
        assert!(!b.join("node_modules").exists(), "ignored content never propagates");
        assert_eq!(read(&b.join("keep.txt")), "k");
        assert_eq!(read(&a.join("b_only.txt")), "b", "no-base create B->A");
        assert_eq!(r.failed, 0);
        assert!(r.archive_saved);
        // map must still SEE the ignored dir (Untracked), not treat it as absent
        let rules = IgnoreRules::new(vec!["node_modules".into()]);
        let (snap, _) = scan_with_cache(&a, &CacheMap::new(), &rules).unwrap();
        let flat = to_flat(&snap);
        assert_eq!(
            flat.get(&RelPath("node_modules".into())).map(|e| e.kind),
            Some(EntryKind::Untracked)
        );
    }
}

