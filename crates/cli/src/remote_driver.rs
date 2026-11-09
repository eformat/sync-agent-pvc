//! One bisync pass between a LOCAL root (side A) and a REMOTE agent root
//! (side B) — the M3 laptop-side driver. It mirrors `sync_core::driver.rs`
//! (the local bisync) flow-for-flow: rules → archive → scans → reconcile →
//! translate → safety → conflict copies → apply → caches → archive-on-proven-
//! convergence. The B-side primitives differ (a protocol session instead of a
//! filesystem); everything else is the same policy with the same tables.
//!
//! ## Side mapping
//! A = local root (full `Snapshot`s available — `scan_with_cache`), B = remote
//! root (flat tree off the wire + the agent's fresh cache bytes). Transition
//! actions for B ride `Session::transition`; A-side actions execute locally
//! through `sync_core::apply` primitives, with file content pulled from the
//! agent (`ReadFile` → digest-verified temp → `atomic_write`).
//!
//! ## Deviations from driver.rs (all deliberate, all documented)
//! 1. **Remote staging**: every B-side `Materialize(File)` is staged BEFORE
//!    `TransitionRun` (the agent materializes from its digest-keyed staging
//!    area — M2 protocol). A staging failure drops that action and counts as
//!    a failure (the agent would only fail it later, with the same report
//!    outcome). Staged digests are deduplicated: identical content transfers
//!    once (the agent consumes staged digests at the end of the run).
//! 2. **Remote directory removals are EXPANDED child-first.** The wire carries
//!    the flat form (children stripped), and the agent's `remove_tree_verified`
//!    validates the on-disk listing against the expected children — a stripped
//!    expectation would abort every real tree removal as "stragglers" (M1
//!    integration lesson 1, remote-side manifestation). A directory removal
//!    becomes: one verified removal per live descendant, then the directory
//!    itself with an empty expectation (its listing is empty by then —
//!    unexpected stragglers still abort the final directory removal loudly).
//! 3. **Safety-count parity**: the expanded removals break
//!    `apply::count_removals`' subsumption assumption (an ancestor Remove
//!    carries full-children weight there; the expanded plan's directory
//!    entries are weight-1). The safety check therefore runs on a GUARD COPY
//!    of the plan whose directory expectations carry their live subtrees
//!    re-attached — the sent plan keeps the stripped (executable) form. Counts
//!    and ratios are then identical to driver.rs's.
//! 4. **Read-side digest gate**: content pulled from the agent must match the
//!    scanned entry's digest (the M2 staging gate, applied to the read
//!    direction). driver.rs blindly copies the peer file; here a digest drift
//!    (remote changed between scan and read) is refused for that path —
//!    propagating drifted content would poison the archive's ancestor digest.
//!    Conflict copies are the exception BY DESIGN: they preserve the CURRENT
//!    loser content (driver.rs reads the live file at execution time too).
//!
//! Never silent: every skipped, failed or left-for-manual thing lands in the
//! report. Dry-run mutates nothing on either side and writes no state.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use sync_core::apply::{
    atomic_write, check_safety, create_symlink, ensure_parents, guard_empty_overwrite,
    remove_tree_verified, remove_verified, ApplyError, HaltReason, Operation, PlannedAction,
    SafetyContext, SafetyLimits, Side,
};
use sync_core::archive::{Archive, ArchiveState, FORMAT_VERSION};
use sync_core::cache::{self, CacheMap};
use sync_core::reconcile::{is_unsynchronizable, reconcile, same};
use sync_core::scan::{load_syncignore, scan_with_cache, to_flat, IgnoreRules};
use sync_core::types::{Action, Entry, EntryKind, FlatTree, RelPath, Snapshot};
use sync_proto::control::{self, ConflictResolution, SyncState};
use sync_proto::messages::{Request, Response, StageResult};
use sync_proto::session::Session;

/// The virtual B-side path for the archive pair hash. The pair hash only needs
/// STABILITY: an absolute constant that does not exist canonicalizes to its
/// literal form (archive.rs falls back on canonicalize failure), so the hash
/// is identical across machines and working directories. Never create this
/// path — it is a name, not a directory.
pub const REMOTE_ENDPOINT: &str = "/sync-agent-pvc-remote";

/// State dir under the local root (scanner-skipped at any depth — the same
/// convention driver.rs uses): archive.bin + cache-a.bin + cache-b.bin.
pub const STATE_DIR_NAME: &str = ".sync-agent";

/// Driver knobs — the same surface as `driver::DriverConfig` minus the state
/// dir override (fixed at `<root>/.sync-agent` so scanner-skipped names line
/// up on both sides).
#[derive(Debug, Clone, Default)]
pub struct RemoteConfig {
    /// Bypass the large-deletion guard (mutagen `--force` semantics).
    pub force: bool,
    /// Plan only: scan both sides, reconcile, safety-check, classify
    /// conflicts — mutate nothing anywhere, write no state.
    pub dry_run: bool,
    /// Extra ignore patterns merged over both roots' `.syncignore` files.
    pub extra_ignores: Vec<String>,
    pub limits: SafetyLimits,
    /// Identity of the remote endpoint — goes into the archive pair key so each
    /// sandbox gets its OWN ancestor. A single shared sentinel made a second
    /// sandbox inherit the first one's archive (claiming a remote state that
    /// didn't exist → a mass-deletion plan; the guard caught it, 2026-11-06).
    pub remote_endpoint: String,
    /// Daemon/UI-side resolutions (the operator console on the laptop). Merged
    /// with the sandbox-fetched ControlFetch requests in apply_resolutions;
    /// for the same path, the LOCAL (UI) decision wins — the laptop owns the
    /// data plane, and a UI click is the operator's latest intent. Consumed
    /// once per pass (the daemon drains its pending set before the pass).
    pub local_resolutions: Vec<ConflictResolution>,
    /// Engine state dir override (archive + scan caches). Default:
    /// `<local_root>/.sync-agent` — the daemon overrides with the global
    /// per-pair dir (2026-11-06: "move them to a global top level —
    /// else we will pollute a lot of folders"; synced git repos shouldn't
    /// carry engine state).
    pub state_dir: Option<PathBuf>,
    /// Live progress sink for the UI (the daemon wires one per pass; None in
    /// the CLI/tests). Without it a 655-file/110MB first sync is 2 silent
    /// minutes — 2026-11-09: "looks dead while staging".
    pub progress: Option<ProgressSink>,
}

/// Live pass progress for the UI: which stage the pass is in plus file/byte
/// counters for the transfer-heavy ones. The daemon throttles reports (≥400ms
/// apart, or on a stage flip — the SSE channel hates floods, 2026-11-06) and
/// publishes them into the target snapshot; cleared when the pass ends.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PassProgress {
    /// "connecting" | "scanning" | "staging" | "applying" | "verifying"
    pub stage: String,
    pub files_total: u64,
    pub files_done: u64,
    pub bytes_total: u64,
    pub bytes_done: u64,
}

/// Daemon-side sink for [`PassProgress`] (wired to the target snapshot).
/// Newtype so `RemoteConfig`'s `Debug` derive survives the unnameable closure.
#[derive(Clone)]
pub struct ProgressSink(pub std::sync::Arc<dyn Fn(PassProgress) + Send + Sync>);

impl std::fmt::Debug for ProgressSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProgressSink(<fn>)")
    }
}

/// Report one progress tick (no-op without a sink — CLI/tests).
pub(crate) fn report_progress(
    sink: &Option<ProgressSink>,
    stage: &str,
    files_done: u64,
    files_total: u64,
    bytes_done: u64,
    bytes_total: u64,
) {
    if let Some(s) = sink {
        s.0(PassProgress {
            stage: stage.to_string(),
            files_total,
            files_done,
            bytes_total,
            bytes_done,
        });
    }
}

/// Outcome of one local ⇄ remote bisync run — mirrors `BisyncReport` 1:1.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteReport {
    pub trust_base: bool,
    pub dry_run: bool,
    pub planned_removes: usize,
    pub planned_materializes: usize,
    pub applied: u64,
    pub deleted: u64,
    pub failed: u64,
    pub halted: Option<HaltReason>,
    /// File conflicts auto-resolved newest-wins (loser preserved as a conflict
    /// copy on BOTH sides — see [`sync_local_to_remote`]).
    pub conflicts_resolved: Vec<RelPath>,
    /// Conflicts left for manual resolution. While non-empty the archive is
    /// NOT saved — the next run re-reports instead of silently propagating.
    pub conflicts_left: Vec<RelPath>,
    pub archive_saved: bool,
    /// The remote MCP server had the sync paused — the pass was skipped before
    /// any scan or mutation.
    pub paused: bool,
    /// Control-plane actions the daemon honored this run (resolutions applied,
    /// ignore patterns appended).
    pub honored: Vec<String>,
    pub problems: Vec<(RelPath, String)>,
    /// Resolutions consumed into a plan that was then HALTED by `check_safety`
    /// (zero mutation, zero state writes). The daemon must push these back into
    /// its pending set — a halted pass silently discarding the operator's
    /// decision made UI resolutions "come back as Conflicts" forever
    /// (2026-11-08: the recreated sandbox's empty root halted every pass and
    /// ate every keep-laptop click).
    pub restored_resolutions: Vec<ConflictResolution>,
}

/// Run one bidirectional sync pass: `local_root` (A) ⇄ remote agent root (B).
///
/// # Errors
/// Transport/protocol failures (a session that died mid-exchange) propagate as
/// `io::Error`; per-path failures are recorded in the report instead.
pub fn sync_local_to_remote<S: Read + Write>(
    local_root: &Path,
    session: &mut Session<S>,
    cfg: &RemoteConfig,
) -> io::Result<RemoteReport> {
    if cfg.remote_endpoint.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote_endpoint is empty — the archive pair key must name the remote \
             (a shared sentinel makes sandboxes inherit each other's ancestors)",
        ));
    }
    let remote = &cfg.remote_endpoint;
    let state_dir = cfg
        .state_dir
        .clone()
        .unwrap_or_else(|| local_root.join(STATE_DIR_NAME));

    // ---- control plane (M3.5): the sandbox MCP server's pending requests ---
    // PEEK first: a pause must stay PENDING (unconsumed) so the MCP server's
    // sync_status keeps showing it; only an unpaused session consumes.
    let peek = match session.call(&Request::ControlFetch { consume: false })? {
        Response::ControlPayload { requests } => requests.unwrap_or_default(),
        other => {
            return Err(io::Error::other(format!(
                "control fetch: unexpected response {other:?}"
            )))
        }
    };
    if peek.paused {
        let mut report = RemoteReport {
            trust_base: Archive::load(
                local_root,
                Path::new(&format!("{REMOTE_ENDPOINT}:{remote}")),
                &state_dir,
            )?
            .is_some(),
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
            paused: true,
            honored: Vec::new(),
            problems: Vec::new(),
            restored_resolutions: Vec::new(),
        };
        report.problems.push((
            RelPath::root(),
            "sync is PAUSED by the sandbox agent (sync_resume to unpause) — nothing scanned, nothing mutated"
                .into(),
        ));
        return Ok(report);
    }
    // Not paused: consume (fetch-and-clear) so honored requests never re-fire.
    // Dry-run only PLANS with the peeked requests — consuming would make the
    // planned honors unrepeatable.
    let requests = if cfg.dry_run {
        peek.clone()
    } else {
        match session.call(&Request::ControlFetch { consume: true })? {
            Response::ControlPayload { requests } => requests.unwrap_or_default(),
            other => {
                return Err(io::Error::other(format!(
                    "control consume: unexpected response {other:?}"
                )))
            }
        }
    };

    // ---- rules (driver.rs: extra + A's + B's .syncignore) ------------------
    // request-controlled patterns apply THIS run; the persistent append to the
    // local .syncignore happens after a successful non-dry-run.
    let mut patterns = cfg.extra_ignores.clone();
    patterns.extend(requests.ignore_add.iter().cloned());
    patterns.extend(load_syncignore(local_root)?);
    let (remote_ignores, remote_ignores_problem) = remote_syncignore(session);
    patterns.extend(remote_ignores);
    let rules = IgnoreRules::new(patterns.clone());

    // ---- state -------------------------------------------------------------
    let archive = Archive::load(
        local_root,
        Path::new(&format!("{REMOTE_ENDPOINT}:{remote}")),
        &state_dir,
    )?;
    let trust_base = archive.is_some();
    let mut base_flat: FlatTree = archive
        .as_ref()
        .map(|s| to_flat(&s.ancestor))
        .unwrap_or_default();
    let prior_a = load_cache(&state_dir, "cache-a.bin");
    // Raw prior-cache bytes for the agent (it parses them; corrupt ⇒ cold scan
    // there — the same safe posture as driver.rs's load_cache).
    let prior_b_bytes = fs::read(state_dir.join("cache-b.bin")).unwrap_or_default();

    let mut report = RemoteReport {
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
        paused: false,
        honored: Vec::new(),
        problems: Vec::new(),
        restored_resolutions: Vec::new(),
    };
    for pattern in &requests.ignore_add {
        report.honored.push(format!(
            "ignore_add {pattern} (applies this run; appended to .syncignore after success)"
        ));
    }
    for rejected in rules.rejected() {
        report.problems.push((
            RelPath::root(),
            format!("rejected ignore pattern: {rejected}"),
        ));
    }
    if let Some(msg) = remote_ignores_problem {
        // A remote .syncignore we cannot read must never silently drop its
        // patterns (that would sync data the user believed excluded).
        report.problems.push((RelPath(".syncignore".into()), msg));
    }

    // ---- scan both sides ---------------------------------------------------
    report_progress(&cfg.progress, "scanning", 0, 0, 0, 0);
    let (snap_a, fresh_a) = scan_with_cache(local_root, &prior_a, &rules)?;
    let flat_a = to_flat(&snap_a);
    let scan_b = session.scan(&prior_b_bytes, &patterns)?;
    let flat_b = scan_b.tree;
    let fresh_b = cache::from_bytes(&scan_b.fresh_cache_bytes)?;

    // ---- reconcile (A = local, B = remote) ---------------------------------
    // Control resolutions FIRST: force the winner by adjusting the BASE under
    // each resolved path (keep-local ⇒ base := remote's state there, so the
    // remote counts as changed and the local content propagates; keep-remote ⇒
    // mirror image). Reconcile then produces ordinary per-path actions through
    // the normal machinery — staging, conflict copies, safety, idempotence.
    // Sources: sandbox-fetched ControlFetch requests + the daemon's own UI-side
    // resolutions. Per-path duplicates: LOCAL (UI) wins — the laptop owns the
    // data plane and a UI click is the operator's latest intent (see
    // RemoteConfig.local_resolutions).
    let mut merged: Vec<ConflictResolution> = Vec::new();
    for r in requests
        .resolutions
        .iter()
        .chain(cfg.local_resolutions.iter())
    {
        if let Some(existing) = merged.iter_mut().find(|x| x.path == r.path) {
            *existing = r.clone();
        } else {
            merged.push(r.clone());
        }
    }
    apply_resolutions(&mut base_flat, &flat_a, &flat_b, &merged, &mut report);
    let raw = reconcile(&flat_a, &flat_b, &base_flat, trust_base);

    // ---- translate to executable actions -----------------------------------
    let mut local_removes: Vec<PlannedAction> = Vec::new();
    let mut local_materials: Vec<PlannedAction> = Vec::new();
    let mut remote_actions: Vec<PlannedAction> = Vec::new();
    let mut conflict_jobs: Vec<ConflictJob> = Vec::new();
    let ancestor_snap: Option<&Snapshot> = archive.as_ref().map(|s| &s.ancestor);

    for (path, action) in raw {
        match action {
            Action::Noop | Action::ConvergeIdentical => {}
            Action::PropagateAtoB => {
                // local → remote: the remote gets a transition action; file
                // content is staged later (post-safety), from the local root.
                // dst_cur rides the remote FLAT tree (remote dir removals go
                // through the expansion); src rides the local snapshot.
                translate_propagate(
                    Side::B,
                    &path,
                    snapshot_entry(Some(&snap_a), &path),
                    flat_b.get(&path),
                    &flat_b,
                    &base_flat,
                    &mut local_removes,
                    &mut local_materials,
                    &mut remote_actions,
                    &mut report,
                );
            }
            Action::PropagateBtoA => {
                // remote → local: the local side gets an action whose file
                // content is pulled from the agent at apply time. dst_cur
                // rides the LOCAL snapshot (full children — local dir
                // removals verify against them, driver.rs style).
                translate_propagate(
                    Side::A,
                    &path,
                    flat_b.get(&path),
                    snapshot_entry(Some(&snap_a), &path),
                    &flat_b,
                    &base_flat,
                    &mut local_removes,
                    &mut local_materials,
                    &mut remote_actions,
                    &mut report,
                );
            }
            Action::DeleteA => {
                push_verified_remove_local(
                    &path,
                    ancestor_snap,
                    &snap_a,
                    &mut local_removes,
                    &mut report,
                );
            }
            Action::DeleteB => {
                // Remote deletion: expand directories into child-first
                // cascades (deviation 2); leaf expectations prefer the
                // ancestor like driver.rs's push_verified_remove.
                let expected = base_flat
                    .get(&path)
                    .cloned()
                    .or_else(|| flat_b.get(&path).cloned());
                match expected {
                    Some(entry) => expand_remote_removal(
                        &path,
                        &entry,
                        &flat_b,
                        &base_flat,
                        true,
                        &mut remote_actions,
                    ),
                    None => {
                        report.problems.push((
                            path,
                            "internal: deletion without base or live expectation — skipped".into(),
                        ));
                        report.failed += 1;
                    }
                }
            }
            Action::Conflict => {
                resolve_conflict(
                    local_root,
                    &path,
                    &fresh_a,
                    &fresh_b,
                    &flat_a,
                    &flat_b,
                    &mut local_materials,
                    &mut remote_actions,
                    &mut conflict_jobs,
                    &mut report,
                );
            }
        }
    }
    // A type-flip expansion and a reconciler DeleteB can target the SAME path
    // (A flipped a dir to a file while B's subtree still matches base): the
    // first removal wins — a duplicate would only fail "content missing at
    // delete time". Materialize/Remove pairs at one path (flip halves) are
    // kept intact.
    dedupe_removes(&mut remote_actions);
    dedupe_removes(&mut local_removes);
    report.planned_removes = local_removes.len()
        + remote_actions
            .iter()
            .filter(|a| matches!(a.op, Operation::Remove(_)))
            .count();
    report.planned_materializes = local_materials.len()
        + remote_actions
            .iter()
            .filter(|a| matches!(a.op, Operation::Materialize(_)))
            .count();

    // ---- safety (BEFORE any mutation, including conflict copies) -----------
    // The guard copy re-attaches live subtrees to the expanded remote
    // directory removals so the deletion guard's subtree weights match
    // driver.rs's exactly (deviation 3).
    let ancestor_root = archive.as_ref().map(|s| deep_root(&s.ancestor));
    let alpha_root = deep_root(&snap_a);
    let beta_root = root_entry_from_flat(&flat_b);
    let sctx = SafetyContext {
        ancestor_root: ancestor_root.as_ref(),
        alpha_root: Some(&alpha_root),
        beta_root: Some(&beta_root),
    };
    let mut guard_plan = guard_actions(&remote_actions, &flat_b, &base_flat);
    guard_plan.extend(local_removes.iter().cloned());
    guard_plan.extend(local_materials.iter().cloned());
    if let Err(ApplyError::Halted(h)) = check_safety(&sctx, &guard_plan, &cfg.limits, cfg.force) {
        // The plan halted before anything mutated: the resolutions were baked
        // into the (now discarded) base rewire, and the honored notes would
        // claim drops that never happened. Surface the halt, retract the
        // notes, and hand the resolutions back to the daemon.
        report.honored.clear();
        report.restored_resolutions = merged.clone();
        report.problems.push((
            RelPath::root(),
            format!("sync halted: {h} — nothing was applied this pass; pending conflict resolutions are preserved and will apply once the halt clears"),
        ));
        report.halted = Some(h);
        return Ok(report); // zero mutation, zero state writes — driver.rs
    }

    if cfg.dry_run {
        // Plan-only pass: nothing applied, nothing persisted — the resolutions
        // were consumed into this discarded plan; hand them back so the
        // confirmed (non-dry) pass still honors them.
        report.restored_resolutions = merged.clone();
        return Ok(report);
    }

    // ---- conflict copies (loser preserved on BOTH sides) -------------------
    // Content is read NOW (post-safety, pre-apply) — the winner's propagation
    // would otherwise overwrite the loser irrecoverably. Local copies go
    // through atomic_write; the remote copy is staged here and materialized
    // by the transition plan below.
    let mut stage_jobs: Vec<StageJob> = Vec::new();
    for job in &conflict_jobs {
        match write_conflict_copies(local_root, job, session) {
            Ok(outcome) => {
                // The remote copy materializes from staging (content staged
                // BEFORE the single TransitionRun — the winner's propagation
                // overwrites the live loser file, but the staged copy content
                // is independent of it).
                stage_jobs.push(StageJob {
                    rel: outcome.copy_rel.clone(),
                    digest: outcome.digest,
                    size: outcome.size,
                    mode: outcome.mode,
                    executable: outcome.executable,
                    source: outcome.source,
                    // The temp (if any) must outlive the staging step; it is
                    // removed when the StageJob drops.
                    _temp: outcome._temp,
                });
                remote_actions.push(PlannedAction {
                    side: Side::B,
                    path: outcome.copy_rel,
                    op: Operation::Materialize(Entry {
                        kind: EntryKind::File,
                        children: BTreeMap::new(),
                        digest: Some(outcome.digest),
                        executable: outcome.executable,
                        target: None,
                        mode: outcome.mode,
                        size: outcome.size,
                        problem: None,
                    }),
                });
            }
            Err(msg) => {
                report.failed += 1;
                report.problems.push((job.path.clone(), msg));
            }
        }
    }

    // ---- stage remote file content (deviation 1) ---------------------------
    // Every B-side Materialize(File) needs its content staged before the run;
    // identical digests are staged once (the agent keys its staging area by
    // digest and consumes it after the whole run).
    for action in &remote_actions {
        let Operation::Materialize(entry) = &action.op else {
            continue;
        };
        if entry.kind != EntryKind::File {
            continue;
        }
        let Some(digest) = entry.digest else {
            report.failed += 1;
            report.problems.push((
                action.path.clone(),
                "file entry without digest — cannot stage".into(),
            ));
            continue;
        };
        if stage_jobs.iter().any(|j| j.digest == digest) {
            continue; // identical content — one transfer covers all actions
        }
        stage_jobs.push(StageJob {
            rel: action.path.clone(),
            digest,
            size: entry.size,
            mode: entry.mode,
            executable: entry.executable,
            source: StageSource::LocalFile(local_root.join(action.path.as_str())),
            _temp: None,
        });
    }
    let total_files = stage_jobs.len() as u64;
    let total_bytes: u64 = stage_jobs.iter().map(|j| j.size).sum();
    // Only report when there IS something to stage — a steady-state pass with
    // zero jobs must not flash a progress row for 400ms.
    if total_files > 0 {
        report_progress(&cfg.progress, "staging", 0, total_files, 0, total_bytes);
    }
    let mut staged_files: u64 = 0;
    let mut staged_bytes: u64 = 0;
    for job in &stage_jobs {
        match stage_to_remote(session, job) {
            Ok(()) => {
                staged_files += 1;
                staged_bytes += job.size;
            }
            Err(msg) => {
                // Drop every Materialize that referenced this digest: the agent
                // would only fail them ("content not staged") — the same report
                // outcome, one clear problem instead of several vague ones.
                let affected: Vec<RelPath> = remote_actions
                    .iter()
                    .filter(|a| {
                        matches!(&a.op, Operation::Materialize(e) if e.kind == EntryKind::File && e.digest == Some(job.digest))
                    })
                    .map(|a| a.path.clone())
                    .collect();
                remote_actions.retain(|a| {
                    !matches!(&a.op, Operation::Materialize(e) if e.kind == EntryKind::File && e.digest == Some(job.digest))
                });
                report.failed += affected.len() as u64;
                for p in affected {
                    report.problems.push((p, format!("stage failed: {msg}")));
                }
            }
        }
        report_progress(
            &cfg.progress,
            "staging",
            staged_files,
            total_files,
            staged_bytes,
            total_bytes,
        );
    }

    // ---- apply: remote transition, then the local two-phase apply ----------
    // Remote first: a protocol failure prevents local mutation entirely
    // (fail fast). The agent re-checks safety with its own knowledge
    // (defense in depth, M2) and runs removals-then-materializations
    // internally — driver.rs's phase order.
    if !remote_actions.is_empty() {
        report_progress(
            &cfg.progress,
            "applying",
            0,
            (remote_actions.len() + local_removes.len() + local_materials.len()) as u64,
            0,
            0,
        );
        match session.transition(&remote_actions, cfg.force) {
            Ok(r) => accumulate(&mut report, &r),
            Err(e) => return Err(e), // session dead — torn-exchange posture
        }
    }

    // Local: removals child-first, then materializations parent-first — the
    // exact phase order of apply_plan (type flips land). Empty verification
    // cache: forces delete-time re-hash, driver.rs's choice.
    let mut sorted_removes = local_removes.clone();
    sorted_removes.sort_by(|a, b| b.path.as_str().cmp(a.path.as_str()));
    for action in &sorted_removes {
        let Operation::Remove(expected) = &action.op else {
            unreachable!("only Remove actions are collected here");
        };
        let fs_path = local_root.join(action.path.as_str());
        let result = if expected.kind == EntryKind::Directory {
            remove_tree_verified(&fs_path, &action.path, expected, &CacheMap::new())
        } else {
            remove_verified(&fs_path, &action.path, expected, &CacheMap::new())
        };
        match result {
            Ok(()) => report.deleted += 1,
            Err(e) => {
                report.failed += 1;
                report.problems.push((action.path.clone(), e.to_string()));
            }
        }
    }
    let mut sorted_materials = local_materials.clone();
    sorted_materials.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    for action in &sorted_materials {
        let Operation::Materialize(entry) = &action.op else {
            unreachable!("only Materialize actions are collected here");
        };
        match materialize_local(local_root, &action.path, entry, session) {
            Ok(()) => report.applied += 1,
            Err(msg) => {
                report.failed += 1;
                report.problems.push((action.path.clone(), msg));
            }
        }
    }

    // ---- persist caches (valid regardless of sync success) -----------------
    save_cache(&state_dir, "cache-a.bin", &cache::to_bytes(&fresh_a));
    save_cache(&state_dir, "cache-b.bin", &scan_b.fresh_cache_bytes);

    // ---- archive (only on proven full convergence) -------------------------
    if report.failed == 0 && report.halted.is_none() && report.conflicts_left.is_empty() {
        report_progress(&cfg.progress, "verifying", 0, 0, 0, 0);
        let (snap_a2, fresh_a2) = scan_with_cache(local_root, &fresh_a, &rules)?;
        let scan_b2 = session.scan(&scan_b.fresh_cache_bytes, &patterns)?;
        let divergences = synchronizable_divergences(&to_flat(&snap_a2), &scan_b2.tree);
        if divergences.is_empty() {
            let state = ArchiveState {
                format_version: FORMAT_VERSION,
                root_pair_hash: Archive::root_pair_hash(
                    local_root,
                    Path::new(&format!("{REMOTE_ENDPOINT}:{remote}")),
                ),
                ancestor: snap_a2,
            };
            match state.save(&state_dir) {
                Ok(()) => report.archive_saved = true,
                Err(e) => report
                    .problems
                    .push((RelPath::root(), format!("archive save failed: {e}"))),
            }
            save_cache(&state_dir, "cache-a.bin", &cache::to_bytes(&fresh_a2));
            save_cache(&state_dir, "cache-b.bin", &scan_b2.fresh_cache_bytes);
        } else {
            report.problems.push((
                RelPath::root(),
                format!(
                    "post-apply verification found {} divergent path(s) — archive not updated",
                    divergences.len()
                ),
            ));
            for d in divergences.iter().take(10) {
                report
                    .problems
                    .push((d.clone(), "still divergent after apply".into()));
            }
        }
    }

    // ---- control-plane persistence (M3.5) ----------------------------------
    // Consumed ignore_add patterns become PERSISTENT (local .syncignore) only
    // after a successful non-dry-run — a failed run must not permanently widen
    // the exclude set. The SyncReport pushes the run's state to the sandbox's
    // MCP server (its sync_status source); failures land in problems, never
    // fail the sync itself.
    if !cfg.dry_run {
        for pattern in &requests.ignore_add {
            match append_syncignore(local_root, pattern) {
                Ok(()) => {}
                Err(e) => report
                    .problems
                    .push((RelPath::root(), format!("ignore_add {pattern}: {e}"))),
            }
        }
        send_sync_report(session, &report, &flat_a);
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// control plane (M3.5)
// ---------------------------------------------------------------------------

/// Force a resolution by adjusting the BASE under `path`: `keep-local` means
/// the remote must become the local version (base := remote's current state →
/// the remote reads as "changed" → PropagateAtoB), `keep-remote` is the mirror.
/// Reconcile then emits ordinary per-path actions — staging, verification, and
/// the deletion guard all still apply. The losing side's divergent content is
/// dropped: an explicit resolution IS the human decision (surfaced in honored).
fn apply_resolutions(
    base: &mut FlatTree,
    local: &FlatTree,
    remote: &FlatTree,
    resolutions: &[ConflictResolution],
    report: &mut RemoteReport,
) {
    for r in resolutions {
        let path = RelPath(r.path.clone());
        if path.as_str().is_empty() || !control::is_valid_choice(&r.choice) {
            report.problems.push((
                path,
                format!("invalid resolution (choice {:?}) — ignored", r.choice),
            ));
            continue;
        }
        let donor = match r.choice.as_str() {
            "keep-local" => remote, // remote must become the local version
            "keep-remote" => local, // local must become the remote version
            other => {
                report.problems.push((
                    path,
                    format!("unknown resolution choice {other:?} — ignored"),
                ));
                continue;
            }
        };
        let keys = subtree_keys(base, &path);
        for k in keys {
            base.remove(&k);
        }
        for (k, e) in subtree_entries(donor, &path) {
            base.insert(k.clone(), e.clone());
        }
        report.honored.push(format!(
            "resolve {} → {} (loser's divergent content dropped)",
            r.path, r.choice
        ));
    }
}

/// `path` itself plus every descendant key (FlatTree string-prefix convention).
fn subtree_keys(tree: &FlatTree, path: &RelPath) -> Vec<RelPath> {
    let prefix = format!("{}/", path.as_str());
    tree.keys()
        .filter(|k| k == &path || k.as_str().starts_with(&prefix))
        .cloned()
        .collect()
}

/// (key, entry) pairs for `path` + descendants, in map order.
fn subtree_entries<'a>(tree: &'a FlatTree, path: &RelPath) -> Vec<(&'a RelPath, &'a Entry)> {
    let prefix = format!("{}/", path.as_str());
    tree.iter()
        .filter(|(k, _)| *k == path || k.as_str().starts_with(&prefix))
        .collect()
}

/// Append a pattern to the local `.syncignore` (persistent honored ignore_add).
/// Duplicates are skipped; the file is created if absent.
fn append_syncignore(root: &Path, pattern: &str) -> io::Result<()> {
    let path = root.join(".syncignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.lines().any(|l| l.trim() == pattern) {
        return Ok(());
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(f, "{pattern}")
}

/// Push the run's state to the sandbox MCP server (`Request::SyncReport`).
/// Never fails the sync: problems land in the report.
fn send_sync_report<S: Read + Write>(
    session: &mut Session<S>,
    report: &RemoteReport,
    flat_a: &FlatTree,
) {
    let conflicts = report
        .conflicts_left
        .iter()
        .map(|p| {
            // Kind from whichever side still has an entry at (or above) the path.
            let kind_of = |e: &Entry| match e.kind {
                EntryKind::Directory => "dir-conflict".to_string(),
                EntryKind::SymbolicLink => "symlink-conflict".to_string(),
                _ => "opaque-conflict".to_string(),
            };
            let kind = flat_a
                .get(p)
                .map(kind_of)
                .or_else(|| {
                    flat_a
                        .iter()
                        .find(|(k, _)| p.as_str().starts_with(&format!("{}/", k.as_str())))
                        .map(|(_, e)| kind_of(e))
                })
                .unwrap_or_else(|| "unknown".to_string());
            control::ConflictInfo {
                path: p.as_str().to_string(),
                kind,
                description: "left for manual resolution — resolve with \
                              sync_resolve_conflict (keep-local | keep-remote)"
                    .to_string(),
            }
        })
        .collect();
    let state = SyncState {
        last_sync_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        paused: false,
        conflicts,
        applied: report.applied,
        deleted: report.deleted,
        failed: report.failed,
        problems: report
            .problems
            .iter()
            .map(|(p, m)| (p.as_str().to_string(), m.clone()))
            .collect(),
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
    };
    match session.call(&Request::SyncReport { state }) {
        Ok(Response::Pong) => {}
        Ok(other) => {
            // send_sync_report takes the report by shared ref (it never fails the
            // sync) — surface a report problem through a channel the caller owns.
            eprintln!(
                "sync: sync report: unexpected response {other:?} (state may be stale in sync_status)"
            );
        }
        Err(e) => {
            eprintln!("sync: sync report failed: {e} (state may be stale in sync_status)");
        }
    }
}

// ---------------------------------------------------------------------------
// translation helpers (driver.rs mirrors)
// ---------------------------------------------------------------------------

fn accumulate(report: &mut RemoteReport, r: &sync_core::apply::ApplyReport) {
    report.applied += r.applied;
    report.deleted += r.deleted;
    report.failed += r.failed;
    if report.halted.is_none() {
        report.halted = r.halted.clone();
    }
    report.problems.extend(r.problems.iter().cloned());
}

fn load_cache(state_dir: &Path, name: &str) -> CacheMap {
    fs::read(state_dir.join(name))
        .ok()
        .and_then(|bytes| cache::from_bytes(&bytes).ok())
        .unwrap_or_default() // corrupt/missing cache = cold scan, never unsafe
}

/// Write `name` into the state dir via temp+rename (driver.rs's discipline).
fn save_cache(state_dir: &Path, name: &str, bytes: &[u8]) {
    if fs::create_dir_all(state_dir).is_err() {
        return;
    }
    let tmp = state_dir.join(format!("{name}.tmp"));
    if fs::write(&tmp, bytes).is_ok() {
        let _ = fs::rename(&tmp, state_dir.join(name));
    }
}

/// Root `Entry` for the safety halts AND the deletion-guard denominator:
/// FULL depth (driver.rs deep_root).
fn deep_root(snap: &Snapshot) -> Entry {
    Entry::directory(snap.root.clone())
}

/// The remote root's `.syncignore`, read through the session (driver.rs merges
/// both roots' files; the remote file is a synced artifact of earlier runs).
/// Returns `(patterns, problem)` — absence is normal, an UNREADABLE file is a
/// reported problem (never a silent pattern drop).
fn remote_syncignore<S: Read + Write>(session: &mut Session<S>) -> (Vec<String>, Option<String>) {
    let (size, digest) = match session.call(&Request::ReadFile {
        path: ".syncignore".into(),
    }) {
        Ok(Response::FileHeader { size, digest, .. }) => (size, digest),
        Ok(other) => {
            return (
                Vec::new(),
                Some(format!(
                    "unexpected response reading .syncignore: {other:?}"
                )),
            )
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("No such file") {
                return (Vec::new(), None); // absent — the normal first-run case
            }
            return (
                Vec::new(),
                Some(format!("unreadable remote .syncignore: {msg}")),
            );
        }
    };
    let mut bytes = Vec::new();
    match session.read_payload_hashed(size, &mut bytes) {
        Ok(d) if d == digest => (),
        Ok(_) => {
            return (
                Vec::new(),
                Some(".syncignore payload failed its digest check — patterns not applied".into()),
            )
        }
        Err(e) => return (Vec::new(), Some(format!(".syncignore read failed: {e}"))),
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect(),
        None,
    )
}

/// Propagate `src` entry to `dst` (driver.rs translate_propagate): remove-first
/// only when the flip involves a directory on either side; files/links replace
/// each other atomically via rename. B-side actions go to `remote_actions`
/// (the transition plan), A-side to `local_removes`/`local_materials`.
#[allow(clippy::too_many_arguments)]
fn translate_propagate(
    dst: Side,
    path: &RelPath,
    src: Option<&Entry>,
    dst_cur: Option<&Entry>,
    flat_b: &FlatTree,
    base_flat: &FlatTree,
    local_removes: &mut Vec<PlannedAction>,
    local_materials: &mut Vec<PlannedAction>,
    remote_actions: &mut Vec<PlannedAction>,
    report: &mut RemoteReport,
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
        if dir_involved && cur.kind != entry.kind {
            match dst {
                Side::B => {
                    // Remote remove-first. A remote directory must be emptied
                    // first (deviation 2 — live expectations, driver.rs uses
                    // the live dst entry here too); a remote file/link is a
                    // single verified removal.
                    if cur.kind == EntryKind::Directory {
                        expand_remote_removal(path, cur, flat_b, base_flat, false, remote_actions);
                    } else {
                        remote_actions.push(PlannedAction {
                            side: Side::B,
                            path: path.clone(),
                            op: Operation::Remove(cur.clone()),
                        });
                    }
                }
                Side::A => {
                    // Local remove-first: the expectation comes from the full
                    // snapshot (children included) for tree verification.
                    local_removes.push(PlannedAction {
                        side: Side::A,
                        path: path.clone(),
                        op: Operation::Remove(cur.clone()),
                    });
                }
            }
        }
    }
    let materialize = PlannedAction {
        side: dst,
        path: path.clone(),
        op: Operation::Materialize(entry),
    };
    if dst == Side::B {
        remote_actions.push(materialize);
    } else {
        local_materials.push(materialize);
    }
}

/// Delete with a verifiable expectation, LOCAL side (driver.rs
/// push_verified_remove): ancestor expectation first, live fallback. Both come
/// from full-children snapshot lookups.
fn push_verified_remove_local(
    path: &RelPath,
    ancestor_snap: Option<&Snapshot>,
    snap_a: &Snapshot,
    removes: &mut Vec<PlannedAction>,
    report: &mut RemoteReport,
) {
    let expected = snapshot_entry(ancestor_snap, path)
        .or_else(|| snapshot_entry(Some(snap_a), path))
        .cloned();
    let Some(expected) = expected else {
        report.problems.push((
            path.clone(),
            "internal: deletion without base or live expectation — skipped".into(),
        ));
        report.failed += 1;
        return;
    };
    removes.push(PlannedAction {
        side: Side::A,
        path: path.clone(),
        op: Operation::Remove(expected),
    });
}

/// Full-children entry lookup in a Snapshot by root-relative path (the flat
/// form strips directory children; delete-time tree verification needs them).
fn snapshot_entry<'a>(snap: Option<&'a Snapshot>, path: &RelPath) -> Option<&'a Entry> {
    let snap = snap?;
    let mut cur: &BTreeMap<String, Entry> = &snap.root;
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

static EMPTY_CHILDREN: BTreeMap<String, Entry> = BTreeMap::new();

/// v1 conflict policy (driver.rs resolve_conflict): opaque content or
/// dir/symlink involvement ⇒ report and leave; file-vs-file ⇒ newest-wins
/// with the loser copied to `<name>.sync-conflict-<epoch>-<side>` on BOTH
/// sides before the winner propagates.
#[allow(clippy::too_many_arguments)]
fn resolve_conflict(
    local_root: &Path,
    path: &RelPath,
    fresh_a: &CacheMap,
    fresh_b: &CacheMap,
    flat_a: &FlatTree,
    flat_b: &FlatTree,
    local_materials: &mut Vec<PlannedAction>,
    remote_actions: &mut Vec<PlannedAction>,
    conflict_jobs: &mut Vec<ConflictJob>,
    report: &mut RemoteReport,
) {
    let a = flat_a.get(path);
    let b = flat_b.get(path);
    let opaque = [a, b].into_iter().flatten().any(is_unsynchronizable)
        || a.is_some_and(|e| e.kind == EntryKind::Directory)
        || b.is_some_and(|e| e.kind == EntryKind::Directory)
        || a.is_some_and(|e| e.kind == EntryKind::SymbolicLink)
        || b.is_some_and(|e| e.kind == EntryKind::SymbolicLink);
    if opaque {
        report.conflicts_left.push(path.clone());
        return;
    }
    // file-vs-file (Conflict never fires on single presence)
    let (Some(ea), Some(eb)) = (a, b) else {
        report.conflicts_left.push(path.clone());
        return;
    };
    let ma = entry_mtime(local_root, path, fresh_a);
    // Remote mtime: from the agent's fresh cache (scan-fresh) — no lstat
    // possible over the wire.
    let mb = fresh_b.get(path).map(|c| c.meta.mtime_nanos);
    // newest wins; deterministic side-A (local) fallback (driver.rs table)
    let winner = match (ma, mb) {
        (Some(x), Some(y)) if y > x => Side::B,
        (Some(x), Some(y)) if x > y => Side::A,
        _ => Side::A,
    };
    let (loser_side, loser_entry) = match winner {
        Side::A => (Side::B, eb),
        Side::B => (Side::A, ea),
    };
    conflict_jobs.push(ConflictJob {
        path: path.clone(),
        loser_side,
        loser_entry: loser_entry.clone(),
    });
    // Winner propagates to the loser side (file-over-file: plain materialize;
    // the winner entry comes from the winner's own scan, driver.rs style).
    let winner_entry = match winner {
        Side::A => flat_a.get(path),
        Side::B => flat_b.get(path),
    };
    if let Some(we) = winner_entry.cloned() {
        let action = PlannedAction {
            side: loser_side,
            path: path.clone(),
            op: Operation::Materialize(we),
        };
        if loser_side == Side::B {
            remote_actions.push(action);
        } else {
            local_materials.push(action);
        }
    }
    report.conflicts_resolved.push(path.clone());
}

/// mtime for newest-wins, LOCAL side: cache first, then lstat, else None
/// (driver.rs entry_mtime).
fn entry_mtime(root: &Path, path: &RelPath, cache: &CacheMap) -> Option<i64> {
    if let Some(c) = cache.get(path) {
        return Some(c.meta.mtime_nanos);
    }
    let md = fs::symlink_metadata(root.join(path.as_str())).ok()?;
    let st = md.modified().ok()?;
    st.duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as i64)
}

// ---------------------------------------------------------------------------
// remote-side primitives (the parts the wire forces to differ)
// ---------------------------------------------------------------------------

/// Copy the loser's file to `<name>.sync-conflict-<epoch>-<side>` on BOTH
/// sides (driver.rs write_conflict_copies semantics, split across the wire):
/// the local copy via `atomic_write`, the remote copy via a StageJob + a
/// Materialize (appended by the caller). Content is the CURRENT loser content
/// (driver.rs reads at execution time — data preservation, not metadata).
fn write_conflict_copies<S: Read + Write>(
    local_root: &Path,
    job: &ConflictJob,
    session: &mut Session<S>,
) -> Result<ConflictCopyOutcome, String> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tag = match job.loser_side {
        Side::A => "a",
        Side::B => "b",
    };
    let leaf = format!("{}.sync-conflict-{epoch}-{tag}", job.path.leaf());
    let copy_rel = match job.path.parent() {
        Some(p) => p.join(&leaf),
        None => RelPath(leaf),
    };

    match job.loser_side {
        Side::A => {
            // Loser is local: local copy from the live file; remote copy
            // staged from the same content (digest = current content hash).
            let source = local_root.join(job.path.as_str());
            let mut f = fs::File::open(&source)
                .map_err(|e| format!("conflict copy source {}: {e}", job.path))?;
            let local_dst = local_root.join(copy_rel.as_str());
            atomic_write(
                &local_dst,
                &mut f,
                job.loser_entry.mode,
                job.loser_entry.executable,
            )
            .map_err(|e| format!("conflict copy {}: {e}", copy_rel))?;
            let (size, digest) = hash_local_file(&source)
                .map_err(|e| format!("conflict copy {}: hashing failed: {e}", copy_rel))?;
            Ok(ConflictCopyOutcome {
                copy_rel,
                digest,
                size,
                mode: job.loser_entry.mode,
                executable: job.loser_entry.executable,
                source: StageSource::LocalFile(source),
                _temp: None,
            })
        }
        Side::B => {
            // Loser is remote: pull the current content once (digest-verified
            // transport), write the LOCAL copy from it, and stage the REMOTE
            // copy from the same bytes. The temp guard rides in the outcome —
            // the temp must outlive the staging step.
            let temp_path = local_root.join(tmp_name());
            let (size, digest) = fetch_remote_to_file(&temp_path, job.path.as_str(), session)?;
            let mut reader = fs::File::open(&temp_path)
                .map_err(|e| format!("conflict copy {}: {e}", copy_rel))?;
            let local_dst = local_root.join(copy_rel.as_str());
            atomic_write(
                &local_dst,
                &mut reader,
                job.loser_entry.mode,
                job.loser_entry.executable,
            )
            .map_err(|e| format!("conflict copy {}: {e}", copy_rel))?;
            drop(reader);
            Ok(ConflictCopyOutcome {
                copy_rel,
                digest,
                size,
                mode: job.loser_entry.mode,
                executable: job.loser_entry.executable,
                source: StageSource::TempFile(temp_path.clone()),
                _temp: Some(TempGuard { path: temp_path }),
            })
        }
    }
}

/// Outcome of one conflict copy: the local side is already written; the
/// remote side rides staging + the transition plan.
struct ConflictCopyOutcome {
    copy_rel: RelPath,
    digest: [u8; 32],
    size: u64,
    mode: u32,
    executable: bool,
    source: StageSource,
    /// Holds the fetched temp alive until staging consumed it.
    _temp: Option<TempGuard>,
}

/// Expand a remote directory removal into child-first per-path removals
/// (deviation 2). Leaf expectations: `prefer_base` mirrors driver.rs —
/// deletions prefer the ancestor entry, type-flip removals use the live entry.
/// Directory expectations are EMPTY: the agent removes children first (it
/// sorts removals child-first), so the on-disk listing is empty by the time
/// the directory itself is removed; any unexpected straggler still aborts
/// that final removal loudly.
fn expand_remote_removal(
    path: &RelPath,
    expected: &Entry,
    live_flat: &FlatTree,
    base_flat: &FlatTree,
    prefer_base: bool,
    out: &mut Vec<PlannedAction>,
) {
    if expected.kind != EntryKind::Directory {
        out.push(PlannedAction {
            side: Side::B,
            path: path.clone(),
            op: Operation::Remove(expected.clone()),
        });
        return;
    }
    let mut victims: Vec<RelPath> = live_flat
        .keys()
        .filter(|p| is_under(p, path) && !p.as_str().is_empty())
        .cloned()
        .collect();
    victims.sort();
    for p in victims {
        let live = live_flat.get(&p).cloned().unwrap_or_else(|| {
            Entry::problematic("expansion: live entry vanished mid-translation")
        });
        let expectation = match live.kind {
            EntryKind::Directory => Entry::directory(BTreeMap::new()),
            _ => {
                if prefer_base {
                    base_flat.get(&p).cloned().unwrap_or(live)
                } else {
                    live
                }
            }
        };
        out.push(PlannedAction {
            side: Side::B,
            path: p,
            op: Operation::Remove(expectation),
        });
    }
    out.push(PlannedAction {
        side: Side::B,
        path: path.clone(),
        op: Operation::Remove(Entry::directory(BTreeMap::new())),
    });
}

/// Strict descendant test (`path` == dir is NOT under).
fn is_under(path: &RelPath, dir: &RelPath) -> bool {
    if dir.as_str().is_empty() {
        return !path.as_str().is_empty();
    }
    path.as_str().len() > dir.as_str().len()
        && path.as_str().starts_with(&format!("{}/", dir.as_str()))
}

/// Keep the FIRST Remove per path (see the dedupe call site for why).
fn dedupe_removes(actions: &mut Vec<PlannedAction>) {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    actions.retain(|a| {
        if matches!(a.op, Operation::Remove(_)) {
            seen.insert(a.path.as_str().to_string())
        } else {
            true
        }
    });
}

/// Guard copy of the plan for `check_safety` (deviation 3): re-attach the live
/// subtree to every expanded directory removal so the deletion guard counts
/// whole subtrees (driver.rs semantics), not weight-1 husks.
fn guard_actions(
    remote_actions: &[PlannedAction],
    live_flat: &FlatTree,
    base_flat: &FlatTree,
) -> Vec<PlannedAction> {
    remote_actions
        .iter()
        .map(|a| {
            let mut a = a.clone();
            if let Operation::Remove(e) = &mut a.op {
                if e.kind == EntryKind::Directory && e.children.is_empty() {
                    e.children = subtree_children(live_flat, &a.path);
                    if e.children.is_empty() {
                        e.children = subtree_children(base_flat, &a.path);
                    }
                }
            }
            a
        })
        .collect()
}

/// Full-children map of `dir`'s subtree from a flat tree (empty when absent).
fn subtree_children(flat: &FlatTree, dir: &RelPath) -> BTreeMap<String, Entry> {
    let mut by_parent: BTreeMap<String, Vec<(String, Entry)>> = BTreeMap::new();
    for (p, e) in flat {
        if !is_under(p, dir) {
            continue;
        }
        let (parent, leaf) = match p.as_str().rsplit_once('/') {
            Some((parent, l)) => (parent.to_string(), l.to_string()),
            None => (String::new(), p.leaf().to_string()),
        };
        by_parent.entry(parent).or_default().push((leaf, e.clone()));
    }
    // The children of `dir` are the entries whose PARENT is dir (the subtree
    // map carries no root-level keys — its keys are dir-prefixed).
    assemble_children(dir.as_str(), &by_parent)
}

/// Assemble one directory's children (recursively) from a parent-grouped flat
/// map — scan.rs's assembly rule: children attach only to real directories.
fn assemble_children(
    dir_rel: &str,
    by_parent: &BTreeMap<String, Vec<(String, Entry)>>,
) -> BTreeMap<String, Entry> {
    let mut out = BTreeMap::new();
    if let Some(children) = by_parent.get(dir_rel) {
        for (leaf, e) in children {
            let mut e = e.clone();
            if e.kind == EntryKind::Directory {
                let child_rel = if dir_rel.is_empty() {
                    leaf.clone()
                } else {
                    format!("{dir_rel}/{leaf}")
                };
                e.children = assemble_children(&child_rel, by_parent);
            }
            out.insert(leaf.clone(), e);
        }
    }
    out
}

/// Rebuild the full-children root `Entry` from a flat tree — scan.rs's
/// assembly rule mirrored: children attach only to real directories.
fn root_entry_from_flat(flat: &FlatTree) -> Entry {
    let mut by_parent: BTreeMap<String, Vec<(String, Entry)>> = BTreeMap::new();
    for (path, e) in flat {
        if path.as_str().is_empty() {
            continue;
        }
        let (parent, leaf) = match path.as_str().rsplit_once('/') {
            Some((p, l)) => (p.to_string(), l.to_string()),
            None => (String::new(), path.leaf().to_string()),
        };
        by_parent.entry(parent).or_default().push((leaf, e.clone()));
    }
    Entry::directory(assemble_children("", &by_parent))
}

/// Cheap in-memory convergence proof (driver.rs synchronizable_divergences):
/// after a fully successful apply, both sides must agree on every
/// synchronizable entry.
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
// staging + local materialization
// ---------------------------------------------------------------------------

/// Content source for one staged upload.
enum StageSource {
    /// A live local file (propagation source or local loser conflict copy).
    LocalFile(PathBuf),
    /// A temp file already holding verified content (remote loser conflict
    /// copy); removed by the TempGuard it came from.
    TempFile(PathBuf),
}

/// One upload to the agent's digest-keyed staging area.
struct StageJob {
    rel: RelPath,
    digest: [u8; 32],
    size: u64,
    mode: u32,
    executable: bool,
    source: StageSource,
    /// Holds a fetched temp alive until the staging step consumed it (drop-only: the side effect IS the point; never read).
    _temp: Option<TempGuard>,
}

/// Stage one job: `StageFile{digest…}` + EXACTLY `size` raw bytes. The agent
/// verifies the digest — a mid-transfer change surfaces as DigestMismatch.
fn stage_to_remote<S: Read + Write>(
    session: &mut Session<S>,
    job: &StageJob,
) -> Result<(), String> {
    let mut source = match &job.source {
        StageSource::LocalFile(p) => fs::File::open(p)
            .map_err(|e| format!("{}: content source unavailable: {e}", job.rel))?,
        StageSource::TempFile(p) => {
            fs::File::open(p).map_err(|e| format!("{}: staged temp unavailable: {e}", job.rel))?
        }
    };
    let req = Request::StageFile {
        path: job.rel.as_str().to_string(),
        size: job.size,
        mode: job.mode,
        executable: job.executable,
        digest: job.digest,
    };
    match session.call_with_payload(&req, &mut source, job.size) {
        Ok(Response::Stage(StageResult::Staged)) => Ok(()),
        Ok(Response::Stage(StageResult::DigestMismatch { got })) => Err(format!(
            "{}: content changed while staging (digest {got:?})",
            job.rel
        )),
        Ok(Response::Stage(StageResult::Io(msg))) => Err(format!("{}: stage io: {msg}", job.rel)),
        Ok(other) => Err(format!("{}: unexpected stage response: {other:?}", job.rel)),
        Err(e) => Err(format!("{}: {e}", job.rel)),
    }
}

/// Materialize one entry on the LOCAL side from remote content (apply.rs
/// semantics with the session as the content source). Directories and
/// symlinks use the apply primitives directly; files stream through a
/// digest-verified temp before `atomic_write`.
fn materialize_local<S: Read + Write>(
    local_root: &Path,
    rel: &RelPath,
    entry: &Entry,
    session: &mut Session<S>,
) -> Result<(), String> {
    if rel.as_str().is_empty() {
        return Err("refusing to materialize the root entry itself".to_string());
    }
    let fs_path = local_root.join(rel.as_str());
    match entry.kind {
        EntryKind::Directory => match fs::create_dir(&fs_path) {
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
        },
        EntryKind::SymbolicLink => {
            let Some(target) = entry.target.as_deref() else {
                return Err(format!("{rel}: symlink entry without a target"));
            };
            create_symlink(target, &fs_path).map_err(|e| format!("{rel}: {e}"))
        }
        EntryKind::File => {
            let Some(want) = entry.digest else {
                return Err(format!("{rel}: remote file entry without a digest"));
            };
            // ReadFile → FileHeader{size,digest} → EXACTLY size raw bytes.
            let (size, header_digest) = match session.call(&Request::ReadFile {
                path: rel.as_str().to_string(),
            }) {
                Ok(Response::FileHeader { size, digest, .. }) => (size, digest),
                Ok(other) => return Err(format!("{rel}: unexpected read response: {other:?}")),
                Err(e) => return Err(format!("{rel}: {e}")),
            };
            if header_digest != want {
                // The header is a length contract: the payload follows whether
                // we want it or not — drain it to keep the session framed,
                // then refuse (deviation 4: propagating drifted content would
                // poison the archive ancestor).
                let mut sink = io::sink();
                session
                    .read_payload(size, &mut sink)
                    .map_err(|e| format!("{rel}: {e}"))?;
                return Err(format!(
                    "{rel}: remote content changed since the scan (digest drift) — refusing to propagate"
                ));
            }
            ensure_parents(&fs_path).map_err(|e| format!("{rel}: {e}"))?;
            let dir = fs_path
                .parent()
                .ok_or_else(|| format!("{rel}: no parent directory"))?;
            let temp_path = dir.join(tmp_name());
            let guard = TempGuard {
                path: temp_path.clone(),
            };
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600) // in-flight only; atomic_write sets the final mode
                .open(&temp_path)
                .map_err(|e| format!("{rel}: temp file: {e}"))?;
            let got = session
                .read_payload_hashed(size, &mut file)
                .map_err(|e| format!("{rel}: {e}"))?;
            drop(file);
            if got != header_digest {
                return Err(format!(
                    "{rel}: payload failed its digest check (transport)"
                ));
            }
            // M6 empty-overwrite guard (the payload is already consumed, so the
            // session framing is intact when we refuse here): an arriving EMPTY
            // file must never rename over a non-empty local copy.
            guard_empty_overwrite(&fs_path, rel, size)?;
            // Fresh handle per destination (M1 lesson: a shared fd offset would
            // start the second read at EOF); atomic_write applies the exact
            // effective-mode + fsync + rename discipline.
            let mut reader = fs::File::open(&guard.path).map_err(|e| format!("{rel}: {e}"))?;
            let result = atomic_write(&fs_path, &mut reader, entry.mode, entry.executable)
                .map_err(|e| format!("{rel}: {e}"));
            drop(reader);
            drop(guard); // temp removed on drop
            result
        }
        // Never materialized (plan §2): opaque entries are scan-side markers.
        EntryKind::Untracked | EntryKind::Problematic => Err(format!(
            "{rel}: refusing to materialize a {:?} entry — untracked content is never transitioned",
            entry.kind
        )),
    }
}

/// Pull one remote file into a scanner-skipped temp file, hashing the payload.
/// Conflict copies preserve CURRENT content, so the header digest (what
/// actually arrived) is authoritative — no comparison against the scan entry
/// here (deviation 4's documented exception). The file is created by the
/// caller's TempGuard.
fn fetch_remote_to_file<S: Read + Write>(
    temp_path: &Path,
    path: &str,
    session: &mut Session<S>,
) -> Result<(u64, [u8; 32]), String> {
    let (size, header_digest) = match session.call(&Request::ReadFile { path: path.into() }) {
        Ok(Response::FileHeader { size, digest, .. }) => (size, digest),
        Ok(other) => return Err(format!("{path}: unexpected read response: {other:?}")),
        Err(e) => return Err(format!("{path}: {e}")),
    };
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp_path)
        .map_err(|e| format!("{path}: temp file: {e}"))?;
    let got = session
        .read_payload_hashed(size, &mut file)
        .map_err(|e| format!("{path}: {e}"))?;
    drop(file);
    if got != header_digest {
        return Err(format!(
            "{path}: payload failed its digest check (transport)"
        ));
    }
    Ok((size, header_digest))
}

/// Streaming blake3 + size of a local file (for staging conflict-copy content).
fn hash_local_file(path: &Path) -> io::Result<(u64, [u8; 32])> {
    let mut f = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, *hasher.finalize().as_bytes()))
}

/// `.sync-agent-tmp-<pid>-<n>` — the scanner-skipped temp convention
/// (apply.rs temp_name is crate-private in sync-core; this is the same shape).
static TEMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmp_name() -> String {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".sync-agent-tmp-{}-{:x}", std::process::id(), n)
}

/// Removes its file on drop (best-effort, like apply.rs's temp cleanup).
struct TempGuard {
    path: PathBuf,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// One file conflict awaiting post-safety-copy execution.
struct ConflictJob {
    path: RelPath,
    loser_side: Side,
    loser_entry: Entry,
}

// ---------------------------------------------------------------------------
// Tests — a filesystem-backed FAKE agent over a UnixStream socketpair. The
// fake speaks the real M2 protocol (sync_proto handshake + chunked scan +
// raw-payload read/stage + transition reports) against a REAL temp filesystem
// using sync-core primitives, so reconcile/apply correctness is exercised
// end-to-end without a cluster. Delete-time verification uses the fake's own
// scan cache (the real agent's semantics); the daemon-side driver safety
// check is the authoritative gate under test.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread::JoinHandle;

    use sync_core::apply::{atomic_write, create_symlink, remove_verified, ApplyReport};
    use sync_proto::convert::{action_from_wire, chunk_bytes, chunk_flat_tree, report_to_wire};
    use sync_proto::messages::{read_request, send_response, StageResult};
    use sync_proto::{exchange_versions_server, server_handshake};

    // ----- fake agent -----

    fn test_hello(root: &Path) -> sync_proto::messages::Hello {
        sync_proto::messages::Hello {
            agent_version: "0.1.0-fake".into(),
            uid: 4242,
            gid: 4242,
            root: root.display().to_string(),
            root_writable: true,
            preserves_executability: true,
        }
    }

    struct FakeState {
        root: PathBuf,
        pending_cache: Vec<u8>,
        last_cache: CacheMap,
        staged: BTreeMap<[u8; 32], Vec<u8>>,
        plan: Vec<PlannedAction>,
    }

    fn read_req_or_eof(stream: &mut UnixStream) -> io::Result<Option<Request>> {
        match read_request(stream) {
            Ok(req) => Ok(Some(req)),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The fake serve loop — mirrors the real agent's dispatch contract:
    /// per-request failures answer Error and keep the session framed.
    fn fake_serve(mut stream: UnixStream, root: PathBuf) -> io::Result<()> {
        server_handshake(&mut stream).map_err(io::Error::other)?;
        exchange_versions_server(&mut stream).map_err(io::Error::other)?;
        send_response(&mut stream, &Response::Hello(test_hello(&root)))?;
        let mut st = FakeState {
            root,
            pending_cache: Vec::new(),
            last_cache: CacheMap::new(),
            staged: BTreeMap::new(),
            plan: Vec::new(),
        };
        loop {
            let Some(req) = read_req_or_eof(&mut stream)? else {
                return Ok(()); // clean EOF / torn frame = cancellation idiom
            };
            match req {
                Request::Ping => send_response(&mut stream, &Response::Pong)?,
                Request::Shutdown => {
                    send_response(&mut stream, &Response::Bye)?;
                    return Ok(());
                }
                Request::CacheChunk(bytes) => st.pending_cache.extend_from_slice(&bytes),
                Request::Scan { rules } => fake_scan(&mut stream, &mut st, rules)?,
                Request::ReadFile { path } => fake_read(&mut stream, &st.root, &path)?,
                Request::StageFile {
                    path,
                    size,
                    mode,
                    executable,
                    digest,
                } => fake_stage(&mut stream, &mut st, &path, size, mode, executable, digest)?,
                Request::TransitionChunk(actions) => {
                    for wa in &actions {
                        st.plan
                            .push(action_from_wire(wa).map_err(io::Error::other)?);
                    }
                }
                Request::TransitionRun { force } => {
                    let report = fake_run(&mut st, force);
                    send_response(
                        &mut stream,
                        &Response::TransitionDone(report_to_wire(&report)),
                    )?;
                }
                // M3.5 control plane: FILE semantics, exactly like the real agent —
                // state persists under <root>/.sync-agent/, requests are consumed
                // atomically (the MCP server's writes are what the daemon fetches).
                Request::SyncReport { state } => {
                    sync_proto::control::write_sync_state(&st.root, &state)?;
                    send_response(&mut stream, &Response::Pong)?;
                }
                Request::ControlFetch { consume } => {
                    let pending = if consume {
                        sync_proto::control::take_control_requests(&st.root)?
                    } else {
                        sync_proto::control::read_control_requests(&st.root)?
                    };
                    send_response(&mut stream, &Response::ControlPayload { requests: pending })?;
                }
            }
        }
    }

    fn fake_scan(
        stream: &mut UnixStream,
        st: &mut FakeState,
        rules: Vec<String>,
    ) -> io::Result<()> {
        let rules = IgnoreRules::new(rules);
        let prior = cache::from_bytes(&st.pending_cache).unwrap_or_default();
        st.pending_cache.clear();
        let (snapshot, fresh) = scan_with_cache(&st.root, &prior, &rules)
            .map_err(|e| io::Error::other(format!("fake scan: {e}")))?;
        send_response(
            stream,
            &Response::ScanBegin {
                file_count: snapshot.file_count,
                dir_count: snapshot.dir_count,
                total_size: snapshot.total_size,
                preserves_executability: snapshot.preserves_executability,
            },
        )?;
        let flat = to_flat(&snapshot);
        st.last_cache = fresh;
        for batch in chunk_flat_tree(&flat) {
            send_response(stream, &Response::ScanChunk(batch))?;
        }
        let cache_bytes = cache::to_bytes(&st.last_cache);
        for chunk in chunk_bytes(&cache_bytes) {
            send_response(stream, &Response::CacheChunk(chunk))?;
        }
        send_response(stream, &Response::ScanDone)
    }

    /// ReadFile: header + EXACTLY `size` raw bytes (regular files only).
    /// Error messages mirror the real agent's (so the driver's absence
    /// detection — "No such file" — matches production).
    fn fake_read(stream: &mut UnixStream, root: &Path, path: &str) -> io::Result<()> {
        let fs_path = root.join(path);
        let meta = match fs::symlink_metadata(&fs_path) {
            Ok(m) => m,
            Err(e) => return send_response(stream, &Response::Error(format!("{path}: {e}"))),
        };
        if !meta.file_type().is_file() {
            return send_response(
                stream,
                &Response::Error(format!("{path}: not a regular file")),
            );
        }
        let bytes = match fs::read(&fs_path) {
            Ok(b) => b,
            Err(e) => return send_response(stream, &Response::Error(format!("{path}: {e}"))),
        };
        let mode = std::os::unix::fs::MetadataExt::mode(&meta) & 0o7777;
        send_response(
            stream,
            &Response::FileHeader {
                path: path.to_string(),
                size: bytes.len() as u64,
                mode,
                executable: mode & 0o111 != 0,
                digest: blake3::hash(&bytes).into(),
            },
        )?;
        stream.write_all(&bytes)?;
        stream.flush()
    }

    /// StageFile: drain EXACTLY `size` bytes, verify the digest, stage.
    fn fake_stage(
        stream: &mut UnixStream,
        st: &mut FakeState,
        path: &str,
        size: u64,
        mode: u32,
        executable: bool,
        digest: [u8; 32],
    ) -> io::Result<()> {
        let _ = (path, mode, executable); // informational, like the real agent
        let mut buf = vec![0u8; size as usize];
        stream.read_exact(&mut buf)?;
        let got: [u8; 32] = blake3::hash(&buf).into();
        let result = if got == digest {
            st.staged.insert(digest, buf);
            StageResult::Staged
        } else {
            StageResult::DigestMismatch { got }
        };
        send_response(stream, &Response::Stage(result))
    }

    /// TransitionRun: removals child-first, then materializations parent-first
    /// (the real agent's execute_plan order), through sync-core primitives —
    /// truthful counts, staged digests consumed after the run.
    fn fake_run(st: &mut FakeState, _force: bool) -> ApplyReport {
        let actions = std::mem::take(&mut st.plan);
        let mut report = ApplyReport::default();

        let mut removals: Vec<&PlannedAction> = actions
            .iter()
            .filter(|a| matches!(a.op, Operation::Remove(_)))
            .collect();
        removals.sort_by(|a, b| b.path.as_str().cmp(a.path.as_str()));
        for action in removals {
            let Operation::Remove(expected) = &action.op else {
                unreachable!("filtered above");
            };
            let fs_path = st.root.join(action.path.as_str());
            let result = if expected.kind == EntryKind::Directory {
                // Empty expectation: children were removed first (child-first
                // sort); a non-empty listing fails loudly — the straggler
                // behavior, minus two-pass atomicity (fake simplification).
                fs::remove_dir(&fs_path).map_err(|e| e.to_string())
            } else {
                remove_verified(&fs_path, &action.path, expected, &st.last_cache)
                    .map_err(|e| e.to_string())
            };
            match result {
                Ok(()) => report.deleted += 1,
                Err(msg) => {
                    report.failed += 1;
                    report.problems.push((action.path.clone(), msg));
                }
            }
        }

        let mut materials: Vec<&PlannedAction> = actions
            .iter()
            .filter(|a| matches!(a.op, Operation::Materialize(_)))
            .collect();
        materials.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
        let mut used: Vec<[u8; 32]> = Vec::new();
        for action in materials {
            let Operation::Materialize(entry) = &action.op else {
                unreachable!("filtered above");
            };
            let fs_path = st.root.join(action.path.as_str());
            let result: Result<(), String> = match entry.kind {
                EntryKind::Directory => match fs::create_dir(&fs_path) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists && fs_path.is_dir() => {
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                },
                EntryKind::File => {
                    let Some(d) = entry.digest else {
                        break_err(&mut report, &action.path, "content not staged");
                        continue;
                    };
                    if !st.staged.contains_key(&d) {
                        report.failed += 1;
                        report.problems.push((
                            action.path.clone(),
                            format!("content not staged for {}", action.path),
                        ));
                        continue;
                    }
                    // Consumed regardless of the write outcome (the real
                    // agent records digests before materializing).
                    used.push(d);
                    let bytes = st.staged[&d].clone();
                    let mut reader = &bytes[..];
                    atomic_write(&fs_path, &mut reader, entry.mode, entry.executable)
                        .map_err(|e| e.to_string())
                }
                EntryKind::SymbolicLink => {
                    let Some(target) = entry.target.as_deref() else {
                        break_err(&mut report, &action.path, "symlink without target");
                        continue;
                    };
                    create_symlink(target, &fs_path).map_err(|e| e.to_string())
                }
                EntryKind::Untracked | EntryKind::Problematic => {
                    Err("refusing to materialize opaque entry".into())
                }
            };
            match result {
                Ok(()) => report.applied += 1,
                Err(msg) => {
                    report.failed += 1;
                    report.problems.push((action.path.clone(), msg));
                }
            }
        }
        for d in used {
            st.staged.remove(&d);
        }
        report
    }

    fn break_err(report: &mut ApplyReport, path: &RelPath, msg: &str) {
        report.failed += 1;
        report.problems.push((path.clone(), msg.to_string()));
    }

    // ----- harness -----

    struct FakeRemote {
        dir: tempfile::TempDir,
    }

    impl FakeRemote {
        fn new() -> Self {
            FakeRemote {
                dir: tempfile::tempdir().unwrap(),
            }
        }
        fn root(&self) -> &Path {
            self.dir.path()
        }
        /// Run one driver pass against a fresh fake-agent connection.
        fn sync(
            &self,
            local_root: &Path,
            cfg: &RemoteConfig,
        ) -> (io::Result<RemoteReport>, JoinHandle<io::Result<()>>) {
            let (client, server) = UnixStream::pair().unwrap();
            let root = self.dir.path().to_path_buf();
            let handle = std::thread::spawn(move || fake_serve(server, root));
            let mut session = Session::client(client).unwrap();
            let result = sync_local_to_remote(local_root, &mut session, cfg);
            // Best-effort clean end (same posture as main.rs).
            let _ = session.call(&Request::Shutdown);
            drop(session);
            (result, handle)
        }
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    fn set_mtime(path: &Path, epoch_secs: u64) {
        let f = fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_times(
            std::fs::FileTimes::new()
                .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(epoch_secs)),
        )
        .unwrap();
    }

    /// Opaque content for the conflict tests: a unix socket is Untracked in
    /// the scan (S_IFSOCK), exactly like a FIFO, without needing libc.
    fn mk_socket(path: &Path) {
        std::os::unix::net::UnixListener::bind(path).unwrap();
    }

    fn default_cfg() -> RemoteConfig {
        RemoteConfig {
            remote_endpoint: "test-remote".into(),
            ..RemoteConfig::default()
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.retain(|n| n != STATE_DIR_NAME);
        v.sort();
        v
    }

    // ----- unit tests of the pure helpers -----

    fn f_entry(digest: u8) -> Entry {
        Entry {
            kind: EntryKind::File,
            children: BTreeMap::new(),
            digest: Some([digest; 32]),
            executable: false,
            target: None,
            mode: 0o644,
            size: 1,
            problem: None,
        }
    }

    fn d_entry() -> Entry {
        Entry::directory(BTreeMap::new())
    }

    fn flat_of(pairs: &[(&str, Entry)]) -> FlatTree {
        let mut m = FlatTree::new();
        m.insert(RelPath::root(), d_entry());
        for (p, e) in pairs {
            m.insert(RelPath(p.to_string()), e.clone());
        }
        m
    }

    #[test]
    fn root_entry_from_flat_reassembles_full_children() {
        let flat = flat_of(&[
            ("d", d_entry()),
            ("d/f1", f_entry(1)),
            ("d/sub", d_entry()),
            ("d/sub/f2", f_entry(2)),
            ("top", f_entry(3)),
        ]);
        let root = root_entry_from_flat(&flat);
        assert_eq!(root.kind, EntryKind::Directory);
        let d = root.children.get("d").unwrap();
        assert_eq!(d.children.len(), 2, "f1 + sub");
        let sub = d.children.get("sub").unwrap();
        assert_eq!(sub.children.get("f2").unwrap().digest, Some([2; 32]));
        assert!(root.children.get("top").unwrap().children.is_empty());
    }

    #[test]
    fn is_under_strict_descendants_only() {
        assert!(is_under(&RelPath("d/x".into()), &RelPath("d".into())));
        assert!(is_under(&RelPath("d/x/y".into()), &RelPath("d".into())));
        assert!(!is_under(&RelPath("d".into()), &RelPath("d".into())));
        assert!(
            !is_under(&RelPath("dd/x".into()), &RelPath("d".into())),
            "prefix ≠ parent"
        );
        assert!(is_under(&RelPath("anything".into()), &RelPath::root()));
        assert!(!is_under(&RelPath::root(), &RelPath::root()));
    }

    #[test]
    fn expand_remote_dir_removal_cascades_child_first_with_empty_dirs() {
        let live = flat_of(&[
            ("d", d_entry()),
            ("d/f1", f_entry(1)),
            ("d/f2", f_entry(2)),
            ("d/sub", d_entry()),
            ("d/sub/f3", f_entry(3)),
        ]);
        let base = live.clone();
        let mut out = Vec::new();
        expand_remote_removal(
            &RelPath("d".into()),
            &d_entry(),
            &live,
            &base,
            true,
            &mut out,
        );
        // 3 leaves + 2 dirs (sub, then d) — dirs carry EMPTY expectations.
        let removes: Vec<&PlannedAction> = out.iter().collect();
        assert_eq!(removes.len(), 5);
        for a in &removes {
            assert_eq!(a.side, Side::B);
            assert!(matches!(a.op, Operation::Remove(_)));
            if let Operation::Remove(e) = &a.op {
                if e.kind == EntryKind::Directory {
                    assert!(e.children.is_empty(), "sent dir expectations are empty");
                }
            }
        }
        // File expectations prefer the base entry (delete semantics).
        let f1 = removes.iter().find(|a| a.path.as_str() == "d/f1").unwrap();
        match &f1.op {
            Operation::Remove(e) => assert_eq!(e.digest, Some([1; 32])),
            _ => unreachable!(),
        }
    }

    #[test]
    fn expand_remote_file_removal_is_a_single_action() {
        let live = flat_of(&[("f", f_entry(9))]);
        let base = live.clone();
        let mut out = Vec::new();
        expand_remote_removal(
            &RelPath("f".into()),
            &f_entry(9),
            &live,
            &base,
            true,
            &mut out,
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn guard_plan_counts_whole_subtrees_so_the_ratio_guard_still_fires() {
        // Ancestor: 41 nodes — d/ with 20 files + d itself, plus 19 sibling
        // files + the root. Removing d/ is 21/41 = 51% > the 50% ratio.
        let mut ancestor_children = BTreeMap::new();
        let mut d_children = BTreeMap::new();
        for i in 0..20 {
            d_children.insert(format!("f{i:02}"), f_entry(i as u8));
        }
        ancestor_children.insert("d".to_string(), Entry::directory(d_children));
        for i in 0..19 {
            ancestor_children.insert(format!("g{i:02}"), f_entry(100 + i as u8));
        }
        let ancestor = Entry::directory(ancestor_children);

        let mut live = FlatTree::new();
        live.insert(RelPath::root(), d_entry());
        live.insert(RelPath("d".into()), d_entry());
        for i in 0..20 {
            live.insert(RelPath(format!("d/f{i:02}")), f_entry(i as u8));
        }
        for i in 0..19 {
            live.insert(RelPath(format!("g{i:02}")), f_entry(100 + i as u8));
        }

        // Expanded remote removal of d: 20 leaf removals + the empty-dir husk.
        let mut sent = Vec::new();
        expand_remote_removal(
            &RelPath("d".into()),
            &d_entry(),
            &live,
            &live,
            true,
            &mut sent,
        );
        assert_eq!(sent.len(), 21);

        let sctx = SafetyContext {
            ancestor_root: Some(&ancestor),
            alpha_root: None,
            beta_root: None,
        };
        // SENT plan (husk weight 1): NO halt — this is exactly the counting
        // gap the guard copy exists to close (deviation 3).
        assert!(check_safety(&sctx, &sent, &SafetyLimits::default(), false).is_ok());
        // GUARD plan: d re-weighted to its 21-node subtree → HALT, with
        // driver.rs-identical numbers.
        let guard = guard_actions(&sent, &live, &live);
        match check_safety(&sctx, &guard, &SafetyLimits::default(), false) {
            Err(ApplyError::Halted(HaltReason::LargeDeletion { count, .. })) => {
                assert_eq!(count, 21)
            }
            other => panic!("expected LargeDeletion halt, got {other:?}"),
        }
    }

    #[test]
    fn synchronizable_divergences_ignores_opaque_and_root() {
        let a = flat_of(&[("f", f_entry(1)), ("p", Entry::untracked())]);
        let mut b = flat_of(&[
            ("f", f_entry(2)),
            ("p", Entry::problematic("different errno")),
        ]);
        b.insert(RelPath::root(), d_entry());
        let div = synchronizable_divergences(&a, &b);
        assert_eq!(
            div,
            vec![RelPath("f".into())],
            "opaque + root never diverge"
        );
    }

    // ----- end-to-end driver tests against the fake agent -----

    #[test]
    fn first_sync_propagates_local_to_remote_and_second_run_is_a_noop() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("a.txt"), "alpha");
        write_file(&local.path().join("sub/inner.txt"), "inner");

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(!r.trust_base, "first sync runs safe no-base");
        assert_eq!(r.applied, 3, "a.txt + sub + sub/inner.txt");
        assert_eq!(r.failed, 0);
        assert!(r.conflicts_left.is_empty());
        assert!(r.archive_saved);
        assert_eq!(read(&fake.root().join("a.txt")), "alpha");
        assert_eq!(read(&fake.root().join("sub/inner.txt")), "inner");

        // Second run: full no-op, archive refreshed.
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(r.trust_base);
        assert_eq!(r.applied, 0);
        assert_eq!(r.deleted, 0);
        assert_eq!(r.failed, 0);
        assert!(r.archive_saved);
    }

    #[test]
    fn modify_propagates_local_to_remote() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("f.txt"), "v1");
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        assert_eq!(r.unwrap().applied, 1);

        write_file(&local.path().join("f.txt"), "v2");
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.applied, 1, "v1->v2 propagated a->b");
        assert_eq!(read(&fake.root().join("f.txt")), "v2");
        assert!(r.archive_saved);
    }

    #[test]
    fn remote_only_change_propagates_back() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("keep.txt"), "k");
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        assert!(r.unwrap().archive_saved);

        // Remote-only new file appears; the next run pulls it locally.
        write_file(&fake.root().join("only_b.txt"), "b side");
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.applied, 1, "no-base-less create B->A");
        assert_eq!(read(&local.path().join("only_b.txt")), "b side");
        assert!(r.archive_saved);
    }

    #[test]
    fn empty_remote_scan_never_overwrites_a_non_empty_local_file() {
        // M6 empty-overwrite guard — the "plan.md went 0-byte on both sides"
        // incident: the sandbox scanner hashed the file inside its own
        // `> file` truncation window, the daemon pulled 0 bytes, and the
        // laptop copy was destroyed with applied:1 and NO problem record.
        // The guard must refuse, record a problem, and leave the content
        // intact; the archive must not advance off a refused pass.
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("keep.txt"), "k");
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        assert!(r.unwrap().archive_saved, "base established");

        // Remote truncated to empty (the torn-scan shape). Old behavior:
        // applied=1, laptop copy silently destroyed.
        write_file(&fake.root().join("keep.txt"), "");
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.applied, 0, "the empty file is NEVER materialized");
        assert_eq!(r.failed, 1, "the guard records a per-file failure");
        assert!(
            r.problems
                .iter()
                .any(|(p, m)| p.as_str() == "keep.txt" && m.contains("EMPTY file")),
            "guard problem recorded: {:?}",
            r.problems
        );
        assert_eq!(
            read(&local.path().join("keep.txt")),
            "k",
            "laptop content intact"
        );
        assert!(
            !r.archive_saved,
            "a refused pass must not advance the archive"
        );

        // The refusal is STABLE (not a one-pass fluke): the next pass sees the
        // same divergence and refuses again — a human resolves the intent.
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.applied, 0, "still refused on the next pass");
        assert_eq!(read(&local.path().join("keep.txt")), "k");
    }

    #[test]
    fn local_delete_propagates_to_remote_with_base_evidence() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("keep.txt"), "k");
        write_file(&local.path().join("gone.txt"), "g");
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();

        fs::remove_file(local.path().join("gone.txt")).unwrap();
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.deleted, 1, "delete A->B with base evidence");
        assert!(!fake.root().join("gone.txt").exists());
        assert!(!local.path().join("gone.txt").exists());
        assert_eq!(read(&local.path().join("keep.txt")), "k");
        assert!(r.archive_saved);
    }

    #[test]
    fn remote_delete_propagates_to_local() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("keep.txt"), "k");
        write_file(&local.path().join("gone.txt"), "g");
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();

        fs::remove_file(fake.root().join("gone.txt")).unwrap();
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.deleted, 1, "delete B->A");
        assert!(!local.path().join("gone.txt").exists(), "A's copy deleted");
        assert_eq!(read(&local.path().join("keep.txt")), "k");
        assert!(r.archive_saved);
    }

    #[test]
    fn file_conflict_newest_wins_with_conflict_copies_on_both_sides() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("f.txt"), "base");
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();

        // Both sides diverge; remote is NEWER (controlled mtimes, no sleeps).
        write_file(&local.path().join("f.txt"), "older edit");
        set_mtime(&local.path().join("f.txt"), 1_000);
        write_file(&fake.root().join("f.txt"), "newer edit");
        set_mtime(&fake.root().join("f.txt"), 2_000);

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.conflicts_resolved, vec![RelPath("f.txt".into())]);
        assert!(r.conflicts_left.is_empty());
        assert!(
            r.archive_saved,
            "file conflicts resolve -> full convergence"
        );
        assert_eq!(
            read(&local.path().join("f.txt")),
            "newer edit",
            "winner (remote) converged"
        );
        assert_eq!(read(&fake.root().join("f.txt")), "newer edit");
        // Loser (local) preserved as a conflict copy on BOTH sides, same name.
        let copies_a = names(local.path())
            .into_iter()
            .filter(|n| n.contains("f.txt.sync-conflict"))
            .count();
        assert_eq!(copies_a, 1, "conflict copy next to the winner locally");
        let copies_b = names(fake.root())
            .into_iter()
            .filter(|n| n.contains("f.txt.sync-conflict"))
            .count();
        assert_eq!(copies_b, 1, "conflict copy next to the winner remotely");
        let copy_name = names(local.path())
            .into_iter()
            .find(|n| n.contains(".sync-conflict"))
            .unwrap();
        assert!(read(&local.path().join(&copy_name)).contains("older edit"));
        assert!(read(&fake.root().join(&copy_name)).contains("older edit"));
    }

    #[test]
    fn opaque_conflict_is_left_untouched_and_blocks_the_archive() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("x"), "a real file");
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();

        // Local replaces the file with opaque content (a socket = Untracked).
        fs::remove_file(local.path().join("x")).unwrap();
        mk_socket(&local.path().join("x"));

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.conflicts_left, vec![RelPath("x".into())]);
        assert!(r.conflicts_resolved.is_empty());
        assert!(!r.archive_saved, "left conflicts must block the archive");
        assert_eq!(r.failed, 0, "left conflict is a report, not a failure");
        assert_eq!(
            read(&fake.root().join("x")),
            "a real file",
            "remote untouched"
        );
        assert!(local.path().join("x").exists(), "opaque content untouched");
    }

    #[test]
    fn dry_run_mutates_nothing_anywhere() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("f.txt"), "content");

        let cfg = RemoteConfig {
            dry_run: true,
            ..default_cfg()
        };
        let (r, h) = fake.sync(local.path(), &cfg);
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(r.dry_run);
        assert!(r.planned_materializes >= 1, "plan produced actions");
        assert!(!fake.root().join("f.txt").exists(), "remote wrote no data");
        assert!(
            !local.path().join(STATE_DIR_NAME).exists(),
            "dry run wrote no local state"
        );
        assert!(!r.archive_saved);
    }

    #[test]
    fn corrupt_archive_is_safe_no_base() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("a.txt"), "alpha");
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();

        // Corrupt the archive, then diverge: new file ONLY on the remote.
        fs::write(
            local.path().join(STATE_DIR_NAME).join("archive.bin"),
            b"garbage not bincode",
        )
        .unwrap();
        write_file(&fake.root().join("only_b.txt"), "b side");

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(!r.trust_base, "corrupt archive -> safe no-base");
        assert_eq!(r.deleted, 0, "NoBaseNeverDeletes through the whole driver");
        assert_eq!(
            read(&local.path().join("only_b.txt")),
            "b side",
            "absence = create"
        );
        assert_eq!(
            read(&local.path().join("a.txt")),
            "alpha",
            "identical content untouched"
        );
        assert!(r.archive_saved, "clean run re-seeds the archive");
    }

    #[test]
    fn dir_to_file_type_flip_applies_remotely_via_expansion() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("d/f1.txt"), "one");
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        assert!(fake.root().join("d/f1.txt").exists());

        // Local replaces the dir with a file: the remote dir (with children)
        // must be removed via the child-first expansion, then materialized.
        fs::remove_dir_all(local.path().join("d")).unwrap();
        write_file(&local.path().join("d"), "now a file");

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(
            r.failed, 0,
            "type flip must apply cleanly: {:?}",
            r.problems
        );
        assert!(fake.root().join("d").is_file(), "remote dir became a file");
        assert_eq!(read(&fake.root().join("d")), "now a file");
        assert!(r.archive_saved);
    }

    #[test]
    fn file_to_dir_type_flip_applies_remotely() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("d"), "was a file");
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();

        fs::remove_file(local.path().join("d")).unwrap();
        write_file(&local.path().join("d/inner.txt"), "now a dir");

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.failed, 0, "flip must apply cleanly: {:?}", r.problems);
        assert!(fake.root().join("d").is_dir());
        assert_eq!(read(&fake.root().join("d/inner.txt")), "now a dir");
        assert!(r.archive_saved);
    }

    #[test]
    fn one_side_root_emptied_halts_before_any_mutation() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("one.txt"), "1");
        write_file(&local.path().join("two.txt"), "2");
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();

        // Local wipes everything: one-sided root emptying.
        fs::remove_file(local.path().join("one.txt")).unwrap();
        fs::remove_file(local.path().join("two.txt")).unwrap();
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(
            r.halted,
            Some(HaltReason::OneSideRootEmptied),
            "safety.go oneEndpointEmptiedRoot"
        );
        assert_eq!(r.applied + r.deleted, 0, "halt = zero mutation");
        assert!(!r.archive_saved);
        assert_eq!(read(&fake.root().join("one.txt")), "1", "remote untouched");
        assert_eq!(read(&fake.root().join("two.txt")), "2");
    }

    #[test]
    fn large_deletion_guard_halts_then_force_bypasses() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        for n in ["one", "two", "three"] {
            write_file(&local.path().join(format!("{n}.txt")), n);
        }
        let (_, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();

        // Local deletes two of three -> plan deletes 2 on the remote; guard
        // allows only 1.
        fs::remove_file(local.path().join("one.txt")).unwrap();
        fs::remove_file(local.path().join("two.txt")).unwrap();
        let cfg = RemoteConfig {
            limits: SafetyLimits {
                max_deletes: 1,
                max_delete_ratio: 0.9,
            },
            ..default_cfg()
        };
        let (r, h) = fake.sync(local.path(), &cfg);
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(matches!(
            r.halted,
            Some(HaltReason::LargeDeletion { count: 2, .. })
        ));
        assert!(
            fake.root().join("one.txt").exists(),
            "halt = nothing deleted"
        );
        assert!(!r.archive_saved);

        // force bypasses the guard (mutagen --force semantics).
        let cfg = RemoteConfig { force: true, ..cfg };
        let (r, h) = fake.sync(local.path(), &cfg);
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.deleted, 2, "force bypasses the guard");
        assert!(!fake.root().join("one.txt").exists());
        assert!(r.archive_saved);
    }

    #[test]
    fn ignored_content_is_untracked_and_never_synced() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("keep.txt"), "k");
        write_file(&local.path().join("node_modules/pkg.js"), "dep");
        write_file(&fake.root().join("b_only.txt"), "b");

        let cfg = RemoteConfig {
            extra_ignores: vec!["node_modules".into()],
            ..default_cfg()
        };
        let (r, h) = fake.sync(local.path(), &cfg);
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(
            !fake.root().join("node_modules").exists(),
            "ignored content never propagates"
        );
        assert_eq!(read(&fake.root().join("keep.txt")), "k");
        assert_eq!(
            read(&local.path().join("b_only.txt")),
            "b",
            "no-base create B->A"
        );
        assert_eq!(r.failed, 0);
        assert!(r.archive_saved);
        // The map must still SEE the ignored dir (Untracked), not treat it as absent.
        let rules = IgnoreRules::new(vec!["node_modules".into()]);
        let (snap, _) = scan_with_cache(local.path(), &CacheMap::new(), &rules).unwrap();
        let flat = to_flat(&snap);
        assert_eq!(
            flat.get(&RelPath("node_modules".into())).map(|e| e.kind),
            Some(EntryKind::Untracked)
        );
    }

    #[test]
    fn symlink_propagates_as_a_link_never_its_target() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("target.txt"), "payload");
        std::os::unix::fs::symlink("target.txt", local.path().join("link")).unwrap();

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.failed, 0, "{:?}", r.problems);
        assert!(
            fs::symlink_metadata(fake.root().join("link"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "remote materialized a LINK"
        );
        assert_eq!(
            fs::read_link(fake.root().join("link"))
                .unwrap()
                .to_str()
                .unwrap(),
            "target.txt"
        );
        assert_eq!(read(&fake.root().join("target.txt")), "payload");
        assert!(r.archive_saved);
    }

    // ----- M3.5 control plane (the sandbox MCP server's requests) -----

    fn seed_requests(fake: &FakeRemote, req: &sync_proto::control::ControlRequests) {
        let dir = fake.root().join(".sync-agent");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(sync_proto::control::CONTROL_REQUESTS_FILE),
            serde_json::to_vec(req).unwrap(),
        )
        .unwrap();
    }

    fn read_state(fake: &FakeRemote) -> sync_proto::control::SyncState {
        serde_json::from_slice(
            &fs::read(
                fake.root()
                    .join(".sync-agent")
                    .join(sync_proto::control::SYNC_STATE_FILE),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn ui_resolutions_override_sandbox_fetched_for_the_same_path() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("a.txt"), "A");
        write_file(&local.path().join("b.txt"), "B");
        write_file(&local.path().join("c.txt"), "C");
        std::os::unix::fs::symlink("a.txt", local.path().join("link")).unwrap();

        // converge, then diverge the symlink (laptop → b.txt, sandbox → c.txt)
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        assert!(r.unwrap().archive_saved);
        fs::remove_file(local.path().join("link")).unwrap();
        std::os::unix::fs::symlink("b.txt", local.path().join("link")).unwrap();
        fs::remove_file(fake.root().join("link")).unwrap();
        std::os::unix::fs::symlink("c.txt", fake.root().join("link")).unwrap();

        // the sandbox requests keep-local; the UI (operator console) overrides
        // with keep-remote on the same path — the UI decision must win.
        seed_requests(
            &fake,
            &sync_proto::control::ControlRequests {
                resolutions: vec![sync_proto::control::ConflictResolution {
                    path: "link".into(),
                    choice: "keep-local".into(),
                }],
                ..Default::default()
            },
        );
        let cfg = RemoteConfig {
            local_resolutions: vec![sync_proto::control::ConflictResolution {
                path: "link".into(),
                choice: "keep-remote".into(),
            }],
            ..default_cfg()
        };
        let (r, h) = fake.sync(local.path(), &cfg);
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(
            !r.conflicts_left.iter().any(|p| p.as_str() == "link"),
            "conflict settled: {:?}",
            r.conflicts_left
        );
        assert_eq!(
            fs::read_link(local.path().join("link"))
                .unwrap()
                .to_str()
                .unwrap(),
            "c.txt",
            "UI's keep-remote won: the local side adopts the sandbox link"
        );
        assert_eq!(
            fs::read_link(fake.root().join("link"))
                .unwrap()
                .to_str()
                .unwrap(),
            "c.txt",
            "sandbox side unchanged by its overridden keep-local"
        );
    }

    #[test]
    fn paused_pass_skips_everything_and_stays_pending() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("a.txt"), "alpha");
        seed_requests(
            &fake,
            &sync_proto::control::ControlRequests {
                paused: true,
                ..Default::default()
            },
        );

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(r.paused, "the pass reports the pause");
        assert!(
            !local.path().join(".sync-agent/archive.bin").exists(),
            "nothing ran"
        );
        assert!(
            !fake.root().join("a.txt").exists(),
            "paused = nothing scanned, nothing mutated"
        );
        // The pause stays PENDING (unconsumed) so sync_status keeps showing it.
        let still = sync_proto::control::read_control_requests(fake.root())
            .unwrap()
            .unwrap();
        assert!(still.paused, "pause not consumed by a skipped pass");
    }

    #[test]
    fn symlink_conflict_resolution_forces_the_chosen_side() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("a.txt"), "A");
        write_file(&local.path().join("b.txt"), "B");
        write_file(&local.path().join("c.txt"), "C");
        std::os::unix::fs::symlink("a.txt", local.path().join("link")).unwrap();

        // run 1: converge both sides on link → a.txt
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        assert!(r.unwrap().archive_saved);

        // both sides diverge on the symlink → left for manual resolution
        fs::remove_file(local.path().join("link")).unwrap();
        std::os::unix::fs::symlink("b.txt", local.path().join("link")).unwrap();
        fs::remove_file(fake.root().join("link")).unwrap();
        std::os::unix::fs::symlink("c.txt", fake.root().join("link")).unwrap();
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(
            r.conflicts_left.iter().any(|p| p.as_str() == "link"),
            "symlink conflict left for manual resolution: {:?}",
            r.conflicts_left
        );
        // The conflicted run still pushes a SyncReport: the sandbox MCP server's
        // sync_status must show the conflict (this is the M3.5 live-gate path).
        let st = read_state(&fake);
        assert!(
            st.conflicts
                .iter()
                .any(|c| c.path == "link" && c.kind == "symlink-conflict"),
            "conflicted run pushes the conflict to the MCP status source: {:?}",
            st.conflicts
        );

        // the sandbox MCP server resolves: keep-remote (link → c.txt wins)
        seed_requests(
            &fake,
            &sync_proto::control::ControlRequests {
                resolutions: vec![sync_proto::control::ConflictResolution {
                    path: "link".into(),
                    choice: "keep-remote".into(),
                }],
                ..Default::default()
            },
        );
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(
            r.honored
                .iter()
                .any(|h| h.contains("link") && h.contains("keep-remote")),
            "resolution honored: {:?}",
            r.honored
        );
        assert!(
            !r.conflicts_left.iter().any(|p| p.as_str() == "link"),
            "resolved conflict does not re-fire"
        );
        assert_eq!(
            fs::read_link(local.path().join("link"))
                .unwrap()
                .to_str()
                .unwrap(),
            "c.txt",
            "keep-remote: the local side adopts the sandbox's link"
        );
        // requests consumed: a following run is a clean no-op
        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert_eq!(r.applied + r.deleted, 0);
        assert!(r.honored.is_empty(), "consumed requests never re-fire");
    }

    #[test]
    fn ignore_add_persists_to_local_syncignore_after_success() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("keep.txt"), "k");
        write_file(&fake.root().join("node_modules/pkg.js"), "dep");
        seed_requests(
            &fake,
            &sync_proto::control::ControlRequests {
                ignore_add: vec!["node_modules".into()],
                ..Default::default()
            },
        );

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        let r = r.unwrap();
        assert!(
            r.honored.iter().any(|h| h.contains("node_modules")),
            "ignore_add honored: {:?}",
            r.honored
        );
        let ignore = fs::read_to_string(local.path().join(".syncignore")).unwrap();
        assert!(
            ignore.lines().any(|l| l.trim() == "node_modules"),
            "persisted"
        );
        assert!(
            !local.path().join("node_modules").exists(),
            "ignored content never propagates"
        );
        // consumed: the pattern survives via .syncignore, not via the requests
        assert!(sync_proto::control::read_control_requests(fake.root())
            .unwrap()
            .is_none());
    }

    #[test]
    fn sync_report_reaches_the_sandbox_mcp_state() {
        let fake = FakeRemote::new();
        let local = tempfile::tempdir().unwrap();
        write_file(&local.path().join("a.txt"), "alpha");
        write_file(&local.path().join("sub/inner.txt"), "inner");

        let (r, h) = fake.sync(local.path(), &default_cfg());
        h.join().unwrap().unwrap();
        r.unwrap();
        let st = read_state(&fake);
        assert_eq!(
            st.applied, 3,
            "the MCP server's status source is the daemon's report"
        );
        assert!(st.conflicts.is_empty());
        assert!(!st.paused);
        assert_eq!(st.daemon_version, env!("CARGO_PKG_VERSION"));
    }
}
