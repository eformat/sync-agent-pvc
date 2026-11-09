// Adapted from paiml/copia (MIT) src/bin/copia/reconcile.rs — 3-way TwoWaySafe case table.
//! Pure 3-way bidirectional reconcile (Unison/mutagen-shaped), TwoWaySafe ONLY.
//!
//! blake3 digests are the SOLE content oracle (mtime never decides anything);
//! the §2 fingerprint is {kind, digest, executable bit} — copia's Fingerprint
//! gained the mode bit so an exec-bit-only change is a CHANGE (plan §2:
//! mode-in-fingerprint). No I/O, no hashing: trees arrive pre-hashed and the
//! whole case table is exhaustively tested (the Kani proofs are ported as
//! exhaustive small-matrix tests — `no_base_never_deletes`,
//! `delete_requires_positive_evidence`).
//!
//! The proven invariants, preserved exactly:
//! 1. **NoBaseNeverDeletes** — with `trust_base = false` (missing/corrupt/
//!    foreign archive) NO delete action is ever emitted; one-sided absences
//!    become creates.
//! 2. **DeleteNeedsEvidence** — deletes require positive base evidence (the
//!    surviving side still equals the base).
//! 3. `alpha == beta` (Equal) → recurse + record ancestor refresh: Noop when
//!    both still equal the base, ConvergeIdentical when both independently
//!    reached the same new state (both-modified-same auto-resolve).
//! 4. One side unmodified vs base → propagate the other, UNLESS the loser has
//!    unsynchronizable content (Problematic/Untracked at or beneath it) →
//!    Conflict.
//! 5. Both purely deletions → propagate the fuller deletion (dir-level).
//! 6. One purely deleted + other modified → overwrite the deleted side
//!    (Propagate) — this is what lets manual resolution by deleting the loser
//!    converge.
//! 7. Both modified differently → `Action::Conflict`.
//!
//! Dir-awareness (copia had no directories; ours must — plan §2): directory
//! nodes compare as "same" iff both are directories (dir modes are not synced,
//! plan §8 — setgid/umask would otherwise churn), so a whole-directory deletion
//! is visible per-path AND is arbitrated at the dir node:
//!   - survivor untouched, or itself only deleted things beneath → the whole-dir
//!     deletion propagates (fuller deletion wins, invariant 5) and the subtree
//!     is suppressed from per-path actions;
//!   - survivor modified/added anything beneath (or holds opaque entries there)
//!     → Conflict at the dir — auto-overwriting would resurrect or destroy
//!     whole subtrees, and the per-path table alone would produce a destructive
//!     mix (Delete at the dir + Propagate at the modified child).
//!
//! Untracked/Problematic entries are opaque: they occupy a slot (so absence is
//! never misread — unreadable ≠ absent, plan §8) but are NEVER transitioned.
//! They block any propagation/deletion that would overwrite, delete, or source
//! them, degrading the action to `Action::Conflict` (metadata-only reporting;
//! the daemon decides policy per types.rs). Recording them via
//! ConvergeIdentical is bookkeeping, not a transition, and is allowed.
//!
//! Policy surface (newest-wins + conflict copy, `plan` dry-run) lives ABOVE
//! this table; the reconciler only ever reports.

use crate::change::{descendant_prefix, subtree_end};
use crate::types::{Action, Entry, EntryKind, FlatTree, RelPath};

/// Content identity of one entry — the §2 fingerprint: kind + blake3 digest +
/// executable bit. Symlinks: the digest is blake3 of the target string, so
/// digest equality IS target equality (copia semantics; both are compared).
/// Directories: identical iff both are directories (contents are reconciled
/// per-path at their own keys; dir modes are not synced, plan §8).
/// Untracked/Problematic: opaque — equal iff same kind; the diagnostic text is
/// not identity (two different errno strings about the same unreadable file
/// must not read as divergence).
#[must_use]
pub fn same(a: &Entry, b: &Entry) -> bool {
    if a.kind != b.kind {
        return false;
    }
    match a.kind {
        EntryKind::Directory => true,
        EntryKind::File => a.digest == b.digest && a.executable == b.executable,
        EntryKind::SymbolicLink => a.digest == b.digest && a.target == b.target,
        EntryKind::Untracked | EntryKind::Problematic => true,
    }
}

/// An entry whose content we cannot represent or transition (copia's
/// FileType::Other lesson generalized): ignored content, FIFOs, sockets,
/// devices (Untracked) and scan failures (Problematic). NEVER transitioned.
#[must_use]
pub fn is_unsynchronizable(e: &Entry) -> bool {
    matches!(e.kind, EntryKind::Untracked | EntryKind::Problematic)
}

/// The reconciled action for a single path from the two live entries and the
/// archive base. `base: None` means "no trustworthy base" (first sync, or the
/// safe mode a lost/mismatched archive forces) — a one-sided absence is then a
/// CREATE, never a delete. Pure: this function alone never blocks anything;
/// `reconcile` layers dir-arbitration and opaque-entry blocking on top.
#[must_use]
// map_or over is_none_or: is_none_or stabilized in 1.82; the workspace MSRV is
// 1.80 (copia made the identical call for its 1.75 floor). clippy's
// `unnecessary_map_or` is not MSRV-gated — deliberately allowed here.
#[allow(clippy::unnecessary_map_or)]
pub fn reconcile_path(a: Option<&Entry>, b: Option<&Entry>, base: Option<&Entry>) -> Action {
    match (a, b) {
        (None, None) => Action::Noop,
        (Some(av), Some(bv)) => {
            if same(av, bv) {
                // Identical now: a true noop if it also equals the base, else
                // both sides independently reached the same new state — record
                // it (invariant 3).
                if base.is_some_and(|z| same(av, z)) {
                    Action::Noop
                } else {
                    Action::ConvergeIdentical
                }
            } else {
                // map_or, not is_none_or: is_none_or is stable 1.82, workspace
                // MSRV is 1.80 (same reason copia used map_or for its 1.75).
                let a_changed = base.map_or(true, |z| !same(av, z));
                let b_changed = base.map_or(true, |z| !same(bv, z));
                match (a_changed, b_changed) {
                    (true, false) => Action::PropagateAtoB,
                    (false, true) => Action::PropagateBtoA,
                    // Both differ from base and from each other (a == b was
                    // handled above) => conflict. Never a silent pick (invariant 7).
                    _ => Action::Conflict,
                }
            }
        }
        // B absent: either B deleted (base present) or A created (base absent).
        (Some(av), None) => match base {
            None => Action::PropagateAtoB, // create A->B, never a delete (invariant 1)
            Some(z) if same(av, z) => Action::DeleteA, // A unchanged, B deleted (invariant 2)
            // A modified, B deleted: A's modification overwrites the deleted
            // side (invariant 6). Copia routed this through
            // Conflict(DeleteVsModify) and then unconditionally restored the
            // survivor anyway — same outcome, one hop less.
            Some(_) => Action::PropagateAtoB,
        },
        // A absent: symmetric.
        (None, Some(bv)) => match base {
            None => Action::PropagateBtoA,
            Some(z) if same(bv, z) => Action::DeleteB,
            Some(_) => Action::PropagateBtoA,
        },
    }
}

/// Reconcile whole trees over the union of paths (deterministic: sorted
/// `BTreeMap` keys). `trust_base = false` (safe mode) forces every base lookup
/// to `None`, so NO deletes are ever produced and all divergence degrades to
/// create/conflict (invariant 1). Noops are omitted.
///
/// On top of the per-path table, two arbitration layers run (both pure):
/// dir-level subtree decisions and opaque-entry blocking — see module docs.
///
/// ANCESTOR-REFRESH CONTRACT for apply.rs/daemon: paths absent from BOTH live
/// trees but present in the base reconcile to `Noop` (both sides deleted them —
/// nothing to transition) and are OMITTED from the action list, copia-style.
/// The caller's ancestor rebuild must still DROP such stale base entries
/// (e.g. prune ancestor paths absent from both live trees), or the archive
/// accumulates dead keys — harmless (they can never produce actions) but unbounded.
#[must_use]
pub fn reconcile(
    a: &FlatTree,
    b: &FlatTree,
    base: &FlatTree,
    trust_base: bool,
) -> Vec<(RelPath, Action)> {
    let mut paths: Vec<&RelPath> = a.keys().chain(b.keys()).collect();
    paths.sort_unstable();
    paths.dedup();

    let blocked_a = blocked_paths(a);
    let blocked_b = blocked_paths(b);

    let mut out = Vec::new();
    // Subtree suppressions (prefix, exclusive end) — same shape as change::diff.
    let mut sups: Vec<(String, String)> = Vec::new();

    for p in paths {
        sups.retain(|(_, end)| p.0.as_str() < end.as_str());
        if sups
            .iter()
            .any(|(pre, _)| p.0.as_str().starts_with(pre.as_str()))
        {
            continue; // subsumed by an ancestor-directory decision
        }

        let av = a.get(p);
        let bv = b.get(p);
        let zv = if trust_base { base.get(p) } else { None };

        let mut act = reconcile_path(av, bv, zv);
        act = arbitrate(p, av, bv, act, a, b, base, &blocked_a, &blocked_b);

        if act == Action::Noop {
            continue;
        }
        // A delete or conflict at a DIRECTORY path decides the whole subtree:
        // deeper paths get no separate actions (whole-subtree semantics).
        let dir_involved = [av, bv, zv]
            .into_iter()
            .flatten()
            .any(|e| e.kind == EntryKind::Directory);
        if matches!(act, Action::DeleteA | Action::DeleteB | Action::Conflict) && dir_involved {
            sups.push((descendant_prefix(p), subtree_end(p)));
        }
        out.push((p.clone(), act));
    }
    out
}

/// Post-table arbitration for one path: opaque-content blocking on every
/// transition, plus the whole-dir deletion rule. Turns unsafe table outcomes
/// into `Action::Conflict`; never weakens a delete into anything but a conflict.
#[allow(clippy::too_many_arguments)]
fn arbitrate(
    path: &RelPath,
    av: Option<&Entry>,
    bv: Option<&Entry>,
    act: Action,
    a: &FlatTree,
    b: &FlatTree,
    base: &FlatTree,
    blocked_a: &[&RelPath],
    blocked_b: &[&RelPath],
) -> Action {
    match act {
        Action::PropagateAtoB => {
            // Source must be synchronizable content. An OPAQUE source (ignored
            // dir, FIFO, unreadable file) is outside the sync set: propagating
            // it into ABSENCE would materialize the unmaterializable — the
            // right outcome is nothing (mutagen never creates ignored content
            // on the peer; laptop node_modules must not block convergence).
            // But if the peer has content at the path, we can neither source
            // the opaque side nor silently overwrite the peer's real content —
            // manual resolution (copia's silent FIFO drop must not return).
            if av.is_some_and(is_unsynchronizable) {
                return if bv.is_none() {
                    Action::Noop
                } else {
                    Action::Conflict
                };
            }
            // Target: replacing B's node-or-subtree must not destroy opaque
            // content at the path or beneath a directory being replaced.
            if bv.is_some() && subtree_blocked(blocked_b, path) {
                return Action::Conflict;
            }
            act
        }
        Action::PropagateBtoA => {
            if bv.is_some_and(is_unsynchronizable) {
                return if av.is_none() {
                    Action::Noop
                } else {
                    Action::Conflict
                };
            }
            if av.is_some() && subtree_blocked(blocked_a, path) {
                return Action::Conflict;
            }
            act
        }
        Action::DeleteA => {
            // Never delete opaque content: the peer's "deletion" concerns an
            // entry that was never part of the sync set (or is unreadable —
            // delete-time verification could not prove it either). Leave it.
            if av.is_some_and(is_unsynchronizable) {
                return Action::Noop;
            }
            // A is the surviving side (B deleted first). Whole-dir deletion:
            // propagating B's deletion is only safe when A made NO
            // non-deletion changes beneath (invariants 4/5); any modification,
            // addition, or opaque entry inside degrades to a conflict.
            if av.is_some_and(|e| e.kind == EntryKind::Directory)
                && survivor_modified(a, base, path)
            {
                return Action::Conflict;
            }
            if subtree_blocked(blocked_a, path) {
                return Action::Conflict;
            }
            act
        }
        Action::DeleteB => {
            if bv.is_some_and(is_unsynchronizable) {
                return Action::Noop;
            }
            if bv.is_some_and(|e| e.kind == EntryKind::Directory)
                && survivor_modified(b, base, path)
            {
                return Action::Conflict;
            }
            if subtree_blocked(blocked_b, path) {
                return Action::Conflict;
            }
            act
        }
        _ => act,
    }
}

/// Whether the surviving side changed anything NON-deletional at-or-under
/// `dir_path`: any survivor entry there that differs from the base (modified,
/// added, or opaque) counts. Pure deletions (survivor entries the base still
/// has) do not — invariant 5: when both sides only deleted, the fuller deletion
/// propagates.
fn survivor_modified(survivor: &FlatTree, base: &FlatTree, dir_path: &RelPath) -> bool {
    let start = if dir_path.as_str().is_empty() {
        RelPath::root()
    } else {
        RelPath(descendant_prefix(dir_path))
    };
    for (p, e) in survivor.range(start..RelPath(subtree_end(dir_path))) {
        match base.get(p) {
            Some(z) if same(e, z) => {}
            _ => return true,
        }
    }
    false
}

/// Paths of opaque entries in a tree, in `BTreeMap` (sorted) order.
fn blocked_paths(t: &FlatTree) -> Vec<&RelPath> {
    t.iter()
        .filter(|(_, e)| is_unsynchronizable(e))
        .map(|(p, _)| p)
        .collect()
}

/// Whether an opaque entry exists AT `path` or anywhere in its subtree, given
/// the sorted blocked-path list. Two-step search: the node itself, then the
/// first blocked path at-or-after the descendant prefix (all true descendants
/// sort before any non-descendant that follows the prefix, so the first hit
/// decides).
fn subtree_blocked(blocked: &[&RelPath], path: &RelPath) -> bool {
    if blocked.is_empty() {
        return false;
    }
    if blocked.binary_search(&path).is_ok() {
        return true;
    }
    let prefix = descendant_prefix(path);
    let idx = blocked.partition_point(|q| q.0.as_str() < prefix.as_str());
    match blocked.get(idx) {
        Some(q) => q.0.as_str().starts_with(&prefix),
        None => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn f(d: u8) -> Entry {
        file(d, false)
    }
    fn file(d: u8, exec: bool) -> Entry {
        Entry {
            kind: EntryKind::File,
            children: BTreeMap::new(),
            digest: Some([d; 32]),
            executable: exec,
            target: None,
            mode: if exec { 0o755 } else { 0o644 },
            size: 1,
            problem: None,
        }
    }
    fn link(target: &str, d: u8) -> Entry {
        Entry {
            kind: EntryKind::SymbolicLink,
            children: BTreeMap::new(),
            digest: Some([d; 32]),
            executable: false,
            target: Some(target.into()),
            mode: 0o644,
            size: 0,
            problem: None,
        }
    }
    fn dir(children: Vec<(&str, Entry)>) -> Entry {
        Entry::directory(
            children
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }
    fn tree(entries: Vec<(&str, Entry)>) -> FlatTree {
        entries
            .into_iter()
            .map(|(p, e)| (RelPath(p.to_string()), e))
            .collect()
    }
    fn actions(out: &[(RelPath, Action)]) -> Vec<(&str, Action)> {
        out.iter()
            .map(|(p, a)| (p.as_str(), *a))
            .collect()
    }

    // ---- the pure case table (copia's reconcile_path tests, ported) ----

    #[test]
    fn both_equal_base_is_noop() {
        assert_eq!(
            reconcile_path(Some(&f(1)), Some(&f(1)), Some(&f(1))),
            Action::Noop
        );
    }

    #[test]
    fn one_sided_change_propagates() {
        assert_eq!(
            reconcile_path(Some(&f(2)), Some(&f(1)), Some(&f(1))),
            Action::PropagateAtoB
        );
        assert_eq!(
            reconcile_path(Some(&f(1)), Some(&f(2)), Some(&f(1))),
            Action::PropagateBtoA
        );
    }

    #[test]
    fn identical_divergence_converges_not_conflicts() {
        // both changed to the SAME new content -> record, never conflict
        assert_eq!(
            reconcile_path(Some(&f(3)), Some(&f(3)), Some(&f(1))),
            Action::ConvergeIdentical
        );
    }

    #[test]
    fn divergent_change_is_conflict() {
        assert_eq!(
            reconcile_path(Some(&f(2)), Some(&f(3)), Some(&f(1))),
            Action::Conflict
        );
    }

    #[test]
    fn delete_needs_positive_evidence() {
        // B deleted, A unchanged since base -> propagate delete to A
        assert_eq!(
            reconcile_path(Some(&f(1)), None, Some(&f(1))),
            Action::DeleteA
        );
        // B deleted, A MODIFIED since base -> overwrite the deleted side (req 6)
        assert_eq!(
            reconcile_path(Some(&f(2)), None, Some(&f(1))),
            Action::PropagateAtoB
        );
    }

    #[test]
    fn no_base_absence_is_create_never_delete() {
        assert_eq!(
            reconcile_path(Some(&f(1)), None, None),
            Action::PropagateAtoB
        );
        assert_eq!(
            reconcile_path(None, Some(&f(1)), None),
            Action::PropagateBtoA
        );
    }

    #[test]
    fn ftype_flip_is_a_change_even_with_same_digest() {
        // A file replaced by a symlink whose digest was derived from the file
        // bytes still differs: kind is part of identity.
        let flip = link("x", 1);
        assert_eq!(
            reconcile_path(Some(&f(1)), Some(&flip), Some(&f(1))),
            Action::PropagateBtoA
        );
    }

    #[test]
    fn exec_bit_only_change_is_a_change() {
        assert_eq!(
            reconcile_path(Some(&file(1, true)), Some(&f(1)), Some(&f(1))),
            Action::PropagateAtoB
        );
    }

    #[test]
    fn symlink_target_change_is_a_change() {
        assert_eq!(
            reconcile_path(Some(&link("t2", 9)), Some(&link("t1", 8)), Some(&link("t1", 8))),
            Action::PropagateAtoB
        );
    }

    #[test]
    fn dirs_compare_equal_regardless_of_mode_noise() {
        let mut d1 = Entry::directory(BTreeMap::new());
        let mut d2 = Entry::directory(BTreeMap::new());
        d1.mode = 0o750; // setgid/umask churn must not read as divergence
        d2.mode = 0o755;
        assert!(same(&d1, &d2));
        assert_eq!(
            reconcile_path(Some(&d1), Some(&d2), Some(&d2)),
            Action::Noop
        );
    }

    // ---- Kani proof intents, ported as exhaustive small-case matrices ----

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum V {
        Absent,
        File1,
        File2,
        File1Exec,
        Link1,
        Link2,
        Dir,
        Opaque,
    }
    const ALL: [V; 8] = [
        V::Absent,
        V::File1,
        V::File2,
        V::File1Exec,
        V::Link1,
        V::Link2,
        V::Dir,
        V::Opaque,
    ];
    fn entry_of(v: V) -> Option<Entry> {
        match v {
            V::Absent => None,
            V::File1 => Some(file(1, false)),
            V::File2 => Some(file(2, false)),
            V::File1Exec => Some(file(1, true)),
            V::Link1 => Some(link("t1", 3)),
            V::Link2 => Some(link("t2", 4)),
            V::Dir => Some(Entry::directory(BTreeMap::new())),
            V::Opaque => Some(Entry::untracked()),
        }
    }

    /// reconcile-kani-001 intent: with NO trustworthy base, reconcile NEVER
    /// emits a delete — a one-sided absence is always a create, so a lost or
    /// corrupt archive can never turn a create into destructive data loss.
    #[test]
    fn no_base_never_deletes() {
        for a in ALL {
            for b in ALL {
                let act = reconcile_path(entry_of(a).as_ref(), entry_of(b).as_ref(), None);
                assert!(
                    !matches!(act, Action::DeleteA | Action::DeleteB),
                    "delete emitted with no base: a={a:?} b={b:?} -> {act:?}"
                );
            }
        }
    }

    /// reconcile-kani-002 intent: a delete is emitted ONLY when the surviving
    /// side's content still equals the base (positive evidence) — a modified
    /// survivor against a deleted peer propagates, never deletes.
    #[test]
    fn delete_requires_positive_evidence() {
        for surv in ALL {
            for base in ALL {
                // A survives, B absent.
                let act = reconcile_path(entry_of(surv).as_ref(), None, entry_of(base).as_ref());
                if matches!(act, Action::DeleteA) {
                    let (s, z) = (entry_of(surv).unwrap(), entry_of(base).unwrap());
                    assert!(
                        same(&s, &z),
                        "DeleteA without survivor==base evidence: {surv:?} vs {base:?}"
                    );
                }
                // A absent, B survives — symmetric.
                let act = reconcile_path(None, entry_of(surv).as_ref(), entry_of(base).as_ref());
                if matches!(act, Action::DeleteB) {
                    let (s, z) = (entry_of(surv).unwrap(), entry_of(base).unwrap());
                    assert!(
                        same(&s, &z),
                        "DeleteB without survivor==base evidence: {surv:?} vs {base:?}"
                    );
                }
            }
        }
    }

    // ---- tree-level behavior (dir-awareness, blocking, suppression) ----

    #[test]
    fn propagates_one_sided_changes() {
        let a = tree(vec![("f", f(2)), ("g", f(1))]);
        let b = tree(vec![("f", f(1)), ("g", f(2))]);
        let base = tree(vec![("f", f(1)), ("g", f(1))]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(
            actions(&out),
            vec![("f", Action::PropagateAtoB), ("g", Action::PropagateBtoA)]
        );
    }

    #[test]
    fn both_modified_same_converges() {
        let a = tree(vec![("f", f(3))]);
        let b = tree(vec![("f", f(3))]);
        let base = tree(vec![("f", f(1))]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("f", Action::ConvergeIdentical)]);
    }

    #[test]
    fn both_modified_differently_conflicts() {
        let a = tree(vec![("f", f(2))]);
        let b = tree(vec![("f", f(3))]);
        let base = tree(vec![("f", f(1))]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("f", Action::Conflict)]);
    }

    #[test]
    fn delete_vs_modify_overwrites_deleted_side() {
        // B deleted the file; A modified it -> A's content recreates it on B
        // (req 6 — manual resolution by deleting the loser converges).
        let a = tree(vec![("f", f(2))]);
        let b = FlatTree::new();
        let base = tree(vec![("f", f(1))]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("f", Action::PropagateAtoB)]);
    }

    #[test]
    fn delete_vs_delete_fuller_deletion_wins() {
        // A deleted d/x only; B deleted the whole dir d. The fuller (whole-dir)
        // deletion propagates to A as ONE action; descendants are subsumed.
        let a = tree(vec![("d", dir(vec![("y", f(2))])), ("d/y", f(2))]);
        let b = FlatTree::new();
        let base = tree(vec![
            ("d", dir(vec![("x", f(1)), ("y", f(2))])),
            ("d/x", f(1)),
            ("d/y", f(2)),
        ]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("d", Action::DeleteA)]);
    }

    #[test]
    fn both_deleted_file_converges_silently() {
        let base = tree(vec![("f", f(1))]);
        let out = reconcile(&FlatTree::new(), &FlatTree::new(), &base, true);
        assert!(out.is_empty());
    }

    #[test]
    fn whole_dir_deletion_propagates_when_survivor_untouched() {
        // B deleted dir d; A untouched -> the deletion propagates to A as ONE
        // DeleteA, subtree subsumed (copia's missing directory-deletion
        // lifecycle, added per plan §2).
        let a = tree(vec![("d", dir(vec![("f", f(1))])), ("d/f", f(1))]);
        let b = FlatTree::new();
        let base = tree(vec![
            ("d", dir(vec![("f", f(1))])),
            ("d/f", f(1)),
        ]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("d", Action::DeleteA)]);
    }

    #[test]
    fn dir_delete_with_modified_interior_conflicts() {
        // B deleted the whole dir; A modified a file INSIDE it. Auto-picking
        // would either resurrect the whole subtree or destroy A's edit (the
        // per-path table alone yields Delete(dir) + Propagate(child)) — so the
        // dir-level arbitration reports ONE conflict and suppresses children.
        let a = tree(vec![
            ("d", dir(vec![("f", f(9)), ("g", f(2))])),
            ("d/f", f(9)),
            ("d/g", f(2)),
        ]);
        let b = FlatTree::new();
        let base = tree(vec![
            ("d", dir(vec![("f", f(1)), ("g", f(2))])),
            ("d/f", f(1)),
            ("d/g", f(2)),
        ]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("d", Action::Conflict)]);
    }

    #[test]
    fn dir_delete_with_added_interior_conflicts() {
        // A added d/new; B deleted the whole dir. Additions inside a deleted
        // dir are divergence too (recreating the dir would undo B's deletion).
        let a = tree(vec![
            ("d", dir(vec![("f", f(1)), ("new", f(7))])),
            ("d/f", f(1)),
            ("d/new", f(7)),
        ]);
        let b = FlatTree::new();
        let base = tree(vec![
            ("d", dir(vec![("f", f(1))])),
            ("d/f", f(1)),
        ]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("d", Action::Conflict)]);
    }

    #[test]
    fn dir_file_flips_propagate() {
        // Dir -> file on A (B unchanged): flip propagates; B's old child gets
        // its own delete (dir-level PROPAGATE does not subsume children).
        let a = tree(vec![("d", f(3))]);
        let b = tree(vec![("d", dir(vec![("f", f(1))])), ("d/f", f(1))]);
        let base = b.clone();
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(
            actions(&out),
            vec![("d", Action::PropagateAtoB), ("d/f", Action::DeleteB)]
        );

        // File -> dir on A (B unchanged): flip propagates the other way's base.
        let a2 = tree(vec![("d", dir(vec![]))]);
        let b2 = tree(vec![("d", f(1))]);
        let base2 = tree(vec![("d", f(1))]);
        let out2 = reconcile(&a2, &b2, &base2, true);
        assert_eq!(actions(&out2), vec![("d", Action::PropagateAtoB)]);
    }

    #[test]
    fn empty_dir_create_and_delete() {
        // Create: A made an empty dir; B and base lack it.
        let a = tree(vec![("d", dir(vec![]))]);
        let out = reconcile(&a, &FlatTree::new(), &FlatTree::new(), true);
        assert_eq!(actions(&out), vec![("d", Action::PropagateAtoB)]);

        // Delete: B removed the empty dir; A unchanged.
        let base = tree(vec![("d", dir(vec![]))]);
        let a2 = tree(vec![("d", dir(vec![]))]);
        let out2 = reconcile(&a2, &FlatTree::new(), &base, true);
        assert_eq!(actions(&out2), vec![("d", Action::DeleteA)]);
    }

    #[test]
    fn exec_bit_only_change_propagates_across_tree() {
        let a = tree(vec![("f", file(1, true))]);
        let b = tree(vec![("f", f(1))]);
        let base = tree(vec![("f", f(1))]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("f", Action::PropagateAtoB)]);
    }

    #[test]
    fn safe_mode_disables_deletes_across_a_tree() {
        // Port of copia's test: trusted base -> DeleteA; safe mode -> create.
        let a = tree(vec![("keep", f(1)), ("only_a", f(2))]);
        let b = tree(vec![("keep", f(1))]);
        let base = tree(vec![("keep", f(1)), ("only_a", f(2))]);
        let trusted = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&trusted), vec![("only_a", Action::DeleteA)]);
        let safe = reconcile(&a, &b, &base, false);
        assert_eq!(
            actions(&safe),
            vec![
                ("keep", Action::ConvergeIdentical),
                ("only_a", Action::PropagateAtoB),
            ]
        );
    }

    #[test]
    fn untracked_entries_are_never_transitioned() {
        // Both sides agree on the untracked entry since the base: noop.
        let u = || Entry::untracked();
        let base = tree(vec![("u", u())]);
        let a = tree(vec![("u", u())]);
        let out = reconcile(&a, &tree(vec![("u", u())]), &base, true);
        assert!(out.is_empty());

        // B's untracked entry vanished; A still has it: deleting A's copy
        // would transition an opaque entry -> noop (integration note: opaque
        // content is OUTSIDE the sync set — one-sided presence differences of
        // ignored dirs are routine (laptop node_modules vs fresh PVC) and must
        // neither transition anything nor wedge the sync with a sticky
        // conflict). Visibility stays with the scanner's Untracked marker.
        let out2 = reconcile(&a, &FlatTree::new(), &base, true);
        assert!(out2.is_empty(), "opaque delete-target: noop, got {out2:?}");

        // A grew a NEW untracked entry; there is nothing to propagate (no
        // content) and nothing on the peer to protect — noop, not a transition.
        let out3 = reconcile(&a, &FlatTree::new(), &FlatTree::new(), true);
        assert!(out3.is_empty(), "opaque source into absence: noop, got {out3:?}");
    }

    #[test]
    fn untracked_inside_deleted_dir_blocks_the_deletion() {
        // B deleted dir d; A's copy contains an agreed untracked entry —
        // deleting A's dir would destroy the opaque entry -> conflict.
        let a = tree(vec![("d", dir(vec![("u", Entry::untracked())])), ("d/u", Entry::untracked())]);
        let b = FlatTree::new();
        let base = tree(vec![("d", dir(vec![("u", Entry::untracked())])), ("d/u", Entry::untracked())]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("d", Action::Conflict)]);
    }

    #[test]
    fn unreadable_side_never_becomes_a_delete_or_overwrite() {
        // §8: unreadable ≠ absent, and unreadable ≠ modified. B deleted the
        // file; A's scan came back Problematic (EACCES). Recreating from an
        // unreadable source is impossible and deleting A's opaque entry is
        // forbidden -> noop (no delete, no overwrite — the name still holds).
        // The EACCES stays visible as a Problematic scan entry (status/UI);
        // unlike a sticky conflict it does not wedge the whole sync.
        let a = tree(vec![("f", Entry::problematic("EACCES"))]);
        let base = tree(vec![("f", f(1))]);
        let out = reconcile(&a, &FlatTree::new(), &base, true);
        assert!(out.is_empty(), "unreadable survivor vs deletion: noop, got {out:?}");

        // Symmetric: A changed the file, B's copy is unreadable — propagating
        // over an unreadable target is not allowed either (real divergence,
        // human decides).
        let a2 = tree(vec![("f", f(2))]);
        let b2 = tree(vec![("f", Entry::problematic("EACCES"))]);
        let base2 = tree(vec![("f", f(1))]);
        let out2 = reconcile(&a2, &b2, &base2, true);
        assert_eq!(actions(&out2), vec![("f", Action::Conflict)]);
    }

    #[test]
    fn problematic_dir_interior_blocks_deletion_propagation() {
        // A's scan of d/sub failed; B deleted the whole dir. We cannot verify
        // A's state beneath d -> conflict, never delete A's unreadable tree.
        let a = tree(vec![
            ("d", dir(vec![("sub", Entry::problematic("EACCES"))])),
            ("d/sub", Entry::problematic("EACCES")),
        ]);
        let b = FlatTree::new();
        let base = tree(vec![
            ("d", dir(vec![("sub", dir(vec![]))])),
            ("d/sub", dir(vec![])),
        ]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("d", Action::Conflict)]);
    }

    #[test]
    fn partial_deletions_inside_surviving_dir_are_per_path() {
        // The dir survives on both sides; only the deleted child's evidence
        // matters — the table handles each path independently.
        let a = tree(vec![("d", dir(vec![("y", f(2))])), ("d/y", f(2))]);
        let b = tree(vec![
            ("d", dir(vec![("x", f(1)), ("y", f(2))])),
            ("d/x", f(1)),
            ("d/y", f(2)),
        ]);
        let base = b.clone();
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("d/x", Action::DeleteB)]);
    }

    #[test]
    fn file_replacing_deleted_dir_propagates_cleanly() {
        // Base had dir d; A replaced it with a file; B deleted d entirely.
        // A's state (a file) simply propagates; the base children converge
        // to absent on both sides (no actions).
        let a = tree(vec![("d", f(3))]);
        let base = tree(vec![
            ("d", dir(vec![("f", f(1))])),
            ("d/f", f(1)),
        ]);
        let out = reconcile(&a, &FlatTree::new(), &base, true);
        assert_eq!(actions(&out), vec![("d", Action::PropagateAtoB)]);
    }

    #[test]
    fn creation_inside_deleted_dir_is_subsumed_by_conflict() {
        // Covered by dir_delete_with_added_interior_conflicts; this variant
        // checks the suppressed child never leaks an action of its own.
        let a = tree(vec![
            ("d", dir(vec![("new", f(7))])),
            ("d/new", f(7)),
        ]);
        let b = FlatTree::new();
        let base = tree(vec![("d", dir(vec![]))]);
        let out = reconcile(&a, &b, &base, true);
        assert_eq!(actions(&out), vec![("d", Action::Conflict)]);
        assert!(out.iter().all(|(p, _)| p.as_str() == "d"));
    }

    #[test]
    fn sibling_between_path_and_its_slash_prefix_is_not_subsumed() {
        // `d!` sorts between `d` and `d/` — subtree suppression must use the
        // prefix test, not a bare lexicographic bound, or this sibling would be
        // swallowed by the dir decision at `d`.
        let a = tree(vec![
            ("d", dir(vec![("f", f(1))])),
            ("d/f", f(1)),
            ("d!", f(9)),
        ]);
        let b = FlatTree::new(); // B deleted dir d AND the d! file
        let base = tree(vec![
            ("d", dir(vec![("f", f(1))])),
            ("d/f", f(1)),
            ("d!", f(1)),
        ]);
        let out = reconcile(&a, &b, &base, true);
        // B deleted everything; d is untouched on A (DeleteA subsumes d/f),
        // but A MODIFIED d! — that modification overwrites B's deletion.
        assert_eq!(
            actions(&out),
            vec![("d", Action::DeleteA), ("d!", Action::PropagateAtoB)]
        );
    }
}
