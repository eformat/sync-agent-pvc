//! Change computation against the ancestor baseline — whole-subtree semantics.
//!
//! `diff` compares a baseline `FlatTree` (the ancestor snapshot) against a current
//! `FlatTree` and emits `Change`s at the shallowest differing node: a directory
//! whose *node identity* changed (type flip, or problem-state) yields ONE change
//! that replaces its entire subtree, while equal directory nodes are descended
//! into so content changes inside them surface at their own (file/symlink) paths.
//! This mirrors mutagen's change granularity (`pkg/synchronization/core`
//! change.proto semantics — one Change per affected node, `Old` informational,
//! `Apply` uses only `New`).
//!
//! Structural convention (load-bearing): a `FlatTree` is the lossless flatten of
//! a `Snapshot` — every path is a key AND directory entries still carry their
//! subtree in `children`. The flat index is the structural authority (reconcilers
//! never *walk* the nested form), but `children` are what let a single `Change`
//! carry a whole replaced subtree into `apply_to_flat`. A flattener that strips
//! `children` breaks subtree reconstruction — don't strip them.
//!
//! Pure: no I/O, no hashing. Trees arrive pre-hashed (digests are the content
//! oracle); iteration is over `BTreeMap`s, so results are deterministic.

use crate::types::{Change, Entry, EntryKind, FlatTree, RelPath};

/// Lexicographic prefix under which every strict descendant of `path` sorts.
/// The root's descendants are all other paths, so its prefix is the empty string.
pub(crate) fn descendant_prefix(path: &RelPath) -> String {
    if path.as_str().is_empty() {
        String::new()
    } else {
        format!("{}/", path.as_str())
    }
}

/// Exclusive lexicographic end of `path`'s subtree interval. Descendant keys are
/// exactly the strings in `[prefix, end)`: for `a/b` that is `["a/b/", "a/b0")`
/// (`'0' == '/' + 1`). The root's interval ends past every valid UTF-8 path.
pub(crate) fn subtree_end(path: &RelPath) -> String {
    if path.as_str().is_empty() {
        String::from(char::MAX)
    } else {
        let mut end = String::with_capacity(path.0.len() + 1);
        end.push_str(path.as_str());
        end.push('0'); // '/' + 1 — always ASCII, never breaks UTF-8
        end
    }
}

/// Whether two entries at the SAME path differ as nodes. Directories are compared
/// on identity only (kind + problem state) — their contents live at descendant
/// paths and are compared there, which is what keeps dir-mode noise (e.g. setgid
/// inheritance on the PVC) out of the change list. Every other kind carries no
/// children (types.rs contract), so full equality is the fingerprint: content
/// digest + executable bit for files, target for symlinks.
fn node_differs(o: &Entry, n: &Entry) -> bool {
    if o.kind != n.kind {
        return true;
    }
    match o.kind {
        EntryKind::Directory => o.problem != n.problem,
        _ => o != n,
    }
}

/// Whole-subtree diff of `current` against `baseline`.
///
/// Emits one `Change` per differing node, walking the sorted union of paths
/// top-down. At the first differing node the change is emitted and its subtree is
/// suppressed (the emitted `Change` carries both entries, directory entries
/// including their subtrees — the replacement is whole-subtree). Nodes equal on
/// both sides — including two directories whose contents match — produce nothing
/// and are descended into, so a modified file inside an unchanged directory is a
/// change at the FILE path, not the directory.
///
/// Deletions are `new: None`, creations `old: None`.
#[must_use]
pub fn diff(baseline: &FlatTree, current: &FlatTree) -> Vec<Change> {
    // Sorted union of both key sets (copia's reconcile walk: collect, sort, dedup).
    let mut paths: Vec<&RelPath> = baseline.keys().chain(current.keys()).collect();
    paths.sort_unstable();
    paths.dedup();

    let mut changes = Vec::new();
    // Active subtree suppressions as (prefix, exclusive_end). Suppressed intervals
    // cannot nest (everything inside one is skipped before it could emit), but a
    // sibling sorting between a subtree's prefix and its end (e.g. `a/b!` against
    // `a/b/`) must NOT be swallowed, hence prefix+end rather than a single bound.
    let mut sups: Vec<(String, String)> = Vec::new();

    for p in paths {
        sups.retain(|(_, end)| p.0.as_str() < end.as_str());
        if sups
            .iter()
            .any(|(pre, _)| p.0.as_str().starts_with(pre.as_str()))
        {
            continue; // covered by an ancestor's whole-subtree change
        }

        let old = baseline.get(p);
        let new = current.get(p);
        let differs = match (old, new) {
            (Some(o), Some(n)) => node_differs(o, n),
            _ => true, // created or deleted
        };
        if !differs {
            continue;
        }
        sups.push((descendant_prefix(p), subtree_end(p)));
        changes.push(Change {
            path: p.clone(),
            old: old.cloned(),
            new: new.cloned(),
        });
    }
    changes
}

/// Apply `changes` to a flat tree in place — the ancestor mutator. `old` is
/// ignored (mutagen semantics: the new state is authoritative).
///
/// Each change first removes the ENTIRE subtree at `path` (node + descendants),
/// then inserts `new` — flattening any directory children back into the flat
/// index so a whole-subtree change reconstructs every descendant path. The
/// nested `children` copies inside every ancestor entry are then re-synced from
/// the flat index along the changed path, so the dual representation (flat
/// index + nested entries) stays lossless-consistent — with
/// `changes = diff(baseline, current)` this transforms a copy of `baseline`
/// into exactly `current` (asserted in tests).
pub fn apply_to_flat(tree: &mut FlatTree, changes: &[Change]) {
    for c in changes {
        remove_subtree(tree, &c.path);
        if let Some(new) = &c.new {
            let entry = new.clone();
            tree.insert(c.path.clone(), entry.clone());
            flatten_children(tree, &c.path, &entry);
        }
        sync_ancestors(tree, &c.path);
    }
}

/// Remove `path` and every descendant key from the flat index.
fn remove_subtree(tree: &mut FlatTree, path: &RelPath) {
    if path.as_str().is_empty() {
        tree.clear(); // the root: everything is in its subtree
        return;
    }
    let doomed: Vec<RelPath> = tree
        .range(RelPath(descendant_prefix(path))..RelPath(subtree_end(path)))
        .map(|(k, _)| k.clone())
        .collect();
    for k in doomed {
        tree.remove(&k);
    }
    tree.remove(path);
}

/// Materialize a directory entry's nested children into the flat index.
fn flatten_children(tree: &mut FlatTree, parent: &RelPath, entry: &Entry) {
    if entry.kind != EntryKind::Directory {
        return;
    }
    for (leaf, child) in &entry.children {
        let child_path = parent.join(leaf);
        tree.insert(child_path.clone(), child.clone());
        flatten_children(tree, &child_path, child);
    }
}

/// Re-sync the nested-children copies of every ancestor of `path` from the flat
/// index (leaf up to the root), so a directory entry's `children` field always
/// mirrors the flat index after a change. Walks at most the path's depth; each
/// step is one child-map update.
fn sync_ancestors(tree: &mut FlatTree, path: &RelPath) {
    let mut child_path = path.clone();
    while let Some(parent) = child_path.parent() {
        let is_dir = tree
            .get(&parent)
            .is_some_and(|e| e.kind == EntryKind::Directory);
        if !is_dir {
            break; // no directory entry to keep in sync (root not materialized, etc.)
        }
        let mut updated = tree.get(&parent).cloned().expect("checked above");
        match tree.get(&child_path) {
            Some(child) => {
                updated.children.insert(child_path.leaf().to_string(), child.clone());
            }
            None => {
                updated.children.remove(child_path.leaf());
            }
        }
        tree.insert(parent.clone(), updated);
        child_path = parent;
    }
}

/// True when `baseline` holds at least one synchronizable entry and `current`
/// holds none — mutagen's "one-sided root emptied" halt (plan §2, safety halt 1).
/// A materialized root *directory* node (`kind == Directory` at `RelPath::root()`)
/// is container, not content; any other root entry counts as content.
#[must_use]
pub fn root_emptied(baseline: &FlatTree, current: &FlatTree) -> bool {
    has_root_content(baseline) && !has_root_content(current)
}

fn has_root_content(t: &FlatTree) -> bool {
    t.keys().any(|p| !p.as_str().is_empty())
        || t.get(&RelPath::root())
            .is_some_and(|e| e.kind != EntryKind::Directory)
}

/// True when both trees materialize the root (an entry at `RelPath::root()`) and
/// its kinds differ — mutagen's root-type-change halt (plan §2, safety halt 3).
/// When the root is not materialized (the common FlatTree convention: keys are
/// strictly below the root), no root type change is representable → `false`.
#[must_use]
pub fn root_type_changed(baseline: &FlatTree, current: &FlatTree) -> bool {
    match (
        baseline.get(&RelPath::root()),
        current.get(&RelPath::root()),
    ) {
        (Some(o), Some(n)) => o.kind != n.kind,
        _ => false,
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
    fn tree(entries: Vec<(&str, Entry)>) -> FlatTree {
        entries
            .into_iter()
            .map(|(p, e)| (RelPath(p.to_string()), e))
            .collect()
    }
    fn paths(changes: &[Change]) -> Vec<String> {
        changes.iter().map(|c| c.path.0.clone()).collect()
    }

    #[test]
    fn whole_subtree_granularity_nested_dir_swap() {
        // `d` flips from directory (two files) to regular file: ONE change at the
        // dir path — the old subtree travels inside `old.children`, no separate
        // deletion changes for the swallowed children. (Fixture honors the
        // lossless-flatten convention: the dir entry's children mirror the flat
        // index.)
        let baseline = tree(vec![
            (
                "d",
                Entry::directory(BTreeMap::from([("f".into(), f(1)), ("x".into(), f(2))])),
            ),
            ("d/f", f(1)),
            ("d/x", f(2)),
        ]);
        let current = tree(vec![("d", f(3))]);
        let changes = diff(&baseline, &current);
        assert_eq!(paths(&changes), vec!["d".to_string()]);
        assert_eq!(changes[0].old.as_ref().unwrap().kind, EntryKind::Directory);
        assert_eq!(changes[0].old.as_ref().unwrap().children.len(), 2);
        assert_eq!(changes[0].new.as_ref().unwrap().kind, EntryKind::File);
    }

    #[test]
    fn content_change_inside_unchanged_dir_is_one_change_at_the_file() {
        // Equal directory nodes are descended into: the change lands at `d/f`,
        // mutagen granularity — NOT a whole-dir replacement.
        let baseline = tree(vec![
            ("d", Entry::directory(BTreeMap::from([("f".into(), f(1))]))),
            ("d/f", f(1)),
        ]);
        let current = tree(vec![
            ("d", Entry::directory(BTreeMap::from([("f".into(), f(2))]))),
            ("d/f", f(2)),
        ]);
        let changes = diff(&baseline, &current);
        assert_eq!(paths(&changes), vec!["d/f".to_string()]);
        assert_eq!(changes[0].old.as_ref().unwrap().digest, Some([1; 32]));
        assert_eq!(changes[0].new.as_ref().unwrap().digest, Some([2; 32]));
    }

    #[test]
    fn deletion_detection_single_change_per_dir() {
        // Deleting a whole directory is ONE change (new: None) covering the tree;
        // deleting a bare file is one change at the file.
        let baseline = tree(vec![
            ("d", Entry::directory(BTreeMap::from([("f".into(), f(1))]))),
            ("d/f", f(1)),
            ("gone", f(2)),
        ]);
        let changes = diff(&baseline, &FlatTree::new());
        assert_eq!(paths(&changes), vec!["d".to_string(), "gone".to_string()]);
        assert!(changes[0].is_deletion());
        assert!(changes[1].is_deletion());
    }

    #[test]
    fn creation_of_dir_carries_whole_subtree() {
        let dir = Entry::directory(BTreeMap::from([
            ("a".into(), f(1)),
            ("sub".into(), Entry::directory(BTreeMap::from([("b".into(), f(2))]))),
        ]));
        let current = tree(vec![("d", dir), ("d/a", f(1)), ("d/sub", Entry::directory(BTreeMap::from([("b".into(), f(2))]))), ("d/sub/b", f(2))]);
        let changes = diff(&FlatTree::new(), &current);
        assert_eq!(paths(&changes), vec!["d".to_string()]);
        assert_eq!(changes[0].old, None);
        assert_eq!(changes[0].new.as_ref().unwrap().children.len(), 2);
    }

    #[test]
    fn exec_bit_only_change_is_detected() {
        let baseline = tree(vec![("f", f(1))]);
        let current = tree(vec![("f", file(1, true))]);
        let changes = diff(&baseline, &current);
        assert_eq!(paths(&changes), vec!["f".to_string()]);
    }

    #[test]
    fn identical_trees_yield_no_changes() {
        let dir = Entry::directory(BTreeMap::from([("f".into(), f(1))]));
        let t = tree(vec![("d", dir.clone()), ("d/f", f(1)), ("l", {
            Entry {
                kind: EntryKind::SymbolicLink,
                children: BTreeMap::new(),
                digest: Some([7; 32]),
                executable: false,
                target: Some("t".into()),
                mode: 0o644,
                size: 0,
                problem: None,
            }
        })]);
        assert!(diff(&t, &t).is_empty());
        let _ = dir; // moved above
    }

    #[test]
    fn root_emptied_detection() {
        let full = tree(vec![("f", f(1))]);
        let empty = FlatTree::new();
        assert!(root_emptied(&full, &empty), "content vanished → halt");
        assert!(!root_emptied(&empty, &full), "creation is not an emptying");
        assert!(!root_emptied(&empty, &empty));
        // A materialized root DIRECTORY alone is not content.
        let root_dir = tree(vec![("d", Entry::directory(BTreeMap::new()))]);
        let root_dir_keyed = FlatTree::from([(RelPath::root(), Entry::directory(BTreeMap::new()))]);
        assert!(root_emptied(&root_dir, &root_dir_keyed));
    }

    #[test]
    fn root_type_changed_detection() {
        let root_file = FlatTree::from([(RelPath::root(), f(1))]);
        let root_dir = FlatTree::from([(RelPath::root(), Entry::directory(BTreeMap::new()))]);
        assert!(root_type_changed(&root_dir, &root_file));
        assert!(!root_type_changed(&root_dir, &root_dir));
        // Root not materialized → not representable → false.
        assert!(!root_type_changed(&tree(vec![("f", f(1))]), &FlatTree::new()));
    }

    #[test]
    fn sibling_between_path_and_its_slash_prefix_is_not_subsumed() {
        // `d!` sorts between `d` and `d/`: suppression must be by prefix, not a
        // bare lexicographic bound, or the sibling's change would be swallowed
        // by the whole-subtree change at `d`.
        let baseline = tree(vec![
            ("d", Entry::directory(BTreeMap::from([("f".into(), f(1))]))),
            ("d/f", f(1)),
            ("d!", f(2)),
        ]);
        let current = tree(vec![("d", f(3)), ("d!", f(4))]);
        let changes = diff(&baseline, &current);
        assert_eq!(paths(&changes), vec!["d".to_string(), "d!".to_string()]);
    }

    #[test]
    fn apply_to_flat_roundtrips_current() {
        // THE load-bearing property: baseline + diff → current, exactly.
        let baseline = tree(vec![
            ("kept", f(1)),
            ("d", Entry::directory(BTreeMap::from([("f".into(), f(2))]))),
            ("d/f", f(2)),
            ("swapped", f(3)),
        ]);
        let current = tree(vec![
            ("kept", f(1)),
            ("d", Entry::directory(BTreeMap::from([
                ("f".into(), f(9)),
                ("new".into(), f(4)),
            ]))),
            ("d/f", f(9)),
            ("d/new", f(4)),
            ("swapped", Entry::directory(BTreeMap::from([("x".into(), f(5))]))),
            ("swapped/x", f(5)),
        ]);
        let changes = diff(&baseline, &current);
        let mut ancestor = baseline;
        apply_to_flat(&mut ancestor, &changes);
        assert_eq!(ancestor, current);
    }

    #[test]
    fn apply_to_flat_deletion_removes_subtree() {
        let mut t = tree(vec![
            ("d", Entry::directory(BTreeMap::from([("f".into(), f(1))]))),
            ("d/f", f(1)),
            ("d/sub", Entry::directory(BTreeMap::new())),
            ("sib", f(2)),
        ]);
        let changes = vec![Change {
            path: RelPath("d".into()),
            old: None,
            new: None,
        }];
        apply_to_flat(&mut t, &changes);
        assert_eq!(t.len(), 1);
        assert!(t.contains_key(&RelPath("sib".into())));
    }

    #[test]
    fn apply_to_flat_root_replacement_clears_everything() {
        let mut t = tree(vec![("a", f(1)), ("b", f(2))]);
        let changes = vec![Change {
            path: RelPath::root(),
            old: None,
            new: Some(Entry::directory(BTreeMap::from([("c".into(), f(3))]))),
        }];
        apply_to_flat(&mut t, &changes);
        assert_eq!(t.len(), 2); // root node + its flattened child
        assert!(t.contains_key(&RelPath::root()));
        assert!(t.contains_key(&RelPath("c".into())));
    }
}
