//! Shared engine types — THE CONTRACT for crates/core modules.
//!
//! scan.rs/cache.rs/ignore.rs/apply.rs (scanner side) and reconcile.rs/archive.rs/change.rs
//! (reconcile side) both build on these. Do not fork these types per-module.
//!
//! Design source: ~/.opencode/plan/sync-agent-pvc.md §2 (mutagen-model + vendored copia cores).
//! Attribution: reconcile/archive semantics adapted from paiml/copia (MIT) — keep the
//! attribution headers in those files.

use std::collections::BTreeMap;

/// Root-relative, `/`-separated path (empty string = root). Load-bearing convention
/// (mutagen): every map key uses this form; never store absolute paths here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(pub String);

impl RelPath {
    pub fn root() -> Self {
        RelPath(String::new())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Join a child leaf name (must not contain '/').
    pub fn join(&self, leaf: &str) -> RelPath {
        if self.0.is_empty() {
            RelPath(leaf.to_string())
        } else {
            RelPath(format!("{}/{}", self.0, leaf))
        }
    }
    /// Parent path (None for root).
    pub fn parent(&self) -> Option<RelPath> {
        match self.0.rsplit_once('/') {
            Some((p, _)) => Some(RelPath(p.to_string())),
            None if self.0.is_empty() => None,
            None => Some(RelPath::root()),
        }
    }
    /// Final leaf name ("" for root).
    pub fn leaf(&self) -> &str {
        match self.0.rsplit_once('/') {
            Some((_, l)) => l,
            None => &self.0,
        }
    }
}

impl std::fmt::Display for RelPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", if self.0.is_empty() { "<root>" } else { &self.0 })
    }
}

/// Synchronizable + representable kinds (mutagen entry.proto analog).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryKind {
    Directory,
    File,
    SymbolicLink,
    /// Ignored content, FIFOs, sockets, devices — occupies a slot so both endpoints
    /// agree it exists, but is NEVER transitioned (copia/mutagen Untracked semantics).
    Untracked,
    /// Scan failed (EACCES etc.). NEVER treated as absent — plan §8: unreadable ≠ absent;
    /// a Problematic entry blocks propagation rather than enabling deletes.
    Problematic,
}

/// blake3 content digest (32 bytes). Sole content oracle — mtime never decides anything.
pub type Digest = [u8; 32];

/// One node of the entry tree (what a scan produces and the archive stores).
/// Directories carry `children`; files carry digest+size+mode; symlinks carry target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// Directories: children keyed by leaf name. Others: empty.
    pub children: BTreeMap<String, Entry>,
    /// File content digest (blake3). Symlink: blake3 of the target string (copia semantics —
    /// target changes are content changes). Untracked/Problematic: none.
    pub digest: Option<Digest>,
    /// Executable bit (files only, preserved-vs-not per snapshot flag; §8: mode bits only).
    pub executable: bool,
    /// Symlink target as stored (raw string; posix-raw mode).
    pub target: Option<String>,
    /// File mode bits we sync (exec propagation result). Directories: default 0755.
    pub mode: u32,
    /// File size in bytes (files only).
    pub size: u64,
    /// Problematic entries: what went wrong (never silently skipped).
    pub problem: Option<String>,
}

impl Entry {
    pub fn directory(children: BTreeMap<String, Entry>) -> Self {
        Entry {
            kind: EntryKind::Directory,
            children,
            digest: None,
            executable: false,
            target: None,
            mode: 0o755,
            size: 0,
            problem: None,
        }
    }
    pub fn untracked() -> Self {
        Entry {
            kind: EntryKind::Untracked,
            ..Self::empty()
        }
    }
    pub fn problematic(msg: impl Into<String>) -> Self {
        Entry {
            kind: EntryKind::Problematic,
            problem: Some(msg.into()),
            ..Self::empty()
        }
    }
    fn empty() -> Self {
        Entry {
            kind: EntryKind::Untracked,
            children: BTreeMap::new(),
            digest: None,
            executable: false,
            target: None,
            mode: 0,
            size: 0,
            problem: None,
        }
    }
}

/// Cache validation metadata (mutagen cache.proto analog): a scan reuses the previous
/// digest only when ALL of these match — otherwise re-hash with blake3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub mode: u32,
    /// Nanosecond-precision mtime (as reported by the platform).
    pub mtime_nanos: i64,
    pub size: u64,
    /// Inode (POSIX). 0 where unavailable.
    pub inode: u64,
}

/// Per-path cache entry: last-known metadata + the digest it validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub meta: FileMeta,
    pub digest: Digest,
}

/// Whole-tree snapshot: the entry tree + behavior flags (mutagen snapshot.proto analog).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub root: BTreeMap<String, Entry>,
    /// Whether this endpoint preserves the executable bit (Linux ext4: true; the PVC may
    /// differ — propagations consult this, mutagen executability.go).
    pub preserves_executability: bool,
    /// Statistics for the UI/dry-run.
    pub file_count: u64,
    pub dir_count: u64,
    pub total_size: u64,
}

/// Flattened view used by the reconciler: path → leaf entry (directories included).
/// Building this from a Snapshot is O(tree); reconcilers never walk the nested form.
pub type FlatTree = BTreeMap<RelPath, Entry>;

/// One detected change vs the baseline: whole-subtree replacement at `path`
/// (copia change.go semantics — Old is informational; Apply ignores it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: RelPath,
    pub old: Option<Entry>,
    pub new: Option<Entry>,
}

impl Change {
    pub fn is_deletion(&self) -> bool {
        self.new.is_none()
    }
}

/// Reconciler decision for one path (copia reconcile_path analog, TwoWaySafe only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Noop,
    PropagateAtoB,
    PropagateBtoA,
    /// Both sides already converged (both-modified-same): refresh the ancestor only.
    ConvergeIdentical,
    DeleteA,
    DeleteB,
    /// Both changed differently — per policy: newest-wins + conflict copy (daemon decides
    /// which side wins; the reconciler only REPORTS the conflict root + both change sets).
    Conflict,
}

/// A reported conflict: the highest path where a forced choice was needed, plus both
/// sides' change lists. Pure metadata — conflicts never feed back into the algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub root: RelPath,
    pub alpha_changes: Vec<Change>,
    pub beta_changes: Vec<Change>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relpath_join_parent_leaf() {
        let p = RelPath::root().join("home").join("file.txt");
        assert_eq!(p.as_str(), "home/file.txt");
        assert_eq!(p.leaf(), "file.txt");
        assert_eq!(p.parent(), Some(RelPath("home".into())));
        assert_eq!(RelPath::root().parent(), None);
        assert_eq!(RelPath::root().leaf(), "");
    }

    #[test]
    fn problematic_is_not_absent() {
        // §8 invariant smoke: a Problematic entry must be distinguishable from deletion
        // (None) everywhere the reconciler makes delete decisions.
        let e = Entry::problematic("EACCES");
        assert_eq!(e.kind, EntryKind::Problematic);
        assert!(e.problem.is_some());
    }
}
