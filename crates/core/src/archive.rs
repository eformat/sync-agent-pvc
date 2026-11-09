// Adapted from paiml/copia (MIT) src/bin/copia/archive.rs — atomic versioned archive, safe no-base semantics.
//! The bidirectional-sync archive: the last-synced common state (ancestor) for
//! one `(dir_a, dir_b)` pair, stored as ONE bincode file per state dir —
//! `<state_dir>/archive.bin` (default convention: `<sync_root>/.sync-agent/`).
//!
//! Keyed by blake3(canonical(dir_a) + NUL + canonical(dir_b)) + a format
//! version, so a lost/mismatched archive degrades to SAFE NO-BASE MODE rather
//! than being blindly trusted: `load` returns `Ok(None)` for missing, corrupt,
//! version-mismatched, or foreign archives — and the caller then runs with
//! `trust_base = false`, which makes deletes impossible (reconcile invariant 1).
//! `load` NEVER panics and NEVER returns a guess.
//!
//! Written atomically: write tmp → fsync tmp → fsync dir → copy current to
//! `.bak` → rename tmp into place → fsync dir again. The previous archive is
//! retained as `archive.bin.bak`.
//!
//! COMMIT-THEN-RECORD CONTRACT: `save` is only ever called AFTER the data the
//! ancestor describes has been committed on both endpoints (apply.rs enforces
//! the ordering — the archive is a record of applied state, never a promise).
//!
//! Serialization note: types.rs contract types (`Snapshot`/`Entry`/`EntryKind`)
//! carry no serde derives and must not be forked, so the stored representation
//! uses private mirror structs with field-by-field conversions. The
//! `Entry { .. }` construction in `From<SerEntry>` fails to compile if a field
//! is ever added to `Entry` without updating the mirror — deliberate safety net
//! against silently dropping fields from the archive.

use crate::types::{Entry, EntryKind, Snapshot};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Bump on any wire-incompatible change to the stored representation.
pub const FORMAT_VERSION: u32 = 1;

/// Archive file name inside the caller-supplied state dir.
pub const ARCHIVE_FILE: &str = "archive.bin";

/// The last-synced common state for one sync pair. Plain data — the caller
/// owns the load → reconcile → apply → save lifecycle (and the save happens
/// only after the data committed; see the module-level contract above).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveState {
    pub format_version: u32,
    /// blake3(canonical(dir_a) + NUL + canonical(dir_b)) — identifies the pair.
    /// Order-sensitive (A then B).
    pub root_pair_hash: [u8; 32],
    /// The ancestor snapshot both endpoints were last converged to.
    pub ancestor: Snapshot,
}

impl ArchiveState {
    /// A fresh (empty-ancestor) archive for the given pair.
    #[must_use]
    pub fn fresh(dir_a: &Path, dir_b: &Path) -> Self {
        ArchiveState {
            format_version: FORMAT_VERSION,
            root_pair_hash: root_pair_hash(dir_a, dir_b),
            ancestor: Snapshot::default(),
        }
    }

    /// Persist atomically (see module docs). Refuses to write a record whose
    /// `format_version` is not current — validate-before-atomic-save, plan §2.
    ///
    /// # Errors
    /// Propagates filesystem errors (unwritable state dir, fsync failures).
    pub fn save(&self, state_dir: &Path) -> std::io::Result<()> {
        if self.format_version != FORMAT_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to save archive with format_version {} (expected {FORMAT_VERSION})",
                    self.format_version
                ),
            ));
        }
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join(ARCHIVE_FILE);
        let tmp = state_dir.join(format!("{ARCHIVE_FILE}.tmp"));
        let bytes = bincode::serialize(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?; // 1. tmp contents durable
        }
        sync_dir(state_dir)?; // 2. tmp dir entry durable
        if path.exists() {
            let bak = state_dir.join(format!("{ARCHIVE_FILE}.bak"));
            // 3. retain the previous archive — copy (not rename) so there is
            // never a moment without a current file.
            let _ = std::fs::copy(&path, &bak);
        }
        std::fs::rename(&tmp, &path)?; // 4. atomic publish
        sync_dir(state_dir)?; // 5. rename durable
        Ok(())
    }
}

/// Namespace for archive file operations (no instances).
pub struct Archive;

impl Archive {
    /// Load the archive for the `(dir_a, dir_b)` pair from `state_dir` — iff it
    /// exists, parses, and matches the expected pair + format version. Any
    /// mismatch or error returns `Ok(None)`: the caller then runs in safe
    /// no-base mode (no deletes). Never trusts a foreign archive; never panics.
    /// In practice this never returns `Err` — every failure mode degrades to
    /// `Ok(None)`, because a state file we cannot make sense of must never
    /// enable destructive behavior.
    pub fn load(
        dir_a: &Path,
        dir_b: &Path,
        state_dir: &Path,
    ) -> std::io::Result<Option<ArchiveState>> {
        let expected = root_pair_hash(dir_a, dir_b);
        let bytes = match std::fs::read(state_dir.join(ARCHIVE_FILE)) {
            Ok(b) => b,
            // Missing — first sync. Unreadable (EACCES, EIO, ...) — equally
            // untrustworthy. Both: safe no-base.
            Err(_) => return Ok(None),
        };
        let state: ArchiveState = match bincode::deserialize(&bytes) {
            Ok(s) => s,
            Err(_) => return Ok(None), // corrupt / wrong format -> safe no-base
        };
        if state.format_version != FORMAT_VERSION {
            return Ok(None); // older/newer writer -> safe no-base
        }
        if state.root_pair_hash != expected {
            return Ok(None); // foreign pair's archive -> safe no-base
        }
        Ok(Some(state))
    }

    /// Deterministic identifier for a root pair (order-sensitive: A then B).
    /// Paths that cannot be canonicalized (should not happen for live roots)
    /// fall back to their literal form — copia's behavior; the hash only needs
    /// to be stable for the same inputs.
    #[must_use]
    pub fn root_pair_hash(dir_a: &Path, dir_b: &Path) -> [u8; 32] {
        root_pair_hash(dir_a, dir_b)
    }

    /// Full path of the archive file inside a state dir.
    #[must_use]
    pub fn state_path(state_dir: &Path) -> PathBuf {
        state_dir.join(ARCHIVE_FILE)
    }
}

fn root_pair_hash(dir_a: &Path, dir_b: &Path) -> [u8; 32] {
    let canon =
        |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let mut h = blake3::Hasher::new();
    h.update(canon(dir_a).as_os_str().as_encoded_bytes());
    h.update(b"\0");
    h.update(canon(dir_b).as_os_str().as_encoded_bytes());
    *h.finalize().as_bytes()
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

// ---- stored representation (private mirrors of the types.rs contract) ----
//
// bincode 1.x encodes structs as their fields in declaration order; the mirror
// declaration order below IS the on-disk format. Do not reorder casually —
// bump FORMAT_VERSION instead.

#[derive(Serialize, Deserialize)]
struct WireState(u32, [u8; 32], SerSnapshot);

#[derive(Serialize, Deserialize)]
struct SerSnapshot {
    root: BTreeMap<String, SerEntry>,
    preserves_executability: bool,
    file_count: u64,
    dir_count: u64,
    total_size: u64,
}

#[derive(Serialize, Deserialize)]
enum SerKind {
    Directory,
    File,
    SymbolicLink,
    Untracked,
    Problematic,
}

#[derive(Serialize, Deserialize)]
struct SerEntry {
    kind: SerKind,
    children: BTreeMap<String, SerEntry>,
    digest: Option<[u8; 32]>,
    executable: bool,
    target: Option<String>,
    mode: u32,
    size: u64,
    problem: Option<String>,
}

impl From<&Entry> for SerEntry {
    fn from(e: &Entry) -> Self {
        SerEntry {
            kind: match e.kind {
                EntryKind::Directory => SerKind::Directory,
                EntryKind::File => SerKind::File,
                EntryKind::SymbolicLink => SerKind::SymbolicLink,
                EntryKind::Untracked => SerKind::Untracked,
                EntryKind::Problematic => SerKind::Problematic,
            },
            children: e
                .children
                .iter()
                .map(|(k, v)| (k.clone(), SerEntry::from(v)))
                .collect(),
            digest: e.digest,
            executable: e.executable,
            target: e.target.clone(),
            mode: e.mode,
            size: e.size,
            problem: e.problem.clone(),
        }
    }
}

impl From<SerEntry> for Entry {
    fn from(s: SerEntry) -> Self {
        Entry {
            kind: match s.kind {
                SerKind::Directory => EntryKind::Directory,
                SerKind::File => EntryKind::File,
                SerKind::SymbolicLink => EntryKind::SymbolicLink,
                SerKind::Untracked => EntryKind::Untracked,
                SerKind::Problematic => EntryKind::Problematic,
            },
            children: s
                .children
                .into_iter()
                .map(|(k, v)| (k, Entry::from(v)))
                .collect(),
            digest: s.digest,
            executable: s.executable,
            target: s.target,
            mode: s.mode,
            size: s.size,
            problem: s.problem,
        }
    }
}

impl From<&Snapshot> for SerSnapshot {
    fn from(s: &Snapshot) -> Self {
        SerSnapshot {
            root: s
                .root
                .iter()
                .map(|(k, v)| (k.clone(), SerEntry::from(v)))
                .collect(),
            preserves_executability: s.preserves_executability,
            file_count: s.file_count,
            dir_count: s.dir_count,
            total_size: s.total_size,
        }
    }
}

impl From<SerSnapshot> for Snapshot {
    fn from(s: SerSnapshot) -> Self {
        Snapshot {
            root: s
                .root
                .into_iter()
                .map(|(k, v)| (k, Entry::from(v)))
                .collect(),
            preserves_executability: s.preserves_executability,
            file_count: s.file_count,
            dir_count: s.dir_count,
            total_size: s.total_size,
        }
    }
}

impl From<&ArchiveState> for WireState {
    fn from(s: &ArchiveState) -> Self {
        WireState(s.format_version, s.root_pair_hash, SerSnapshot::from(&s.ancestor))
    }
}

impl From<WireState> for ArchiveState {
    fn from(w: WireState) -> Self {
        ArchiveState {
            format_version: w.0,
            root_pair_hash: w.1,
            ancestor: Snapshot::from(w.2),
        }
    }
}

impl Serialize for ArchiveState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WireState::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ArchiveState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        WireState::deserialize(deserializer).map(ArchiveState::from)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn f(d: u8) -> Entry {
        Entry {
            kind: EntryKind::File,
            children: BTreeMap::new(),
            digest: Some([d; 32]),
            executable: false,
            target: None,
            mode: 0o644,
            size: 1,
            problem: None,
        }
    }

    fn state_with(entries: Vec<(&str, Entry)>) -> ArchiveState {
        let mut ancestor = Snapshot::default();
        let count = entries.len();
        for (p, e) in entries {
            ancestor.root.insert(p.to_string(), e);
        }
        ancestor.file_count = count as u64;
        ArchiveState {
            format_version: FORMAT_VERSION,
            root_pair_hash: [7; 32],
            ancestor,
        }
    }

    #[test]
    fn roundtrip_preserves_ancestor_and_pair_hash() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("side-a"), dir.path().join("side-b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let state_dir = dir.path().join(".sync-agent");

        let mut state = ArchiveState::fresh(&a, &b);
        state.ancestor = state_with(vec![("f", f(9)), ("d", Entry::directory(BTreeMap::from([("g".into(), f(1))])))])
            .ancestor;
        state.ancestor.preserves_executability = true;
        let expected_hash = state.root_pair_hash;
        state.save(&state_dir).unwrap();

        let loaded = Archive::load(&a, &b, &state_dir).unwrap().expect("round-trips");
        assert_eq!(loaded, state);
        assert_eq!(loaded.root_pair_hash, expected_hash);
        assert_eq!(loaded.ancestor.root["f"].digest, Some([9; 32]));
        assert_eq!(
            loaded.ancestor.root["d"].children["g"].digest,
            Some([1; 32])
        );
        assert!(loaded.ancestor.preserves_executability);
    }

    #[test]
    fn missing_archive_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("x"), dir.path().join("y"));
        let got = Archive::load(&a, &b, dir.path()).unwrap();
        assert!(got.is_none(), "first sync has no archive: safe no-base");
    }

    #[test]
    fn corrupt_archive_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("x"), dir.path().join("y"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let state_dir = dir.path().join(".sync-agent");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(Archive::state_path(&state_dir), b"not bincode at all \xff\xfe").unwrap();
        assert!(Archive::load(&a, &b, &state_dir).unwrap().is_none());
        // Truncated-but-parseable-prefix garbage too.
        let state = state_with(vec![("f", f(1))]);
        let bytes = bincode::serialize(&state).unwrap();
        std::fs::write(Archive::state_path(&state_dir), &bytes[..bytes.len() / 2]).unwrap();
        assert!(Archive::load(&a, &b, &state_dir).unwrap().is_none());
    }

    #[test]
    fn corrupt_archive_and_bak_is_safe_no_base() {
        // M6 chaos gate: a killed machine can leave BOTH the archive and its
        // .bak torn (the save is tmp → fsync → .bak copy → rename, but a
        // dying disk does not respect discipline). Load must degrade to a
        // safe no-base — full rescan with deletes disabled — never panic,
        // never guess, never fall back to a foreign tree.
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("x"), dir.path().join("y"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let state_dir = dir.path().join(".sync-agent");
        std::fs::create_dir_all(&state_dir).unwrap();
        let mut state = state_with(vec![("f", f(1))]);
        state.root_pair_hash = Archive::root_pair_hash(&a, &b);
        state.save(&state_dir).unwrap();
        assert!(Archive::load(&a, &b, &state_dir).unwrap().is_some(), "sanity: pair matches");
        std::fs::write(Archive::state_path(&state_dir), b"\xde\xadgarbage").unwrap();
        std::fs::write(state_dir.join(format!("{ARCHIVE_FILE}.bak")), b"\xbe\xefgarbage").unwrap();
        assert!(Archive::load(&a, &b, &state_dir).unwrap().is_none(), "both torn → no-base");
        // And the next save re-seeds a clean archive + .bak from scratch.
        state.save(&state_dir).unwrap();
        assert!(Archive::load(&a, &b, &state_dir).unwrap().is_some());
    }

    #[test]
    fn version_mismatch_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("x"), dir.path().join("y"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let state_dir = dir.path().join(".sync-agent");
        std::fs::create_dir_all(&state_dir).unwrap();
        // Hand-write a future-version record (save() refuses to produce one).
        let future = ArchiveState {
            format_version: FORMAT_VERSION + 1,
            ..state_with(vec![("f", f(1))])
        };
        let bytes = bincode::serialize(&future).unwrap();
        std::fs::write(Archive::state_path(&state_dir), bytes).unwrap();
        assert!(Archive::load(&a, &b, &state_dir).unwrap().is_none());
    }

    #[test]
    fn pair_mismatch_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("x"), dir.path().join("y"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let other = dir.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        let state_dir = dir.path().join(".sync-agent");
        ArchiveState::fresh(&a, &b).save(&state_dir).unwrap();
        // The right pair loads...
        assert!(Archive::load(&a, &b, &state_dir).unwrap().is_some());
        // ...any foreign pair (including order-swapped) is rejected.
        assert!(Archive::load(&a, &other, &state_dir).unwrap().is_none());
        assert!(Archive::load(&other, &b, &state_dir).unwrap().is_none());
    }

    #[test]
    fn bak_retained_on_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join(".sync-agent");
        let v1 = state_with(vec![("old", f(1))]);
        v1.save(&state_dir).unwrap();
        let v2 = state_with(vec![("new", f(2))]);
        v2.save(&state_dir).unwrap();

        let bak_path = state_dir.join(format!("{ARCHIVE_FILE}.bak"));
        assert!(bak_path.exists(), "previous archive retained as .bak");
        let bak: ArchiveState = bincode::deserialize(&std::fs::read(&bak_path).unwrap()).unwrap();
        assert_eq!(bak, v1, ".bak holds the PREVIOUS archive");
        let cur = Archive::state_path(&state_dir);
        let cur: ArchiveState = bincode::deserialize(&std::fs::read(&cur).unwrap()).unwrap();
        assert_eq!(cur, v2);
        // No tmp litter.
        assert!(!state_dir.join(format!("{ARCHIVE_FILE}.tmp")).exists());
    }

    #[test]
    fn save_refuses_wrong_format_version() {
        let dir = tempfile::tempdir().unwrap();
        let bad = ArchiveState {
            format_version: 0,
            ..state_with(vec![])
        };
        assert!(bad.save(dir.path()).is_err());
    }

    #[test]
    fn root_pair_hash_is_order_sensitive_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("x"), dir.path().join("y"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        assert_eq!(root_pair_hash(&a, &b), root_pair_hash(&a, &b));
        assert_ne!(root_pair_hash(&a, &b), root_pair_hash(&b, &a));
        // Nonexistent roots fall back to literal paths — still stable.
        let (g1, g2) = (dir.path().join("ghost1"), dir.path().join("ghost2"));
        assert_eq!(root_pair_hash(&g1, &g2), root_pair_hash(&g1, &g2));
    }

    #[test]
    fn fresh_state_hashes_its_pair() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("x"), dir.path().join("y"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let s = ArchiveState::fresh(&a, &b);
        assert_eq!(s.format_version, FORMAT_VERSION);
        assert_eq!(s.root_pair_hash, root_pair_hash(&a, &b));
        assert!(s.ancestor.root.is_empty());
        // Save + load through the real API round-trips the pair identity.
        let state_dir = dir.path().join(".sync-agent");
        s.save(&state_dir).unwrap();
        assert!(Archive::load(&a, &b, &state_dir).unwrap().is_some());
        // Swapped roots are a DIFFERENT pair -> safe no-base.
        assert!(Archive::load(&b, &a, &state_dir).unwrap().is_none());
    }
}
