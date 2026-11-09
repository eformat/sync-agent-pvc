//! Scanner: parallel filesystem walk → `Snapshot` (+ fresh metadata cache).
//!
//! Semantics ported from mutagen (design source, Go — ported ideas, not code):
//! - `pkg/synchronization/core/scan.go` (`cacheContentMatch`): a prior digest is
//!   reusable only when type/mtime/size/file-ID all match; we compare the full
//!   `FileMeta{mode, mtime_nanos, size, inode}` (mode included per plan §8).
//! - Plan §8, CRITICAL: problematic ≠ absent. Stat/read/hash errors (EACCES, EIO, …)
//!   produce `EntryKind::Problematic` entries — NEVER silent skips. A skipped file
//!   looks absent to the reconciler, which would then delete the peer's copy (the
//!   copia defect from M0 spike (e)).
//! - `EntryKind::Untracked`: ignored content, FIFOs, sockets, devices — present in
//!   the tree so both endpoints agree it exists; never opened, never hashed, never
//!   transitioned. Ignored directories collapse to a single Untracked leaf (mutagen
//!   never traverses ignored content; negations cannot re-include inside an ignored
//!   dir). No copia phantom-dir machinery.
//! - Symlinks: never followed (`symlink_metadata` everywhere), posix-raw target
//!   strings, digest = blake3(target bytes) — retargeting is a content change.
//!
//! Attribution: ignore-pattern parsing/matching is a port of mutagen
//! `pkg/synchronization/core/ignore/mutagen/ignore.go` semantics.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ignore::{DirEntry, Error as WalkError, WalkBuilder, WalkState};

use crate::cache::{validate, CacheMap};
use crate::types::{CacheEntry, Digest, Entry, EntryKind, FileMeta, FlatTree, RelPath, Snapshot};

/// v1 executability probe (plan §2/§8): ext4/btrfs/xfs/tmpfs (and the gp3 PVC) all
/// preserve the exec bit, so v1 assumes `true` unconditionally. TODO(M6): replace with
/// a cheap fstatfs `f_type` check (or copia-style probe files) when a FAT/9p/SMB
/// target becomes possible.
const PRESERVES_EXECUTABILITY_V1: bool = true;

/// 64 KiB streaming hash buffer (plan §2: blake3, chunked).
const HASH_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Ignore rules (mutagen-style syntax)
// ---------------------------------------------------------------------------

/// One parsed Mutagen-style ignore pattern. Port of mutagen
/// `pkg/synchronization/core/ignore/mutagen/ignore.go::newIgnorePattern`:
/// - `!` prefix negates (re-includes); last matching pattern wins.
/// - leading `/` anchors to the sync root; otherwise a slash-free pattern also
///   matches any path's leaf name (`match_leaf`).
/// - trailing `/` restricts the pattern to directories.
/// - a slash anywhere inside the pattern makes it root-anchored.
#[derive(Debug, Clone)]
struct IgnorePattern {
    negated: bool,
    directory_only: bool,
    match_leaf: bool,
    matcher: globset::GlobMatcher,
}

/// `globset` with `literal_separator(true)` gives doublestar semantics: `*` never
/// crosses `/`, `**` does. Mutagen matches with `doublestar.Match`, so this is the
/// faithful Rust equivalent.
fn parse_pattern(pattern: &str) -> Result<IgnorePattern, String> {
    if pattern.is_empty() {
        return Err("empty pattern".to_string());
    }
    let (negated, pattern) = match pattern.strip_prefix('!') {
        Some(rest) => {
            if rest.is_empty() {
                return Err("negated empty pattern".to_string());
            }
            (true, rest)
        }
        None => (false, pattern),
    };

    // Clean the pattern while preserving the leading/trailing slash markers
    // (mutagen cleanPreservingTrailingSlash).
    let absolute = pattern.starts_with('/');
    let directory_only = pattern.len() > 1 && pattern.ends_with('/');
    let joined = pattern
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != ".")
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        return Err("pattern targets the sync root".to_string());
    }
    let contains_slash = joined.contains('/');
    let matcher = globset::GlobBuilder::new(&joined)
        .literal_separator(true)
        .build()
        .map_err(|e| format!("invalid glob: {e}"))?
        .compile_matcher();
    Ok(IgnorePattern {
        negated,
        directory_only,
        match_leaf: !absolute && !contains_slash,
        matcher,
    })
}

fn pattern_matches(p: &IgnorePattern, path: &str, is_dir: bool) -> bool {
    if p.directory_only && !is_dir {
        return false;
    }
    if p.matcher.is_match(path) {
        return true;
    }
    if p.match_leaf {
        let leaf = match path.rsplit_once('/') {
            Some((_, l)) => l,
            None => path,
        };
        if p.matcher.is_match(leaf) {
            return true;
        }
    }
    false
}

/// Ordered ignore-rule set. Evaluation port of mutagen's `ignorer.Ignore`: patterns
/// apply in order and the last match decides, so `!` negation re-includes.
///
/// Patterns that fail to parse are recorded in `rejected` (surfaced by the caller —
/// silently dropping a pattern would sync data the user believed excluded) and do
/// not participate in matching.
#[derive(Debug, Clone, Default)]
pub struct IgnoreRules {
    patterns: Vec<IgnorePattern>,
    rejected: Vec<String>,
}

impl IgnoreRules {
    /// Build rules from a pattern list (config order = evaluation order; later
    /// matches win, so negations come after the patterns they refine).
    pub fn new(patterns: Vec<String>) -> Self {
        let mut rules = IgnoreRules::default();
        for p in patterns {
            match parse_pattern(&p) {
                Ok(ip) => rules.patterns.push(ip),
                Err(e) => rules.rejected.push(format!("{p}: {e}")),
            }
        }
        rules
    }

    /// Patterns that failed to parse (caller surfaces these — never silent).
    pub fn rejected(&self) -> &[String] {
        &self.rejected
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// True when `path` is ignore-masked. The root ("") is never ignored (mutagen:
    /// the root is never evaluated for ignoring).
    pub fn matches(&self, path: &RelPath, is_dir: bool) -> bool {
        let path = path.as_str();
        if path.is_empty() {
            return false;
        }
        let mut ignored = false;
        for p in &self.patterns {
            if pattern_matches(p, path, is_dir) {
                ignored = !p.negated;
            }
        }
        ignored
    }
}

/// Load `<root>/.syncignore` (same syntax as the config pattern list). A missing file
/// is not an error. Blank lines and `#` comments are skipped (this is a line-oriented
/// file, unlike the YAML pattern lists mutagen uses). Callers merge the result with
/// config patterns via `IgnoreRules::new`; order decides precedence.
pub fn load_syncignore(root: &Path) -> io::Result<Vec<String>> {
    let path = root.join(".syncignore");
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

// ---------------------------------------------------------------------------
// Shared scan helpers
// ---------------------------------------------------------------------------

/// Our own transient artifacts are never part of the tree (plan §2: temp-name
/// convention + the `.sync-agent` state dir; mutagen skips its staging names the
/// same way). Applied at any depth.
///
/// SELF-INVERSION CONTRACT (M6): every writer's temp/state name MUST match one
/// of these two shapes, or the scanner sees our own writes as user changes and
/// the next pass syncs them back and forth forever. Writers, KEEP IN SYNC:
/// - core apply.rs `temp_name`            → `.sync-agent-tmp-<pid>-<n>`
/// - agent serve.rs `stage_temp_name`     → `.sync-agent-tmp-<pid>-<n>`
/// - cli remote_driver.rs `tmp_name`      → `.sync-agent-tmp-<pid>-<n>`
/// - cli transport.rs `upload_tmp_path`   → `.sync-agent-tmp-upload-<pid>`
///
/// Conflict copies (`*.sync-conflict-*`) are intentionally NOT skipped — they
/// are user-facing tree entries. The `scanner_skips_every_writer_temp_prefix`
/// test pins this contract.
pub(crate) fn is_internal_name(leaf: &str) -> bool {
    leaf.starts_with(".sync-agent-tmp-") || leaf == ".sync-agent"
}

/// Streaming blake3 over a regular file in 64 KiB chunks. Verifies that the bytes
/// read match the stat size (mutagen scan.go flags "hashed size mismatch" as a
/// problem rather than trusting the short read).
///
/// RACE: the file may change between stat and hash; the digest is a point-in-time
/// value. Delete-time verification (apply.rs) re-checks before destructive ops.
pub(crate) fn hash_file(path: &Path, expected_size: u64) -> io::Result<Digest> {
    // EACCES here propagates to the caller → Problematic, never "absent" (plan §8).
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    if total != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("hashed size mismatch: {total} != {expected_size}"),
        ));
    }
    Ok(hasher.finalize().into())
}

fn has_ignored_ancestor(set: &HashSet<String>, rel: &str) -> bool {
    let mut cur = rel;
    while let Some(pos) = cur.rfind('/') {
        let parent = &cur[..pos];
        if set.contains(parent) {
            return true;
        }
        cur = parent;
    }
    false
}

// ---------------------------------------------------------------------------
// Parallel walk
// ---------------------------------------------------------------------------

/// Flat rel-path → entry map accumulated during the walk, plus stats and the fresh
/// cache. Inserted entries are classified per visit; the nested `Snapshot` is built
/// once at the end, so thread interleaving cannot affect the result.
#[derive(Default)]
struct ScanState {
    flat: BTreeMap<String, Entry>,
    new_cache: CacheMap,
    file_count: u64,
    dir_count: u64,
    total_size: u64,
    /// Walker errors that carried no path (vanishingly rare) — counted and
    /// surfaced in the scan summary. Per-path attribution is impossible by
    /// construction (the walk error carries no path); the COUNT is the
    /// observable, and a nonzero count means the tree was not fully trusted
    /// this scan. (Resolves the M6 tracing TODO: nothing more to attach
    /// without upstream walkdar changes.)
    pathless_errors: u64,
}

struct ScanShared<'a> {
    rules: IgnoreRules,
    prior_cache: &'a CacheMap,
    /// Rel paths of collapsed ignored directories. The walker filter owns insertion
    /// (parent-before-child is guaranteed: a directory is yielded before its
    /// children are listed); the visitor consults it as belt-and-suspenders.
    ignored_dirs: Arc<Mutex<HashSet<String>>>,
    state: Mutex<ScanState>,
}

/// Problematic is sticky: a later yield for the same path must never downgrade an
/// error marker back to a normal entry — the error is the safety signal (plan §8).
fn insert_entry(st: &mut ScanState, rel: &str, entry: Entry) {
    if let Some(prev) = st.flat.get(rel) {
        if prev.kind == EntryKind::Problematic && entry.kind != EntryKind::Problematic {
            return;
        }
    }
    st.flat.insert(rel.to_string(), entry);
}

fn mark_problematic(shared: &ScanShared<'_>, rel: &str, msg: String) {
    let mut st = shared.state.lock().unwrap();
    if rel.is_empty() {
        // No representable parent to attach to (e.g. non-UTF-8 name at the top
        // level): count loudly instead of pretending all is well.
        st.pathless_errors += 1;
        eprintln!("sync-core scan: {msg}");
        return;
    }
    insert_entry(&mut st, rel, Entry::problematic(msg));
}

/// Extract a path from an ignore-crate error, when one exists.
fn walk_error_path(err: &WalkError) -> Option<PathBuf> {
    match err {
        WalkError::WithPath { path, .. } => Some(path.clone()),
        WalkError::Loop { child, .. } => Some(child.clone()),
        WalkError::Partial(errs) => errs.iter().find_map(walk_error_path),
        WalkError::WithDepth { err, .. } => walk_error_path(err),
        WalkError::WithLineNumber { err, .. } => walk_error_path(err),
        _ => None,
    }
}

/// One classified entry, ready to commit under the state lock (classification does
/// I/O — hashing must not hold the lock or parallelism dies).
struct Classified {
    entry: Entry,
    cache: Option<(String, CacheEntry)>,
    files: u64,
    dirs: u64,
    bytes: u64,
}

fn classify(shared: &ScanShared<'_>, rel: &str, path: &Path, meta: &fs::Metadata) -> Classified {
    use libc::{S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK};
    let mode = meta.mode();
    match mode & S_IFMT {
        S_IFDIR => Classified {
            entry: Entry::directory(BTreeMap::new()),
            cache: None,
            files: 0,
            dirs: 1,
            bytes: 0,
        },
        S_IFREG => {
            let size = meta.len();
            // Full-precision mtime in nanoseconds: mtime_nsec() alone is only the
            // nanoseconds-within-the-second field (st_mtim.tv_nsec) — seconds must
            // be folded in or two timestamps 2s apart (same subsecond position)
            // would compare equal and the quick-check would reuse a stale digest.
            let mtime_nanos = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();
            let fm = FileMeta {
                mode: mode & 0o7777,
                mtime_nanos,
                size,
                inode: meta.ino(),
            };
            // Quick-check (mutagen scan.go cacheContentMatch): reuse the prior digest
            // only when mode+mtime+size+inode all match; otherwise re-hash.
            let prior = shared.prior_cache.get(&RelPath(rel.to_string()));
            let digest = match validate(&fm, prior) {
                Some(d) => d,
                None => match hash_file(path, size) {
                    Ok(d) => d,
                    // CRITICAL (plan §8): unreadable ≠ absent. EACCES on open/read
                    // lands here as Problematic, blocking propagation of this path —
                    // never enabling a delete of the peer's copy.
                    Err(e) => {
                        return Classified {
                            entry: Entry::problematic(format!("unable to hash file: {e}")),
                            cache: None,
                            files: 0,
                            dirs: 0,
                            bytes: 0,
                        }
                    }
                },
            };
            let executable = PRESERVES_EXECUTABILITY_V1 && mode & 0o111 != 0;
            Classified {
                entry: Entry {
                    kind: EntryKind::File,
                    children: BTreeMap::new(),
                    digest: Some(digest),
                    executable,
                    target: None,
                    mode: mode & 0o7777,
                    size,
                    problem: None,
                },
                cache: Some((
                    rel.to_string(),
                    CacheEntry {
                        meta: fm,
                        digest,
                    },
                )),
                files: 1,
                dirs: 0,
                bytes: size,
            }
        }
        S_IFLNK => {
            // Never followed, never opened. The digest covers the raw target string
            // (copia semantics — retargeting is a content change).
            match fs::read_link(path) {
                Ok(target) => match target.into_os_string().into_string() {
                    Ok(t) => Classified {
                        entry: Entry {
                            kind: EntryKind::SymbolicLink,
                            children: BTreeMap::new(),
                            digest: Some(blake3::hash(t.as_bytes()).into()),
                            executable: false,
                            target: Some(t),
                            mode: mode & 0o7777,
                            size: 0,
                            problem: None,
                        },
                        cache: None,
                        files: 0,
                        dirs: 0,
                        bytes: 0,
                    },
                    Err(_) => Classified {
                        entry: Entry::problematic("non-UTF-8 symlink target".to_string()),
                        cache: None,
                        files: 0,
                        dirs: 0,
                        bytes: 0,
                    },
                },
                Err(e) => Classified {
                    entry: Entry::problematic(format!("unable to read symlink target: {e}")),
                    cache: None,
                    files: 0,
                    dirs: 0,
                    bytes: 0,
                },
            }
        }
        // FIFOs/sockets/devices: present in the tree, never opened, never hashed,
        // never transitioned (mutagen Untracked semantics).
        S_IFIFO | S_IFSOCK | S_IFBLK | S_IFCHR => Classified {
            entry: Entry::untracked(),
            cache: None,
            files: 0,
            dirs: 0,
            bytes: 0,
        },
        _ => Classified {
            entry: Entry::problematic(format!("unknown file type 0o{:o}", mode & S_IFMT)),
            cache: None,
            files: 0,
            dirs: 0,
            bytes: 0,
        },
    }
}

fn visit_ok(shared: &ScanShared<'_>, root: &Path, entry: DirEntry) {
    let path = entry.path();
    let rel_os = match path.strip_prefix(root) {
        Ok(r) => r,
        Err(_) => return,
    };
    if rel_os.as_os_str().is_empty() {
        return; // the root itself — validated by scan() up front
    }
    // Internal temp names are never part of the tree (the filter prunes them; this
    // repeat check keeps the visitor self-sufficient).
    if let Some(leaf) = path.file_name() {
        if is_internal_name(&leaf.to_string_lossy()) {
            return;
        }
    }
    // Non-UTF-8 names cannot be keyed (RelPath is a String): mark the parent dir
    // Problematic so the condition is loud, never silent (plan §8).
    let rel = match rel_os.to_str() {
        Some(r) => r.to_string(),
        None => {
            let parent = rel_os
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let msg = format!("{parent} contains non-UTF-8 names; contents unrepresentable");
            mark_problematic(shared, &parent, msg);
            return;
        }
    };
    let walker_is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);

    // Ignore classification (mutagen ignorer semantics; last matching pattern wins).
    // An ignored directory collapses to a single Untracked leaf and is never
    // traversed; its contents cannot be re-included by later negations (mutagen
    // traversal semantics).
    let ancestor_ignored = {
        let set = shared.ignored_dirs.lock().unwrap();
        has_ignored_ancestor(&set, &rel)
    };
    if ancestor_ignored || shared.rules.matches(&RelPath(rel.clone()), walker_is_dir) {
        if walker_is_dir {
            shared
                .ignored_dirs
                .lock()
                .unwrap()
                .insert(rel.clone());
        }
        let mut st = shared.state.lock().unwrap();
        insert_entry(&mut st, &rel, Entry::untracked());
        return;
    }

    // RACE: the walker listed this path moments ago; it may have changed or vanished.
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if walker_is_dir {
                // The directory was listed (children may still be in flight): keep a
                // shell so children do not orphan. The next scan corrects this
                // point-in-time view.
                let mut st = shared.state.lock().unwrap();
                st.dir_count += 1;
                insert_entry(&mut st, &rel, Entry::directory(BTreeMap::new()));
            }
            // A vanished file is genuinely absent — skipping it is accurate, not the
            // copia bug (which conflated EACCES with absence).
            return;
        }
        Err(e) => {
            let mut st = shared.state.lock().unwrap();
            insert_entry(&mut st, &rel, Entry::problematic(format!("stat failed: {e}")));
            return;
        }
    };

    let classified = classify(shared, &rel, path, &meta);
    let mut st = shared.state.lock().unwrap();
    st.file_count += classified.files;
    st.dir_count += classified.dirs;
    st.total_size += classified.bytes;
    if let Some((rel_key, ce)) = classified.cache {
        st.new_cache.insert(RelPath(rel_key), ce);
    }
    insert_entry(&mut st, &rel, classified.entry);
}

fn visit_err(shared: &ScanShared<'_>, root: &Path, err: WalkError) {
    // A walker error (unreadable directory, loop detection, …) is NEVER dropped
    // silently: it becomes a Problematic entry so the reconciler blocks propagation
    // for that path instead of treating it as absent (plan §8).
    let Some(path) = walk_error_path(&err) else {
        let mut st = shared.state.lock().unwrap();
        st.pathless_errors += 1;
        eprintln!("sync-core scan: pathless walker error: {err}");
        return;
    };
    let Ok(rel_os) = path.strip_prefix(root) else {
        return;
    };
    let Some(rel) = rel_os.to_str() else {
        return; // non-UTF-8 error path: nothing keyable; counted only
    };
    let mut st = shared.state.lock().unwrap();
    insert_entry(&mut st, rel, Entry::problematic(format!("walk error: {err}")));
}

fn visit_entry(shared: &ScanShared<'_>, root: &Path, result: Result<DirEntry, WalkError>) {
    match result {
        Ok(entry) => visit_ok(shared, root, entry),
        Err(err) => visit_err(shared, root, err),
    }
}

fn make_visitor<'a, 's>(
    shared: Arc<ScanShared<'a>>,
    root: PathBuf,
) -> Box<dyn FnMut(Result<DirEntry, WalkError>) -> WalkState + Send + 's>
where
    'a: 's,
{
    Box::new(move |entry| {
        visit_entry(&shared, &root, entry);
        WalkState::Continue
    })
}

// ---------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------

fn build_dir_children<'a>(
    rel: &str,
    by_parent: &BTreeMap<&'a str, Vec<(&'a str, &'a Entry)>>,
) -> BTreeMap<String, Entry> {
    let mut out = BTreeMap::new();
    if let Some(children) = by_parent.get(rel) {
        for (leaf, entry) in children {
            let mut e = (*entry).clone();
            if e.kind == EntryKind::Directory {
                // Children attach only to real directories. A Problematic or
                // Untracked parent means its listing was untrustworthy or pruned —
                // those entries stay leaves.
                let child_rel = if rel.is_empty() {
                    (*leaf).to_string()
                } else {
                    format!("{rel}/{leaf}")
                };
                e.children = build_dir_children(&child_rel, by_parent);
            }
            out.insert((*leaf).to_string(), e);
        }
    }
    out
}

fn assemble_snapshot(flat: &BTreeMap<String, Entry>) -> Snapshot {
    // Group children by parent rel. Every recorded child's parent was yielded by the
    // walker and recorded (or upgraded to Problematic, in which case the children are
    // dropped as untrustworthy), so no orphan synthesis is needed.
    let mut by_parent: BTreeMap<&str, Vec<(&str, &Entry)>> = BTreeMap::new();
    for (rel, entry) in flat {
        let (parent, leaf) = match rel.rsplit_once('/') {
            Some((p, l)) => (p, l),
            None => ("", rel.as_str()),
        };
        by_parent.entry(parent).or_default().push((leaf, entry));
    }
    let (file_count, dir_count, total_size) = {
        let mut f = 0u64;
        let mut d = 0u64;
        let mut s = 0u64;
        for e in flat.values() {
            match e.kind {
                EntryKind::File => {
                    f += 1;
                    s += e.size;
                }
                EntryKind::Directory => d += 1,
                _ => {}
            }
        }
        (f, d, s)
    };
    Snapshot {
        root: build_dir_children("", &by_parent),
        preserves_executability: PRESERVES_EXECUTABILITY_V1,
        file_count,
        dir_count,
        total_size,
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan `root` into a `Snapshot`, using `prior_cache` for the quick-check and
/// `rules` for ignore classification. See `scan_with_cache` for details.
pub fn scan(root: &Path, prior_cache: &CacheMap, rules: &IgnoreRules) -> io::Result<Snapshot> {
    scan_with_cache(root, prior_cache, rules).map(|(s, _)| s)
}

/// Full scan: returns the `Snapshot` plus the fresh per-file cache (one `CacheEntry`
/// per successfully scanned regular file — reused or re-hashed). The caller persists
/// the cache alongside the baseline archive.
pub fn scan_with_cache(
    root: &Path,
    prior_cache: &CacheMap,
    rules: &IgnoreRules,
) -> io::Result<(Snapshot, CacheMap)> {
    // Root validation: must be a real directory, never a symlink (symlinks are
    // entries, not roots — resolve at the caller layer). Errors propagate loudly.
    let meta = fs::symlink_metadata(root)
        .map_err(|e| io::Error::new(e.kind(), format!("cannot stat sync root {}: {e}", root.display())))?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sync root must not be a symbolic link",
        ));
    }
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sync root is not a directory",
        ));
    }

    let ignored_dirs: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let shared = Arc::new(ScanShared {
        rules: rules.clone(),
        prior_cache,
        ignored_dirs: Arc::clone(&ignored_dirs),
        state: Mutex::new(ScanState::default()),
    });

    let mut builder = WalkBuilder::new(root);
    builder
        // Symlinks are entries, never traversed (posix-raw model, plan §2).
        .follow_links(false)
        // In this API `hidden(true)` means "skip dotfiles" — disabled, because the
        // sync set includes ~/.config, .syncignore, … (plan §7 anchoring).
        .hidden(false)
        // ALL built-in ignore machinery off: ignore rules come from our own
        // IgnoreRules only (plan §2). Standard parallel walker + thread pool.
        .ignore(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .parents(false);

    // Prune ignored directories and our own temp artifacts at the walker level so
    // their contents are never even listed (mutagen never traverses ignored
    // content). The ignored dir itself is still yielded (true) so it can be recorded
    // as an Untracked leaf; only its descendants are pruned. Parent-before-child
    // yield order guarantees the set is populated before descendants are filtered.
    {
        let rules2 = rules.clone();
        let ignored2 = Arc::clone(&ignored_dirs);
        let root2 = root.to_path_buf();
        builder.filter_entry(move |entry: &DirEntry| {
            let path = entry.path();
            let Ok(rel_os) = path.strip_prefix(&root2) else {
                return false;
            };
            if rel_os.as_os_str().is_empty() {
                return true; // the root itself
            }
            if let Some(leaf) = path.file_name() {
                if is_internal_name(&leaf.to_string_lossy()) {
                    return false;
                }
            }
            let Some(rel) = rel_os.to_str() else {
                return true; // non-UTF-8: yielded so the visitor can flag the parent
            };
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir && rules2.matches(&RelPath(rel.to_string()), true) {
                ignored2.lock().unwrap().insert(rel.to_string());
            }
            let set = ignored2.lock().unwrap();
            !has_ignored_ancestor(&set, rel)
        });
    }

    let walker = builder.build_parallel();
    {
        let shared2 = Arc::clone(&shared);
        let root2 = root.to_path_buf();
        walker.run(move || make_visitor(Arc::clone(&shared2), root2.clone()));
    }

    let mut st = shared.state.lock().unwrap();
    if st.pathless_errors > 0 {
        // Never silent in aggregate either: the per-path cases above carry entries;
        // this covers the (rare) pathless remainder.
        eprintln!(
            "sync-core scan: {} pathless walker error(s) could not be attributed to a path",
            st.pathless_errors
        );
    }
    let snapshot = assemble_snapshot(&st.flat);
    let cache = std::mem::take(&mut st.new_cache);
    Ok((snapshot, cache))
}

/// Flatten a `Snapshot` into the reconciler's path-keyed form.
///
/// Convention: the root itself is present at `RelPath::root()` as a Directory with
/// empty children (the flat form carries no children — descendants are discovered by
/// path prefix). Emission is pre-order (parents before descendants) and
/// deterministic (BTreeMap order).
pub fn to_flat(snapshot: &Snapshot) -> FlatTree {
    let mut out = FlatTree::new();
    out.insert(RelPath::root(), Entry::directory(BTreeMap::new()));
    fn walk(prefix: &str, children: &BTreeMap<String, Entry>, out: &mut FlatTree) {
        for (leaf, entry) in children {
            let rel = if prefix.is_empty() {
                leaf.clone()
            } else {
                format!("{prefix}/{leaf}")
            };
            let mut e = entry.clone();
            let kids = std::mem::take(&mut e.children);
            out.insert(RelPath(rel.clone()), e);
            if entry.kind == EntryKind::Directory {
                walk(&rel, &kids, out);
            }
        }
    }
    walk("", &snapshot.root, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    #[test]
    fn scanner_skips_every_writer_temp_prefix() {
        // The self-inversion contract (see is_internal_name): the shapes every
        // crate's writers emit MUST be scanner-skipped, and ordinary visible
        // names MUST stay visible. Pin both directions.
        for name in [
            ".sync-agent",                 // the state dir itself
            ".sync-agent-tmp-1234-0",      // apply/serve/remote_driver temps
            ".sync-agent-tmp-upload-9999", // transport upload temp
        ] {
            assert!(is_internal_name(name), "{name} must be scanner-skipped");
        }
        for name in [".syncignore", "plan.md", ".git", "node_modules", ".config"] {
            assert!(!is_internal_name(name), "{name} must stay visible");
        }
    }

    use std::time::Duration;

    fn is_root() -> bool {
        let uid = unsafe { libc::getuid() };
        uid == 0
    }

    fn mkfifo(path: &Path) {
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }

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

    fn write_file(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn basic_tree_kinds_digests_stats() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("a.txt"), b"hello");
        write_file(&dir.path().join("sub/nested.txt"), b"nested content!");
        fs::set_permissions(
            dir.path().join("a.txt"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink("a.txt", dir.path().join("link")).unwrap();

        let snap = scan(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let a = snap.root.get("a.txt").unwrap();
        assert_eq!(a.kind, EntryKind::File);
        assert!(a.executable); // 0o755
        assert_eq!(a.mode, 0o755);
        assert_eq!(a.size, 5);
        assert_eq!(a.digest, Some(blake3::hash(b"hello").into()));

        let link = snap.root.get("link").unwrap();
        assert_eq!(link.kind, EntryKind::SymbolicLink);
        assert_eq!(link.target.as_deref(), Some("a.txt"));
        assert_eq!(link.digest, Some(blake3::hash(b"a.txt").into()));

        let sub = snap.root.get("sub").unwrap();
        assert_eq!(sub.kind, EntryKind::Directory);
        assert_eq!(sub.children.len(), 1);

        assert_eq!(snap.file_count, 2);
        assert_eq!(snap.dir_count, 1);
        assert_eq!(snap.total_size, 5 + 15);
        assert!(snap.preserves_executability);
    }

    #[test]
    fn broken_symlink_is_still_a_symlink_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("no-such-file-anywhere", dir.path().join("dangling"))
            .unwrap();
        let snap = scan(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let e = snap.root.get("dangling").unwrap();
        assert_eq!(e.kind, EntryKind::SymbolicLink);
        assert_eq!(e.target.as_deref(), Some("no-such-file-anywhere"));
        assert_eq!(
            e.digest,
            Some(blake3::hash(b"no-such-file-anywhere").into())
        );
    }

    #[test]
    fn fifo_and_socket_are_untracked_and_never_opened() {
        // This test doubles as the no-hang proof: scanning must never open either
        // special file (the copia bisync hang from M0 spike (e)).
        let dir = tempfile::tempdir().unwrap();
        mkfifo(&dir.path().join("pipe"));
        let sock = dir.path().join("sock");
        UnixListener::bind(&sock).unwrap();
        write_file(&dir.path().join("plain.txt"), b"x");

        let snap = scan(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        assert_eq!(snap.root.get("pipe").unwrap().kind, EntryKind::Untracked);
        assert_eq!(snap.root.get("sock").unwrap().kind, EntryKind::Untracked);
        assert_eq!(snap.root.get("plain.txt").unwrap().kind, EntryKind::File);
        assert_eq!(snap.file_count, 1); // untracked not counted
    }

    #[test]
    fn ignored_dir_collapses_to_untracked_leaf() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("logs/deep/x.log"), b"1");
        write_file(&dir.path().join("keep.txt"), b"k");
        let rules = IgnoreRules::new(vec!["logs/".to_string()]);
        let snap = scan(dir.path(), &CacheMap::new(), &rules).unwrap();
        let logs = snap.root.get("logs").unwrap();
        assert_eq!(logs.kind, EntryKind::Untracked);
        assert!(logs.children.is_empty()); // contents never traversed
        let flat = to_flat(&snap);
        assert!(!flat.contains_key(&RelPath("logs/deep/x.log".into())));
        assert_eq!(flat.get(&RelPath("keep.txt".into())).unwrap().kind, EntryKind::File);
    }

    #[test]
    fn dir_with_only_masked_children_stays_directory() {
        // Leaf pattern: the directory itself is not ignored, so it stays a Directory
        // whose children are Untracked (plan wording: no phantom-dir machinery).
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("logs/a.log"), b"1");
        write_file(&dir.path().join("logs/b.log"), b"2");
        let rules = IgnoreRules::new(vec!["*.log".to_string()]);
        let snap = scan(dir.path(), &CacheMap::new(), &rules).unwrap();
        let logs = snap.root.get("logs").unwrap();
        assert_eq!(logs.kind, EntryKind::Directory);
        assert_eq!(logs.children["a.log"].kind, EntryKind::Untracked);
        assert_eq!(logs.children["b.log"].kind, EntryKind::Untracked);
    }

    #[test]
    fn negation_reincludes() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("drop.log"), b"1");
        write_file(&dir.path().join("keep.log"), b"2");
        let rules = IgnoreRules::new(vec!["*.log".to_string(), "!keep.log".to_string()]);
        let snap = scan(dir.path(), &CacheMap::new(), &rules).unwrap();
        assert_eq!(snap.root.get("drop.log").unwrap().kind, EntryKind::Untracked);
        assert_eq!(snap.root.get("keep.log").unwrap().kind, EntryKind::File);
    }

    #[test]
    fn anchored_and_dir_only_patterns() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("top.txt"), b"1");
        write_file(&dir.path().join("sub/top.txt"), b"2");
        write_file(&dir.path().join("sub/deep.md"), b"3");
        write_file(&dir.path().join("other/deep.md"), b"4");
        let rules = IgnoreRules::new(vec![
            "/top.txt".to_string(),    // anchored: only the root copy
            "sub/*.md".to_string(),    // slash-in-pattern: anchored to root
        ]);
        let snap = scan(dir.path(), &CacheMap::new(), &rules).unwrap();
        assert_eq!(snap.root.get("top.txt").unwrap().kind, EntryKind::Untracked);
        assert_eq!(snap.root["sub"].children["top.txt"].kind, EntryKind::File);
        assert_eq!(snap.root["sub"].children["deep.md"].kind, EntryKind::Untracked);
        assert_eq!(snap.root["other"].children["deep.md"].kind, EntryKind::File);
    }

    #[test]
    fn syncignore_loading_and_merge() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("drop.log"), b"1");
        write_file(&dir.path().join("keep.log"), b"2");
        fs::write(dir.path().join(".syncignore"), "*.log\n# comment\n\n!keep.log\n").unwrap();
        let lines = load_syncignore(dir.path()).unwrap();
        assert_eq!(lines, vec!["*.log", "!keep.log"]);
        let rules = IgnoreRules::new(lines);
        assert!(rules.rejected().is_empty());
        let snap = scan(dir.path(), &CacheMap::new(), &rules).unwrap();
        assert_eq!(snap.root.get("drop.log").unwrap().kind, EntryKind::Untracked);
        assert_eq!(snap.root.get("keep.log").unwrap().kind, EntryKind::File);
        // .syncignore itself is ordinary synced content.
        assert_eq!(snap.root.get(".syncignore").unwrap().kind, EntryKind::File);
    }

    #[test]
    fn invalid_patterns_are_rejected_not_dropped_silently() {
        let rules = IgnoreRules::new(vec![
            String::new(),      // empty
            "!".to_string(),    // negated empty
            "/".to_string(),    // root pattern
            "ok/**".to_string(),
        ]);
        assert_eq!(rules.rejected().len(), 3);
        assert_eq!(rules.patterns.len(), 1);
    }

    #[test]
    fn unreadable_file_is_problematic_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("locked.txt");
        write_file(&f, b"secret");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o000)).unwrap();
        let snap = scan(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let e = snap.root.get("locked.txt").unwrap();
        if is_root() {
            // Root bypasses DAC: the file hashes fine and is a normal File entry.
            assert_eq!(e.kind, EntryKind::File);
        } else {
            // §8 invariant: EACCES must be Problematic (never silently absent —
            // that is the copia delete-the-peer's-copy bug).
            assert_eq!(e.kind, EntryKind::Problematic);
            assert!(e.problem.is_some());
        }
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn unreadable_dir_is_problematic() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("locked-dir");
        fs::create_dir_all(&sub).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o000)).unwrap();
        write_file(&dir.path().join("visible.txt"), b"x");
        let snap = scan(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let e = snap.root.get("locked-dir").unwrap();
        if is_root() {
            assert_eq!(e.kind, EntryKind::Directory);
        } else {
            assert_eq!(e.kind, EntryKind::Problematic);
            assert!(e.problem.is_some());
        }
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn cache_quick_check_reuse_vs_rehash() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("data.bin");
        write_file(&f, b"AAAA");

        let (_, cache1) = scan_with_cache(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let key = RelPath("data.bin".into());
        let d1 = cache1.get(&key).unwrap().digest;
        let mtime0 = fs::metadata(&f).unwrap().modified().unwrap();

        // In-place same-size edit (inode preserved) with the mtime restored: the
        // quick-check MUST reuse the stale digest (mutagen's accepted mtime race).
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut fh = fs::OpenOptions::new().write(true).open(&f).unwrap();
            fh.seek(SeekFrom::Start(0)).unwrap();
            fh.write_all(b"AAAB").unwrap();
            fh.set_times(
                std::fs::FileTimes::new().set_modified(mtime0),
            )
            .unwrap();
        }
        let (_, cache2) = scan_with_cache(dir.path(), &cache1, &IgnoreRules::default()).unwrap();
        assert_eq!(cache2.get(&key).unwrap().digest, d1, "quick-check must reuse");

        // Without a prior cache the file is hashed for real and the change surfaces.
        let (snap3, _) = scan_with_cache(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let d2 = snap3.root["data.bin"].digest.unwrap();
        assert_ne!(d2, d1, "fresh scan must re-hash");

        // Touch (mtime bump; content is still the edited "AAAB"): validate()
        // rejects → re-hash runs, yielding the true content digest d2, and the
        // fresh cache entry carries the new mtime.
        let bumped = mtime0 + Duration::from_secs(2);
        {
            let fh = fs::OpenOptions::new().write(true).open(&f).unwrap();
            fh.set_times(std::fs::FileTimes::new().set_modified(bumped)).unwrap();
        }
        let (_, cache4) = scan_with_cache(dir.path(), &cache1, &IgnoreRules::default()).unwrap();
        assert_eq!(cache4.get(&key).unwrap().digest, d2, "re-hash after mtime bump");
        assert_ne!(
            cache4.get(&key).unwrap().meta.mtime_nanos,
            cache1.get(&key).unwrap().meta.mtime_nanos,
            "mtime bump must force a re-hash (cache refresh)"
        );
    }

    #[test]
    fn internal_temp_names_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join(".sync-agent-tmp-4242-abc"), b"temp");
        write_file(&dir.path().join(".sync-agent/state.bin"), b"state");
        write_file(&dir.path().join("real.txt"), b"r");
        write_file(&dir.path().join("sub/.sync-agent-tmp-1-x"), b"temp2");
        let snap = scan(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let flat = to_flat(&snap);
        assert!(!flat.contains_key(&RelPath(".sync-agent-tmp-4242-abc".into())));
        assert!(!flat.contains_key(&RelPath(".sync-agent".into())));
        assert!(!flat.contains_key(&RelPath(".sync-agent/state.bin".into())));
        assert!(!flat.contains_key(&RelPath("sub/.sync-agent-tmp-1-x".into())));
        assert!(flat.contains_key(&RelPath("real.txt".into())));
        assert_eq!(snap.file_count, 1);
    }

    #[test]
    fn to_flat_shape_and_order() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("a/b/c.txt"), b"x");
        write_file(&dir.path().join("top.txt"), b"y");
        let snap = scan(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let flat = to_flat(&snap);
        let keys: Vec<&RelPath> = flat.keys().collect();
        // Root first, then pre-order parents-before-children, deterministic order.
        assert_eq!(keys[0], &RelPath::root());
        assert_eq!(flat.get(&RelPath::root()).unwrap().kind, EntryKind::Directory);
        let pos = |p: &str| keys.iter().position(|k| k.as_str() == p).unwrap();
        assert!(pos("a") < pos("a/b"));
        assert!(pos("a/b") < pos("a/b/c.txt"));
        assert!(pos("top.txt") > pos("a/b/c.txt")); // lexicographic, deterministic
        // Flat form carries no children.
        assert!(flat.get(&RelPath("a".into())).unwrap().children.is_empty());
    }

    #[test]
    fn non_root_scan_of_symlinked_dir_entry() {
        // A symlink pointing at a directory must appear as a SymbolicLink entry and
        // must NOT be descended into (no traversal through links).
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("real/inside.txt"), b"x");
        std::os::unix::fs::symlink("real", dir.path().join("dirlink")).unwrap();
        let snap = scan(dir.path(), &CacheMap::new(), &IgnoreRules::default()).unwrap();
        let e = snap.root.get("dirlink").unwrap();
        assert_eq!(e.kind, EntryKind::SymbolicLink);
        assert_eq!(e.target.as_deref(), Some("real"));
        let flat = to_flat(&snap);
        assert!(!flat.contains_key(&RelPath("dirlink/inside.txt".into())));
    }

    #[test]
    fn file_entry_helper_matches_scan_shape() {
        // Guard the test helper's shape against types.rs drift.
        let e = file_entry(Some([7u8; 32]), true, 0o755, 3);
        assert_eq!(e.kind, EntryKind::File);
        assert!(e.children.is_empty() && e.target.is_none() && e.problem.is_none());
    }
}
