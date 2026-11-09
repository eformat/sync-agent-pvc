//! sync-core — the sync engine (M1).
//!
//! Design source of truth: the project plan §2.
//!
//! Module map (file ownership — coordinate via the maintainer's session, don't fork types.rs):
//! - `types`     — shared contract (Entry/Snapshot/Change/Action/Conflict/CacheEntry)
//! - `scan`      — parallel walker, ignores, metadata quick-check, Problematic ≠ absent
//! - `cache`     — metadata map + quick-check logic (part of the single archive file)
//! - `reconcile` — vendored copia 3-way table (TwoWaySafe only), MIT-attributed
//! - `archive`   — vendored copia archive (atomic, version-checked, safe no-base), MIT
//! - `change`    — Change computation vs baseline (whole-subtree semantics)
//! - `apply`     — atomic applies, symlink-aware, mode-only, safety halts, delete verification

pub mod apply;
pub mod archive;
pub mod cache;
pub mod change;
pub mod driver;
pub mod reconcile;
pub mod scan;
pub mod types;

pub use cache::CacheMap;
pub use driver::{bisync, BisyncReport, DriverConfig};
pub use scan::{scan_with_cache, IgnoreRules};
pub use types::{Action, CacheEntry, Change, Conflict, Digest, Entry, EntryKind, FileMeta, FlatTree, RelPath, Snapshot};
