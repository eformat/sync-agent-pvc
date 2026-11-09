//! Metadata cache: the digest quick-check plus the (de)serialization codec that the
//! archive module embeds in the versioned archive file.
//!
//! Quick-check semantics ported from mutagen `pkg/synchronization/core/scan.go`
//! (`cacheContentMatch`, lines ~171-177): a cached digest is reusable ONLY when the
//! file's type, modification time, size and file-ID (inode) are all unchanged.
//! mutagen splits this into "content match" (digest reuse) and "entry reuse" (full
//! mode equality); our `FileMeta` carries the mode explicitly (plan §8: mode is part
//! of the fingerprint), so a single all-four comparison covers both.
//!
//! Fresh code (no copia lineage) — attribution is by reference only.

use std::collections::BTreeMap;
use std::io;

use serde::{Deserialize, Serialize};

use crate::types::{CacheEntry, Digest, FileMeta, RelPath};

/// Prior-scan metadata keyed by root-relative path (the same key space as
/// `FlatTree`). Persisted in the archive file so warm scans skip re-hashing.
pub type CacheMap = BTreeMap<RelPath, CacheEntry>;

/// The quick-check: return the prior digest only when every recorded metadata field
/// still matches what the filesystem reports now. Any mismatch (or no prior entry)
/// forces a full blake3 re-hash.
pub fn validate(meta: &FileMeta, prior: Option<&CacheEntry>) -> Option<Digest> {
    let entry = prior?;
    if entry.meta == *meta {
        Some(entry.digest)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------
//
// `types.rs` deliberately carries no serde derives (it is the shared contract, not a
// wire format), so the codec mirrors the two structs locally and converts at the
// boundary. The archive module owns file I/O and versioning; this codec is
// self-versioned so a future field addition fails loudly instead of deserializing
// garbage.

const CODEC_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct FileMetaWire {
    mode: u32,
    mtime_nanos: i64,
    size: u64,
    inode: u64,
}

#[derive(Serialize, Deserialize)]
struct CacheEntryWire {
    meta: FileMetaWire,
    digest: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct CacheFileWire {
    version: u32,
    entries: BTreeMap<String, CacheEntryWire>,
}

impl From<&FileMeta> for FileMetaWire {
    fn from(m: &FileMeta) -> Self {
        FileMetaWire {
            mode: m.mode,
            mtime_nanos: m.mtime_nanos,
            size: m.size,
            inode: m.inode,
        }
    }
}

impl From<&FileMetaWire> for FileMeta {
    fn from(w: &FileMetaWire) -> Self {
        FileMeta {
            mode: w.mode,
            mtime_nanos: w.mtime_nanos,
            size: w.size,
            inode: w.inode,
        }
    }
}

impl From<&CacheEntry> for CacheEntryWire {
    fn from(e: &CacheEntry) -> Self {
        CacheEntryWire {
            meta: FileMetaWire::from(&e.meta),
            digest: e.digest,
        }
    }
}

impl From<&CacheEntryWire> for CacheEntry {
    fn from(w: &CacheEntryWire) -> Self {
        CacheEntry {
            meta: FileMeta::from(&w.meta),
            digest: w.digest,
        }
    }
}

/// Serialize the cache for embedding in the archive file (bincode).
pub fn to_bytes(cache: &CacheMap) -> Vec<u8> {
    let wire = CacheFileWire {
        version: CODEC_VERSION,
        entries: cache
            .iter()
            .map(|(k, v)| (k.0.clone(), CacheEntryWire::from(v)))
            .collect(),
    };
    bincode::serialize(&wire).unwrap_or_else(|e| {
        // In-memory structs always serialize; a failure is a programming error.
        panic!("cache codec: serialize failed: {e}");
    })
}

/// Deserialize a cache previously written by `to_bytes`. Corrupt or future-versioned
/// input is an error — the archive layer treats that as "no usable prior cache"
/// (safe no-base / full re-hash), never as empty truth.
pub fn from_bytes(bytes: &[u8]) -> io::Result<CacheMap> {
    let wire: CacheFileWire = bincode::deserialize(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("cache codec: {e}")))?;
    if wire.version != CODEC_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cache codec: unsupported version {} (expected {CODEC_VERSION})",
                wire.version
            ),
        ));
    }
    let mut out = CacheMap::new();
    for (k, v) in wire.entries {
        out.insert(RelPath(k), CacheEntry::from(&v));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(mode: u32, mtime: i64, size: u64, inode: u64) -> FileMeta {
        FileMeta {
            mode,
            mtime_nanos: mtime,
            size,
            inode,
        }
    }

    fn entry(mode: u32, mtime: i64, size: u64, inode: u64, d: u8) -> CacheEntry {
        let mut digest = [0u8; 32];
        digest[0] = d;
        CacheEntry {
            meta: meta(mode, mtime, size, inode),
            digest,
        }
    }

    #[test]
    fn validate_all_four_match_reuses() {
        let prior = entry(0o644, 1_000, 42, 7, 9);
        let cur = meta(0o644, 1_000, 42, 7);
        assert_eq!(validate(&cur, Some(&prior)), Some(prior.digest));
    }

    #[test]
    fn validate_any_mismatch_forces_rehash() {
        let prior = entry(0o644, 1_000, 42, 7, 9);
        // Each field mismatched one at a time (mutagen cacheContentMatch analog).
        assert_eq!(validate(&meta(0o600, 1_000, 42, 7), Some(&prior)), None, "mode");
        assert_eq!(validate(&meta(0o644, 2_000, 42, 7), Some(&prior)), None, "mtime");
        assert_eq!(validate(&meta(0o644, 1_000, 43, 7), Some(&prior)), None, "size");
        assert_eq!(validate(&meta(0o644, 1_000, 42, 8), Some(&prior)), None, "inode");
    }

    #[test]
    fn validate_missing_prior_rehashes() {
        let cur = meta(0o644, 1_000, 42, 7);
        assert_eq!(validate(&cur, None), None);
    }

    #[test]
    fn codec_round_trip_and_rejection() {
        let mut cache = CacheMap::new();
        cache.insert(RelPath("a.txt".into()), entry(0o644, 111, 3, 10, 1));
        cache.insert(
            RelPath("dir/b.bin".into()),
            entry(0o755, -2_225_604_529, 1 << 40, u64::MAX, 2),
        );
        let bytes = to_bytes(&cache);
        let back = from_bytes(&bytes).unwrap();
        assert_eq!(back, cache);

        // Empty map round-trips too.
        let empty = to_bytes(&CacheMap::new());
        assert_eq!(from_bytes(&empty).unwrap(), CacheMap::new());

        // Corrupt input is a loud error, never a silently-empty cache. Flipping the
        // version byte deterministically trips the version gate.
        let corrupted = {
            let mut b = bytes.clone();
            b[0] = b[0].wrapping_add(0x5A);
            b
        };
        assert_eq!(
            from_bytes(&corrupted).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // Truncated input fails to parse at all.
        assert!(from_bytes(&bytes[..bytes.len() - 1]).is_err());

        // Future/unknown version is rejected (the archive layer falls back to
        // safe no-base behavior).
        let future = {
            let w = CacheFileWire {
                version: CODEC_VERSION + 1,
                entries: BTreeMap::new(),
            };
            // Serialize via the same bincode path the codec uses.
            bincode::serialize(&w).unwrap()
        };
        assert_eq!(
            from_bytes(&future).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
