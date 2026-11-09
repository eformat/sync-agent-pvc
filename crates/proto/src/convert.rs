//! sync-core ⇄ wire mirrors (M2).
//!
//! `sync-core` types are deliberately serde-free (M1 design: `types.rs` is the shared
//! engine contract, not a wire format). The wire carries the serde mirrors from
//! `messages.rs`; every conversion here is TOTAL (no panics, no partial states) and
//! roundtrip-exact: `x → wire → x == x` for every entry kind, Option none/some, exec
//! bit, mode, problem string and halt variant (tests below).
//!
//! Lossy BY DESIGN in exactly one place: `Entry.children` never rides the wire. The
//! protocol speaks the FLAT form (`FlatTree`: path → leaf entry; descendants are
//! their own paths — messages.rs `WireEntry`). Roundtrips through the wire yield
//! entries with EMPTY `children`; nothing on the wire needs the nested form (the
//! agent reassembles full-children expectations locally where removal verification
//! needs them — M1 integration lesson (1) in the plan).
//!
//! The chunking helpers bound every listing/cache frame well under `MAX_FRAME`:
//! the copia defect "single 1 MiB `List` frame dies >~15-20k files" is exactly what
//! this avoids (plan §2 "chunked listings").

use std::collections::BTreeMap;

use sync_core::apply::{ApplyReport, HaltReason, Operation, PlannedAction, Side};
use sync_core::types::{Entry, EntryKind, FlatTree, RelPath};

use crate::messages::{
    WireApplyReport, WireEntry, WireHaltReason, WireOperation, WirePlannedAction, WireSide,
    CHUNK_BYTES, SCAN_CHUNK_ENTRIES,
};

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// Wire kind tag for an [`EntryKind`] (0=Directory, 1=File, 2=SymbolicLink,
/// 3=Untracked, 4=Problematic — messages.rs `WireEntry.kind`).
fn kind_to_wire(k: EntryKind) -> u8 {
    match k {
        EntryKind::Directory => 0,
        EntryKind::File => 1,
        EntryKind::SymbolicLink => 2,
        EntryKind::Untracked => 3,
        EntryKind::Problematic => 4,
    }
}

/// Inverse of [`kind_to_wire`]; unknown tags are rejected loudly (never guessed).
fn kind_from_wire(k: u8) -> Result<EntryKind, String> {
    match k {
        0 => Ok(EntryKind::Directory),
        1 => Ok(EntryKind::File),
        2 => Ok(EntryKind::SymbolicLink),
        3 => Ok(EntryKind::Untracked),
        4 => Ok(EntryKind::Problematic),
        other => Err(format!("unknown wire entry kind {other} (expected 0..=4)")),
    }
}

/// `Entry` → wire mirror. `children` is NOT carried (flat form — see module docs);
/// every other field copies across unchanged.
pub fn entry_to_wire(e: &Entry) -> WireEntry {
    WireEntry {
        kind: kind_to_wire(e.kind),
        digest: e.digest,
        executable: e.executable,
        target: e.target.clone(),
        mode: e.mode,
        size: e.size,
        problem: e.problem.clone(),
    }
}

/// Wire mirror → `Entry`. Inverse of [`entry_to_wire`]; `children` comes back EMPTY
/// (the wire carries the flat form). Unknown kind tags (>4) → `Err`.
pub fn entry_from_wire(w: &WireEntry) -> Result<Entry, String> {
    Ok(Entry {
        kind: kind_from_wire(w.kind)?,
        children: BTreeMap::new(),
        digest: w.digest,
        executable: w.executable,
        target: w.target.clone(),
        mode: w.mode,
        size: w.size,
        problem: w.problem.clone(),
    })
}

// ---------------------------------------------------------------------------
// Side / Operation / PlannedAction
// ---------------------------------------------------------------------------

fn side_to_wire(s: Side) -> WireSide {
    match s {
        Side::A => WireSide::A,
        Side::B => WireSide::B,
    }
}

fn side_from_wire(s: WireSide) -> Side {
    match s {
        WireSide::A => Side::A,
        WireSide::B => Side::B,
    }
}

fn op_to_wire(op: &Operation) -> WireOperation {
    match op {
        Operation::Materialize(e) => WireOperation::Materialize(entry_to_wire(e)),
        Operation::Remove(e) => WireOperation::Remove(entry_to_wire(e)),
    }
}

fn op_from_wire(op: WireOperation) -> Result<Operation, String> {
    match op {
        WireOperation::Materialize(e) => Ok(Operation::Materialize(entry_from_wire(&e)?)),
        WireOperation::Remove(e) => Ok(Operation::Remove(entry_from_wire(&e)?)),
    }
}

/// `PlannedAction` → wire mirror (path flattened to its `/`-separated string form).
pub fn action_to_wire(a: &PlannedAction) -> WirePlannedAction {
    WirePlannedAction {
        side: side_to_wire(a.side),
        path: a.path.as_str().to_string(),
        op: op_to_wire(&a.op),
    }
}

/// Wire mirror → `PlannedAction`. Inverse of [`action_to_wire`]; unknown entry kinds
/// inside the operation → `Err`.
pub fn action_from_wire(w: &WirePlannedAction) -> Result<PlannedAction, String> {
    Ok(PlannedAction {
        side: side_from_wire(w.side),
        path: RelPath(w.path.clone()),
        op: op_from_wire(w.op.clone())?,
    })
}

// ---------------------------------------------------------------------------
// HaltReason / ApplyReport
// ---------------------------------------------------------------------------

/// `HaltReason` → wire mirror (infallible — every variant is representable).
pub fn halt_to_wire(h: &HaltReason) -> WireHaltReason {
    match h {
        HaltReason::OneSideRootEmptied => WireHaltReason::OneSideRootEmptied,
        HaltReason::RootDeletionProposed => WireHaltReason::RootDeletionProposed,
        HaltReason::RootTypeChanged => WireHaltReason::RootTypeChanged,
        HaltReason::LargeDeletion { count, ratio } => WireHaltReason::LargeDeletion {
            count: *count,
            ratio: *ratio,
        },
    }
}

/// Wire mirror → `HaltReason`. Inverse of [`halt_to_wire`] (infallible).
pub fn halt_from_wire(w: &WireHaltReason) -> HaltReason {
    match w {
        WireHaltReason::OneSideRootEmptied => HaltReason::OneSideRootEmptied,
        WireHaltReason::RootDeletionProposed => HaltReason::RootDeletionProposed,
        WireHaltReason::RootTypeChanged => HaltReason::RootTypeChanged,
        WireHaltReason::LargeDeletion { count, ratio } => HaltReason::LargeDeletion {
            count: *count,
            ratio: *ratio,
        },
    }
}

/// `ApplyReport` → wire mirror: problems lose their `RelPath` wrapper (the wire key
/// is the same `/`-separated string the flat tree uses, empty string = root).
pub fn report_to_wire(r: &ApplyReport) -> WireApplyReport {
    WireApplyReport {
        applied: r.applied,
        deleted: r.deleted,
        failed: r.failed,
        halted: r.halted.as_ref().map(halt_to_wire),
        problems: r
            .problems
            .iter()
            .map(|(path, msg)| (path.as_str().to_string(), msg.clone()))
            .collect(),
    }
}

/// Wire mirror → `ApplyReport`. Inverse of [`report_to_wire`].
pub fn report_from_wire(w: &WireApplyReport) -> ApplyReport {
    ApplyReport {
        applied: w.applied,
        deleted: w.deleted,
        failed: w.failed,
        halted: w.halted.as_ref().map(halt_from_wire),
        problems: w
            .problems
            .iter()
            .map(|(path, msg)| (RelPath(path.clone()), msg.clone()))
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Chunking (bounded frames — plan §2 "chunked listings")
// ---------------------------------------------------------------------------

/// Streaming batches of a `FlatTree` in wire form: at most [`SCAN_CHUNK_ENTRIES`]
/// entries per batch, in BTreeMap (sorted) order. A tree with ≤ the batch limit
/// still emits its entries; an EMPTY tree emits no batches at all (a scan of an
/// empty root is `ScanBegin` → `ScanDone` with zero `ScanChunk` frames).
struct FlatTreeChunks<'a> {
    iter: std::collections::btree_map::Iter<'a, RelPath, Entry>,
    done: bool,
}

impl Iterator for FlatTreeChunks<'_> {
    type Item = Vec<(String, WireEntry)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut batch = Vec::with_capacity(SCAN_CHUNK_ENTRIES);
        for _ in 0..SCAN_CHUNK_ENTRIES {
            match self.iter.next() {
                Some((path, entry)) => {
                    batch.push((path.as_str().to_string(), entry_to_wire(entry)))
                }
                None => {
                    self.done = true;
                    break;
                }
            }
        }
        (!batch.is_empty()).then_some(batch)
    }
}

/// Split a flat tree into sorted `ScanChunk` payloads of ≤ [`SCAN_CHUNK_ENTRIES`]
/// wire entries each (keys via [`RelPath::as_str`], empty string = root). Batches
/// stream lazily off the BTreeMap — no whole-tree materialization.
pub fn chunk_flat_tree(flat: &FlatTree) -> impl Iterator<Item = Vec<(String, WireEntry)>> + '_ {
    FlatTreeChunks {
        iter: flat.iter(),
        done: false,
    }
}

/// Split raw bytes (cache bytes, or the raw content streams that bracket frames)
/// into owned chunks of at most [`CHUNK_BYTES`]. Empty input yields no chunks.
pub fn chunk_bytes(data: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    data.chunks(CHUNK_BYTES).map(<[u8]>::to_vec)
}

// ---------------------------------------------------------------------------
// Tests — every kind, Option none/some, exec bits, problem strings, halt
// variants, batching and chunk bounds (roundtrip-exactness is the contract).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_kind_roundtrips() {
        let kinds = [
            (EntryKind::Directory, 0u8),
            (EntryKind::File, 1),
            (EntryKind::SymbolicLink, 2),
            (EntryKind::Untracked, 3),
            (EntryKind::Problematic, 4),
        ];
        for (kind, tag) in kinds {
            let e = Entry {
                kind,
                ..Entry::untracked()
            };
            let w = entry_to_wire(&e);
            assert_eq!(w.kind, tag, "{kind:?} must map to wire tag {tag}");
            assert_eq!(entry_from_wire(&w).unwrap().kind, kind);
        }
    }

    #[test]
    fn entry_fields_survive_the_roundtrip() {
        // File: digest Some, exec bit, mode, size — all preserved.
        let file = Entry {
            kind: EntryKind::File,
            digest: Some([7u8; 32]),
            executable: true,
            mode: 0o750,
            size: 123_456,
            ..Entry::untracked()
        };
        assert_eq!(entry_from_wire(&entry_to_wire(&file)).unwrap(), file);

        // None side of every Option (plain untracked marker).
        let bare = Entry::untracked();
        assert_eq!(entry_from_wire(&entry_to_wire(&bare)).unwrap(), bare);

        // Symlink: target string + symlink digest (blake3 of the target) preserved.
        let link = Entry {
            kind: EntryKind::SymbolicLink,
            digest: Some([9u8; 32]),
            target: Some("../elsewhere".into()),
            mode: 0o777,
            ..Entry::untracked()
        };
        assert_eq!(entry_from_wire(&entry_to_wire(&link)).unwrap(), link);

        // Problematic: the problem string is the point — never silently dropped.
        let bad = Entry::problematic("EACCES on stat");
        assert_eq!(entry_from_wire(&entry_to_wire(&bad)).unwrap(), bad);

        // Directory default (0755, no children on the wire).
        let dir = Entry::directory(BTreeMap::new());
        assert_eq!(entry_from_wire(&entry_to_wire(&dir)).unwrap(), dir);
    }

    #[test]
    fn unknown_wire_kind_is_rejected() {
        let mut w = entry_to_wire(&Entry::untracked());
        for bad in [5u8, 42, 255] {
            w.kind = bad;
            assert!(entry_from_wire(&w).is_err(), "kind {bad} must be rejected");
        }
    }

    #[test]
    fn action_report_halt_roundtrip() {
        for &side in &[Side::A, Side::B] {
            let mat = PlannedAction {
                side,
                path: RelPath("a/b/c.txt".into()),
                op: Operation::Materialize(Entry {
                    kind: EntryKind::File,
                    digest: Some([1u8; 32]),
                    executable: true,
                    mode: 0o755,
                    size: 9,
                    ..Entry::untracked()
                }),
            };
            let rem = PlannedAction {
                side,
                path: RelPath("stale-dir".into()),
                op: Operation::Remove(Entry {
                    kind: EntryKind::Directory,
                    ..Entry::untracked()
                }),
            };
            for a in [&mat, &rem] {
                assert_eq!(&action_from_wire(&action_to_wire(a)).unwrap(), a);
            }
        }

        for h in [
            HaltReason::OneSideRootEmptied,
            HaltReason::RootDeletionProposed,
            HaltReason::RootTypeChanged,
            HaltReason::LargeDeletion {
                count: 4242,
                ratio: 0.375,
            },
        ] {
            assert_eq!(halt_from_wire(&halt_to_wire(&h)), h);
        }

        let report = ApplyReport {
            applied: 12,
            deleted: 3,
            failed: 1,
            halted: Some(HaltReason::LargeDeletion {
                count: 10,
                ratio: 0.9,
            }),
            problems: vec![
                (RelPath("x/y".into()), "boom".into()),
                (RelPath::root(), "root problem".into()),
            ],
        };
        assert_eq!(report_from_wire(&report_to_wire(&report)), report);

        // Clean report (all defaults, empty problems).
        let clean = ApplyReport::default();
        assert_eq!(report_from_wire(&report_to_wire(&clean)), clean);
    }

    #[test]
    fn chunk_flat_tree_batches_and_preserves_order() {
        let mut flat: FlatTree = BTreeMap::new();
        flat.insert(RelPath::root(), Entry::directory(BTreeMap::new()));
        for i in 0..2499 {
            flat.insert(
                RelPath(format!("p{i:05}")),
                Entry {
                    kind: EntryKind::File,
                    digest: Some([2u8; 32]),
                    mode: 0o644,
                    size: i as u64,
                    ..Entry::untracked()
                },
            );
        }
        assert_eq!(flat.len(), 2500);

        let chunks: Vec<_> = chunk_flat_tree(&flat).collect();
        assert_eq!(
            chunks.len(),
            2,
            "2500 entries at {SCAN_CHUNK_ENTRIES}/chunk = exactly 2 frames"
        );
        assert_eq!(chunks[0].len(), SCAN_CHUNK_ENTRIES);
        assert_eq!(chunks[0].len() + chunks[1].len(), 2500);

        // Root-path key form: RelPath::root() rides as the empty string.
        assert_eq!(chunks[0][0].0, "", "root carries the empty-string key");

        // Concatenated batches reproduce the sorted key sequence exactly.
        let mut keys = chunks.into_iter().flatten().map(|(k, _)| k);
        for (want, got) in flat.keys().map(|p| p.as_str().to_string()).zip(&mut keys) {
            assert_eq!(want, got);
        }
        assert!(keys.next().is_none(), "no extra keys after the tree");

        // The wire entries convert back to the original entries.
        for (path, wire) in chunk_flat_tree(&flat).flatten() {
            let orig = &flat[&RelPath(path)];
            assert_eq!(&entry_from_wire(&wire).unwrap(), orig);
        }
    }

    #[test]
    fn chunk_bytes_exact_multiple_remainder_and_empty() {
        // Exact multiple: 2 full chunks, no remainder.
        let exact = vec![7u8; CHUNK_BYTES * 2];
        let chunks: Vec<Vec<u8>> = chunk_bytes(&exact).collect();
        assert_eq!(chunks.len(), 2);
        assert!(chunks.iter().all(|c| c.len() == CHUNK_BYTES));
        assert_eq!(chunks.concat(), exact);

        // Remainder: one full chunk + a 7-byte tail.
        let tail = vec![9u8; CHUNK_BYTES + 7];
        let chunks: Vec<Vec<u8>> = chunk_bytes(&tail).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), CHUNK_BYTES);
        assert_eq!(chunks[1].len(), 7);
        assert_eq!(chunks.concat(), tail);

        // Empty input → no frames; sub-chunk input → one frame, bytes unchanged.
        assert_eq!(chunk_bytes(&[]).count(), 0);
        let small = vec![1u8; 100];
        assert_eq!(chunk_bytes(&small).collect::<Vec<_>>(), vec![small]);
    }
}
