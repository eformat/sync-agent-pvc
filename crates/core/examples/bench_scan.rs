//! M1 gate benchmark: 200k-file synthetic tree scan (plan phases table — "warm scan < few s").
//!
//! Generate the tree first: `python3 scripts/m1-bench-gen.py` (default target/bench-tree).
//! Run: `cargo run --release -p sync-core --example bench_scan -- target/bench-tree`
//!
//! Phases:
//!   cold  — empty prior cache: every file hashed with blake3
//!   warm  — prior cache from cold, NO changes: pure quick-check path (the gate)
//!   dirty — ~1% of files rewritten, warm cache: re-hash only what changed

use std::path::{Path, PathBuf};
use std::time::Instant;

use sync_core::cache::CacheMap;
use sync_core::scan::{self, IgnoreRules};

fn count_dirty(root: &Path) -> std::io::Result<usize> {
    // rewrite ~1% of leaf files so the warm re-scan must re-hash them
    let mut rewritten = 0;
    for t in 0..20u32 {
        let dir = root.join(format!("top{t:02}")).join("sub00").join("dir000");
        for f in 0..5u32 {
            let p = dir.join(format!("file{f:04}.txt"));
            if p.exists() {
                std::fs::write(&p, format!("dirty rewrite {t}/{f}\n").repeat(64))?;
                rewritten += 1;
            }
        }
    }
    Ok(rewritten)
}

fn main() {
    let root = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: bench_scan <tree-root>  (generate with scripts/m1-bench-gen.py)");
        std::process::exit(2);
    });
    let root = PathBuf::from(root);
    if !root.is_dir() {
        eprintln!("not a directory: {}", root.display());
        std::process::exit(2);
    }
    let rules = IgnoreRules::new(Vec::new());

    // cold: empty cache — full hash of everything
    let empty = CacheMap::new();
    let t = Instant::now();
    let (snap_cold, cache) = match scan::scan_with_cache(&root, &empty, &rules) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cold scan failed: {e}");
            std::process::exit(1);
        }
    };
    let cold = t.elapsed();
    eprintln!(
        "cold  {:>10.3?}  files={} dirs={} bytes={}",
        cold, snap_cold.file_count, snap_cold.dir_count, snap_cold.total_size
    );

    // warm: nothing changed — quick-check must dominate (THE GATE)
    let t = Instant::now();
    let (snap_warm, cache_warm) = match scan::scan_with_cache(&root, &cache, &rules) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("warm scan failed: {e}");
            std::process::exit(1);
        }
    };
    let warm = t.elapsed();
    eprintln!(
        "warm  {:>10.3?}  files={} (quick-check reuse path)",
        warm, snap_warm.file_count
    );

    // dirty: rewrite ~1%, warm cache — re-hash only the dirty subset
    let dirty_n = count_dirty(&root).unwrap_or(0);
    let t = Instant::now();
    let (snap_dirty, _cache_dirty) = match scan::scan_with_cache(&root, &cache_warm, &rules) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("dirty scan failed: {e}");
            std::process::exit(1);
        }
    };
    let dirty = t.elapsed();
    eprintln!(
        "dirty {:>10.3?}  files={} ({} rewritten, re-hashed)",
        dirty, snap_dirty.file_count, dirty_n
    );

    let gate = warm.as_secs_f64();
    println!(
        "bench: cold={:.3}s warm={:.3}s dirty={:.3}s | GATE warm<5s: {}",
        cold.as_secs_f64(),
        gate,
        dirty.as_secs_f64(),
        if gate < 5.0 { "PASS" } else { "FAIL" }
    );
}
