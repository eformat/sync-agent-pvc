// Pair-state debug tool (added 2026-11-08 while chasing "resolved conflicts
// come back"): dumps one pair dir's archive (the three-way merge base) +
// cache-a/cache-b (last scans of each side), filtered by path substring.
// Bypasses the pair-hash gate (read-only) — pair dirs live under
// ~/.local/state/sync-agent-pvc/pairs/<blake3-16 of "sync-agent-pvc/pair/<sandbox>:<root_remote>">.
use sync_core::archive::{ArchiveState, FORMAT_VERSION};
use sync_core::cache;

fn main() -> std::io::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: dump-pair <state-dir> [filter]");
    let filter = std::env::args().nth(2).unwrap_or_default();

    let bytes = std::fs::read(format!("{dir}/archive.bin"))?;
    let state: ArchiveState = match bincode::deserialize(&bytes) {
        Ok(s) => s,
        Err(e) => {
            println!("== archive: decode error {e}");
            return Ok(());
        }
    };
    if state.format_version != FORMAT_VERSION {
        println!(
            "== archive: format {} != {FORMAT_VERSION}",
            state.format_version
        );
    }
    println!(
        "== archive: file_count={} dir_count={}",
        state.ancestor.file_count, state.ancestor.dir_count
    );
    for (p, e) in &state.ancestor.root {
        if p.contains(&filter) {
            println!("  base   {:<44} {:?} exec={}", p, e.kind, e.executable);
        }
    }
    for (name, file) in [("cache-a", "cache-a.bin"), ("cache-b", "cache-b.bin")] {
        let bytes = match std::fs::read(format!("{dir}/{file}")) {
            Ok(b) => b,
            Err(_) => {
                println!("== {name}: (absent)");
                continue;
            }
        };
        match cache::from_bytes(&bytes) {
            Ok(c) => {
                println!("== {name}: {} entries", c.len());
                for (p, e) in c.iter() {
                    if p.as_str().contains(&filter) {
                        println!("  {:<44} mtime={}", p.as_str(), e.meta.mtime_nanos);
                    }
                }
            }
            Err(e) => println!("== {name}: decode error {e}"),
        }
    }
    Ok(())
}
