#!/usr/bin/env python3
"""M1 gate bench tree generator: 200k-file synthetic tree (plan phases table, M1 gate).

Layout: 20 top dirs x 10 x 10 leaf dirs x ~100 files = ~200k files, depth 4.
Size mix (agent-context realistic): ~70% <1KiB, ~25% 1-10KiB, ~5% 10-100KiB.
Plus: 2k symlinks, 20 FIFOs, an ignored-name dir tree (excludes exercise).
Deterministic content (no /dev/urandom) — blake3 only needs bytes, not entropy.

Usage: python3 scripts/m1-bench-gen.py [TARGET_DIR]  (default: target/bench-tree)
Idempotent: refuses to regrow an existing tree (rm -rf it first for a fresh one).
"""
import os
import stat
import sys
import random

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.join("target", "bench-tree")
TOPS, SUBS, LEAFDIRS, FILES_PER_LEAF = 20, 10, 10, 100
rng = random.Random(20261105)

if os.path.isdir(ROOT) and os.listdir(ROOT):
    sys.exit(f"{ROOT} already exists and is non-empty — rm -rf it first")

BUF = (b"sync-agent-pvc bench line 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ\n" * 32)  # ~2KiB

n_files = n_symlinks = n_fifos = 0
for t in range(TOPS):
    top = os.path.join(ROOT, f"top{t:02d}")
    for s in range(SUBS):
        for d in range(LEAFDIRS):
            leaf = os.path.join(top, f"sub{s:02d}", f"dir{d:03d}")
            os.makedirs(leaf, exist_ok=True)
            for f in range(FILES_PER_LEAF):
                r = rng.random()
                if r < 0.70:
                    n = rng.randint(1, 3)          # <1KiB
                elif r < 0.95:
                    n = rng.randint(4, 44)         # 1-10KiB ish
                else:
                    n = rng.randint(100, 1000)     # 10-100KiB ish
                path = os.path.join(leaf, f"file{f:04d}.txt")
                with open(path, "wb") as fh:
                    fh.write(BUF * min(n, 8))
                    if n > 8:
                        fh.write(BUF * (n - 8))
                if rng.random() < 0.05:
                    os.chmod(path, 0o755)          # exec-bit mix
                n_files += 1
    # symlinks: relative + absolute targets per top dir
    for i in range(100):
        tgt = f"sub00/dir000/file{i:04d}.txt"
        try:
            os.symlink(tgt, os.path.join(top, f"rel_link_{i:04d}"))
            os.symlink(os.path.abspath(os.path.join(top, tgt)),
                       os.path.join(top, f"abs_link_{i:04d}"))
            n_symlinks += 2
        except OSError:
            pass
    # FIFOs (never hashed/opened by the engine)
    for i in range(1):
        try:
            os.mkfifo(os.path.join(top, f"pipe{i:02d}.fifo"))
            n_fifos += 1
        except (OSError, AttributeError):
            pass

# ignored-content exercise: node_modules-like tree the engine must mark Untracked
ign = os.path.join(ROOT, "top00", "node_modules", "somepkg")
os.makedirs(ign, exist_ok=True)
for f in range(500):
    with open(os.path.join(ign, f"dep{f:04d}.js"), "wb") as fh:
        fh.write(BUF)
n_files += 500

total, dirs = 0, 0
for _, _, files in os.walk(ROOT):
    total += len(files)
for _, dirs_, _ in os.walk(ROOT):
    dirs += len(dirs_)
print(f"generated {ROOT}: {total} files ({n_files} plain + {n_symlinks} symlinks), "
      f"{dirs} dirs, {n_fifos} FIFOs")
