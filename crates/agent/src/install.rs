//! Self-install + version GC (mutagen install.go pattern).
//!
//! The daemon uploads the agent binary to a hidden name on the sync root
//! (`<root>/.sync-agent/tmp-…`, same filesystem) and then runs
//! `sync-agent install <staged-path> [--root R]` INSIDE the sandbox: the binary
//! renames itself to `<root>/.sync-agent/agents/<CARGO_PKG_VERSION>/sync-agent`,
//! chmods 0755 (mode bits ONLY — §8: pods cannot and must not chown), and
//! garbage-collects every OTHER version directory.
//!
//! `<root>/.sync-agent/` is scanner-skipped (sync-core scan::is_internal_name), so
//! installed binaries never enter the sync tree — but they DO survive pod restarts,
//! which is the whole point of the versioned path.
//!
//! STDOUT IS PROTOCOL-CRITICAL on exec transports: this module prints NOTHING to
//! stdout; the caller reports the final path on stderr.

use std::fs;
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Install the staged binary into `<root>/.sync-agent/agents/<version>/` and GC
/// older versions. Returns the final path. Same-filesystem renames are the happy
/// path (the daemon uploads under the root); a cross-device upload falls back to
/// copy + fsync + rename-into-place.
pub fn install(staged: &Path, root: &Path) -> io::Result<PathBuf> {
    // The version comes from the FILE being installed — never from the
    // running binary (env!("CARGO_PKG_VERSION") made the 0.1.3 installer
    // write a 0.1.4 upload INTO agents/0.1.3/, leaving no versioned 0.1.4
    // dir for the drift check and re-arming the version-drift respawn loop;
    // caught live in the M6 rollout, 2026-11-07). The staged file is run with
    // --version: it is daemon-authored (uploaded over the paired session), so
    // executing it is the same trust level as installing it, and a corrupt /
    // wrong-arch upload fails LOUDLY here instead of mis-versioning silently.
    let out = std::process::Command::new(staged)
        .arg("--version")
        .output()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("staged binary {} would not execute: {e}", staged.display()),
            )
        })?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "staged binary {} failed --version (status {:?})",
                staged.display(),
                out.status.code()
            ),
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let version = stdout
        .split_whitespace()
        .last()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty --version output"))?;
    // The version becomes a PATH component — sanitize hard (no traversal, no
    // separators, no shell metacharacters). Sync-agent versions are semver-ish.
    let sane = !version.is_empty()
        && version.len() <= 32
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if !sane {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("staged binary reported a unusable version {version:?}"),
        ));
    }
    let version = version.to_string();
    let dir = root.join(".sync-agent").join("agents").join(&version);
    // Created with default mode + umask (0755 typical); setgid inheritance on the
    // PVC handles group ownership (§8 — we never force owner/group).
    fs::create_dir_all(&dir)?;
    let final_path = dir.join("sync-agent");

    match fs::rename(staged, &final_path) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            // The staged upload landed on a different filesystem than the root
            // (defensive parity with apply.rs's cross-device fallback): copy into
            // a temp file in the TARGET directory (same-device rename by
            // construction), fsync, then rename into place.
            let temp = dir.join(temp_name());
            let result = (|| -> io::Result<()> {
                let mut src = fs::File::open(staged)?;
                let mut dst = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600) // in-flight only; the final chmod below is exact
                    .open(&temp)?;
                io::copy(&mut src, &mut dst)?;
                dst.sync_all()?;
                drop(dst);
                fs::rename(&temp, &final_path)
            })();
            if let Err(e2) = result {
                let _ = fs::remove_file(&temp);
                return Err(e2);
            }
        }
        Err(e) => return Err(e),
    }

    // Mode bits ONLY (§8: never uid/gid, no chown anywhere) — mutagen installs 0755.
    fs::set_permissions(&final_path, fs::Permissions::from_mode(0o755))?;

    gc_other_versions(root, &version);
    refresh_current_link(root, &version);
    Ok(final_path)
}

/// Maintain the STABLE `agents/current` symlink → the just-installed version.
///
/// Consumers that live OUTSIDE the version lifecycle (the sandbox opencode.json
/// `mcpServers` entry, whose `command` cannot be rewritten by every install)
/// point at `<root>/.sync-agent/agents/current/sync-agent` and survive version
/// bumps + GC. The symlink swap is atomic (tmp → rename); a failure is logged
/// and never fails the install (the versioned path remains the truth).
fn refresh_current_link(root: &Path, version: &str) {
    let agents = root.join(".sync-agent").join("agents");
    let link = agents.join("current");
    let tmp = agents.join(format!(".current-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    if let Err(e) = std::os::unix::fs::symlink(version, &tmp) {
        eprintln!("sync-agent install: 'current' symlink not created: {e} (non-fatal)");
        return;
    }
    if let Err(e) = fs::rename(&tmp, &link) {
        let _ = fs::remove_file(&tmp);
        eprintln!("sync-agent install: 'current' symlink not swapped: {e} (non-fatal)");
    }
}

/// Remove every OTHER version entry under `<root>/.sync-agent/agents/` (mutagen
/// install.go GC). Failures are logged to stderr and NEVER fail the install — a
/// stale version dir is untidy, not broken.
fn gc_other_versions(root: &Path, keep: &str) {
    let agents_dir = root.join(".sync-agent").join("agents");
    let entries = match fs::read_dir(&agents_dir) {
        Ok(e) => e,
        Err(_) => return, // no agents dir (or unreadable): nothing to GC
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy() == keep {
            continue;
        }
        let path = entry.path();
        let result = if path.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        if let Err(e) = result {
            eprintln!(
                "sync-agent: version GC could not remove {}: {e}",
                path.display()
            );
        }
    }
}

static GC_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `.sync-agent-tmp-<pid>-<uniq>` — same convention as apply.rs `temp_name` (that
/// helper is crate-private), so our in-flight copy is scanner-skipped (plan §2).
fn temp_name() -> String {
    let n = GC_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".sync-agent-tmp-{}-{n:x}", unsafe { libc::getpid() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o7777
    }

    /// A staged upload must be EXECUTABLE and self-identifying: install runs
    /// `<staged> --version` to derive the target directory (M6 — the version
    /// comes from the FILE, never from the running binary). This helper mints
    /// a minimal sh script that behaves like the real binary for exactly that
    /// one question.
    fn fake_binary(dir: &Path, version: &str) -> PathBuf {
        let p = dir.join(format!("upload-{version}"));
        fs::write(&p, format!("#!/bin/sh\necho sync-agent {version}\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn install_places_binary_versioned_and_0755() {
        let root = tempfile::tempdir().unwrap();
        let staged_dir = tempfile::tempdir().unwrap();
        let staged = fake_binary(staged_dir.path(), env!("CARGO_PKG_VERSION"));

        let final_path = install(&staged, root.path()).unwrap();
        let expected = root
            .path()
            .join(".sync-agent")
            .join("agents")
            .join(env!("CARGO_PKG_VERSION"))
            .join("sync-agent");
        assert_eq!(final_path, expected);
        assert!(fs::metadata(&final_path).unwrap().len() > 0, "real content moved");
        assert_eq!(mode_of(&final_path), 0o755);
        // The staged upload still exists (rename moved it) — its dir is untouched.
        assert!(!staged.exists());
    }

    #[test]
    fn install_derives_the_version_from_the_staged_file_not_itself() {
        // M6 regression (caught live in the 0.1.4 rollout): install ran with
        // env!(CARGO_PKG_VERSION) — the RUNNING binary's version — so a 0.1.3
        // installer wrote a 0.1.4 upload INTO agents/0.1.3/, no versioned
        // 0.1.4 dir existed, and the daemon's drift check re-armed its
        // respawn loop. The version must come from the FILE.
        let root = tempfile::tempdir().unwrap();
        let staged_dir = tempfile::tempdir().unwrap();
        let staged = fake_binary(staged_dir.path(), "9.9.9");

        let final_path = install(&staged, root.path()).unwrap();
        let expected = root.path().join(".sync-agent").join("agents").join("9.9.9").join("sync-agent");
        assert_eq!(final_path, expected, "versioned dir = the FILE's version");
        assert!(
            root.path().join(".sync-agent").join("agents").join("current").exists(),
            "current symlink follows the installed version"
        );
    }

    #[test]
    fn install_rejects_a_staged_file_that_cannot_identify_itself() {
        // A corrupt / wrong-arch / non-executable upload must fail LOUDLY —
        // never install under a guessed version.
        let root = tempfile::tempdir().unwrap();
        let staged_dir = tempfile::tempdir().unwrap();
        let staged = staged_dir.path().join("upload");
        fs::write(&staged, b"definitely not a binary").unwrap(); // no +x

        assert!(install(&staged, root.path()).is_err());
        assert!(
            !root.path().join(".sync-agent").join("agents").exists(),
            "nothing installed on a failed version probe"
        );
    }

    #[test]
    fn install_maintains_the_stable_current_symlink_across_versions() {
        let root = tempfile::tempdir().unwrap();
        let agents = root.path().join(".sync-agent").join("agents");

        // Install "0.0.9" by faking the version (the symlink logic is
        // version-agnostic; drive it through refresh_current_link directly for
        // an older version, then a real install for the current one).
        fs::create_dir_all(agents.join("0.0.9")).unwrap();
        fs::write(agents.join("0.0.9").join("sync-agent"), b"old").unwrap();
        refresh_current_link(root.path(), "0.0.9");
        let link = agents.join("current");
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            std::path::PathBuf::from("0.0.9"),
            "current → the installed version"
        );
        assert!(link.join("sync-agent").exists(), "the stable path resolves");

        // A REAL install of the current version swaps the symlink atomically.
        let staged_dir = tempfile::tempdir().unwrap();
        let staged = fake_binary(staged_dir.path(), env!("CARGO_PKG_VERSION"));
        install(&staged, root.path()).unwrap();
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            std::path::PathBuf::from(env!("CARGO_PKG_VERSION")),
            "current follows the new version after the swap"
        );
        assert!(!agents.join("0.0.9").exists(), "GC removed the old version");
        assert!(
            link.join("sync-agent").exists(),
            "the stable path STILL resolves after the GC (the whole point)"
        );
    }

    #[test]
    fn install_gcs_other_version_dirs() {
        let root = tempfile::tempdir().unwrap();
        let agents = root.path().join(".sync-agent").join("agents");
        fs::create_dir_all(agents.join("0.0.9")).unwrap();
        fs::write(agents.join("0.0.9").join("sync-agent"), b"old").unwrap();

        let staged_dir = tempfile::tempdir().unwrap();
        let staged = fake_binary(staged_dir.path(), env!("CARGO_PKG_VERSION"));
        install(&staged, root.path()).unwrap();

        assert!(
            !agents.join("0.0.9").exists(),
            "old version dir must be GC'd"
        );
        assert!(
            agents
                .join(env!("CARGO_PKG_VERSION"))
                .join("sync-agent")
                .exists(),
            "current version must survive its own GC"
        );
    }

    #[test]
    fn install_missing_source_fails_loudly() {
        let root = tempfile::tempdir().unwrap();
        let err = install(Path::new("/nonexistent/upload"), root.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    // EXDEV fallback (cross-device install) is NOT exercised in tests — it needs a
    // second filesystem (tmpfs mount) which CI sandboxes may not grant. The path
    // mirrors apply.rs's proven copy+fsync+rename fallback; keep the coverage gap
    // in mind when touching it.
}
