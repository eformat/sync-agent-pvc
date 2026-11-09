//! M2 gate tests: the full protocol over a REAL `sync-agent serve` child process
//! (os pipes — the same shape as the `oc exec` fallback transport), plus the
//! three M2 gates from the plan: banner noise, 1 GB file, mid-transfer change.
//!
//! The 1 GB gate is `#[ignore]` (release-only runtime): run with
//!   cargo test -p sync-agent --release --test e2e_loopback -- --ignored

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use sync_core::apply::{Operation, PlannedAction, Side};
use sync_core::types::{Entry, EntryKind, RelPath};
use sync_proto::messages::{Request, Response, StageResult};
use sync_proto::session::Session;

/// Read+Write half-pair over a child's piped stdio (the exec-transport shape).
struct ChildDuplex {
    out: ChildStdoutPipe,
    in_: ChildStdinPipe,
}
type ChildStdoutPipe = std::process::ChildStdout;
type ChildStdinPipe = std::process::ChildStdin;

impl Read for ChildDuplex {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.out.read(buf)
    }
}
impl Write for ChildDuplex {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.in_.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.in_.flush()
    }
}

fn agent_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sync-agent")
}

struct ServeChild {
    child: Child,
}

impl ServeChild {
    /// Spawn `sync-agent serve --root R`, optionally behind a banner-emitting shell
    /// (the exec-transport banner-noise shape: rc files/motd precede the protocol).
    fn spawn(root: &Path, banner: bool) -> (ServeChild, Session<ChildDuplex>) {
        let mut cmd = if banner {
            let mut c = Command::new("sh");
            // Banner on stdout BEFORE exec: exactly what a login shell on a noisy
            // transport does. exec replaces the shell so the protocol stream is clean
            // after the noise.
            c.arg("-c")
                .arg("echo 'bash: rc-file noise line 1'; echo 'motd line 2'; exec \"$0\" \"$@\"")
                .arg(agent_bin())
                .arg("serve")
                .arg("--root")
                .arg(root);
            c
        } else {
            let mut c = Command::new(agent_bin());
            c.arg("serve").arg("--root").arg(root);
            c
        };
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sync-agent serve");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let duplex = ChildDuplex {
            out: stdout,
            in_: stdin,
        };
        let session = Session::client(duplex).expect("client session (handshake+hello)");
        (ServeChild { child }, session)
    }

    fn shutdown(mut session: Session<ChildDuplex>, child: &mut Child) {
        let _ = session.call(&Request::Shutdown);
        let _ = session.call(&Request::Ping); // may fail after Bye — ignore
        let _ = child.wait();
    }
}

fn seed(root: &Path, rel: &str, content: &[u8], exec: bool) -> PathBuf {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, content).unwrap();
    if exec {
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
    }
    p
}

#[test]
fn e2e_hello_ping_scan_read_stage_transition_over_child_process() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    seed(root, "dir/file.txt", b"hello wire", false);
    seed(root, "run.sh", b"#!/bin/sh\necho hi\n", true);
    std::os::unix::fs::symlink("dir/file.txt", root.join("link")).unwrap();

    let (mut srv, session) = ServeChild::spawn(root, false);
    let mut session = session;

    // Hello identity (§8): version, uid, root.
    let hello = session.hello().clone();
    assert_eq!(hello.agent_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(hello.uid, unsafe { libc::getuid() });
    assert!(hello.root.ends_with(
        root.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
    ));
    assert!(hello.root_writable, "temp root must be writable");

    // Ping → Pong.
    assert!(matches!(session.call(&Request::Ping), Ok(Response::Pong)));

    // Chunked scan: tree reassembles with kinds intact.
    let scan = session.scan(&[], &[]).unwrap();
    assert_eq!(scan.file_count, 2);
    assert_eq!(scan.dir_count, 1);
    let got_file = scan.tree.get(&RelPath("dir/file.txt".into()));
    assert_eq!(got_file.map(|e| e.kind), Some(EntryKind::File));
    let got_link = scan.tree.get(&RelPath("link".into()));
    assert_eq!(got_link.map(|e| e.kind), Some(EntryKind::SymbolicLink));

    // ReadFile: header digest matches the streamed payload (memory-bounded).
    let resp = session
        .call(&Request::ReadFile { path: "run.sh".into() })
        .unwrap();
    let Response::FileHeader { size, digest, executable, .. } = resp else {
        panic!("expected FileHeader, got {resp:?}");
    };
    assert!(executable, "exec bit propagated");
    let mut sink = Vec::new();
    let got_digest = session.read_payload_hashed(size, &mut sink).unwrap();
    assert_eq!(got_digest, digest);
    assert_eq!(sink, b"#!/bin/sh\necho hi\n");

    // Stage + transition: materialize a NEW file remotely with mode bits.
    let want = b"staged content";
    let digest = blake3::hash(want);
    let resp = session
        .call_with_payload(
            &Request::StageFile {
                path: "new/staged.txt".into(),
                size: want.len() as u64,
                mode: 0o600,
                executable: true,
                digest: digest.into(),
            },
            &mut std::io::Cursor::new(want),
            want.len() as u64,
        )
        .unwrap();
    assert_eq!(resp, Response::Stage(StageResult::Staged));

    // Build a Materialize action for the staged content (as the daemon driver would) —
    // core types; the Session converts to wire internally.
    let action = PlannedAction {
        side: Side::B,
        path: RelPath("new/staged.txt".into()),
        op: Operation::Materialize(Entry {
            kind: EntryKind::File,
            children: Default::default(),
            digest: Some(digest.into()),
            executable: true,
            target: None,
            mode: 0o600,
            size: want.len() as u64,
            problem: None,
        }),
    };
    let report = session
        .transition(std::slice::from_ref(&action), false)
        .unwrap();
    assert_eq!(report.applied, 1, "report: {report:?}");
    assert_eq!(report.failed, 0);

    // The file landed with content + exec bit (mode bits only, §8).
    let landed = std::fs::read(root.join("new/staged.txt")).unwrap();
    assert_eq!(landed, want);
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(root.join("new/staged.txt")).unwrap().permissions().mode();
    assert_eq!(mode & 0o111, 0o100, "exec bit set");

    // Session state discipline: another ping still works after a transition.
    assert!(matches!(session.call(&Request::Ping), Ok(Response::Pong)));

    ServeChild::shutdown(session, &mut srv.child);
}

#[test]
fn gate_banner_noise_is_skipped_by_the_session_handshake() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    std::fs::write(root.join("f.txt"), b"x").unwrap();

    // Banner on stdout before exec — rc files/motd on exec-like transports.
    let (mut srv, session) = ServeChild::spawn(root, true);
    let mut session = session;
    assert_eq!(session.hello().agent_version, env!("CARGO_PKG_VERSION"));
    assert!(matches!(session.call(&Request::Ping), Ok(Response::Pong)));
    ServeChild::shutdown(session, &mut srv.child);
}

#[test]
fn gate_mid_transfer_change_is_caught_and_never_materialized() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    std::fs::write(root.join("existing.txt"), b"old").unwrap();

    let (mut srv, session) = ServeChild::spawn(root, false);
    let mut session = session;

    // Upload content that does NOT match the declared digest (the source changed
    // between the daemon's read and its stage — the exact mid-transfer race).
    let declared = blake3::hash(b"what the daemon read first");
    let actually = b"what the file contains now";
    let resp = session
        .call_with_payload(
            &Request::StageFile {
                path: "victim.txt".into(),
                size: actually.len() as u64,
                mode: 0o644,
                executable: false,
                digest: declared.into(),
            },
            &mut std::io::Cursor::new(actually),
            actually.len() as u64,
        )
        .unwrap();
    let Response::Stage(StageResult::DigestMismatch { got }) = resp else {
        panic!("expected DigestMismatch, got {resp:?}");
    };
    assert_eq!(got, *blake3::hash(actually).as_bytes());

    // The daemon-side transition that would have materialized it MUST fail with
    // "content not staged" — the file never appears, nothing is corrupted.
    let report = session
        .transition(
            &[PlannedAction {
                side: Side::B,
                path: RelPath("victim.txt".into()),
                op: Operation::Materialize(Entry {
                    kind: EntryKind::File,
                    children: Default::default(),
                    digest: Some(declared.into()),
                    executable: false,
                    target: None,
                    mode: 0o644,
                    size: actually.len() as u64,
                    problem: None,
                }),
            }],
            false,
        )
        .unwrap();
    assert_eq!(report.failed, 1, "report: {report:?}");
    assert!(!root.join("victim.txt").exists(), "no corrupt file may land");

    ServeChild::shutdown(session, &mut srv.child);
}

#[test]
fn e2e_self_install_and_version_gc() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();

    // Simulate the daemon's exec upload: binary bytes staged as a temp file.
    let upload = root.join(".sync-agent-tmp-upload");
    std::fs::create_dir_all(root.join(".sync-agent")).unwrap();
    std::fs::copy(agent_bin(), &upload).unwrap();

    // An "old version" the GC must remove.
    let old = root.join(".sync-agent/agents/0.0.9");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("sync-agent"), b"stale").unwrap();

    let out = Command::new(agent_bin())
        .args(["install", upload.to_str().unwrap(), "--root", root.to_str().unwrap()])
        .output()
        .expect("run install");
    assert!(out.status.success(), "install stderr: {}", String::from_utf8_lossy(&out.stderr));

    let version = env!("CARGO_PKG_VERSION");
    let installed = root.join(format!(".sync-agent/agents/{version}/sync-agent"));
    assert!(installed.exists(), "versioned install path exists");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&installed).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    assert!(!old.exists(), "GC removed the stale version");
    // stdout stays protocol-clean (M2 contract: path on stderr only).
    assert!(out.stdout.is_empty(), "stdout must stay clean: {:?}", out.stdout);
}

/// THE 1 GB GATE (#[ignore] — release-only): scan sees it, read streams it
/// digest-verified, stage+transition lands a byte-identical copy, all O(64 KiB)
/// memory. Run: cargo test -p sync-agent --release --test e2e_loopback -- --ignored
#[test]
#[ignore = "1 GB gate — release-only, run explicitly"]
fn gate_one_gigabyte_file_end_to_end() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    let big = root.join("big.bin");
    // 1 GB of deterministic content (repeat a 1 MiB pattern — blake3 doesn't care).
    let pattern: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();
    {
        let mut f = std::fs::File::create(&big).unwrap();
        for _ in 0..1024 {
            f.write_all(&pattern).unwrap();
        }
        f.sync_all().unwrap();
    }
    let expected_digest: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        let mut f = std::fs::File::open(&big).unwrap();
        std::io::copy(&mut f, &mut h).unwrap();
        h.finalize().into()
    };

    let (mut srv, session) = ServeChild::spawn(root, false);
    let mut session = session;

    // Scan sees the 1 GB file.
    let scan = session.scan(&[], &[]).unwrap();
    assert_eq!(scan.file_count, 1);
    assert_eq!(scan.total_size, 1 << 30);

    // Read: streamed, digest-verified, O(64 KiB) memory.
    let resp = session
        .call(&Request::ReadFile { path: "big.bin".into() })
        .unwrap();
    let Response::FileHeader { size, digest, .. } = resp else {
        panic!("expected FileHeader");
    };
    assert_eq!(size, 1 << 30);
    let mut sink = std::io::sink();
    let got = session.read_payload_hashed(size, &mut sink).unwrap();
    assert_eq!(got, expected_digest, "read digest");
    assert_eq!(digest, expected_digest, "header digest");

    // Stage the SAME 1 GB back (from the file, streamed) → Staged.
    let mut src = std::fs::File::open(&big).unwrap();
    let resp = session
        .call_with_payload(
            &Request::StageFile {
                path: "copy.bin".into(),
                size: 1 << 30,
                mode: 0o644,
                executable: false,
                digest: expected_digest,
            },
            &mut src,
            1 << 30,
        )
        .unwrap();
    assert_eq!(resp, Response::Stage(StageResult::Staged));

    // Transition materializes it; byte-identical on disk.
    let report = session
        .transition(
            &[PlannedAction {
                side: Side::B,
                path: RelPath("copy.bin".into()),
                op: Operation::Materialize(Entry {
                    kind: EntryKind::File,
                    children: Default::default(),
                    digest: Some(expected_digest),
                    executable: false,
                    target: None,
                    mode: 0o644,
                    size: 1 << 30,
                    problem: None,
                }),
            }],
            false,
        )
        .unwrap();
    assert_eq!(report.applied, 1, "report: {report:?}");

    let copy_digest: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        let mut f = std::fs::File::open(root.join("copy.bin")).unwrap();
        std::io::copy(&mut f, &mut h).unwrap();
        h.finalize().into()
    };
    assert_eq!(copy_digest, expected_digest, "landed copy byte-identical");

    ServeChild::shutdown(session, &mut srv.child);
}
