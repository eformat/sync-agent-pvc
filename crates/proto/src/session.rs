//! Client-side session (M2): the daemon (and tests) drive the agent through one
//! handshaked, version-checked connection.
//!
//! [`Session`] wraps any blocking std duplex (oc-exec stdio today, libp2p stream in
//! M3, in-memory duplex in tests) and maps 1:1 onto the exchanges documented in
//! `messages.rs`:
//!
//! - [`Session::call`] — one request frame → one response frame (`Ping`→`Pong`,
//!   `Shutdown`→`Bye`, `StageFile`→`Stage`, `ReadFile`→`FileHeader`,
//!   `TransitionRun`→`TransitionDone`).
//! - [`Session::call_with_payload`] / [`Session::read_payload`] /
//!   [`Session::read_payload_hashed`] — RAW content streams AROUND the frames (the
//!   header frame is the length contract; bulk bytes are never inline).
//! - [`Session::scan`] / [`Session::transition`] — the two CHUNKED exchanges:
//!   listing/cache fragments and planned actions never exceed their per-frame
//!   budgets, so a 200k-file tree cannot die the copia "single 1 MiB frame >~15-20k
//!   files" death (plan §2).
//!
//! Failure posture: every protocol-level surprise (wrong response kind,
//! `Response::Error(msg)`, truncated stream, payload source dying mid-upload)
//! surfaces as `io::Error` — `ErrorKind::InvalidData` with the message, or
//! `UnexpectedEof` for truncation. No method panics on peer input. After an error
//! the session state is undefined: the caller tears the transport down (v1
//! cancellation idiom — kill/close; nothing partial is ever applied, and staged
//! content lives under `.sync-agent/` where the next session finds it).

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use sync_core::apply::{ApplyReport, PlannedAction};
use sync_core::types::{FlatTree, RelPath};

use crate::convert::{action_to_wire, chunk_bytes, entry_from_wire, report_from_wire};
use crate::messages::{
    read_response, send_request, Hello, Request, Response, WirePlannedAction, CHUNK_BYTES,
};

/// Leading-noise tolerance `Session::client` allows before giving up on the server
/// magic (exec-like transports may spew rc/motd/banner output on connect; the M2
/// gate proves 64 KiB of it). 1 MiB = the frame-bound scale. A wrong binary fails
/// `BadMagic` at this cap or at EOF, whichever comes first.
pub const DEFAULT_MAX_HANDSHAKE_NOISE: usize = 1 << 20;

/// Everything one [`Session::scan`] exchange returns: the flat tree (path → leaf
/// entry, children empty — the wire carries the flat form) plus the agent's scan
/// stats and the fresh cache bytes reassembled from `CacheChunk*` fragments (the
/// daemon persists them for the next warm scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub tree: FlatTree,
    pub file_count: u64,
    pub dir_count: u64,
    pub total_size: u64,
    pub preserves_executability: bool,
    pub fresh_cache_bytes: Vec<u8>,
}

fn protocol_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// One client session against a sync agent: handshaked, version-checked, holding
/// the agent's [`Hello`] identity (§8 — version, uid/gid, root, writability,
/// executability probe). Generic over any blocking std duplex.
pub struct Session<S: Read + Write> {
    stream: S,
    hello: Hello,
}

impl<S: Read + Write> Session<S> {
    /// Noise-tolerant magic handshake ([`crate::client_handshake_noisy`] with
    /// [`DEFAULT_MAX_HANDSHAKE_NOISE`]) + exact version exchange + `Response::Hello`.
    /// A missing/`Error` hello (or any handshake/version failure) → `Err(InvalidData)`
    /// carrying the message; truncation → `Err(UnexpectedEof)`.
    pub fn client(mut stream: S) -> io::Result<Self> {
        crate::client_handshake_noisy(&mut stream, DEFAULT_MAX_HANDSHAKE_NOISE)
            .map_err(|e| protocol_err(e.to_string()))?;
        crate::exchange_versions_client(&mut stream).map_err(|e| protocol_err(e.to_string()))?;
        let hello = match read_response(&mut stream)? {
            Response::Hello(hello) => hello,
            Response::Error(msg) => return Err(protocol_err(msg)),
            other => {
                return Err(protocol_err(format!(
                    "expected Hello after handshake, got {other:?}"
                )))
            }
        };
        Ok(Session { stream, hello })
    }

    /// The agent's identity + root facts, sent once after the version exchange (§8).
    pub fn hello(&self) -> &Hello {
        &self.hello
    }

    /// Single-frame request → single-frame response. `Response::Error(msg)` →
    /// `Err(InvalidData(msg))`; any other variant is returned as-is for the caller
    /// to match (this primitive does not police which response belongs to which
    /// request — the exchange helpers below do).
    pub fn call(&mut self, req: &Request) -> io::Result<Response> {
        send_request(&mut self.stream, req)?;
        self.read_checked()
    }

    /// `req` frame, then EXACTLY `len` RAW payload bytes streamed from `payload` in
    /// `CHUNK_BYTES` pieces (`StageFile` upload), then the response frame.
    ///
    /// If the payload source dies mid-stream the session is left mid-exchange; the
    /// caller tears the transport down (the agent verifies the blake3 digest
    /// server-side, so a mid-transfer change surfaces as `DigestMismatch` there and
    /// nothing partial is ever staged — M2 gate).
    pub fn call_with_payload(
        &mut self,
        req: &Request,
        payload: &mut dyn Read,
        len: u64,
    ) -> io::Result<Response> {
        send_request(&mut self.stream, req)?;
        let mut buf = vec![0u8; CHUNK_BYTES];
        let mut remaining = len;
        while remaining > 0 {
            let want = remaining.min(CHUNK_BYTES as u64) as usize;
            let n = payload.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "payload source ended before its declared size (mid-transfer change?)",
                ));
            }
            self.stream.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        self.stream.flush()?;
        self.read_checked()
    }

    /// Consume EXACTLY `len` RAW bytes following a `FileHeader` frame, writing them
    /// to `out` through a fixed `CHUNK_BYTES` buffer (memory-bounded whatever the
    /// file size — the M2 1 GB gate). Returns nothing: the caller hashes/compares
    /// if it needs to (or use [`Session::read_payload_hashed`]).
    pub fn read_payload(&mut self, len: u64, out: &mut dyn Write) -> io::Result<()> {
        self.copy_payload(len, out, None)
    }

    /// [`Session::read_payload`] plus a streaming blake3 over the same bytes;
    /// returns the digest so the caller can compare against the `FileHeader`'s.
    /// Same fixed-buffer posture: the file never sits in memory whole.
    pub fn read_payload_hashed(&mut self, len: u64, out: &mut dyn Write) -> io::Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        self.copy_payload(len, out, Some(&mut hasher))?;
        Ok(*hasher.finalize().as_bytes())
    }

    /// Shared payload loop: EXACTLY `len` bytes from the stream into `out`,
    /// updating `hasher` when present. One CHUNK_BYTES working buffer — never the
    /// whole payload. Truncation is a loud protocol error, never a short read.
    fn copy_payload(
        &mut self,
        len: u64,
        out: &mut dyn Write,
        mut hasher: Option<&mut blake3::Hasher>,
    ) -> io::Result<()> {
        let mut buf = vec![0u8; CHUNK_BYTES];
        let mut remaining = len;
        while remaining > 0 {
            let want = remaining.min(CHUNK_BYTES as u64) as usize;
            let n = self.stream.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("stream ended {remaining} bytes short of the declared payload"),
                ));
            }
            if let Some(h) = hasher.as_deref_mut() {
                h.update(&buf[..n]);
            }
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        out.flush()
    }

    /// Full chunked scan exchange: send the prior cache as `CacheChunk*` fragments
    /// (`prior_cache_bytes` may be empty → zero frames) + `Scan{rules}`, then
    /// accumulate `ScanBegin` → `ScanChunk*` → `CacheChunk*` → `ScanDone` into the
    /// [`ScanResult`]. Duplicate/missing markers and unexpected response kinds are
    /// protocol errors (`InvalidData`), never silent mis-reassembly.
    pub fn scan(&mut self, prior_cache_bytes: &[u8], rules: &[String]) -> io::Result<ScanResult> {
        for chunk in chunk_bytes(prior_cache_bytes) {
            send_request(&mut self.stream, &Request::CacheChunk(chunk))?;
        }
        send_request(
            &mut self.stream,
            &Request::Scan {
                rules: rules.to_vec(),
            },
        )?;

        let mut tree: FlatTree = BTreeMap::new();
        let mut stats: Option<(u64, u64, u64, bool)> = None;
        let mut fresh_cache_bytes = Vec::new();
        loop {
            match read_response(&mut self.stream)? {
                Response::ScanBegin {
                    file_count,
                    dir_count,
                    total_size,
                    preserves_executability,
                } => {
                    if stats
                        .replace((file_count, dir_count, total_size, preserves_executability))
                        .is_some()
                    {
                        return Err(protocol_err("duplicate ScanBegin in scan sequence"));
                    }
                }
                Response::ScanChunk(entries) => {
                    for (path, wire) in entries {
                        let entry = entry_from_wire(&wire).map_err(protocol_err)?;
                        tree.insert(RelPath(path), entry);
                    }
                }
                Response::CacheChunk(bytes) => fresh_cache_bytes.extend_from_slice(&bytes),
                Response::ScanDone => break,
                Response::Error(msg) => return Err(protocol_err(msg)),
                other => {
                    return Err(protocol_err(format!(
                        "unexpected response in scan sequence: {other:?}"
                    )))
                }
            }
        }
        let (file_count, dir_count, total_size, preserves_executability) = stats
            .ok_or_else(|| protocol_err("scan sequence ended with ScanDone before ScanBegin"))?;
        Ok(ScanResult {
            tree,
            file_count,
            dir_count,
            total_size,
            preserves_executability,
            fresh_cache_bytes,
        })
    }

    /// Chunked transition exchange: the plan rides as `TransitionChunk*` frames
    /// (converted via [`action_to_wire`], size-bounded well under MAX_FRAME — see
    /// [`Self::TRANSITION_CHUNK_BUDGET`]) + `TransitionRun{force}` →
    /// `TransitionDone(report)` (converted back via [`report_from_wire`]).
    pub fn transition(
        &mut self,
        actions: &[PlannedAction],
        force: bool,
    ) -> io::Result<ApplyReport> {
        // Byte-budgeted framing: each action's exact encoded size decides when a
        // frame is full, so pathological path lengths can never push a frame past
        // the wire bound. An empty plan still sends ONE empty chunk frame — the
        // protocol wants ≥1 TransitionChunk before TransitionRun (messages.rs).
        let mut frame: Vec<WirePlannedAction> = Vec::new();
        let mut frame_bytes = 0usize;
        for action in actions {
            let wire = action_to_wire(action);
            let size = bincode::serialized_size(&wire)
                .map_err(|e| protocol_err(format!("size transition action: {e}")))?
                as usize;
            if !frame.is_empty() && frame_bytes + size > Self::TRANSITION_CHUNK_BUDGET {
                send_request(
                    &mut self.stream,
                    &Request::TransitionChunk(std::mem::take(&mut frame)),
                )?;
                frame_bytes = 0;
            }
            frame_bytes += size;
            frame.push(wire);
        }
        send_request(&mut self.stream, &Request::TransitionChunk(frame))?;

        match self.call(&Request::TransitionRun { force })? {
            Response::TransitionDone(wire_report) => Ok(report_from_wire(&wire_report)),
            other => Err(protocol_err(format!(
                "expected TransitionDone, got {other:?}"
            ))),
        }
    }

    /// Byte budget per `TransitionChunk` frame body (bincode-encoded plan fragment).
    /// Half of MAX_FRAME: bincode's framing overhead cannot push a frame past the
    /// 1 MiB wire bound whatever the path lengths. Each action lands in exactly one
    /// frame; a SINGLE action bigger than MAX_FRAME cannot ride the protocol and
    /// fails loudly in `write_frame` (correct for a corrupt plan).
    const TRANSITION_CHUNK_BUDGET: usize = 512 * 1024;

    /// Read one response frame, mapping the protocol's `Error(msg)` to
    /// `Err(InvalidData(msg))` (every exchange helper funnels through here).
    fn read_checked(&mut self) -> io::Result<Response> {
        match read_response(&mut self.stream)? {
            Response::Error(msg) => Err(protocol_err(msg)),
            resp => Ok(resp),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — scripted fake agent on the other half of an in-memory Duplex.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{read_request, send_response, StageResult, WirePlannedAction};
    use crate::tests::Duplex;
    use sync_core::apply::{Operation, Side};
    use sync_core::types::{Entry, EntryKind};

    /// The §8 hello a fake agent presents.
    fn test_hello() -> Hello {
        Hello {
            agent_version: "0.1.0-test".into(),
            uid: 1000,
            gid: 1000,
            root: "/sandbox".into(),
            root_writable: true,
            preserves_executability: true,
        }
    }

    /// Handshake errors flattened into io::Error (JoinHandle carries one error type).
    fn hs_err(e: crate::HandshakeError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e.to_string())
    }

    /// Server-side prelude every fake agent runs: magic handshake + version
    /// exchange + Hello.
    fn agent_prelude(d: &mut Duplex, hello: &Hello) -> io::Result<()> {
        crate::server_handshake(d).map_err(hs_err)?;
        crate::exchange_versions_server(d).map_err(hs_err)?;
        send_response(d, &Response::Hello(hello.clone()))
    }

    fn expect_ping(d: &mut Duplex) -> io::Result<()> {
        match read_request(d)? {
            Request::Ping => Ok(()),
            other => Err(protocol_err(format!(
                "fake agent expected Ping, got {other:?}"
            ))),
        }
    }

    /// Deterministic pseudo-random bytes (xorshift64), no external RNG — payload
    /// material for the 3 MB hashed-read gate and the multi-chunk upload test.
    fn pseudo_bytes(n: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(n);
        out
    }

    /// A synthetic flat tree big enough to need 2 ScanChunks at
    /// SCAN_CHUNK_ENTRIES: root + 4 kind representatives + 2495 files = 2500,
    /// with the root-path key form ("") included. Flat form throughout —
    /// children empty — matching what the wire carries.
    fn synthetic_tree() -> FlatTree {
        let mut tree = FlatTree::new();
        tree.insert(RelPath::root(), Entry::directory(BTreeMap::new()));
        let d = [3u8; 32];
        tree.insert(
            RelPath("a-symlink".into()),
            Entry {
                kind: EntryKind::SymbolicLink,
                digest: Some(d),
                target: Some("target.txt".into()),
                mode: 0o777,
                ..Entry::untracked()
            },
        );
        tree.insert(RelPath("b-untracked".into()), Entry::untracked());
        tree.insert(
            RelPath("c-problematic".into()),
            Entry::problematic("EACCES on stat"),
        );
        tree.insert(
            RelPath("d-exec.sh".into()),
            Entry {
                kind: EntryKind::File,
                digest: Some(d),
                executable: true,
                mode: 0o755,
                size: 4,
                ..Entry::untracked()
            },
        );
        for i in 0..2495 {
            tree.insert(
                RelPath(format!("f{i:05}")),
                Entry {
                    kind: EntryKind::File,
                    digest: Some(d),
                    mode: 0o644,
                    size: i as u64,
                    ..Entry::untracked()
                },
            );
        }
        tree
    }

    #[test]
    fn hello_and_ping_roundtrip() {
        let (srv, cli) = Duplex::channel();
        let hello_main = test_hello();
        let hello_srv = hello_main.clone();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let mut d = srv;
            agent_prelude(&mut d, &hello_srv)?;
            expect_ping(&mut d)?;
            send_response(&mut d, &Response::Pong)
        });

        let mut session = Session::client(cli).unwrap();
        assert_eq!(session.hello(), &hello_main);
        assert_eq!(session.call(&Request::Ping).unwrap(), Response::Pong);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn error_response_surfaces_as_invalid_data_with_message() {
        let (srv, cli) = Duplex::channel();
        let hello_srv = test_hello();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let mut d = srv;
            agent_prelude(&mut d, &hello_srv)?;
            expect_ping(&mut d)?;
            send_response(&mut d, &Response::Error("boom: root unwritable".into()))
        });

        let mut session = Session::client(cli).unwrap();
        let err = session.call(&Request::Ping).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("root unwritable"), "got: {err}");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn scan_chunked_exchange_reassembles_tree_stats_and_cache() {
        let (srv, cli) = Duplex::channel();
        let hello_srv = test_hello();
        let fresh_cache = vec![0xABu8; 100_000];
        let fresh_cache_srv = fresh_cache.clone();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let mut d = srv;
            agent_prelude(&mut d, &hello_srv)?;
            // Prior cache upload: fragments accumulate until the Scan request.
            let mut got_prior = Vec::new();
            loop {
                match read_request(&mut d)? {
                    Request::CacheChunk(bytes) => got_prior.extend_from_slice(&bytes),
                    Request::Scan { rules } => {
                        assert_eq!(rules, vec!["target/**".to_string()]);
                        break;
                    }
                    other => {
                        return Err(protocol_err(format!(
                            "fake agent expected CacheChunk*/Scan, got {other:?}"
                        )))
                    }
                }
            }
            assert_eq!(got_prior, b"prior-cache-bytes".to_vec());

            // Response sequence: ScanBegin + 2 ScanChunks (chunk_flat_tree over a
            // 2500-entry tree) + CacheChunk + ScanDone.
            send_response(
                &mut d,
                &Response::ScanBegin {
                    file_count: 2499,
                    dir_count: 1,
                    total_size: 4242,
                    preserves_executability: true,
                },
            )?;
            let tree = synthetic_tree();
            for chunk in crate::convert::chunk_flat_tree(&tree) {
                send_response(&mut d, &Response::ScanChunk(chunk))?;
            }
            send_response(&mut d, &Response::CacheChunk(fresh_cache_srv))?;
            send_response(&mut d, &Response::ScanDone)
        });

        let mut session = Session::client(cli).unwrap();
        let result = session
            .scan(b"prior-cache-bytes", &["target/**".to_string()])
            .unwrap();
        assert_eq!(result.tree, synthetic_tree());
        assert_eq!(result.file_count, 2499);
        assert_eq!(result.dir_count, 1);
        assert_eq!(result.total_size, 4242);
        assert!(result.preserves_executability);
        assert_eq!(result.fresh_cache_bytes, fresh_cache);
        server.join().unwrap().unwrap();
    }

    #[test]
    fn read_payload_hashed_3mb_matches_blake3_of_the_original() {
        let payload = pseudo_bytes(3 * 1024 * 1024);
        let expected = *blake3::hash(&payload).as_bytes();
        let size = payload.len() as u64;
        let payload_srv = payload.clone();
        let (srv, cli) = Duplex::channel();
        let hello_srv = test_hello();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let mut d = srv;
            agent_prelude(&mut d, &hello_srv)?;
            match read_request(&mut d)? {
                Request::ReadFile { path } => assert_eq!(path, "big.bin"),
                other => {
                    return Err(protocol_err(format!(
                        "fake agent expected ReadFile, got {other:?}"
                    )))
                }
            }
            send_response(
                &mut d,
                &Response::FileHeader {
                    path: "big.bin".into(),
                    size,
                    mode: 0o644,
                    executable: false,
                    digest: expected,
                },
            )?;
            // RAW payload after the frame — never framed (length contract).
            d.write_all(&payload_srv)?;
            d.flush()
        });

        let mut session = Session::client(cli).unwrap();
        let (size, header_digest) = match session
            .call(&Request::ReadFile {
                path: "big.bin".into(),
            })
            .unwrap()
        {
            Response::FileHeader {
                path, size, digest, ..
            } => {
                assert_eq!(path, "big.bin");
                (size, digest)
            }
            other => panic!("expected FileHeader, got {other:?}"),
        };
        let mut sink = Vec::new();
        let got = session.read_payload_hashed(size, &mut sink).unwrap();
        assert_eq!(got, header_digest);
        assert_eq!(got, expected);
        assert_eq!(sink, payload, "payload bytes must pass through untouched");
        server.join().unwrap().unwrap();
    }

    #[test]
    fn read_payload_streams_exactly_len_bytes() {
        let payload = b"short and sweet".to_vec();
        let size = payload.len() as u64;
        let payload_srv = payload.clone();
        let (srv, cli) = Duplex::channel();
        let hello_srv = test_hello();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let mut d = srv;
            agent_prelude(&mut d, &hello_srv)?;
            expect_ping(&mut d)?;
            send_response(&mut d, &Response::Pong)?;
            // RAW payload after the response frame.
            d.write_all(&payload_srv)?;
            d.flush()
        });

        let mut session = Session::client(cli).unwrap();
        session.call(&Request::Ping).unwrap();
        let mut sink = Vec::new();
        session.read_payload(size, &mut sink).unwrap();
        assert_eq!(sink, payload);
        // The stream must be EXACTLY consumed: EOF next, not more bytes.
        assert!(session.read_payload(1, &mut sink).is_err());
        server.join().unwrap().unwrap();
    }

    #[test]
    fn call_with_payload_streams_multi_chunk_upload() {
        // 2×CHUNK_BYTES + 1 → exactly 3 payload pieces on the wire.
        let payload = pseudo_bytes(CHUNK_BYTES * 2 + 1);
        let digest = *blake3::hash(&payload).as_bytes();
        let size = payload.len() as u64;
        let (srv, cli) = Duplex::channel();
        let hello_srv = test_hello();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let mut d = srv;
            agent_prelude(&mut d, &hello_srv)?;
            match read_request(&mut d)? {
                Request::StageFile {
                    path,
                    size: s,
                    digest: req_digest,
                    ..
                } => {
                    assert_eq!(path, "staged.bin");
                    assert_eq!(s, size, "declared size must match the payload");
                    // EXACTLY `size` RAW bytes follow the request frame.
                    let mut got = vec![0u8; s as usize];
                    d.read_exact(&mut got)?;
                    // Digest verification is the agent's mid-transfer-change gate.
                    let staged = if blake3::hash(&got).as_bytes() == &req_digest {
                        StageResult::Staged
                    } else {
                        StageResult::DigestMismatch {
                            got: *blake3::hash(&got).as_bytes(),
                        }
                    };
                    send_response(&mut d, &Response::Stage(staged))
                }
                other => Err(protocol_err(format!(
                    "fake agent expected StageFile, got {other:?}"
                ))),
            }
        });

        let mut session = Session::client(cli).unwrap();
        let req = Request::StageFile {
            path: "staged.bin".into(),
            size,
            mode: 0o644,
            executable: false,
            digest,
        };
        let resp = session
            .call_with_payload(&req, &mut payload.as_slice(), size)
            .unwrap();
        assert_eq!(resp, Response::Stage(StageResult::Staged));
        server.join().unwrap().unwrap();
    }

    #[test]
    fn transition_chunked_exchange_roundtrips_the_plan_and_report() {
        // 4500 actions → several size-bounded TransitionChunk frames.
        let actions: Vec<PlannedAction> = (0..4500)
            .map(|i| PlannedAction {
                side: if i % 2 == 0 { Side::A } else { Side::B },
                path: RelPath(format!("p{i:05}")),
                op: if i % 3 == 0 {
                    Operation::Remove(Entry {
                        kind: EntryKind::File,
                        digest: Some([1u8; 32]),
                        mode: 0o644,
                        size: 2,
                        ..Entry::untracked()
                    })
                } else {
                    Operation::Materialize(Entry {
                        kind: EntryKind::File,
                        digest: Some([2u8; 32]),
                        executable: true,
                        mode: 0o755,
                        size: i as u64,
                        ..Entry::untracked()
                    })
                },
            })
            .collect();

        let expected_report = ApplyReport {
            applied: 3000,
            deleted: 1500,
            failed: 1,
            halted: None,
            problems: vec![(RelPath("p00001".into()), "boom".into())],
        };

        let (srv, cli) = Duplex::channel();
        let hello_srv = test_hello();
        let report_srv = expected_report.clone();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let mut d = srv;
            agent_prelude(&mut d, &hello_srv)?;
            // Accumulate the plan until the run request.
            let mut plan: Vec<WirePlannedAction> = Vec::new();
            loop {
                match read_request(&mut d)? {
                    Request::TransitionChunk(chunk) => plan.extend(chunk),
                    Request::TransitionRun { force } => {
                        assert!(!force);
                        break;
                    }
                    other => {
                        return Err(protocol_err(format!(
                            "fake agent expected TransitionChunk*/Run, got {other:?}"
                        )))
                    }
                }
            }
            assert_eq!(plan.len(), 4500, "every action must arrive exactly once");
            // Roundtrip every action back through the wire mirror — the agent
            // side must be able to reconstruct what the daemon planned.
            for wire in &plan {
                crate::convert::action_from_wire(wire).unwrap();
            }
            send_response(
                &mut d,
                &Response::TransitionDone(crate::convert::report_to_wire(&report_srv)),
            )
        });

        let mut session = Session::client(cli).unwrap();
        let report = session.transition(&actions, false).unwrap();
        assert_eq!(report, expected_report);
        server.join().unwrap().unwrap();
    }
}
