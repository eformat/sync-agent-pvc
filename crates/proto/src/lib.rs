//! sync-proto — wire framing for sync-agent-pvc.
//!
//! Protocol shape (design: plan §2, borrowed from copia's wire.rs pattern):
//! 1. Handshake: server sends MAGIC_SERVER bytes, client replies MAGIC_CLIENT bytes.
//!    Purpose: distinguish a real agent stream from shell banner/rc-file noise that exec
//!    transports may spew on connect.
//! 2. Version exchange (u32 BE major/minor) — exact match required in v1; re-inject agent
//!    on mismatch.
//! 3. Frames: u32 BE length prefix (bounded by MAX_FRAME) + opaque body (CBOR in M2).
//!    Bulk file content streams as raw bytes after the frame header, never inline.
//!
//! Everything here is std-only and generic over Read/Write so it rides any duplex:
//! oc-exec stdio (fallback), a libp2p muxed stream (M3 target), or an in-memory duplex (tests).

use std::io::{self, Read, Write};

pub mod convert;
pub mod control;
pub mod messages;
pub mod p2p;
pub mod session;

/// Server→client magic: ASCII "SYN1" + 0x01 (mirrors copia's COPIA1 prologue concept).
pub const MAGIC_SERVER: [u8; 5] = [b'S', b'Y', b'N', b'1', 0x01];
/// Client→server magic: reversed sentinel, so a mis-wired pipe fails loudly and fast.
pub const MAGIC_CLIENT: [u8; 5] = [0x01, b'1', b'N', b'Y', b'S'];

/// Hard cap on a single frame body. Path/metadata frames are small; anything bigger
/// than this is a protocol error, not data. Bulk file content streams as raw bytes
/// outside frames, never inline.
pub const MAX_FRAME: u32 = 1 << 20; // 1 MiB

pub const PROTOCOL_VERSION_MAJOR: u32 = 0;
pub const PROTOCOL_VERSION_MINOR: u32 = 1;

#[derive(Debug)]
pub enum HandshakeError {
    Io(io::Error),
    /// Peer sent bytes that are not our magic (banner noise, wrong binary, TLS-in-plaintext…).
    BadMagic,
    /// Peer is a real agent but a different protocol version — re-inject the binary.
    VersionMismatch {
        peer: (u32, u32),
        ours: (u32, u32),
    },
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Io(e) => write!(f, "handshake i/o error: {e}"),
            HandshakeError::BadMagic => write!(
                f,
                "peer did not send the sync-agent magic (banner noise or wrong binary?)"
            ),
            HandshakeError::VersionMismatch { peer, ours } => {
                write!(f, "protocol version mismatch: peer {peer:?}, ours {ours:?}")
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<io::Error> for HandshakeError {
    fn from(e: io::Error) -> Self {
        HandshakeError::Io(e)
    }
}

/// Read exactly `buf.len()` bytes, treating clean EOF as an error (a truncated handshake
/// or frame is a protocol failure, not a normal end).
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended mid-frame/handshake",
            ));
        }
        filled += n;
    }
    Ok(())
}

/// Server side of the magic handshake: send MAGIC_SERVER, expect MAGIC_CLIENT back.
pub fn server_handshake<S: Read + Write>(stream: &mut S) -> Result<(), HandshakeError> {
    stream.write_all(&MAGIC_SERVER)?;
    stream.flush()?;
    let mut got = [0u8; 5];
    read_exact_or_eof(stream, &mut got)?;
    if got != MAGIC_CLIENT {
        return Err(HandshakeError::BadMagic);
    }
    Ok(())
}

/// Client side: expect MAGIC_SERVER, reply MAGIC_CLIENT.
pub fn client_handshake<S: Read + Write>(stream: &mut S) -> Result<(), HandshakeError> {
    let mut got = [0u8; 5];
    read_exact_or_eof(stream, &mut got)?;
    if got != MAGIC_SERVER {
        return Err(HandshakeError::BadMagic);
    }
    stream.write_all(&MAGIC_CLIENT)?;
    stream.flush()?;
    Ok(())
}

/// Client handshake tolerating leading banner noise (rc files, motd — anything an
/// exec-like transport may spew before the agent runs): scans the stream with a
/// 5-byte sliding window for MAGIC_SERVER, consuming up to `max_noise` bytes that
/// precede a match (the magic may straddle read boundaries — the window never
/// assumes alignment), then replies MAGIC_CLIENT exactly like [`client_handshake`].
/// No match within the cap → `BadMagic`; EOF or I/O failure mid-scan → `Io`.
///
/// Reads one byte at a time ON PURPOSE: a buffered read could swallow protocol
/// bytes that follow the magic (version exchange, Hello frame) and there is no way
/// to un-read them; byte-at-a-time keeps every post-magic byte in the stream. The
/// scan is bounded by `max_noise`, so the cost is bounded too. Noise accounting:
/// each full 5-byte window that does not match evicts its oldest byte, which no
/// future match can ever include — that eviction is one noise byte; the check
/// fires when noise EXCEEDS the cap, so exactly `max_noise` garbage bytes before a
/// magic still connects (M2 gate).
pub fn client_handshake_noisy<S: Read + Write>(
    stream: &mut S,
    max_noise: usize,
) -> Result<(), HandshakeError> {
    let mut window = [0u8; MAGIC_SERVER.len()];
    let mut filled = 0usize; // bytes currently in the window (≤ MAGIC_SERVER.len())
    let mut noise = 0usize; // bytes consumed that no future match can include
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte)? == 0 {
            return Err(HandshakeError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended before the agent magic (noise scan)",
            )));
        }
        if filled == window.len() {
            window.copy_within(1.., 0);
            filled -= 1;
        }
        window[filled] = byte[0];
        filled += 1;
        if filled == window.len() {
            if window == MAGIC_SERVER {
                stream.write_all(&MAGIC_CLIENT)?;
                stream.flush()?;
                return Ok(());
            }
            // The window's oldest byte can never start a future match — it is noise.
            noise += 1;
            if noise > max_noise {
                return Err(HandshakeError::BadMagic);
            }
        }
    }
}

fn write_u32_be<W: Write>(w: &mut W, v: u32) -> io::Result<()> {
    w.write_all(&v.to_be_bytes())
}

fn read_u32_be<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    read_exact_or_eof(r, &mut b)?;
    Ok(u32::from_be_bytes(b))
}

/// Exchange protocol versions (server-then-client, u32 BE major/minor pairs).
/// Exact match required in v1 (mutagen posture); caller re-injects the agent on mismatch.
pub fn exchange_versions_server<S: Read + Write>(
    stream: &mut S,
) -> Result<(u32, u32), HandshakeError> {
    write_u32_be(stream, PROTOCOL_VERSION_MAJOR)?;
    write_u32_be(stream, PROTOCOL_VERSION_MINOR)?;
    stream.flush()?;
    let major = read_u32_be(stream)?;
    let minor = read_u32_be(stream)?;
    expect_version(major, minor)
}

pub fn exchange_versions_client<S: Read + Write>(
    stream: &mut S,
) -> Result<(u32, u32), HandshakeError> {
    let major = read_u32_be(stream)?;
    let minor = read_u32_be(stream)?;
    expect_version(major, minor)?;
    write_u32_be(stream, PROTOCOL_VERSION_MAJOR)?;
    write_u32_be(stream, PROTOCOL_VERSION_MINOR)?;
    stream.flush()?;
    Ok((PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR))
}

fn expect_version(major: u32, minor: u32) -> Result<(u32, u32), HandshakeError> {
    let ours = (PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR);
    if (major, minor) != ours {
        return Err(HandshakeError::VersionMismatch {
            peer: (major, minor),
            ours,
        });
    }
    Ok(ours)
}

/// Write one frame: u32 BE length + body. Errors if the body exceeds MAX_FRAME.
pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame body exceeds u32"))?;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame body {len} exceeds MAX_FRAME {MAX_FRAME}"),
        ));
    }
    write_u32_be(w, len)?;
    w.write_all(body)?;
    w.flush()
}

/// Read one frame body into a fresh Vec. Oversized prefixes are rejected BEFORE allocation.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let len = read_u32_be(r)?;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("peer sent frame length {len} > MAX_FRAME {MAX_FRAME}"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    read_exact_or_eof(r, &mut body)?;
    Ok(body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Condvar, Mutex};

    /// Blocking in-memory duplex half. Pairs via `Duplex::channel()`.
    /// (std has no duplex stream; this stays dependency-free and blocks like a real pipe.)
    /// NOTE: each direction has its OWN queue — a single shared queue is racy
    /// (both halves pop the same bytes; the old helper passed by timing luck).
    pub struct Duplex {
        rx: Arc<Queue>,
        tx: Arc<Queue>,
        queues: [Arc<Queue>; 2], // shutdown both on drop
    }
    struct Queue {
        buf: Mutex<VecDeque<u8>>,
        cv: Condvar,
        open: Mutex<bool>,
    }

    impl Duplex {
        pub fn channel() -> (Duplex, Duplex) {
            let mk = || {
                Arc::new(Queue {
                    buf: Mutex::new(VecDeque::new()),
                    cv: Condvar::new(),
                    open: Mutex::new(true),
                })
            };
            let (q1, q2) = (mk(), mk());
            // a: reads q1 (what b writes), writes q2 (b reads)
            let a = Duplex {
                rx: q1.clone(),
                tx: q2.clone(),
                queues: [q1.clone(), q2.clone()],
            };
            // b: reads q2, writes q1
            let b = Duplex {
                rx: q2.clone(),
                tx: q1.clone(),
                queues: [q1, q2],
            };
            (a, b)
        }
        fn shutdown(&self) {
            for q in &self.queues {
                *q.open.lock().unwrap() = false;
                q.cv.notify_all();
            }
        }
    }

    impl Read for Duplex {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let mut buf = self.rx.buf.lock().unwrap();
            loop {
                if let Some(n) = buf.pop_front() {
                    out[0] = n;
                    // cheap byte-at-a-time is fine for tests
                    return Ok(1);
                }
                if !*self.rx.open.lock().unwrap() {
                    return Ok(0); // EOF
                }
                buf = self.rx.cv.wait(buf).unwrap();
            }
        }
    }

    impl Write for Duplex {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let mut buf = self.tx.buf.lock().unwrap();
            buf.extend(data.iter().copied());
            self.tx.cv.notify_all();
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Duplex {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    #[test]
    fn handshake_roundtrip_in_memory() {
        let (mut a, mut b) = Duplex::channel();
        let server = std::thread::spawn(move || {
            server_handshake(&mut a).unwrap();
            exchange_versions_server(&mut a).unwrap()
        });
        let client = {
            client_handshake(&mut b).unwrap();
            exchange_versions_client(&mut b).unwrap()
        };
        let server = server.join().unwrap();
        assert_eq!(server, client);
        assert_eq!(client, (PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let (mut a, mut b) = Duplex::channel();
        let server = std::thread::spawn(move || server_handshake(&mut a));
        // Client writes garbage instead of the expected magic (banner noise).
        b.write_all(b"bash: line 1: something: command not found\n")
            .unwrap();
        drop(b); // close stream
        let err = server.join().unwrap().unwrap_err();
        assert!(matches!(err, HandshakeError::BadMagic));
    }

    #[test]
    fn noisy_handshake_survives_64k_banner() {
        let (mut a, mut b) = Duplex::channel();
        let server = std::thread::spawn(move || -> Result<(u32, u32), HandshakeError> {
            // 64 KiB of motd/rc-style banner noise, then the real magic —
            // server_handshake appends MAGIC_SERVER right after the noise.
            a.write_all(&[b'#'; 64 * 1024])?;
            server_handshake(&mut a)?;
            exchange_versions_server(&mut a)
        });
        // Exactly the cap's worth of noise, then the magic: must connect.
        client_handshake_noisy(&mut b, 64 * 1024).unwrap();
        let client = exchange_versions_client(&mut b).unwrap();
        assert_eq!(server.join().unwrap().unwrap(), client);
    }

    #[test]
    fn noisy_handshake_finds_magic_straddling_write_boundaries() {
        let (mut a, mut b) = Duplex::channel();
        let server = std::thread::spawn(move || -> Result<(u32, u32), HandshakeError> {
            // Noise, then the magic split across two writes — the match must
            // straddle the write boundary. The reply is consumed manually here
            // (server_handshake would write a second magic into the stream).
            a.write_all(b"motd line\nbash: warning\n")?;
            a.write_all(&MAGIC_SERVER[..2])?;
            a.write_all(&MAGIC_SERVER[2..])?;
            let mut reply = [0u8; 5];
            a.read_exact(&mut reply)?;
            if reply != MAGIC_CLIENT {
                return Err(HandshakeError::BadMagic);
            }
            exchange_versions_server(&mut a)
        });
        client_handshake_noisy(&mut b, 1024).unwrap();
        let client = exchange_versions_client(&mut b).unwrap();
        assert_eq!(server.join().unwrap().unwrap(), client);
    }

    #[test]
    fn noisy_handshake_gives_up_badmagic_past_the_cap() {
        let (mut a, mut b) = Duplex::channel();
        // Twice the cap of pure garbage, no magic anywhere.
        a.write_all(&[b'x'; 8192]).unwrap();
        let err = client_handshake_noisy(&mut b, 4096).unwrap_err();
        assert!(matches!(err, HandshakeError::BadMagic), "got {err:?}");
    }

    #[test]
    fn noisy_handshake_eof_mid_noise_is_an_io_error() {
        let (mut a, mut b) = Duplex::channel();
        a.write_all(&[b'y'; 100]).unwrap();
        drop(a); // close before any magic
        let err = client_handshake_noisy(&mut b, 4096).unwrap_err();
        assert!(matches!(err, HandshakeError::Io(_)), "got {err:?}");
    }

    #[test]
    fn frame_roundtrip_and_bounds() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, b"hello frame").unwrap();
        let mut cur = io::Cursor::new(buf);
        assert_eq!(read_frame(&mut cur).unwrap(), b"hello frame");

        // Oversized length prefix must be rejected before allocation.
        let mut evil = Vec::new();
        evil.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut cur = io::Cursor::new(evil);
        assert!(read_frame(&mut cur).is_err());
    }
}
