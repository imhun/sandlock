//! Control protocol between the daemon and the in-sandbox `sandlock-init`.
//! Explicitly framed JSON; `RunExec` additionally carries 3 SCM_RIGHTS fds.
//!
//! Every verb is **instance-level**: `RunMain`/`RunExec` spawn registered
//! children, `Shutdown` tears the whole container down, and `Signal` delivers
//! `signum` to every registered child group. There is deliberately **no**
//! pid-addressed signal verb: a frame on this channel (which a compromised
//! workload could hold, SL-4) must never be able to name an arbitrary process
//! for the host to signal. Direct same-uid `kill(2)` between sandbox
//! processes is a kernel boundary sandlock does not mediate (see
//! `docs/sandbox-exec-security.md` §4.6/§4.15).
use serde::{Deserialize, Serialize};

/// Fixed fd number the daemon maps the control channel onto in the child.
pub const CONTROL_FD: i32 = 3;

// ── Frame envelope (F1.6 / SL-5 / F15) ─────────────────────────────────────
//
//   offset 0..4   magic      = FRAME_MAGIC ("SLKF")
//   offset 4      version    = FRAME_VERSION (2)
//   offset 5      type       = 1 (Req), 2 (Resp)
//   offset 6      n_fds      = descriptors this frame owns (0 except RunExec)
//   offset 7..11  length     = payload length, little-endian u32
//   offset 11..   payload    = serde_json bytes (unchanged from the
//                              pre-F1.6 newline-JSON payloads)
//
// The length prefix makes the frame boundary explicit, so a receiver never
// guesses it from a single `recvmsg` shape; the version field exists so a
// future envelope change is detectable (old/new builds of this same repo are
// deliberately incompatible). Oversized frames (payload > MAX_FRAME_PAYLOAD)
// and truncated frames are rejected with an error, never half-consumed.
// The channel is a `SOCK_STREAM`, so one `recvmsg` may return several frames
// while the kernel hands back **one concatenated SCM_RIGHTS list** (F15):
// `n_fds` tells the receiver how many of the read unit's descriptors each
// frame owns, and the receiver fails the whole unit closed when a declaration
// cannot be satisfied — a frame never guesses by position.

/// Fixed 4-byte frame magic.
pub const FRAME_MAGIC: [u8; 4] = *b"SLKF";
/// Current wire version. Bump (and gate on) this when the envelope layout
/// changes; payloads are serde-versioned by their own tags.
pub const FRAME_VERSION: u8 = 2;
/// Frame type byte for supervisor -> init requests.
pub const FRAME_TYPE_REQ: u8 = 1;
/// Frame type byte for init -> supervisor replies.
pub const FRAME_TYPE_RESP: u8 = 2;
/// Fixed header size: magic (4) + version (1) + type (1) + fd count (1) + length (4).
pub const FRAME_HEADER_LEN: usize = 11;
/// Most descriptors one frame may declare it owns. Only `RunExec` uses any
/// (exactly 3); the ceiling exists to reject an absurd declaration before it
/// can starve the reader's control buffer.
pub const MAX_FDS_PER_FRAME: u8 = 8;
/// Most descriptors one read unit may carry (`fdrecv`'s control buffer).
pub const MAX_FDS_PER_READ: usize = 16;
/// Hard cap on one frame's JSON payload (64 KiB); larger declarations are
/// rejected as oversize.
pub const MAX_FRAME_PAYLOAD: usize = 64 * 1024;

/// Which direction a frame travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Req,
    Resp,
}

impl FrameKind {
    fn wire_byte(self) -> u8 {
        match self {
            FrameKind::Req => FRAME_TYPE_REQ,
            FrameKind::Resp => FRAME_TYPE_RESP,
        }
    }
}

/// One decoded frame borrowing from the read buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: FrameKind,
    pub payload: &'a [u8],
    /// Descriptors this frame owns, taken from the front of the read unit's fd
    /// queue (F15). `0` for every verb but `RunExec`.
    pub n_fds: u8,
    /// Header + payload bytes this frame occupies; the caller advances its
    /// read cursor by this much and may decode the next frame behind it.
    pub consumed: usize,
}

/// One decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: FrameKind,
    pub n_fds: u8,
    pub payload_len: usize,
}

/// Why a frame was rejected at the envelope level. Payload JSON failures are
/// a separate serde error, not a frame error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer bytes than the header (or header-declared payload) were present.
    Truncated,
    /// First four bytes are not [`FRAME_MAGIC`].
    BadMagic,
    /// Version byte is not [`FRAME_VERSION`].
    Version(u8),
    /// Type byte is neither Req nor Resp.
    BadType(u8),
    /// Declared payload length exceeds [`MAX_FRAME_PAYLOAD`].
    Oversize(u64),
    /// Declared descriptor count exceeds [`MAX_FDS_PER_FRAME`]: nothing may be
    /// assigned from the fd queue on its behalf.
    TooManyFds(u8),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Truncated => write!(
                f,
                "frame truncated: fewer bytes than the header-declared length were available"
            ),
            FrameError::BadMagic => write!(f, "bad frame magic"),
            FrameError::Version(v) => write!(
                f,
                "unsupported frame version {v}: expected {FRAME_VERSION}"
            ),
            FrameError::BadType(t) => write!(f, "bad frame type byte {t}"),
            FrameError::Oversize(n) => write!(
                f,
                "frame payload of {n} bytes exceeds the {MAX_FRAME_PAYLOAD}-byte cap"
            ),
            FrameError::TooManyFds(n) => write!(
                f,
                "frame declares {n} fds, exceeding the per-frame cap of {MAX_FDS_PER_FRAME}"
            ),
        }
    }
}

/// Encode `payload` into one complete frame of `kind` that declares it owns
/// `n_fds` descriptors from the read unit's SCM_RIGHTS list.
pub fn encode_frame(
    kind: FrameKind,
    payload: &[u8],
    n_fds: u8,
) -> std::io::Result<Vec<u8>> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "cannot frame {} payload bytes: cap is {MAX_FRAME_PAYLOAD}",
                payload.len()
            ),
        ));
    }
    if n_fds > MAX_FDS_PER_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("cannot declare {n_fds} fds on one frame: cap is {MAX_FDS_PER_FRAME}"),
        ));
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.push(kind.wire_byte());
    out.push(n_fds);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Validate the `FRAME_HEADER_LEN`-byte header at the front of `bytes`.
pub fn decode_header(bytes: &[u8]) -> Result<Header, FrameError> {
    // A 10-byte v1 header (the pre-F15 envelope) must surface as a version
    // error, not a generic truncation: the version byte is readable at offset
    // 4, and the wire change is what the operator needs to see.
    if bytes.len() < 5 {
        return Err(FrameError::Truncated);
    }
    if bytes[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    if bytes[4] != FRAME_VERSION {
        return Err(FrameError::Version(bytes[4]));
    }
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(FrameError::Truncated);
    }
    let kind = match bytes[5] {
        FRAME_TYPE_REQ => FrameKind::Req,
        FRAME_TYPE_RESP => FrameKind::Resp,
        t => return Err(FrameError::BadType(t)),
    };
    let n_fds = bytes[6];
    if n_fds > MAX_FDS_PER_FRAME {
        return Err(FrameError::TooManyFds(n_fds));
    }
    let payload_len = u32::from_le_bytes(bytes[7..11].try_into().expect("11-byte header slice"))
        as usize;
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(FrameError::Oversize(payload_len as u64));
    }
    Ok(Header {
        kind,
        n_fds,
        payload_len,
    })
}

/// Decode the first frame at the front of `bytes`, which must contain that
/// frame's complete header + payload (a whole read unit). A declared length
/// that exceeds the available bytes is [`FrameError::Truncated`] — the frame
/// is never half-consumed or guessed.
pub fn decode_frame(bytes: &[u8]) -> Result<Frame<'_>, FrameError> {
    let header = decode_header(bytes)?;
    let total = FRAME_HEADER_LEN + header.payload_len;
    if bytes.len() < total {
        return Err(FrameError::Truncated);
    }
    Ok(Frame {
        kind: header.kind,
        payload: &bytes[FRAME_HEADER_LEN..total],
        n_fds: header.n_fds,
        consumed: total,
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "req", rename_all = "lowercase")]
pub enum Req {
    RunMain { argv: Vec<String>, env: Vec<(String, String)>, cwd: Option<String> },
    RunExec {
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cwd: Option<String>,
        detach: bool,
        /// F4.1: per-exec `clean_env` — start the child from an empty
        /// environment, then apply `env` (as opposed to additive overrides
        /// over the inherited init environment). `#[serde(default)]` keeps
        /// pre-F4 frames (which never carried the field) parseable.
        #[serde(default)]
        clean_env: bool,
        /// F4.1/F4.2: per-exec extra writable paths (absolute). Carried for
        /// the host-side audit/registry and the subset validation; init's
        /// `spawn` needs only cwd/env/clean_env. Host-side validation
        /// already refused anything wider than the instance ceiling, so a
        /// well-formed supervisor never sends an out-of-ceiling grant.
        #[serde(default)]
        extra_writable: Vec<String>,
        /// F4.1/F4.2: per-exec TCP bind ports (absolute grants inside the
        /// instance `net_allow_bind` ceiling). Same carrying semantics as
        /// `extra_writable`: init does not consume them.
        #[serde(default)]
        bind_ports: Vec<u16>,
        /// N25/C: tighten this child's `RLIMIT_FSIZE` (bytes). Per-exec
        /// *tightening* only; init applies it in the forked child, before
        /// execve. `#[serde(default)]` keeps pre-C frames parseable.
        #[serde(default)]
        max_file_size: Option<u64>,
    },
    /// Instance-level signal: `sandlock-init` delivers `signum` to every
    /// registered child's process group (group-first killpg + pidfd
    /// complement). No pid payload — see the module docs.
    Signal { signum: i32 },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "resp", rename_all = "lowercase")]
pub enum Resp {
    Started { pid: i32 },
    Exited { pid: i32, code: Option<i32>, signal: Option<i32> },
    Err { msg: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: u8, n_fds: u8, len: u32) -> Vec<u8> {
        let mut h = vec![0u8; FRAME_HEADER_LEN];
        h[..4].copy_from_slice(&FRAME_MAGIC);
        h[4] = FRAME_VERSION;
        h[5] = kind;
        h[6] = n_fds;
        h[7..11].copy_from_slice(&len.to_le_bytes());
        h
    }

    #[test]
    fn frame_decoder_rejects_oversize_and_truncated() {
        // A complete frame round-trips with exact fields and an exact consume
        // length (no half-consumption of a following frame).
        let payload = serde_json::to_vec(&Req::Signal { signum: 9 }).unwrap();
        let frame = encode_frame(FrameKind::Req, &payload, 0).unwrap();
        assert_eq!(&frame[..4], &FRAME_MAGIC);
        assert_eq!(frame[4], FRAME_VERSION);
        assert_eq!(frame[5], FRAME_TYPE_REQ);
        assert_eq!(frame[6], 0, "a no-fd frame declares zero descriptors");
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.kind, FrameKind::Req);
        assert_eq!(decoded.n_fds, 0);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.consumed, frame.len());

        let mut two = frame.clone();
        two.extend_from_slice(&frame);
        let first = decode_frame(&two).unwrap();
        assert_eq!(first.consumed, frame.len(), "decode consumes exactly one frame");
        assert_eq!(first.payload, payload);

        // Oversize: the declared length alone is rejected, with no payload.
        let over = (MAX_FRAME_PAYLOAD + 1) as u32;
        let mut oversize = header(FRAME_TYPE_REQ, 0, over);
        oversize.push(b'x');
        assert_eq!(decode_frame(&oversize).unwrap_err(), FrameError::Oversize(over as u64));
        assert!(encode_frame(FrameKind::Resp, &vec![0u8; MAX_FRAME_PAYLOAD + 1], 0).is_err());
        let max_frame =
            encode_frame(FrameKind::Resp, &vec![b'x'; MAX_FRAME_PAYLOAD], 0).unwrap();
        assert_eq!(decode_frame(&max_frame).unwrap().payload.len(), MAX_FRAME_PAYLOAD);

        // Truncated: a header-declared payload longer than the available bytes
        // is rejected, never returned as a partial frame.
        let mut truncated = header(FRAME_TYPE_REQ, 0, 100);
        truncated.extend_from_slice(b"only twenty bytes");
        assert_eq!(decode_frame(&truncated).unwrap_err(), FrameError::Truncated);
        // A header shorter than FRAME_HEADER_LEN is truncated too.
        assert_eq!(decode_frame(&truncated[..5]).unwrap_err(), FrameError::Truncated);

        // Bad magic / version / type are explicit errors, not panics.
        let mut bad_magic = header(FRAME_TYPE_RESP, 0, 1);
        bad_magic[0] ^= 0xff;
        assert_eq!(decode_frame(&bad_magic).unwrap_err(), FrameError::BadMagic);
        let mut bad_version = header(FRAME_TYPE_RESP, 0, 1);
        bad_version[4] = 99;
        assert_eq!(decode_frame(&bad_version).unwrap_err(), FrameError::Version(99));
        // A 10-byte v1 header surfaces as a version error (F15 wire bump),
        // with a message that names the expected version.
        let v1 = {
            let mut h = vec![0u8; 10];
            h[..4].copy_from_slice(&FRAME_MAGIC);
            h[4] = 1;
            h[5] = FRAME_TYPE_RESP;
            h[6..10].copy_from_slice(&1u32.to_le_bytes());
            h
        };
        let err = decode_frame(&v1).unwrap_err();
        assert_eq!(err, FrameError::Version(1));
        assert_eq!(
            err.to_string(),
            format!("unsupported frame version 1: expected {FRAME_VERSION}")
        );
        for bad_type in [0u8, 3, 255] {
            let bad = header(bad_type, 0, 1);
            assert_eq!(decode_frame(&bad).unwrap_err(), FrameError::BadType(bad_type));
        }
    }

    #[test]
    fn req_roundtrip() {
        let r = Req::RunExec {
            argv: vec!["sh".into()],
            env: vec![("A".into(), "1".into())],
            cwd: Some("/".into()),
            detach: false,
            clean_env: false,
            extra_writable: vec![],
            bind_ports: vec![],
            max_file_size: None,
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("runexec"));
        assert!(matches!(serde_json::from_str::<Req>(&j).unwrap(), Req::RunExec { .. }));
        // F4 wire evolution: a pre-F4 RunExec frame (no per-exec fields) is
        // still parseable — the new fields default to "no per-exec change".
        let old = r#"{"req":"runexec","argv":["sh"],"env":[],"cwd":null,"detach":false}"#;
        match serde_json::from_str::<Req>(old).unwrap() {
            Req::RunExec { clean_env, extra_writable, bind_ports, .. } => {
                assert!(!clean_env);
                assert!(extra_writable.is_empty());
                assert!(bind_ports.is_empty());
            }
            other => panic!("expected RunExec, got {other:?}"),
        }
    }
    #[test]
    fn resp_roundtrip() {
        let r = Resp::Exited { pid: 7, code: Some(0), signal: None };
        let j = serde_json::to_string(&r).unwrap();
        assert!(matches!(serde_json::from_str::<Resp>(&j).unwrap(), Resp::Exited { pid: 7, .. }));
    }
    #[test]
    fn signal_req_roundtrip() {
        let j = r#"{"req":"signal","signum":9}"#;
        match serde_json::from_str::<Req>(j).unwrap() {
            Req::Signal { signum } => assert_eq!(signum, libc::SIGKILL),
            other => panic!("expected Req::Signal, got {:?}", other),
        }
        // No arbitrary-pid variant may ever serialize onto this channel: a
        // pid-bearing frame must either stay instance-level (unknown fields
        // are ignored) or fail to parse — never become a per-pid verb.
        let pid_frame = r#"{"req":"signal","pid":424242,"signum":9}"#;
        match serde_json::from_str::<Req>(pid_frame) {
            Ok(Req::Signal { signum }) => assert_eq!(signum, libc::SIGKILL),
            Ok(other) => panic!("expected Req::Signal, got {:?}", other),
            Err(_) => {}
        }
    }
}
