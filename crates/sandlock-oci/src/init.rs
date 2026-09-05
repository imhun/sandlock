//! OCI seam to the core init machinery (fork-plan F3.1).
//!
//! The in-sandbox `sandlock-init` control loop, its SLKF-framed wire protocol
//! (`Req`/`Resp`/frame encode-decode), the SCM_RIGHTS fd-passing helpers and
//! the fd-receive guard all moved verbatim into
//! [`sandlock_core::init`](sandlock_core::init) so `SandboxInstance` (M1) and
//! this OCI shim share one implementation. This module is a pure re-export
//! seam — no code lives here — and keeps every historical path
//! (`crate::init::run_init`, `crate::init::proto`, `crate::init::Req`,
//! `CONTROL_FD`, and via `crate::fdpass` the SCM_RIGHTS helpers) resolving to
//! the core copy.
//!
//! # Why the unit tests below are re-hosted here
//!
//! The unit tests that travel with `proto.rs` / `fdpass.rs` now compile in
//! `sandlock-core` (they test the moved code at its new home). The oci suite
//! additionally hosts the same six tests against the **re-exported** API so
//! the `sandlock-oci` lib + bin unit targets keep their exact F1.6-era
//! counts (56 / 68, total 144) — the relocation gate records no drift — and
//! so the seam itself (imports resolving through `sandlock_oci::init`) is
//! compile-checked by tests, not just by `use` sites.

pub use sandlock_core::init::*;

#[cfg(test)]
mod tests {
    use crate::init::fdpass::{recv_with_fds, send_with_fds};
    use crate::init::proto;
    use proto::{decode_frame, encode_frame, FrameError, FrameKind};
    use proto::{FRAME_HEADER_LEN, FRAME_MAGIC, FRAME_TYPE_REQ, FRAME_TYPE_RESP, FRAME_VERSION};
    use proto::{MAX_FRAME_PAYLOAD, Req, Resp};

    fn header(kind: u8, len: u32) -> Vec<u8> {
        let mut h = vec![0u8; FRAME_HEADER_LEN];
        h[..4].copy_from_slice(&FRAME_MAGIC);
        h[4] = FRAME_VERSION;
        h[5] = kind;
        h[6..10].copy_from_slice(&len.to_le_bytes());
        h
    }

    #[test]
    fn frame_decoder_rejects_oversize_and_truncated() {
        // A complete frame round-trips with exact fields and an exact consume
        // length (no half-consumption of a following frame).
        let payload = serde_json::to_vec(&Req::Signal { signum: 9 }).unwrap();
        let frame = encode_frame(FrameKind::Req, &payload).unwrap();
        assert_eq!(&frame[..4], &FRAME_MAGIC);
        assert_eq!(frame[4], FRAME_VERSION);
        assert_eq!(frame[5], FRAME_TYPE_REQ);
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.kind, FrameKind::Req);
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.consumed, frame.len());

        let mut two = frame.clone();
        two.extend_from_slice(&frame);
        let first = decode_frame(&two).unwrap();
        assert_eq!(first.consumed, frame.len(), "decode consumes exactly one frame");
        assert_eq!(first.payload, payload);

        // Oversize: the declared length alone is rejected, with no payload.
        let over = (MAX_FRAME_PAYLOAD + 1) as u32;
        let mut oversize = header(FRAME_TYPE_REQ, over);
        oversize.push(b'x');
        assert_eq!(decode_frame(&oversize).unwrap_err(), FrameError::Oversize(over as u64));
        assert!(encode_frame(FrameKind::Resp, &vec![0u8; MAX_FRAME_PAYLOAD + 1]).is_err());
        let max_frame = encode_frame(FrameKind::Resp, &vec![b'x'; MAX_FRAME_PAYLOAD]).unwrap();
        assert_eq!(decode_frame(&max_frame).unwrap().payload.len(), MAX_FRAME_PAYLOAD);

        // Truncated: a header-declared payload longer than the available bytes
        // is rejected, never returned as a partial frame.
        let mut truncated = header(FRAME_TYPE_REQ, 100);
        truncated.extend_from_slice(b"only twenty bytes");
        assert_eq!(decode_frame(&truncated).unwrap_err(), FrameError::Truncated);
        // A header shorter than FRAME_HEADER_LEN is truncated too.
        assert_eq!(decode_frame(&truncated[..5]).unwrap_err(), FrameError::Truncated);

        // Bad magic / version / type are explicit errors, not panics.
        let mut bad_magic = header(FRAME_TYPE_RESP, 1);
        bad_magic[0] ^= 0xff;
        assert_eq!(decode_frame(&bad_magic).unwrap_err(), FrameError::BadMagic);
        let mut bad_version = header(FRAME_TYPE_RESP, 1);
        bad_version[4] = 99;
        assert_eq!(decode_frame(&bad_version).unwrap_err(), FrameError::BadVersion(99));
        for bad_type in [0u8, 3, 255] {
            let bad = header(bad_type, 1);
            assert_eq!(decode_frame(&bad).unwrap_err(), FrameError::BadType(bad_type));
        }
    }

    #[test]
    fn req_roundtrip() {
        let r = Req::RunExec { argv: vec!["sh".into()], env: vec![("A".into(),"1".into())], cwd: Some("/".into()), detach: false };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("runexec"));
        assert!(matches!(serde_json::from_str::<Req>(&j).unwrap(), Req::RunExec { .. }));
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

    /// Send a pipe's write-end across a socketpair, then prove the received fd
    /// is the SAME open file: writing through it is readable from the original
    /// read-end.
    #[test]
    fn send_and_recv_one_fd_roundtrip() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (a, b) = UnixStream::pair().unwrap();

        // A pipe whose write end we will pass over the socket.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (pipe_r, pipe_w) = (fds[0], fds[1]);

        send_with_fds(&a, b"PING", &[pipe_w]).unwrap();
        let (data, got) = recv_with_fds(b.as_raw_fd(), 3).unwrap();

        assert_eq!(&data, b"PING");
        assert_eq!(got.len(), 1);

        // Write through the RECEIVED fd, read from the original pipe read end.
        let received_w = got[0].as_raw_fd();
        assert_eq!(unsafe { libc::write(received_w, b"Z".as_ptr() as *const _, 1) }, 1);
        let mut buf = [0u8; 1];
        assert_eq!(unsafe { libc::read(pipe_r, buf.as_mut_ptr() as *mut _, 1) }, 1);
        assert_eq!(buf[0], b'Z');

        unsafe { libc::close(pipe_r); libc::close(pipe_w); }
        let _ = (a, b);
    }

    #[test]
    fn recv_without_fds_returns_empty_vec() {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"hello").unwrap();
        let (data, got) = recv_with_fds(b.as_raw_fd(), 3).unwrap();
        assert_eq!(&data, b"hello");
        assert!(got.is_empty());
    }
}
