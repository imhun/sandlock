use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};

use super::proto::{FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD};

/// Blocking recvmsg of whatever is queued on the control socket (up to one
/// full maximum-size frame) plus up to `max_fds` SCM_RIGHTS fds.
///
/// Every received fd is handed back as an [`OwnedFd`] — ownership transfers
/// at the recvmsg boundary, so the caller's RAII guard (not a later branch)
/// decides when it closes. Returns (bytes, fds); empty bytes means
/// EOF/peer closed. The read buffer is at least one header + the maximum
/// payload, so a legitimate single-sendmsg frame always arrives whole (the
/// F1.6 wire contract: one frame per sendmsg, fds bound to that sendmsg).
pub fn recv(
    fd: RawFd,
    max_fds: usize,
) -> std::io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut buf = vec![0u8; FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
    let space =
        unsafe { libc::CMSG_SPACE((max_fds * std::mem::size_of::<RawFd>()) as u32) as usize };
    let mut cbuf = vec![0u8; space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = space as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 { return Err(std::io::Error::last_os_error()); }
    let mut fds: Vec<OwnedFd> = Vec::new();
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let p = libc::CMSG_DATA(c) as *const RawFd;
                for i in 0..(payload / std::mem::size_of::<RawFd>()) {
                    fds.push(OwnedFd::from_raw_fd(*p.add(i)));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    buf.truncate(n as usize);
    Ok((buf, fds))
}
