//! Notice interface changes as they happen: a netlink socket on Linux
//! (link and address groups), a routing socket on macOS / BSD. Either one
//! just says "something changed"; the link then re-enumerates. A periodic
//! rescan backs this up (and is all there is elsewhere).

use std::io;

/// Resolves each time the OS reports a link or address change.
pub struct Watcher {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
    fd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

impl Watcher {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
    pub fn new() -> io::Result<Watcher> {
        use std::os::fd::{FromRawFd, OwnedFd};
        let fd = open()?;
        // SAFETY: `open` returned a fresh descriptor we now own.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Watcher { fd: tokio::io::unix::AsyncFd::new(fd)? })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios")))]
    pub fn new() -> io::Result<Watcher> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no interface change notifications here"))
    }

    /// Wait for the next change (reads and discards the messages).
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
    pub async fn changed(&self) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        loop {
            let mut guard = self.fd.readable().await?;
            let mut buf = [0u8; 8192];
            let mut got = false;
            loop {
                // SAFETY: reading into a local buffer of the given length.
                let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
                if n > 0 {
                    got = true;
                    continue;
                }
                let e = io::Error::last_os_error();
                if n < 0 && e.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    break;
                }
                if n < 0 && e.raw_os_error() == Some(libc::ENOBUFS) {
                    // the kernel dropped messages: something changed anyway
                    got = true;
                    continue;
                }
                return Err(if n == 0 { io::Error::other("route socket closed") } else { e });
            }
            if got {
                return Ok(());
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios")))]
    pub async fn changed(&self) -> io::Result<()> {
        std::future::pending().await
    }
}

// <linux/rtnetlink.h> multicast groups (libc has them for Linux, not Android).
#[cfg(any(target_os = "linux", target_os = "android"))]
const RTMGRP_LINK: u32 = 0x1;
#[cfg(any(target_os = "linux", target_os = "android"))]
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
#[cfg(any(target_os = "linux", target_os = "android"))]
const RTMGRP_IPV6_IFADDR: u32 = 0x100;

/// On Android 11+ the sandbox may refuse the bind; the caller then relies on
/// the periodic rescan.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn open() -> io::Result<libc::c_int> {
    // SAFETY: plain socket(2) / bind(2) calls on a zeroed sockaddr_nl.
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
        let len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        if libc::bind(fd, (&sa as *const libc::sockaddr_nl).cast(), len) < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn open() -> io::Result<libc::c_int> {
    // SAFETY: plain socket(2) / fcntl(2) calls.
    unsafe {
        let fd = libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0
            || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
            || libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0
        {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(fd)
    }
}
