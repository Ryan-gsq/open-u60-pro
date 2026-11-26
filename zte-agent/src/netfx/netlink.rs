use std::io;
use std::os::fd::{FromRawFd, OwnedFd};

pub(crate) fn open_route() -> io::Result<OwnedFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn the_route_socket_is_raw_and_close_on_exec() {
        let socket = open_route().unwrap();
        let fd = socket.as_raw_fd();
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, libc::FD_CLOEXEC);
        for (option, expected) in [
            (libc::SO_DOMAIN, libc::AF_NETLINK),
            (libc::SO_PROTOCOL, libc::NETLINK_ROUTE),
            (libc::SO_TYPE, libc::SOCK_RAW),
        ] {
            let mut value = 0i32;
            let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
            let result = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::from_mut(&mut value).cast(),
                    &mut len,
                )
            };
            assert_eq!(result, 0, "{}", io::Error::last_os_error());
            assert_eq!(value, expected);
        }
    }
}
