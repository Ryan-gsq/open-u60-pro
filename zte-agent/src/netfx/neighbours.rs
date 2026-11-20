//! Read the current IPv4 neighbour table with RTM_GETNEIGH. Never use a
//! partial dump after an interrupt, truncation, or missing NLMSG_DONE.
use std::net::Ipv4Addr;

pub struct Entry { pub ip: Ipv4Addr, pub mac: String, pub reachable: bool }

#[cfg(target_os = "linux")]
pub fn list(device: &str) -> Result<Vec<Entry>, String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let device = std::ffi::CString::new(device).map_err(|e| e.to_string())?;
    let index = unsafe { libc::if_nametoindex(device.as_ptr()) };
    let os_error = || std::io::Error::last_os_error().to_string();
    if index == 0 { return Err(os_error()); }
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
    if fd < 0 { return Err(os_error()); }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = socket.as_raw_fd();
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as _;
    if unsafe { libc::connect(fd, std::ptr::from_ref(&kernel).cast(), std::mem::size_of_val(&kernel) as _) } != 0 { return Err(os_error()); }
    let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
    if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, std::ptr::from_ref(&timeout).cast(), std::mem::size_of_val(&timeout) as _) } != 0 { return Err(os_error()); }
    let mut request = [0u8; 28]; // nlmsghdr + ndmsg
    request[..4].copy_from_slice(&28u32.to_ne_bytes());
    request[4..6].copy_from_slice(&30u16.to_ne_bytes()); // RTM_GETNEIGH
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1u32.to_ne_bytes()); // dedicated socket, one request
    request[16] = libc::AF_INET as u8;
    request[20..24].copy_from_slice(&index.to_ne_bytes());
    if unsafe { libc::send(fd, request.as_ptr().cast(), request.len(), 0) } != request.len() as isize { return Err(os_error()); }
    let mut buf = vec![0u8; 32768];
    let mut entries = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
        if n <= 0 { return Err(os_error()); }
        let packet = buf.get(..n as usize).ok_or("Incomplete neighbour dump")?;
        if decode(packet, index, &mut entries)? { return Ok(entries); }
    }
    Err("Neighbour dump timed out".into())
}

#[cfg(not(target_os = "linux"))]
pub fn list(_: &str) -> Result<Vec<Entry>, String> { Err("Neighbour table requires Linux".into()) }

#[cfg(any(test, target_os = "linux"))]
fn decode(mut packet: &[u8], index: u32, entries: &mut Vec<Entry>) -> Result<bool, String> {
    fn word(bytes: &[u8]) -> u16 { u16::from_ne_bytes([bytes[0], bytes[1]]) }
    fn dword(bytes: &[u8]) -> u32 { u32::from_ne_bytes(bytes[..4].try_into().unwrap()) }
    while !packet.is_empty() {
        let h = packet.get(..16).ok_or("Short neighbour message")?;
        let len = dword(h) as usize;
        let body = packet.get(16..len).ok_or("Invalid neighbour length")?;
        packet = packet.get((len + 3) & !3..).unwrap_or_default();
        if dword(&h[8..]) != 1 || word(&h[6..]) & 16 != 0 { return Err("Interrupted neighbour dump".into()); }
        match word(&h[4..]) {
            3 if body.is_empty() || body.get(..4) == Some(&[0; 4]) => return Ok(true),
            28 => {}, // RTM_NEWNEIGH
            _ => return Err("Neighbour dump failed".into()),
        }
        let nd = body.get(..12).ok_or("Short neighbour entry")?;
        let state = word(&nd[8..]);
        if nd[0] != 2 || dword(&nd[4..]) != index || state & 0x21 != 0 { continue; } // INCOMPLETE or FAILED
        let (mut ip, mut mac) = (None, None);
        let mut attrs = &body[12..];
        while !attrs.is_empty() {
            let header = attrs.get(..4).ok_or("Short neighbour attribute")?;
            let n = usize::from(word(header));
            let data = attrs.get(4..n).ok_or("Invalid neighbour attribute")?;
            match (word(&header[2..]), data.len()) {
                (1,4) => ip = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                (2,6) if data != [0; 6] => mac = Some(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",data[0],data[1],data[2],data[3],data[4],data[5])),
                _ => {}
            }
            attrs = attrs.get((n + 3) & !3..).unwrap_or_default();
        }
        if let (Some(ip), Some(mac)) = (ip,mac) { entries.push(Entry { ip, mac, reachable: state == 2 }); }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_or_truncated_dumps_are_never_complete() {
        let mut done = [0; 16];
        done[..4].copy_from_slice(&16u32.to_ne_bytes());
        done[4..6].copy_from_slice(&3u16.to_ne_bytes());
        done[8..12].copy_from_slice(&1u32.to_ne_bytes());
        assert!(decode(&done, 1, &mut vec![]).unwrap());
        assert!(decode(&done[..12], 1, &mut vec![]).is_err());
        done[6..8].copy_from_slice(&16u16.to_ne_bytes());
        assert!(decode(&done, 1, &mut vec![]).is_err());
    }
}
