//! Read the current IPv4 neighbour table with RTM_GETNEIGH. Never use a
//! partial dump after an interrupt, truncation, or missing NLMSG_DONE.
use std::net::Ipv4Addr;

pub struct Entry {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub reachable: bool,
}

#[cfg(target_os = "linux")]
fn open(device: &str) -> Result<(std::os::fd::OwnedFd, u32), String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let device = std::ffi::CString::new(device).map_err(|e| e.to_string())?;
    let index = unsafe { libc::if_nametoindex(device.as_ptr()) };
    let os_error = || std::io::Error::last_os_error().to_string();
    if index == 0 {
        return Err(os_error());
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let fd = socket.as_raw_fd();
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as _;
    if unsafe {
        libc::connect(
            fd,
            std::ptr::from_ref(&kernel).cast(),
            std::mem::size_of_val(&kernel) as _,
        )
    } != 0
    {
        return Err(os_error());
    }
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            std::mem::size_of_val(&timeout) as _,
        )
    } != 0
    {
        return Err(os_error());
    }
    Ok((socket, index))
}

#[cfg(target_os = "linux")]
pub fn list(device: &str) -> Result<Vec<Entry>, String> {
    use std::os::fd::AsRawFd;
    let (socket, index) = open(device)?;
    let fd = socket.as_raw_fd();
    let os_error = || std::io::Error::last_os_error().to_string();
    let mut request = [0u8; 28]; // nlmsghdr + ndmsg
    request[..4].copy_from_slice(&28u32.to_ne_bytes());
    request[4..6].copy_from_slice(&30u16.to_ne_bytes()); // RTM_GETNEIGH
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | DUMP
    request[8..12].copy_from_slice(&1u32.to_ne_bytes()); // dedicated socket, one request
    request[16] = libc::AF_INET as u8;
    request[20..24].copy_from_slice(&index.to_ne_bytes());
    if unsafe { libc::send(fd, request.as_ptr().cast(), request.len(), 0) }
        != request.len() as isize
    {
        return Err(os_error());
    }
    let mut buf = vec![0u8; 32768];
    let mut entries = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_TRUNC) };
        if n <= 0 {
            return Err(os_error());
        }
        let packet = buf.get(..n as usize).ok_or("Incomplete neighbour dump")?;
        if decode(packet, index, &mut entries)? {
            return Ok(entries);
        }
    }
    Err("Neighbour dump timed out".into())
}

#[cfg(not(target_os = "linux"))]
pub fn list(_: &str) -> Result<Vec<Entry>, String> {
    Err("Neighbour table requires Linux".into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    ChangeStale,
    ReplaceStale,
    ReplaceReachable,
    Delete,
}

impl Change {
    #[cfg(any(test, target_os = "linux"))]
    fn request(self, index: u32, ip: Ipv4Addr, mac: &str) -> Result<Vec<u8>, String> {
        let mut message = vec![0; if self == Self::Delete { 36 } else { 48 }];
        let len = message.len() as u32;
        message[..4].copy_from_slice(&len.to_ne_bytes());
        let (kind, flags, state): (u16, u16, u16) = match self {
            Self::ChangeStale => (28, 0x105, 4), // REQUEST | ACK | REPLACE, no CREATE
            Self::ReplaceStale => (28, 0x505, 4),
            Self::ReplaceReachable => (28, 0x505, 2),
            Self::Delete => (29, 5, 0),
        };
        message[4..6].copy_from_slice(&kind.to_ne_bytes());
        message[6..8].copy_from_slice(&flags.to_ne_bytes());
        message[8..12].copy_from_slice(&1u32.to_ne_bytes());
        message[16] = 2; // AF_INET
        message[20..24].copy_from_slice(&index.to_ne_bytes());
        message[24..26].copy_from_slice(&state.to_ne_bytes());
        message[28..30].copy_from_slice(&8u16.to_ne_bytes());
        message[30..32].copy_from_slice(&1u16.to_ne_bytes()); // NDA_DST
        message[32..36].copy_from_slice(&ip.octets());
        if self != Self::Delete {
            message[36..38].copy_from_slice(&10u16.to_ne_bytes());
            message[38..40].copy_from_slice(&2u16.to_ne_bytes()); // NDA_LLADDR
            let mut parts = mac.split(':');
            for byte in &mut message[40..46] {
                let part = parts
                    .next()
                    .filter(|p| p.len() == 2)
                    .ok_or("Invalid neighbour MAC")?;
                *byte = u8::from_str_radix(part, 16).map_err(|_| "Invalid neighbour MAC")?;
            }
            if parts.next().is_some() {
                return Err("Invalid neighbour MAC".into());
            }
        }
        Ok(message)
    }

    #[cfg(target_os = "linux")]
    pub fn apply(self, device: &str, ip: Ipv4Addr, mac: &str) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        let (socket, index) = open(device)?;
        let message = self.request(index, ip, mac)?;
        let fd = socket.as_raw_fd();
        if unsafe { libc::send(fd, message.as_ptr().cast(), message.len(), 0) }
            != message.len() as isize
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut reply = [0u8; 4096];
        let n = unsafe { libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), libc::MSG_TRUNC) };
        if n < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if n < 20
            || n as usize > reply.len()
            || reply[4..6] != 2u16.to_ne_bytes()
            || reply[8..12] != 1u32.to_ne_bytes()
        {
            return Err("Invalid neighbour acknowledgement".into());
        }
        let status = i32::from_ne_bytes(reply[16..20].try_into().unwrap());
        if status == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(status.saturating_neg()).to_string())
        }
    }
    #[cfg(not(target_os = "linux"))]
    pub fn apply(self, _: &str, _: Ipv4Addr, _: &str) -> Result<(), String> {
        Err("Neighbour updates require Linux".into())
    }
}

#[cfg(any(test, target_os = "linux"))]
fn decode(mut packet: &[u8], index: u32, entries: &mut Vec<Entry>) -> Result<bool, String> {
    fn word(bytes: &[u8]) -> u16 {
        u16::from_ne_bytes([bytes[0], bytes[1]])
    }
    fn dword(bytes: &[u8]) -> u32 {
        u32::from_ne_bytes(bytes[..4].try_into().unwrap())
    }
    while !packet.is_empty() {
        let h = packet.get(..16).ok_or("Short neighbour message")?;
        let len = dword(h) as usize;
        let body = packet.get(16..len).ok_or("Invalid neighbour length")?;
        packet = packet.get((len + 3) & !3..).unwrap_or_default();
        if dword(&h[8..]) != 1 || word(&h[6..]) & 16 != 0 {
            return Err("Interrupted neighbour dump".into());
        }
        match word(&h[4..]) {
            3 if body.is_empty() || body.get(..4) == Some(&[0; 4]) => return Ok(true),
            28 => {} // RTM_NEWNEIGH
            _ => return Err("Neighbour dump failed".into()),
        }
        let nd = body.get(..12).ok_or("Short neighbour entry")?;
        let state = word(&nd[8..]);
        if nd[0] != 2 || dword(&nd[4..]) != index || state & 0x21 != 0 {
            continue;
        } // INCOMPLETE or FAILED
        let (mut ip, mut mac) = (None, None);
        let mut attrs = &body[12..];
        while !attrs.is_empty() {
            let header = attrs.get(..4).ok_or("Short neighbour attribute")?;
            let n = usize::from(word(header));
            let data = attrs.get(4..n).ok_or("Invalid neighbour attribute")?;
            match (word(&header[2..]), data.len()) {
                (1, 4) => ip = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                (2, 6) if data != [0; 6] => {
                    mac = Some(format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        data[0], data[1], data[2], data[3], data[4], data[5]
                    ))
                }
                _ => {}
            }
            attrs = attrs.get((n + 3) & !3..).unwrap_or_default();
        }
        if let (Some(ip), Some(mac)) = (ip, mac) {
            entries.push(Entry {
                ip,
                mac,
                reachable: state == 2,
            });
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires the disposable network namespace and qa-neigh interface"]
    fn isolated_feature_neighbour_ack_and_dump() {
        assert_eq!(std::env::var("U60_ISOLATED_FEATURES").as_deref(), Ok("1"));
        let ip = Ipv4Addr::new(192, 0, 2, 5);
        let mac = "02:00:00:00:00:05";
        assert!(Change::ChangeStale.apply("qa-neigh", ip, mac).is_err());
        Change::ReplaceReachable.apply("qa-neigh", ip, mac).unwrap();
        assert!(list("qa-neigh")
            .unwrap()
            .iter()
            .any(|e| e.ip == ip && e.mac == mac && e.reachable));
        Change::ChangeStale.apply("qa-neigh", ip, mac).unwrap();
        assert!(list("qa-neigh")
            .unwrap()
            .iter()
            .any(|e| e.ip == ip && !e.reachable));
        Change::Delete.apply("qa-neigh", ip, mac).unwrap();
        assert!(list("qa-neigh").unwrap().iter().all(|e| e.ip != ip));
    }

    #[test]
    fn a_stale_change_cannot_create_a_missing_client() {
        let ip = Ipv4Addr::new(192, 0, 2, 9);
        let change = Change::ChangeStale
            .request(7, ip, "02:00:00:00:00:09")
            .unwrap();
        assert_eq!(
            u16::from_ne_bytes(change[6..8].try_into().unwrap()) & 0x400,
            0
        );
        assert_eq!(&change[24..26], &4u16.to_ne_bytes());
        assert_eq!(&change[32..36], &ip.octets());
        assert_eq!(&change[40..46], &[2, 0, 0, 0, 0, 9]);
        assert!(Change::ReplaceStale.request(7, ip, "bad").is_err());
    }

    #[test]
    fn ipv4_neighbours_are_scoped_to_the_device_and_state() {
        let mut msg = [0; 48];
        msg[..4].copy_from_slice(&48u32.to_ne_bytes());
        msg[4..6].copy_from_slice(&28u16.to_ne_bytes());
        msg[8..12].copy_from_slice(&1u32.to_ne_bytes());
        msg[16] = 2;
        msg[20..24].copy_from_slice(&7u32.to_ne_bytes());
        msg[24..26].copy_from_slice(&2u16.to_ne_bytes());
        msg[28..30].copy_from_slice(&8u16.to_ne_bytes());
        msg[30..32].copy_from_slice(&1u16.to_ne_bytes());
        msg[32..36].copy_from_slice(&[192, 0, 2, 3]);
        msg[36..38].copy_from_slice(&10u16.to_ne_bytes());
        msg[38..40].copy_from_slice(&2u16.to_ne_bytes());
        msg[40..46].copy_from_slice(&[2, 0, 0, 0, 0, 10]);
        let mut entries = Vec::new();
        assert!(!decode(&msg, 8, &mut entries).unwrap());
        assert!(entries.is_empty());
        assert!(!decode(&msg, 7, &mut entries).unwrap());
        assert_eq!(entries[0].mac, "02:00:00:00:00:0a");
        assert!(entries[0].reachable);
        msg[24..26].copy_from_slice(&32u16.to_ne_bytes());
        decode(&msg, 7, &mut entries).unwrap();
        assert_eq!(entries.len(), 1);
    }

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
