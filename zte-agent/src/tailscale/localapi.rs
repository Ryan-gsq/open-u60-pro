use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use super::{cli_with_timeout, SOCK};

/// LocalAPI over the daemon socket: the same `ipnstate.Status` the CLI
/// prints, without forking the Go binary. HTTP/1.0 so the body ends at EOF
/// (Go never chunks a 1.0 response); the Host is the only one tailscaled
/// accepts over the socket.
const STATUS_PATH: &str = "/localapi/v0/status?peers=false";
const FULL_STATUS_PATH: &str = "/localapi/v0/status";
const PREFS_PATH: &str = "/localapi/v0/prefs";
/// A peerless status is a few KB; anything larger is not tailscaled.
const LOCALAPI_MAX_BYTES: usize = 1024 * 1024;
/// Streaming cap for full `/localapi/v0/status` including large tailnet peer maps.
const FULL_STATUS_MAX_BYTES: usize = 16 * 1024 * 1024;
const LOCALAPI_MAX_HEADER_BYTES: usize = 16 * 1024;

/// Logged once per process: LocalAPI failing while the CLI works means the
/// fork-free path is broken, which would otherwise be invisible.
static LOCALAPI_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Status {
    #[serde(default)]
    pub backend_state: String,
    #[serde(rename = "TUN")]
    pub tun: Option<bool>,
    #[serde(rename = "AuthURL")]
    pub auth_url: Option<String>,
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Option<Vec<String>>,
    #[serde(rename = "Self")]
    pub self_status: Option<SelfStatus>,
    #[serde(default, deserialize_with = "null_default")]
    pub health: Vec<String>,
    pub version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct SelfStatus {
    #[serde(default)]
    pub online: bool,
    #[serde(rename = "DNSName")]
    pub dns_name: Option<String>,
    pub relay: Option<String>,
    pub cur_addr: Option<String>,
    pub key_expiry: Option<String>,
    #[serde(default)]
    pub expired: bool,
    #[serde(rename = "TailscaleIPs", default, deserialize_with = "null_default")]
    pub tailscale_ips: Vec<String>,
    #[serde(rename = "AllowedIPs", default, deserialize_with = "null_default")]
    pub allowed_ips: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    pub primary_routes: Vec<String>,
    #[serde(default)]
    pub exit_node_option: bool,
    #[serde(rename = "ExitNode", default)]
    pub _exit_node: bool,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct PeerStatus {
    #[serde(default)]
    pub online: bool,
    #[serde(rename = "TailscaleIPs", default, deserialize_with = "null_default")]
    pub tailscale_ips: Vec<String>,
}

/// Compact streaming representation of `/localapi/v0/status` peer entries:
/// skips peer keys and unused fields while deserializing so large tailnets
/// never hold the full JSON document in memory.
#[derive(Debug)]
pub(super) struct FullStatus {
    pub status: Status,
    pub peers: Vec<PeerStatus>,
}

impl<'de> Deserialize<'de> for FullStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{IgnoredAny, MapAccess, Visitor};

        struct PeersVec(Vec<PeerStatus>);
        impl<'de> Deserialize<'de> for PeersVec {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct MapVisitor;
                impl<'de> Visitor<'de> for MapVisitor {
                    type Value = Vec<PeerStatus>;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a map of peers or null")
                    }
                    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                        Ok(Vec::new())
                    }
                    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                        Ok(Vec::new())
                    }
                    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                        let mut peers = Vec::new();
                        while map.next_key::<IgnoredAny>()?.is_some() {
                            if let Some(peer) = map.next_value::<Option<PeerStatus>>()? {
                                peers.push(peer);
                            }
                        }
                        Ok(peers)
                    }
                }
                deserializer.deserialize_any(MapVisitor).map(PeersVec)
            }
        }

        struct FullVisitor;
        impl<'de> Visitor<'de> for FullVisitor {
            type Value = FullStatus;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a tailscaled status object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut backend_state = String::new();
                let mut tun = None;
                let mut auth_url = None;
                let mut tailscale_ips = None;
                let mut self_status = None;
                let mut health = Vec::new();
                let mut version = None;
                let mut peers = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "BackendState" => {
                            backend_state = map.next_value::<Option<String>>()?.unwrap_or_default();
                        }
                        "TUN" => tun = map.next_value()?,
                        "AuthURL" => auth_url = map.next_value()?,
                        "TailscaleIPs" => tailscale_ips = map.next_value()?,
                        "Self" => self_status = map.next_value()?,
                        "Health" => {
                            health = map.next_value::<Option<Vec<String>>>()?.unwrap_or_default();
                        }
                        "Version" => version = map.next_value()?,
                        "Peer" => {
                            peers = map.next_value::<Option<PeersVec>>()?.map_or_else(Vec::new, |p| p.0);
                        }
                        _ => {
                            let _ = map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(FullStatus {
                    status: Status {
                        backend_state,
                        tun,
                        auth_url,
                        tailscale_ips,
                        self_status,
                        health,
                        version,
                    },
                    peers,
                })
            }
        }

        deserializer.deserialize_map(FullVisitor)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct Prefs {
    pub netfilter_mode: Option<i32>,
    #[serde(default, deserialize_with = "null_default")]
    pub advertise_routes: Vec<String>,
    #[serde(rename = "WantRunning")]
    pub _want_running: Option<bool>,
    #[serde(rename = "CorpDNS")]
    pub corp_dns: Option<bool>,
    #[serde(rename = "RouteAll")]
    pub route_all: Option<bool>,
    #[serde(rename = "RunSSH")]
    pub run_ssh: Option<bool>,
    pub hostname: Option<String>,
}

fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    deserializer: D,
) -> Result<T, D::Error> {
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug)]
enum LocalApiError {
    /// The CLI talks to the same socket and would stall the same way.
    Timeout,
    Other(String),
}

fn remaining(deadline: Instant) -> Result<Duration, LocalApiError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(LocalApiError::Timeout);
    }
    Ok(remaining)
}

fn io_err(e: std::io::Error) -> LocalApiError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => LocalApiError::Timeout,
        _ => LocalApiError::Other(e.to_string()),
    }
}

fn wait_for_stream(
    stream: &UnixStream,
    events: libc::c_short,
    deadline: Instant,
) -> Result<(), LocalApiError> {
    let mut poll = libc::pollfd {
        fd: stream.as_raw_fd(),
        events,
        revents: 0,
    };
    loop {
        let millis = remaining(deadline)?.as_millis().clamp(1, i32::MAX as u128) as i32;
        match unsafe { libc::poll(&mut poll, 1, millis) } {
            0 => continue,
            -1 => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(io_err(error));
                }
            }
            _ => return Ok(()),
        }
    }
}

fn connect_until(path: &Path, deadline: Instant) -> Result<UnixStream, LocalApiError> {
    remaining(deadline)?;
    let bytes = path.as_os_str().as_bytes();
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= addr.sun_path.len() {
        return Err(LocalApiError::Other("invalid LocalAPI socket path".into()));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &byte) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = byte as libc::c_char;
    }
    let len =
        (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = len as u8;
    }

    #[cfg(target_os = "linux")]
    let socket_type = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let socket_type = libc::SOCK_STREAM;
    let fd = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if fd < 0 {
        return Err(io_err(io::Error::last_os_error()));
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    #[cfg(not(target_os = "linux"))]
    {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io_err(io::Error::last_os_error()));
        }
        stream.set_nonblocking(true).map_err(io_err)?;
    }

    loop {
        let time_left = remaining(deadline)?;
        if unsafe { libc::connect(fd, (&raw const addr).cast(), len) } == 0 {
            return Ok(stream);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EISCONN) => return Ok(stream),
            Some(libc::EINTR) => continue,
            Some(libc::EINPROGRESS | libc::EALREADY) => {
                wait_for_stream(&stream, libc::POLLOUT, deadline)?;
                if let Some(error) = stream.take_error().map_err(io_err)? {
                    return Err(io_err(error));
                }
                return Ok(stream);
            }
            // Linux AF_UNIX returns EAGAIN for a full listen queue. The
            // unconnected socket cannot signal when that queue has room.
            Some(libc::EAGAIN) => std::thread::sleep(time_left.min(Duration::from_millis(10))),
            _ => {
                return Err(LocalApiError::Other(format!(
                    "connect {}: {error}",
                    path.display()
                )));
            }
        }
    }
}

fn localapi_get<T: DeserializeOwned>(path: &str, deadline: Instant) -> Result<T, LocalApiError> {
    localapi_get_at(Path::new(SOCK), path, deadline)
}

fn localapi_get_at<T: DeserializeOwned>(
    sock: &Path,
    path: &str,
    deadline: Instant,
) -> Result<T, LocalApiError> {
    let mut stream = connect_until(sock, deadline)?;
    let head = format!("GET {path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\n\r\n");
    let mut request = head.as_bytes();
    while !request.is_empty() {
        remaining(deadline)?;
        match stream.write(request) {
            Ok(0) => return Err(LocalApiError::Other("LocalAPI socket closed".into())),
            Ok(written) => request = &request[written..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_for_stream(&stream, libc::POLLOUT, deadline)?;
            }
            Err(e) => return Err(io_err(e)),
        }
    }
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        wait_for_stream(&stream, libc::POLLIN, deadline)?;
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > LOCALAPI_MAX_BYTES {
                    return Err(LocalApiError::Other(format!(
                        "response over {LOCALAPI_MAX_BYTES} bytes"
                    )));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(e) => return Err(io_err(e)),
        }
    }
    parse_localapi_response(&raw).map_err(LocalApiError::Other)
}

struct BoundedStreamReader {
    stream: UnixStream,
    deadline: Instant,
    remaining_bytes: usize,
    max_bytes: usize,
    prefix: Vec<u8>,
    prefix_pos: usize,
    timed_out: bool,
    overflow: bool,
}

impl Read for BoundedStreamReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.prefix_pos < self.prefix.len() {
            let avail = &self.prefix[self.prefix_pos..];
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            self.prefix_pos += n;
            return Ok(n);
        }
        loop {
            match wait_for_stream(&self.stream, libc::POLLIN, self.deadline) {
                Ok(()) => {}
                Err(LocalApiError::Timeout) => {
                    self.timed_out = true;
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "LocalAPI timed out"));
                }
                Err(LocalApiError::Other(msg)) => {
                    return Err(io::Error::other(msg));
                }
            }
            match self.stream.read(buf) {
                Ok(0) => return Ok(0),
                Ok(n) => {
                    if n > self.remaining_bytes {
                        self.overflow = true;
                        return Err(io::Error::other(format!(
                            "response over {} bytes",
                            self.max_bytes
                        )));
                    }
                    self.remaining_bytes -= n;
                    return Ok(n);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn validate_localapi_headers(head_bytes: &[u8]) -> Result<(), String> {
    let head = String::from_utf8_lossy(head_bytes);
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err("not an HTTP response".into());
    }
    if code != "200" {
        let code = code
            .parse::<u16>()
            .map_err(|_| "invalid HTTP status code")?;
        return Err(format!("LocalAPI returned HTTP {code}"));
    }
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
            {
                return Err("chunked localapi response".into());
            }
        }
    }
    Ok(())
}

fn localapi_get_stream_at<T: DeserializeOwned>(
    sock: &Path,
    path: &str,
    deadline: Instant,
    max_bytes: usize,
) -> Result<T, LocalApiError> {
    let mut stream = connect_until(sock, deadline)?;
    let head = format!("GET {path} HTTP/1.0\r\nHost: local-tailscaled.sock\r\n\r\n");
    let mut request = head.as_bytes();
    while !request.is_empty() {
        remaining(deadline)?;
        match stream.write(request) {
            Ok(0) => return Err(LocalApiError::Other("LocalAPI socket closed".into())),
            Ok(written) => request = &request[written..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_for_stream(&stream, libc::POLLOUT, deadline)?;
            }
            Err(e) => return Err(io_err(e)),
        }
    }

    let mut header_buf = Vec::new();
    let mut buf = [0u8; 4096];
    let (head_len, sep_len) = loop {
        if let Some(found) = (0..header_buf.len()).find_map(|i| {
            if header_buf[i..].starts_with(b"\r\n\r\n") {
                Some((i, 4))
            } else if header_buf[i..].starts_with(b"\n\n") {
                Some((i, 2))
            } else {
                None
            }
        }) {
            break found;
        }
        wait_for_stream(&stream, libc::POLLIN, deadline)?;
        match stream.read(&mut buf) {
            Ok(0) => {
                return Err(LocalApiError::Other(
                    "incomplete HTTP response (no end of headers)".into(),
                ));
            }
            Ok(n) => {
                header_buf.extend_from_slice(&buf[..n]);
                if header_buf.len() > max_bytes {
                    return Err(LocalApiError::Other(format!(
                        "response over {max_bytes} bytes"
                    )));
                }
                let scanned = header_buf.len().saturating_sub(4);
                if scanned > LOCALAPI_MAX_HEADER_BYTES {
                    return Err(LocalApiError::Other(
                        "LocalAPI HTTP headers exceed limit".into(),
                    ));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(e) => return Err(io_err(e)),
        }
    };

    validate_localapi_headers(&header_buf[..head_len]).map_err(LocalApiError::Other)?;
    let prefix = header_buf[head_len + sep_len..].to_vec();
    let remaining_bytes = max_bytes.saturating_sub(header_buf.len());
    let mut reader = BoundedStreamReader {
        stream,
        deadline,
        remaining_bytes,
        max_bytes,
        prefix,
        prefix_pos: 0,
        timed_out: false,
        overflow: false,
    };
    let result = {
        let buffered = io::BufReader::new(&mut reader);
        serde_json::from_reader(buffered)
    };
    match result {
        Ok(value) => Ok(value),
        Err(e) => {
            if reader.timed_out {
                Err(LocalApiError::Timeout)
            } else if reader.overflow {
                Err(LocalApiError::Other(format!(
                    "response over {max_bytes} bytes"
                )))
            } else {
                Err(LocalApiError::Other(format!(
                    "parse localapi JSON at line {}, column {}",
                    e.line(),
                    e.column()
                )))
            }
        }
    }
}

/// Body of a `200` HTTP/1.x response as JSON. Headers end at the first blank
/// line (CRLF or bare LF); a chunked body is refused rather than decoded
/// because tailscaled never sends one to an HTTP/1.0 request.
fn parse_localapi_response<T: DeserializeOwned>(raw: &[u8]) -> Result<T, String> {
    let (head_len, sep_len) = (0..raw.len())
        .find_map(|i| {
            if raw[i..].starts_with(b"\r\n\r\n") {
                Some((i, 4))
            } else if raw[i..].starts_with(b"\n\n") {
                Some((i, 2))
            } else {
                None
            }
        })
        .ok_or_else(|| "incomplete HTTP response (no end of headers)".to_string())?;
    validate_localapi_headers(&raw[..head_len])?;
    let body = &raw[head_len + sep_len..];
    serde_json::from_slice(body).map_err(|e| {
        format!(
            "parse localapi JSON at line {}, column {}",
            e.line(),
            e.column()
        )
    })
}

/// `tailscale status --json --peers=false` without the fork: LocalAPI first,
/// the Go CLI on any failure except a timeout, so a LocalAPI problem costs a
/// fork, never a feature, and a wedged daemon still stalls GET /status for
/// at most `timeout_secs` (the CLI would only hit the same wall).
pub(super) fn daemon_status(timeout_secs: u64) -> Result<Value, String> {
    daemon_status_until(Instant::now() + Duration::from_secs(timeout_secs.max(1)))
}

pub(super) fn daemon_status_until<T: DeserializeOwned>(deadline: Instant) -> Result<T, String> {
    let reason = match localapi_get(STATUS_PATH, deadline) {
        Ok(v) => return Ok(v),
        Err(LocalApiError::Timeout) => return Err("tailscale status timed out".into()),
        Err(LocalApiError::Other(e)) => e,
    };
    let timeout = remaining(deadline).map_err(|_| "tailscale status timed out")?;
    let result =
        cli_with_timeout(&["status", "--json", "--peers=false"], timeout).and_then(|stdout| {
            serde_json::from_str(&stdout).map_err(|_| "parse tailscale status JSON".into())
        });
    if result.is_ok() && !LOCALAPI_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
        eprintln!("[tailscale] localapi status failed ({reason}) — using the CLI");
    }
    result
}

pub(super) fn daemon_prefs_until(deadline: Instant) -> Option<Prefs> {
    localapi_get(PREFS_PATH, deadline).ok()
}

pub(super) fn daemon_status_at_until<T: DeserializeOwned>(
    sock: &Path,
    deadline: Instant,
) -> Result<T, String> {
    match localapi_get_at(sock, STATUS_PATH, deadline) {
        Ok(v) => Ok(v),
        Err(LocalApiError::Timeout) => Err("tailscale status timed out".into()),
        Err(LocalApiError::Other(e)) => Err(e),
    }
}

pub(super) fn daemon_prefs_at_until(sock: &Path, deadline: Instant) -> Option<Prefs> {
    localapi_get_at(sock, PREFS_PATH, deadline).ok()
}

pub(super) fn daemon_full_status_until(deadline: Instant) -> Result<FullStatus, String> {
    match localapi_get_stream_at(Path::new(SOCK), FULL_STATUS_PATH, deadline, FULL_STATUS_MAX_BYTES) {
        Ok(v) => Ok(v),
        Err(LocalApiError::Timeout) => Err("tailscale full status timed out".into()),
        Err(LocalApiError::Other(e)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::thread;

    /// Tab-indented like tailscaled's encoder (`SetIndent("", "\t")`).
    const STATUS_BODY: &str = "{\n\t\"Version\": \"1.86.2\",\n\t\"BackendState\": \"Running\",\n\t\"Self\": {\n\t\t\"Online\": true,\n\t\t\"DNSName\": \"u60-pro.tail.ts.net.\"\n\t},\n\t\"Health\": []\n}\n";

    #[test]
    fn parses_a_200_with_crlf_headers() {
        let raw = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{STATUS_BODY}"
        );
        let v: Value = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["BackendState"], "Running");
        assert_eq!(v["Self"]["Online"], true);
        assert_eq!(v["Self"]["DNSName"], "u60-pro.tail.ts.net.");
        assert_eq!(v["Version"], "1.86.2");
    }

    #[test]
    fn streams_large_full_status_over_1mib_without_hitting_peerless_limit() {
        let path = sock_path("large-full-status");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let padding = "x".repeat(4096);
            let mut body = String::from(
                "{\"BackendState\":\"Running\",\"TUN\":true,\"TailscaleIPs\":[\"100.75.1.1\"],\"Self\":{\"Online\":true,\"TailscaleIPs\":[\"100.75.1.1\"]},\"Peer\":{",
            );
            // ~300 peers * >4 KiB each => >1.2 MiB body (exceeds 1 MiB LOCALAPI_MAX_BYTES).
            for i in 0..300usize {
                if i > 0 {
                    body.push(',');
                }
                let third = (i / 250) as u8;
                let fourth = ((i % 250) + 1) as u8;
                body.push_str(&format!(
                    "\"nodekey:{i}\":{{\"Online\":true,\"TailscaleIPs\":[\"100.88.{third}.{fourth}\"],\"HostName\":\"{padding}\"}}"
                ));
            }
            body.push_str("}}");
            assert!(body.len() > LOCALAPI_MAX_BYTES);
            let resp = format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{body}");
            let _ = stream.write_all(resp.as_bytes());
        });

        let full: FullStatus = localapi_get_stream_at(
            &path,
            FULL_STATUS_PATH,
            Instant::now() + Duration::from_secs(5),
            FULL_STATUS_MAX_BYTES,
        )
        .unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(full.status.backend_state, "Running");
        assert_eq!(full.peers.len(), 300);
        assert_eq!(full.peers[0].tailscale_ips, ["100.88.0.1"]);

        // Tighter cap rejects oversized stream cleanly.
        let path2 = sock_path("large-full-status-cap");
        let _ = std::fs::remove_file(&path2);
        let listener2 = UnixListener::bind(&path2).unwrap();
        let server2 = thread::spawn(move || {
            let (mut stream, _) = listener2.accept().unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf);
            let resp = format!("HTTP/1.0 200 OK\r\n\r\n{{\"BackendState\":\"{}\"}}", "a".repeat(512));
            let _ = stream.write_all(resp.as_bytes());
        });
        let err = localapi_get_stream_at::<FullStatus>(
            &path2,
            FULL_STATUS_PATH,
            Instant::now() + Duration::from_secs(5),
            128,
        )
        .unwrap_err();
        server2.join().unwrap();
        let _ = std::fs::remove_file(&path2);
        assert!(matches!(err, LocalApiError::Other(msg) if msg.contains("response over 128 bytes")));
    }

    #[test]
    fn parses_bare_lf_headers_and_an_http11_status_line() {
        let raw = format!("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{STATUS_BODY}");
        let v: Value = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["BackendState"], "Running");
    }

    #[test]
    fn body_is_everything_after_the_first_blank_line() {
        let body = "{\n\t\"BackendState\": \"NeedsLogin\",\n\n\t\"AuthURL\": \"https://login.tailscale.com/a/abc\"\n}";
        let raw = format!("HTTP/1.0 200 OK\r\n\r\n{body}");
        let v: Value = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["AuthURL"], "https://login.tailscale.com/a/abc");
    }

    #[test]
    fn rejects_non_200_incomplete_chunked_and_non_http() {
        let forbidden =
            b"HTTP/1.0 403 Forbidden\r\nContent-Type: text/plain\r\n\r\ninvalid localapi request\n";
        let err = parse_localapi_response::<Value>(forbidden).unwrap_err();
        assert_eq!(err, "LocalAPI returned HTTP 403");
        assert!(parse_localapi_response::<Value>(
            b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n"
        )
        .unwrap_err()
        .contains("incomplete"));
        assert!(
            parse_localapi_response::<Value>(b"HTTP/1.0 200 OK\r\n\r\n{\"Backend")
                .unwrap_err()
                .contains("parse localapi JSON")
        );
        let chunked = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{STATUS_BODY}");
        assert!(parse_localapi_response::<Value>(chunked.as_bytes())
            .unwrap_err()
            .contains("chunked"));
        assert!(parse_localapi_response::<Value>(b"").is_err());
        assert!(parse_localapi_response::<Value>(b"garbage\r\n\r\n{}")
            .unwrap_err()
            .contains("not an HTTP response"));
    }

    fn sock_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("zte-ts-{}-{name}.sock", std::process::id()))
    }

    /// One-shot fake tailscaled: records the request head, then answers
    /// `response` and closes (HTTP/1.0 semantics) or, given an empty
    /// response, stays silent past the client's deadline.
    fn serve_once(path: &Path, response: &'static str) -> thread::JoinHandle<Vec<String>> {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut head = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                head.push(line.trim_end().to_string());
            }
            if response.is_empty() {
                thread::sleep(Duration::from_secs(3));
            } else {
                let stream = reader.get_mut();
                stream.write_all(response.as_bytes()).unwrap();
                stream.shutdown(std::net::Shutdown::Both).unwrap();
            }
            head
        })
    }

    #[test]
    fn localapi_round_trip_over_a_unix_socket() {
        let path = sock_path("ok");
        let server = serve_once(
            &path,
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"BackendState\": \"Running\", \"Self\": {\"Online\": true}}\n",
        );
        let v: Status =
            localapi_get_at(&path, STATUS_PATH, Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(v.backend_state, "Running");
        assert!(v.self_status.unwrap().online);
        let head = server.join().unwrap();
        assert_eq!(head[0], "GET /localapi/v0/status?peers=false HTTP/1.0");
        assert!(
            head.contains(&"Host: local-tailscaled.sock".to_string()),
            "{head:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parses_tun_and_self_route_approval_fields() {
        let status: Status = serde_json::from_str(
            r#"{
          "BackendState":"Running", "TUN":false, "Health":null, "Version":"1.104.7",
          "TailscaleIPs":["100.75.1.1","fd7a:115c:a1e0::1234"],
          "Self":{
            "Online":true, "TailscaleIPs":["100.75.1.1"],
            "AllowedIPs":["100.75.1.1/32","192.168.0.0/24","0.0.0.0/0"],
            "PrimaryRoutes":["192.168.0.0/24","100.78.0.1/32"],
            "ExitNode":false,"ExitNodeOption":true
          }
        }"#,
        )
        .unwrap();
        assert_eq!(status.tun, Some(false));
        assert!(status.health.is_empty());
        assert_eq!(status.version.as_deref(), Some("1.104.7"));
        let self_status = status.self_status.unwrap();
        assert_eq!(self_status.tailscale_ips, ["100.75.1.1"]);
        assert_eq!(
            self_status.allowed_ips,
            ["100.75.1.1/32", "192.168.0.0/24", "0.0.0.0/0"]
        );
        assert_eq!(
            self_status.primary_routes,
            ["192.168.0.0/24", "100.78.0.1/32"]
        );
        assert!(self_status.exit_node_option);
        assert!(!self_status._exit_node);
    }

    #[test]
    fn prefs_round_trip_deserializes_only_whitelisted_fields() {
        let path = sock_path("prefs");
        let server = serve_once(
            &path,
            concat!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n",
                r#"{"NetfilterMode":2,"AdvertiseRoutes":["192.168.0.0/24"],"WantRunning":true,
                    "CorpDNS":false,"RouteAll":false,"RunSSH":true,"Hostname":"u60-pro",
                    "Persist":{"PrivateNodeKey":"fixture-key"}}"#,
            ),
        );
        let prefs: Prefs =
            localapi_get_at(&path, PREFS_PATH, Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(prefs.netfilter_mode, Some(2));
        assert_eq!(prefs.advertise_routes, ["192.168.0.0/24"]);
        assert_eq!(prefs._want_running, Some(true));
        assert_eq!(prefs.corp_dns, Some(false));
        assert_eq!(prefs.route_all, Some(false));
        assert_eq!(prefs.run_ssh, Some(true));
        assert_eq!(prefs.hostname.as_deref(), Some("u60-pro"));
        assert!(!format!("{prefs:?}").contains("fixture-key"));
        assert_eq!(server.join().unwrap()[0], "GET /localapi/v0/prefs HTTP/1.0");
        let _ = std::fs::remove_file(&path);

        let absent: Prefs = serde_json::from_str(r#"{"AdvertiseRoutes":null}"#).unwrap();
        assert_eq!(absent.netfilter_mode, None);
        assert!(absent.advertise_routes.is_empty());
    }

    #[test]
    fn a_silent_daemon_is_a_timeout_not_a_cli_fallback() {
        let path = sock_path("silent");
        let _server = serve_once(&path, "");
        let started = Instant::now();
        assert!(matches!(
            localapi_get_at::<Status>(&path, STATUS_PATH, started + Duration::from_secs(1)),
            Err(LocalApiError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unaccepted_connection_expires_the_shared_deadline() {
        let path = sock_path("unaccepted");
        let _ = std::fs::remove_file(&path);
        let _listener = UnixListener::bind(&path).unwrap();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(100);
        assert!(matches!(
            localapi_get_at::<Status>(&path, STATUS_PATH, deadline),
            Err(LocalApiError::Timeout)
        ));
        assert!((deadline..started + Duration::from_secs(1)).contains(&Instant::now()));
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_full_unix_listen_queue_expires_the_connect_deadline() {
        let path = sock_path("full-queue");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let _queued = UnixStream::connect(&path).unwrap();
        let started = Instant::now();
        let deadline = started + Duration::from_millis(100);
        assert!(matches!(
            localapi_get_at::<Status>(&path, STATUS_PATH, deadline),
            Err(LocalApiError::Timeout)
        ));
        assert!((deadline..started + Duration::from_secs(1)).contains(&Instant::now()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_socket_is_an_ordinary_error() {
        let path = sock_path("missing");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            localapi_get_at::<Status>(&path, STATUS_PATH, Instant::now() + Duration::from_secs(1)),
            Err(LocalApiError::Other(_))
        ));
        assert!(matches!(
            localapi_get_at::<Prefs>(&path, PREFS_PATH, Instant::now()),
            Err(LocalApiError::Timeout)
        ));
    }
}
