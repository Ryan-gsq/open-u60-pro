use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::{cli, SOCK};

/// LocalAPI over the daemon socket: the same `ipnstate.Status` the CLI
/// prints, without forking the Go binary. HTTP/1.0 so the body ends at EOF
/// (Go never chunks a 1.0 response); the Host is the only one tailscaled
/// accepts over the socket.
const LOCALAPI_STATUS_REQUEST: &str =
    "GET /localapi/v0/status?peers=false HTTP/1.0\r\nHost: local-tailscaled.sock\r\n\r\n";
/// A peerless status is a few KB; anything larger is not tailscaled.
const LOCALAPI_MAX_BYTES: usize = 1024 * 1024;

/// Logged once per process: LocalAPI failing while the CLI works means the
/// fork-free path is broken, which would otherwise be invisible.
static LOCALAPI_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);

fn cli_json(args: &[&str], timeout_secs: u64) -> Result<Value, String> {
    let stdout = cli(args, timeout_secs)?;
    serde_json::from_str(stdout.trim()).map_err(|e| format!("parse tailscale JSON: {e}"))
}

#[derive(Debug)]
enum LocalApiError {
    /// tailscaled accepted the connection but did not answer in time. The
    /// CLI talks to the same socket and would stall the same way.
    Timeout,
    Other(String),
}

/// `ipnstate.Status` (peers omitted) from tailscaled's LocalAPI socket.
fn localapi_status(timeout_secs: u64) -> Result<Value, LocalApiError> {
    localapi_status_at(Path::new(SOCK), timeout_secs)
}

fn localapi_status_at(sock: &Path, timeout_secs: u64) -> Result<Value, LocalApiError> {
    use std::io::Write;
    let io_err = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => LocalApiError::Timeout,
        _ => LocalApiError::Other(e.to_string()),
    };
    let timeout = Duration::from_secs(timeout_secs.max(1));
    let deadline = Instant::now() + timeout;
    let mut stream = UnixStream::connect(sock)
        .map_err(|e| LocalApiError::Other(format!("connect {}: {e}", sock.display())))?;
    stream.set_write_timeout(Some(timeout)).map_err(io_err)?;
    // Armed once, up front: tailscaled answers and closes in one go, and
    // setsockopt on a socket whose peer has already closed fails (EINVAL on
    // macOS). The socket timeout bounds each read; the deadline bounds the
    // total should the daemon trickle.
    stream.set_read_timeout(Some(timeout)).map_err(io_err)?;
    stream
        .write_all(LOCALAPI_STATUS_REQUEST.as_bytes())
        .map_err(io_err)?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > LOCALAPI_MAX_BYTES {
                    return Err(LocalApiError::Other(format!(
                        "response over {LOCALAPI_MAX_BYTES} bytes"
                    )));
                }
                if Instant::now() >= deadline {
                    return Err(LocalApiError::Timeout);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(e)),
        }
    }
    parse_localapi_response(&raw).map_err(LocalApiError::Other)
}

/// Body of a `200` HTTP/1.x response as JSON. Headers end at the first blank
/// line (CRLF or bare LF); a chunked body is refused rather than decoded
/// because tailscaled never sends one to an HTTP/1.0 request.
fn parse_localapi_response(raw: &[u8]) -> Result<Value, String> {
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
    let head = String::from_utf8_lossy(&raw[..head_len]);
    let body = &raw[head_len + sep_len..];
    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(format!("not an HTTP response: {status_line:?}"));
    }
    if code != "200" {
        let text = String::from_utf8_lossy(body);
        return Err(format!("{status_line}: {}", text.trim()));
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
    serde_json::from_slice(body).map_err(|e| format!("parse localapi JSON: {e}"))
}

/// `tailscale status --json --peers=false` without the fork: LocalAPI first,
/// the Go CLI on any failure except a timeout, so a LocalAPI problem costs a
/// fork, never a feature, and a wedged daemon still stalls GET /status for
/// at most `timeout_secs` (the CLI would only hit the same wall).
pub(super) fn daemon_status(timeout_secs: u64) -> Result<Value, String> {
    let reason = match localapi_status(timeout_secs) {
        Ok(v) => return Ok(v),
        Err(LocalApiError::Timeout) => return Err(format!("timed out after {timeout_secs}s")),
        Err(LocalApiError::Other(e)) => e,
    };
    let result = cli_json(&["status", "--json", "--peers=false"], timeout_secs);
    if result.is_ok() && !LOCALAPI_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
        eprintln!("[tailscale] localapi status failed ({reason}) — using the CLI");
    }
    result
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
        let v = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["BackendState"], "Running");
        assert_eq!(v["Self"]["Online"], true);
        assert_eq!(v["Self"]["DNSName"], "u60-pro.tail.ts.net.");
        assert_eq!(v["Version"], "1.86.2");
    }

    #[test]
    fn parses_bare_lf_headers_and_an_http11_status_line() {
        let raw = format!("HTTP/1.1 200 OK\nContent-Type: application/json\n\n{STATUS_BODY}");
        let v = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["BackendState"], "Running");
    }

    #[test]
    fn body_is_everything_after_the_first_blank_line() {
        let body = "{\n\t\"BackendState\": \"NeedsLogin\",\n\n\t\"AuthURL\": \"https://login.tailscale.com/a/abc\"\n}";
        let raw = format!("HTTP/1.0 200 OK\r\n\r\n{body}");
        let v = parse_localapi_response(raw.as_bytes()).unwrap();
        assert_eq!(v["AuthURL"], "https://login.tailscale.com/a/abc");
    }

    #[test]
    fn rejects_non_200_incomplete_chunked_and_non_http() {
        let forbidden =
            b"HTTP/1.0 403 Forbidden\r\nContent-Type: text/plain\r\n\r\ninvalid localapi request\n";
        let err = parse_localapi_response(forbidden).unwrap_err();
        assert!(
            err.contains("403") && err.contains("invalid localapi request"),
            "{err}"
        );
        assert!(
            parse_localapi_response(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n")
                .unwrap_err()
                .contains("incomplete")
        );
        assert!(
            parse_localapi_response(b"HTTP/1.0 200 OK\r\n\r\n{\"Backend")
                .unwrap_err()
                .contains("parse localapi JSON")
        );
        let chunked = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{STATUS_BODY}");
        assert!(parse_localapi_response(chunked.as_bytes())
            .unwrap_err()
            .contains("chunked"));
        assert!(parse_localapi_response(b"").is_err());
        assert!(parse_localapi_response(b"garbage\r\n\r\n{}")
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
        let v = localapi_status_at(&path, 5).unwrap();
        assert_eq!(v["BackendState"], "Running");
        let head = server.join().unwrap();
        assert_eq!(head[0], "GET /localapi/v0/status?peers=false HTTP/1.0");
        assert!(
            head.contains(&"Host: local-tailscaled.sock".to_string()),
            "{head:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_silent_daemon_is_a_timeout_not_a_cli_fallback() {
        let path = sock_path("silent");
        let _server = serve_once(&path, "");
        let started = Instant::now();
        assert!(matches!(
            localapi_status_at(&path, 1),
            Err(LocalApiError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_missing_socket_is_an_ordinary_error() {
        let path = sock_path("missing");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            localapi_status_at(&path, 1),
            Err(LocalApiError::Other(_))
        ));
    }
}
