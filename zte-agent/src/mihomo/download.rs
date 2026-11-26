//! One bounded HTTPS path for subscriptions, geodata and pinned assets. A
//! running core is used explicitly; never silently retry through direct WAN.

use super::Mihomo;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

pub(super) const PROXY: &str = "127.0.0.1:17893";
pub(super) const USER: &str = "u60-download";

/// Readiness must include the authenticated inbound, not just the controller.
pub(super) fn ready() -> bool {
    ready_at(PROXY.parse().unwrap())
}

fn ready_at(addr: SocketAddr) -> bool {
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    if stream
        .write_all(b"CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = [0u8; 12];
    stream.read_exact(&mut response).is_ok() && &response == b"HTTP/1.1 407"
}

pub(super) struct Download {
    dns: Vec<Ipv4Addr>,
    secret: Option<String>,
}

impl Mihomo {
    pub(super) fn downloader(&self) -> Download {
        Download {
            dns: self
                .subscription_dns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            secret: self.secret(),
        }
    }
}

pub(super) fn https_url(url: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(url).map_err(|_| "Invalid HTTPS URL")?;
    if url.as_str().len() > 4096
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("Use HTTPS without username, password or fragment".into());
    }
    Ok(url)
}

impl Download {
    pub(super) fn bytes(&self, url: &str, max: u64, timeout: Duration) -> Result<Vec<u8>, String> {
        self.bytes_with(url, max, timeout, PROXY, |builder| builder)
    }

    fn bytes_with(
        &self,
        url: &str,
        max: u64,
        timeout: Duration,
        proxy: &str,
        configure: impl Fn(reqwest::blocking::ClientBuilder) -> reqwest::blocking::ClientBuilder,
    ) -> Result<Vec<u8>, String> {
        let mut url = https_url(url)?;
        let deadline = Instant::now() + timeout;
        let mut cached = None;
        for _ in 0..=4 {
            let domain = if self.secret.is_none() && !self.dns.is_empty() { url.domain().map(str::to_owned) } else { None };
            if cached.as_ref().is_none_or(|(previous, _)| *previous != domain) {
                let mut builder = reqwest::blocking::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::from_secs(10));
                if let Some(secret) = &self.secret {
                    let proxy = reqwest::Proxy::https(format!("http://{proxy}"))
                        .map_err(|_| "Cannot configure the local download proxy")?
                        .basic_auth(USER, secret);
                    builder = builder.proxy(proxy);
                } else if !self.dns.is_empty() {
                    if let Some(host) = url.domain() {
                        builder = builder.resolve_to_addrs(host, &lookup(host, &self.dns, deadline)?);
                    }
                }
                cached = Some((domain, configure(builder).build().map_err(|_| "Cannot initialize HTTPS download")?));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { return Err("Download timed out".into()); }
            let (_, client) = cached.as_ref().unwrap();
            let response = client.get(url.clone()).timeout(remaining)
                .header("User-Agent", format!("clash.meta/{}", super::VERSION))
                .header("Accept", "*/*").send().map_err(|_| if self.secret.is_some() {
                    "Download through Mihomo failed; check the selected node. No direct fallback was attempted"
                } else { "Direct HTTPS download failed; check upstream DNS and Internet access" })?;
            if response.status().is_redirection() {
                let target = response
                    .headers()
                    .get("location")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|h| url.join(h).ok())
                    .ok_or("Invalid download redirect")?;
                url = https_url(target.as_str())?;
                continue;
            }
            if !response.status().is_success() {
                return Err(format!(
                    "Download server returned HTTP {}",
                    response.status().as_u16()
                ));
            }
            if response.content_length().is_some_and(|n| n > max) {
                return Err("Download exceeded its size limit".into());
            }
            let mut bytes = Vec::new();
            response
                .take(max + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Download interrupted or timed out")?;
            if bytes.len() as u64 > max {
                return Err("Download exceeded its size limit".into());
            }
            return Ok(bytes);
        }
        Err("Download has too many redirects".into())
    }
}

fn lookup(host: &str, dns: &[Ipv4Addr], deadline: Instant) -> Result<Vec<SocketAddr>, String> {
    lookup_with(host, dns, deadline, super::dns::upstream)
}

fn lookup_with(
    host: &str,
    dns: &[Ipv4Addr],
    deadline: Instant,
    mut query: impl FnMut(&str, Ipv4Addr, Instant) -> Result<Vec<SocketAddr>, String>,
) -> Result<Vec<SocketAddr>, String> {
    if host.starts_with('-') || host.len() > 253 {
        return Err("Invalid download host".into());
    }
    for server in dns.iter().take(2) {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_secs(5));
        if remaining.is_zero() {
            break;
        }
        if let Ok(answers) = query(host, *server, Instant::now() + remaining) {
            if !answers.is_empty() { return Ok(answers); }
        }
    }
    Err("Download hostname could not be resolved through upstream Wi-Fi DNS".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;

    fn listener() -> TcpListener {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    }

    fn accept(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                    return stream;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "fixture got no request");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    }

    fn request_head(stream: &mut impl Read) -> String {
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        loop {
            let start = head.len();
            assert_ne!(reader.read_line(&mut head).unwrap(), 0);
            if &head[start..] == "\r\n" { return head; }
        }
    }

    #[derive(Debug)]
    struct Cert(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for Cert {
        fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
            assert_eq!(hello.server_name(), Some("u60.home.arpa"));
            Some(Arc::clone(&self.0))
        }
    }

    fn tls_replies(responses: Vec<String>, max: u64) -> (Result<Vec<u8>, String>, Vec<String>) {
        let world = crate::tls::tests::World::new("mihomo-download");
        world.wall.store(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64, std::sync::atomic::Ordering::Relaxed);
        let tls = world.tls();
        tls.turn_on().unwrap();
        let ca = reqwest::Certificate::from_der(&tls.ca_der().unwrap()).unwrap();
        let key = tls.keys().read().unwrap().clone().unwrap();
        let config = Arc::new(rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_cert_resolver(Arc::new(Cert(key))));
        let origin = listener();
        let addr = origin.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            responses.into_iter().map(|response| {
                let conn = rustls::ServerConnection::new(Arc::clone(&config)).unwrap();
                let mut wire = rustls::StreamOwned::new(conn, accept(&origin));
                let request = request_head(&mut wire);
                wire.write_all(response.as_bytes()).unwrap();
                wire.conn.send_close_notify();
                let _ = wire.flush();
                request.lines().next().unwrap().to_owned()
            }).collect::<Vec<_>>()
        });
        let result = Download { dns: Vec::new(), secret: None }.bytes_with(
            &format!("https://u60.home.arpa:{}/0", addr.port()), max, Duration::from_secs(4), PROXY,
            |builder| builder.add_root_certificate(ca.clone()).resolve("u60.home.arpa", addr),
        );
        (result, server.join().unwrap())
    }

    fn redirect(location: &str) -> String {
        format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    }

    #[test]
    fn download_allows_five_https_requests_but_rejects_a_fifth_redirect() {
        let first: Vec<_> = (1..=4).map(|n| redirect(&format!("/{n}"))).collect();
        for (last, expected) in [
            ("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody".to_owned(), Ok(b"body".to_vec())),
            (redirect("/5"), Err("Download has too many redirects".into())),
        ] {
            let mut replies = first.clone();
            replies.push(last);
            let (result, seen) = tls_replies(replies, 4);
            assert_eq!(result, expected);
            assert_eq!(seen, (0..=4).map(|n| format!("GET /{n} HTTP/1.1")).collect::<Vec<_>>());
        }
    }

    #[test]
    fn download_rejects_a_redirect_to_http_before_contacting_it() {
        let insecure = listener();
        let (result, seen) = tls_replies(vec![redirect(&format!("http://{}/", insecure.local_addr().unwrap()))], 4);
        assert_eq!(result.unwrap_err(), "Use HTTPS without username, password or fragment");
        assert_eq!(seen, ["GET /0 HTTP/1.1"]);
        assert!(matches!(insecure.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }

    #[test]
    fn download_rejects_both_declared_and_streamed_size_overruns() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\n123\r\n2\r\n45\r\n0\r\n\r\n",
        ] {
            let (result, _) = tls_replies(vec![response.into()], 4);
            assert_eq!(result.unwrap_err(), "Download exceeded its size limit");
        }
    }

    #[test]
    fn failed_authenticated_proxy_does_not_contact_the_origin() {
        let origin = listener();
        let origin_addr = origin.local_addr().unwrap();
        let proxy = listener();
        let proxy_addr = proxy.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let mut stream = accept(&proxy);
            let request = request_head(&mut stream);
            stream.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            request
        });
        let error = Download { dns: Vec::new(), secret: Some("test".into()) }.bytes_with(
            &format!("https://u60.home.arpa:{}/", origin_addr.port()), 4, Duration::from_secs(4), &proxy_addr,
            |builder| builder.resolve("u60.home.arpa", origin_addr),
        ).unwrap_err();
        let request = server.join().unwrap();
        assert!(request.starts_with(&format!("CONNECT u60.home.arpa:{} HTTP/1.1\r\n", origin_addr.port())), "{request}");
        let credentials = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{USER}:test"));
        let expected = format!("proxy-authorization: Basic {credentials}");
        assert!(request.lines().any(|line| line.eq_ignore_ascii_case(&expected)), "{request}");
        assert_eq!(error, "Download through Mihomo failed; check the selected node. No direct fallback was attempted");
        assert!(matches!(origin.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }

    #[test]
    fn download_proxy_readiness_requires_a_complete_407_prefix() {
        for (reply, expected) in [(Some("HTTP/1.1 407"), true), (Some("HTTP/1.1 200"), false), (Some("HTTP/1.1 40"), false), (None, false)] {
            let proxy = listener();
            let addr = proxy.local_addr().unwrap();
            let (release, released) = std::sync::mpsc::channel();
            let server = std::thread::spawn(move || {
                let mut stream = accept(&proxy);
                assert!(request_head(&mut stream).starts_with("CONNECT example.invalid:443 HTTP/1.1"));
                if let Some(reply) = reply {
                    stream.write_all(reply.as_bytes()).unwrap();
                } else {
                    let _ = released.recv_timeout(Duration::from_secs(3));
                }
            });
            let ready = ready_at(addr);
            let _ = release.send(());
            server.join().unwrap();
            assert_eq!(ready, expected);
        }
    }

    #[test]
    fn upstream_lookup_validates_the_host_and_tries_only_the_first_two_servers() {
        let dns = ["192.0.2.1", "192.0.2.2", "192.0.2.3"].map(|addr| addr.parse().unwrap());
        for host in ["-bad.example", &"a".repeat(254)] {
            assert_eq!(lookup_with(host, &dns, Instant::now() + Duration::from_secs(1), |_, _, _| panic!("invalid host reached DNS")).unwrap_err(), "Invalid download host");
        }
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(1);
        let result = lookup_with("valid.example", &dns, deadline, |host, server, query_deadline| {
            assert_eq!(host, "valid.example");
            assert!(query_deadline <= deadline + Duration::from_millis(50));
            seen.push(server);
            if server == dns[0] { Err("failure".into()) } else { Ok(Vec::new()) }
        });
        assert_eq!(seen, dns[..2]);
        assert_eq!(result.unwrap_err(), "Download hostname could not be resolved through upstream Wi-Fi DNS");
        assert_eq!(lookup_with("valid.example", &dns, Instant::now(), |_, _, _| panic!("expired lookup queried DNS")).unwrap_err(), "Download hostname could not be resolved through upstream Wi-Fi DNS");
    }

    #[test]
    fn downloads_never_allow_insecure_redirects() {
        for url in [
            "http://example.com/",
            "file:///etc/passwd",
            "https://u:p@example.com",
            "https://example.com/#token",
        ] {
            assert!(https_url(url).is_err());
        }
    }
}
