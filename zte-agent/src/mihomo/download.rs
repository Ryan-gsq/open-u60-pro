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
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&PROXY.parse().unwrap(), Duration::from_millis(200))
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
                    let proxy = reqwest::Proxy::https(format!("http://{PROXY}"))
                        .map_err(|_| "Cannot configure the local download proxy")?
                        .basic_auth(USER, secret);
                    builder = builder.proxy(proxy);
                } else if !self.dns.is_empty() {
                    if let Some(host) = url.domain() {
                        builder = builder.resolve_to_addrs(host, &lookup(host, &self.dns, deadline)?);
                    }
                }
                cached = Some((domain, builder.build().map_err(|_| "Cannot initialize HTTPS download")?));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { return Err("Download timed out".into()); }
            let (_, client) = cached.as_ref().unwrap();
            let response = client.get(url.clone()).timeout(remaining)
                .header("User-Agent", format!("clash.meta/{}", super::VERSION))
                .header("Accept", "*/*").send().map_err(|_| if self.secret.is_some() {
                    "Download through Clash failed; check the selected node. No direct fallback was attempted"
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
        if let Ok(answers) = super::dns::upstream(host, *server, Instant::now() + remaining) {
            if !answers.is_empty() { return Ok(answers); }
        }
    }
    Err("Download hostname could not be resolved through upstream Wi-Fi DNS".into())
}

#[cfg(test)]
mod tests {
    use super::*;
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
