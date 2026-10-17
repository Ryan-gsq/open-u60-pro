mod cache;
pub mod config;
mod dns_packet;
mod upstream;

pub use config::DohConfig;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

/// How many times `stop()` nudges a listener blocked in `recv_from` before it
/// gives up nudging and simply joins (the thread may be inside an upstream query).
const STOP_WAKE_ATTEMPTS: u32 = 50;
/// Pause between two nudges in `stop()`.
const STOP_WAKE_INTERVAL: Duration = Duration::from_millis(20);

pub struct DohProxy {
    config: Mutex<DohConfig>,
    cache: Mutex<cache::DnsCache>,
    running: AtomicBool,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
    /// Address the listener socket is actually bound to (set by `start()`,
    /// cleared by `stop()`). `stop()` sends its wake-up datagram here rather
    /// than to `config.listen_addr`, which may have been patched since the bind.
    bound_addr: Mutex<Option<SocketAddr>>,
    /// Upstream HTTP agent shared across queries; see `upstream::SharedAgent`.
    agent: Mutex<upstream::SharedAgent>,
    queries_total: Mutex<u64>,
    cache_hits: Mutex<u64>,
    cache_misses: Mutex<u64>,
}

impl DohProxy {
    pub fn new() -> Self {
        Self::from_config(config::load())
    }

    fn from_config(cfg: DohConfig) -> Self {
        let cache_size = cfg.cache_max_entries;
        let timeout_ms = cfg.timeout_ms;
        Self {
            config: Mutex::new(cfg),
            cache: Mutex::new(cache::DnsCache::new(cache_size)),
            running: AtomicBool::new(false),
            handle: Mutex::new(None),
            bound_addr: Mutex::new(None),
            agent: Mutex::new(upstream::SharedAgent::new(timeout_ms)),
            queries_total: Mutex::new(0),
            cache_hits: Mutex::new(0),
            cache_misses: Mutex::new(0),
        }
    }

    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        if self.running.load(Ordering::Relaxed) {
            return Err("already running".to_string());
        }

        let addr = self.config.lock().unwrap().listen_addr.clone();
        // No read timeout: the listener blocks in recv_from until a datagram
        // arrives, and stop() sends one to wake it (see wake_listener).
        let socket = UdpSocket::bind(&addr).map_err(|e| format!("bind {addr}: {e}"))?;
        let bound = socket
            .local_addr()
            .map_err(|e| format!("local_addr {addr}: {e}"))?;

        *self.bound_addr.lock().unwrap() = Some(bound);
        self.running.store(true, Ordering::Relaxed);

        let proxy = Arc::clone(self);
        let spawned = thread::Builder::new()
            .name("doh-udp".to_string())
            .spawn(move || listener_loop(socket, proxy));
        match spawned {
            Ok(handle) => {
                *self.handle.lock().unwrap() = Some(handle);
                Ok(())
            }
            Err(e) => {
                self.running.store(false, Ordering::Relaxed);
                *self.bound_addr.lock().unwrap() = None;
                Err(format!("spawn listener: {e}"))
            }
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        let handle = self.handle.lock().unwrap().take();
        let bound = self.bound_addr.lock().unwrap().take();
        if let Some(h) = handle {
            for _ in 0..STOP_WAKE_ATTEMPTS {
                if h.is_finished() {
                    break;
                }
                if let Some(addr) = bound {
                    wake_listener(addr);
                }
                thread::sleep(STOP_WAKE_INTERVAL);
            }
            if !h.is_finished() {
                eprintln!(
                    "[doh] listener still busy after {} ms, waiting for it to finish",
                    STOP_WAKE_INTERVAL.as_millis() * u128::from(STOP_WAKE_ATTEMPTS)
                );
            }
            let _ = h.join();
        }
    }

    pub fn status(&self) -> Value {
        let cfg = self.config.lock().unwrap().clone();
        let running = self.running.load(Ordering::Relaxed);
        let cache_len = self.cache.lock().unwrap().len();
        let total = *self.queries_total.lock().unwrap();
        let hits = *self.cache_hits.lock().unwrap();
        let misses = *self.cache_misses.lock().unwrap();
        json!({
            "running": running,
            "config": cfg,
            "stats": {
                "queries_total": total,
                "cache_hits": hits,
                "cache_misses": misses,
                "cache_entries": cache_len,
            }
        })
    }

    pub fn update_config(&self, body: &[u8]) -> Result<(), String> {
        let patch: config::DohConfigPatch =
            serde_json::from_slice(body).map_err(|e| format!("invalid config JSON: {e}"))?;
        let mut cfg = self.config.lock().unwrap();
        cfg.apply_patch(patch);
        self.cache.lock().unwrap().prune();
        self.agent.lock().unwrap().set_timeout(cfg.timeout_ms);
        config::save(&cfg)?;
        Ok(())
    }

    pub fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
    }

    pub fn cache_entries(&self) -> Value {
        let entries = self.cache.lock().unwrap().list_entries();
        let list: Vec<Value> = entries
            .into_iter()
            .map(|(qname, qtype, ttl)| {
                json!({"domain": qname, "type": qtype_name(qtype), "type_id": qtype, "ttl": ttl})
            })
            .collect();
        json!(list)
    }

    pub fn config(&self) -> DohConfig {
        self.config.lock().unwrap().clone()
    }

    pub fn set_enabled(&self, enabled: bool) {
        let mut cfg = self.config.lock().unwrap();
        cfg.enabled = enabled;
        let _ = config::save(&cfg);
    }

    /// Called on startup — reads config and starts if enabled.
    /// If not enabled, cleans up dnsmasq to prevent orphaned forwarding.
    pub fn auto_start(self: &Arc<Self>) {
        let cfg = self.config.lock().unwrap().clone();
        if cfg.enabled {
            if self.start().is_err() {
                return;
            }
            // Re-create dnsmasq drop-in (lost on reboot since /tmp is tmpfs)
            let _ = std::fs::write(
                "/tmp/dnsmasq.d/doh.conf",
                "server=127.0.0.1#5353\nno-resolv\n",
            );
            let _ = std::process::Command::new("sh")
                .args(["-c", "/etc/init.d/dnsmasq restart"])
                .output();
        } else {
            // Only clean up if DoH was previously configured
            if std::path::Path::new("/data/local/tmp/doh_config.json").exists() {
                crate::server::dnsmasq_restore_defaults();
            }
        }
    }
}

/// Where to send the wake-up datagram for a listener bound to `bound`: an
/// unspecified address (0.0.0.0 / ::) is rewritten to the loopback address of
/// the same family, anything else is used as-is.
fn wake_target(bound: SocketAddr) -> SocketAddr {
    let ip = match bound.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    SocketAddr::new(ip, bound.port())
}

/// Send one throwaway datagram to the listener so a blocked `recv_from`
/// returns. The payload is shorter than a DNS header, so the listener discards
/// it via `is_valid_query` and re-checks `running`.
fn wake_listener(bound: SocketAddr) {
    let target = wake_target(bound);
    let local: SocketAddr = if target.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    if let Ok(sock) = UdpSocket::bind(local) {
        let _ = sock.send_to(&[0u8], target);
    }
}

fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        43 => "DS",
        46 => "RRSIG",
        48 => "DNSKEY",
        65 => "HTTPS",
        255 => "ANY",
        _ => "OTHER",
    }
}

fn listener_loop(socket: UdpSocket, proxy: Arc<DohProxy>) {
    let mut buf = [0u8; 512];
    loop {
        if !proxy.running.load(Ordering::Relaxed) {
            break;
        }
        let (len, src) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let query = &buf[..len];
        if !dns_packet::is_valid_query(query) {
            continue;
        }

        let (qname, qtype, _) = match dns_packet::parse_question(query) {
            Some(q) => q,
            None => continue,
        };
        let client_id = u16::from_be_bytes([query[0], query[1]]);

        // Check cache
        {
            let cache = proxy.cache.lock().unwrap();
            if let Some(cached) = cache.get(&qname, qtype, client_id) {
                *proxy.cache_hits.lock().unwrap() += 1;
                *proxy.queries_total.lock().unwrap() += 1;
                let _ = socket.send_to(&cached, src);
                continue;
            }
        }
        *proxy.cache_misses.lock().unwrap() += 1;
        *proxy.queries_total.lock().unwrap() += 1;

        // Query upstream (agent cloned out of the lock so the lock is not held
        // for the duration of the request)
        let config = proxy.config.lock().unwrap().clone();
        let agent = proxy.agent.lock().unwrap().checkout();
        match upstream::query_doh(&agent, query, &config.upstream_url) {
            Ok(response) => {
                if config.cache_enabled {
                    let ttl = dns_packet::extract_min_ttl(&response);
                    let mut cache = proxy.cache.lock().unwrap();
                    cache.insert(qname, qtype, &response, ttl);
                }
                let _ = socket.send_to(&response, src);
            }
            Err(_) => {
                // Return SERVFAIL
                let mut fail = query.to_vec();
                if fail.len() >= 4 {
                    fail[2] = 0x81; // QR=1, RD=1
                    fail[3] = 0x82; // RA=1, RCODE=2 (SERVFAIL)
                }
                let _ = socket.send_to(&fail, src);
            }
        }
    }
}

#[cfg(test)]
mod listener_tests {
    use super::*;
    use std::time::Instant;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Pick a currently free UDP port on loopback so the tests never collide
    /// with the default 5353 (mDNS on the development machine).
    fn free_loopback_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn proxy_on(listen_addr: &str) -> Arc<DohProxy> {
        let cfg = DohConfig {
            listen_addr: listen_addr.to_string(),
            ..DohConfig::default()
        };
        Arc::new(DohProxy::from_config(cfg))
    }

    /// Standard query: header + one question for `name`/`qtype`, class IN.
    fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // RD
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    /// Positive answer to `query`: same question, one A record via a name pointer.
    fn build_answer(query: &[u8]) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] = 0x81; // QR, RD
        r[3] = 0x80; // RA, NOERROR
        r[7] = 1; // ANCOUNT
        r.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        r.extend_from_slice(&1u16.to_be_bytes()); // type A
        r.extend_from_slice(&1u16.to_be_bytes()); // class IN
        r.extend_from_slice(&300u32.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&[93, 184, 216, 34]);
        r
    }

    #[test]
    fn wake_target_rewrites_unspecified_to_loopback() {
        assert_eq!(wake_target(addr("0.0.0.0:5353")), addr("127.0.0.1:5353"));
        assert_eq!(wake_target(addr("[::]:5353")), addr("[::1]:5353"));
        assert_eq!(wake_target(addr("127.0.0.1:5353")), addr("127.0.0.1:5353"));
        assert_eq!(wake_target(addr("[::1]:5353")), addr("[::1]:5353"));
        assert_eq!(
            wake_target(addr("192.168.0.1:5353")),
            addr("192.168.0.1:5353")
        );
    }

    #[test]
    fn wake_datagram_is_rejected_by_query_validator() {
        // stop() relies on the 1-byte nudge being dropped before any parsing.
        assert!(!dns_packet::is_valid_query(&[0u8]));
    }

    #[test]
    fn stop_without_start_is_a_noop() {
        let proxy = proxy_on("127.0.0.1:0");
        proxy.stop();
        proxy.stop();
        assert!(!proxy.running.load(Ordering::Relaxed));
        assert!(proxy.bound_addr.lock().unwrap().is_none());
    }

    #[test]
    fn listener_serves_cache_then_stops_promptly_and_rebinds_same_port() {
        let port = free_loopback_port();
        let proxy = proxy_on(&format!("127.0.0.1:{port}"));

        proxy.start().expect("first start");
        assert_eq!(proxy.start().unwrap_err(), "already running");
        let bound = proxy.bound_addr.lock().unwrap().expect("bound_addr set");
        assert_eq!(bound, addr(&format!("127.0.0.1:{port}")));

        // Seed the cache so the query is answered without touching the network.
        let query = build_query(0x1234, "example.com", 1);
        let answer = build_answer(&query);
        proxy
            .cache
            .lock()
            .unwrap()
            .insert("example.com".to_string(), 1, &answer, 300);

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.send_to(&query, bound).unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = client.recv_from(&mut buf).expect("cached reply");
        assert_eq!(&buf[..n], &answer[..], "reply must carry the client's ID");

        // Stop must wake the blocked recv_from itself, not wait for a client.
        let t0 = Instant::now();
        proxy.stop();
        let took = t0.elapsed();
        assert!(
            took < Duration::from_secs(2),
            "stop() took {took:?}; the wake datagram did not reach the listener"
        );
        assert!(!proxy.running.load(Ordering::Relaxed));
        assert!(proxy.handle.lock().unwrap().is_none());
        assert!(proxy.bound_addr.lock().unwrap().is_none());

        // disable -> enable must re-bind the very same port (no EADDRINUSE).
        for i in 0..3 {
            proxy
                .start()
                .unwrap_or_else(|e| panic!("re-bind #{i} failed: {e}"));
            proxy.stop();
        }

        let status = proxy.status();
        assert_eq!(status["running"], false);
        assert_eq!(status["stats"]["queries_total"], 1);
        assert_eq!(status["stats"]["cache_hits"], 1);
        assert_eq!(status["stats"]["cache_misses"], 0);
    }

    #[test]
    fn update_config_changes_timeout_without_restart() {
        let proxy = proxy_on("127.0.0.1:0");
        proxy.start().expect("start");
        // save() targets the on-device path and fails here; the in-memory
        // config and the agent must already be updated by then.
        let _ = proxy.update_config(br#"{"timeout_ms": 1234}"#);
        assert_eq!(proxy.config().timeout_ms, 1234);
        let agent = proxy.agent.lock().unwrap().checkout();
        assert_eq!(
            agent.config().timeouts().global,
            Some(Duration::from_millis(1234))
        );
        proxy.stop();
    }
}
