//! Clean DNS resolver (`127.0.0.54:53`, dual-protocol UDP + TCP) and private
//! mount namespace isolation for kernel-TUN `tailscaled` (Strategy B Exit Node).
//!
//! `tailscaled` runs in its own mount namespace with `/tmp/resolv.conf.d`
//! read-only directory-bind-mounted to a private directory containing only
//! `resolv.conf.auto` (`nameserver 127.0.0.54`). Directory-level mounting keeps
//! the isolation intact across host atomic `rename()` updates to
//! `/tmp/resolv.conf.d/resolv.conf.auto`.
//!
//! Queries to `127.0.0.54:53` (UDP & TCP) are answered exclusively via
//! encrypted HTTPS DoH:
//! - When Mihomo is running and `exit_via_mihomo` is enabled: through Mihomo's
//!   authenticated loopback HTTP proxy (`127.0.0.1:17893`), returning real
//!   unpolluted IPs without fake-ip contamination.
//! - When Mihomo is stopped, in D3 backoff, in Direct mode, or
//!   `exit_via_mihomo` is off: direct IP-literal HTTPS DoH (`223.5.5.5`,
//!   `1.1.1.1`) with zero bootstrap DNS deadlock and zero plaintext DNS leaks.

use std::collections::VecDeque;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use futures_util::future::{self, Either};
use reqwest::redirect::Policy;
use reqwest::Client;
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::doh::cache::DnsCache;
use crate::doh::dns_packet;
use crate::doh::upstream::AGENT_IDLE_MAX;
use crate::netfx::ids;

pub const LISTEN_IP: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 54);
pub const PRIMARY_PORT: u16 = ids::CLEAN_DNS_PORT;
pub const FALLBACK_PORT: u16 = ids::CLEAN_DNS_FALLBACK_PORT;
pub const QUERY_BUDGET: Duration = Duration::from_secs(5);

pub const RESOLV_DIR: &str = "/tmp/zte-agent-run/tailscale-resolv";
pub const TARGET_RESOLV_DIR: &str = "/tmp/resolv.conf.d";
pub const RESOLV_FILE_NAME: &str = "resolv.conf.auto";
pub const RESOLV_CONTENT: &str = "nameserver 127.0.0.54\n";

const DIRECT_UPSTREAMS: [&str; 2] = ["https://223.5.5.5/dns-query", "https://1.1.1.1/dns-query"];
const PROXY_UPSTREAMS: [&str; 2] = [
    "https://dns.google/dns-query",
    "https://1.1.1.1/dns-query",
];

const CACHE_MAX_ENTRIES: usize = 512;
const MAX_DNS_MSG: usize = 4096;
const UDP_WORKERS: usize = 4;
const UDP_QUEUE_CAPACITY: usize = 128;
const TCP_WORKERS: usize = 4;
const TCP_QUEUE_CAPACITY: usize = 32;
const MAX_TCP_QUERIES_PER_CONN: usize = 16;
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_POLL_SLICE: Duration = Duration::from_millis(100);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);
const STOP_WAKE_ATTEMPTS: u32 = 40;
const STOP_WAKE_INTERVAL: Duration = Duration::from_millis(25);
const MAX_SYMLINK_HOPS: usize = 16;

#[derive(Clone, PartialEq, Eq)]
pub enum UpstreamMode {
    Direct,
    Proxy {
        addr: String,
        username: String,
        secret: String,
    },
}

impl fmt::Debug for UpstreamMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "Direct"),
            Self::Proxy { addr, username, .. } => f
                .debug_struct("Proxy")
                .field("addr", addr)
                .field("username", username)
                .field("secret", &"<redacted>")
                .finish(),
        }
    }
}

impl UpstreamMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Proxy { .. } => "proxy",
        }
    }
}

#[derive(Clone, Debug)]
struct Endpoints {
    direct: Vec<String>,
    proxy: Vec<String>,
    #[cfg(test)]
    allow_http_for_test: bool,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            direct: DIRECT_UPSTREAMS.iter().map(|s| (*s).to_string()).collect(),
            proxy: PROXY_UPSTREAMS.iter().map(|s| (*s).to_string()).collect(),
            #[cfg(test)]
            allow_http_for_test: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanDnsBinding {
    pub addr: SocketAddr,
    pub dnat_port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanDnsSnapshot {
    pub running: bool,
    pub listen: Option<String>,
    pub dnat_port: Option<u16>,
    pub mode: &'static str,
    pub error: Option<String>,
}

impl CleanDnsSnapshot {
    pub fn to_status_json(
        &self,
        tailscale_enabled: bool,
        kernel_tun_active: bool,
        mount_isolated: Result<bool, &str>,
    ) -> Value {
        let (state, isolated, reason) = if !tailscale_enabled {
            ("disabled", false, None)
        } else if !kernel_tun_active {
            if let Some(err) = &self.error {
                ("degraded", false, Some(err.clone()))
            } else {
                ("inactive", false, None)
            }
        } else if !self.running {
            (
                "degraded",
                matches!(mount_isolated, Ok(true)),
                Some(
                    self.error
                        .clone()
                        .unwrap_or_else(|| "clean DNS listener is not running".into()),
                ),
            )
        } else {
            match mount_isolated {
                Ok(true) => ("active", true, None),
                Ok(false) => (
                    "degraded",
                    false,
                    Some("tailscaled mount namespace isolation is not active".into()),
                ),
                Err(err) => ("degraded", false, Some(err.to_string())),
            }
        };
        let mode = if state == "disabled" || !self.running {
            "off"
        } else {
            self.mode
        };
        json!({
            "state": state,
            "mode": mode,
            "listen": self.listen,
            "dnat_port": self.dnat_port,
            "mount_isolated": isolated,
            "reason": reason,
        })
    }
}

struct SharedState {
    mode: UpstreamMode,
    generation: u64,
    cache: DnsCache,
    endpoints: Endpoints,
    budget: Duration,
    last_error: Option<String>,
}

struct Runtime {
    binding: CleanDnsBinding,
    running: Arc<AtomicBool>,
    shutdown: watch::Sender<bool>,
    tcp_queue: Arc<TcpQueue>,
    udp_socket: UdpSocket,
    threads: Vec<JoinHandle<()>>,
}

impl Runtime {
    fn is_alive(&self) -> bool {
        self.running.load(Ordering::Acquire) && self.threads.iter().all(|h| !h.is_finished())
    }
}

/// Ensures any unexpected exit or panic of a listener or worker thread
/// immediately marks the Clean DNS runtime unhealthy (`running = false`).
struct RunningDropGuard(Arc<AtomicBool>);

impl Drop for RunningDropGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

const LISTENER_MAX_CONSECUTIVE_ERRORS: u32 = 5;

struct UdpJob {
    query: Vec<u8>,
    peer: SocketAddr,
    received: Instant,
}

struct TcpJob {
    stream: TcpStream,
    accepted: Instant,
}

struct TcpQueueState {
    items: VecDeque<TcpJob>,
    closed: bool,
}

/// Bounded FIFO accept queue whose front entries can be expired directly by
/// the listener thread even when all TCP workers are busy on keep-alive streams.
struct TcpQueue {
    cap: usize,
    state: Mutex<TcpQueueState>,
    cv: Condvar,
}

impl TcpQueue {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            state: Mutex::new(TcpQueueState {
                items: VecDeque::with_capacity(cap),
                closed: false,
            }),
            cv: Condvar::new(),
        }
    }

    fn reap_expired(&self, budget: Duration) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        while let Some(front) = guard.items.front() {
            if now.saturating_duration_since(front.accepted) >= budget {
                if let Some(expired) = guard.items.pop_front() {
                    let _ = expired.stream.shutdown(std::net::Shutdown::Both);
                }
            } else {
                break;
            }
        }
    }

    fn push(&self, job: TcpJob, budget: Duration) -> Result<(), TcpJob> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.closed {
            return Err(job);
        }
        let now = Instant::now();
        while let Some(front) = guard.items.front() {
            if now.saturating_duration_since(front.accepted) >= budget {
                if let Some(expired) = guard.items.pop_front() {
                    let _ = expired.stream.shutdown(std::net::Shutdown::Both);
                }
            } else {
                break;
            }
        }
        if guard.items.len() >= self.cap {
            return Err(job);
        }
        guard.items.push_back(job);
        self.cv.notify_one();
        Ok(())
    }

    fn pop(&self, running: &AtomicBool) -> Option<TcpJob> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if !running.load(Ordering::Acquire) || guard.closed {
                return None;
            }
            if let Some(job) = guard.items.pop_front() {
                return Some(job);
            }
            guard = self.cv.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn has_waiting(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .items
            .is_empty()
    }

    fn close(&self) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.closed = true;
        while let Some(job) = guard.items.pop_front() {
            let _ = job.stream.shutdown(std::net::Shutdown::Both);
        }
        self.cv.notify_all();
    }
}

pub struct CleanDns {
    bind_ip: Ipv4Addr,
    primary_port: u16,
    fallback_port: Option<u16>,
    shared: Arc<Mutex<SharedState>>,
    runtime: Mutex<Option<Runtime>>,
}

impl Default for CleanDns {
    fn default() -> Self {
        Self::new()
    }
}

impl CleanDns {
    pub fn new() -> Self {
        Self::with_bind(LISTEN_IP, PRIMARY_PORT, Some(FALLBACK_PORT), Endpoints::default(), QUERY_BUDGET)
    }

    fn with_bind(
        bind_ip: Ipv4Addr,
        primary_port: u16,
        fallback_port: Option<u16>,
        endpoints: Endpoints,
        budget: Duration,
    ) -> Self {
        Self {
            bind_ip,
            primary_port,
            fallback_port,
            shared: Arc::new(Mutex::new(SharedState {
                mode: UpstreamMode::Direct,
                generation: 1,
                cache: DnsCache::new(CACHE_MAX_ENTRIES),
                endpoints,
                budget,
                last_error: None,
            })),
            runtime: Mutex::new(None),
        }
    }

    /// Ensure the dual-protocol UDP + TCP listener is running. Returns the
    /// active socket address and optional DNAT fallback port.
    pub fn ensure_running(&self) -> Result<CleanDnsBinding, String> {
        self.ensure_running_with_spawner(|name, f| {
            thread::Builder::new().name(name).spawn(f)
        })
    }

    fn ensure_running_with_spawner<S>(&self, mut spawn: S) -> Result<CleanDnsBinding, String>
    where
        S: FnMut(String, Box<dyn FnOnce() + Send + 'static>) -> io::Result<JoinHandle<()>>,
    {
        let mut rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = rt.as_ref() {
            if existing.is_alive() {
                return Ok(existing.binding.clone());
            }
        }
        if let Some(stale) = rt.take() {
            stop_runtime(stale);
        }

        let (udp, tcp, binding) =
            match bind_dual_stack(self.bind_ip, self.primary_port, self.fallback_port) {
                Ok(bound) => {
                    self.shared
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .last_error = None;
                    bound
                }
                Err(error) => {
                    self.shared
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .last_error = Some(error.clone());
                    return Err(error);
                }
            };

        let running = Arc::new(AtomicBool::new(true));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let tcp_queue = Arc::new(TcpQueue::new(TCP_QUEUE_CAPACITY));
        let mut threads = Vec::with_capacity(UDP_WORKERS + TCP_WORKERS + 3);
        let (udp_tx, udp_rx) = mpsc::sync_channel::<UdpJob>(UDP_QUEUE_CAPACITY);
        let udp_rx = Arc::new(Mutex::new(udp_rx));
        let mut udp_tx_slot = Some(udp_tx);
        let mut tcp_listener_slot = Some(tcp);

        let doh_rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let error = format!("build clean DNS DoH runtime: {e}");
                self.shared
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .last_error = Some(error.clone());
                return Err(error);
            }
        };
        let doh_handle = doh_rt.handle().clone();
        let mut doh_rt_slot = Some(doh_rt);

        let startup: Result<(), String> = (|| {
            // Single-threaded async DoH driver so stop() cancels in-flight HTTP immediately.
            {
                let rt_driver = doh_rt_slot
                    .take()
                    .ok_or_else(|| "DoH runtime already moved".to_string())?;
                let mut stop_rx = shutdown_rx.clone();
                let handle = spawn(
                    "u60-ts-dns-io".into(),
                    Box::new(move || {
                        rt_driver.block_on(async move {
                            let _ = stop_rx.wait_for(|&stopped| stopped).await;
                        });
                    }),
                )
                .map_err(|e| format!("spawn clean DNS DoH driver: {e}"))?;
                threads.push(handle);
            }

            // UDP worker pool
            for idx in 0..UDP_WORKERS {
                let rx = Arc::clone(&udp_rx);
                let shared = Arc::clone(&self.shared);
                let flag = Arc::clone(&running);
                let doh = doh_handle.clone();
                let stop_rx = shutdown_rx.clone();
                let sock = udp
                    .try_clone()
                    .map_err(|e| format!("clone clean DNS UDP socket: {e}"))?;
                let handle = spawn(
                    format!("u60-ts-dns-u{idx}"),
                    Box::new(move || udp_worker_loop(rx, shared, sock, flag, doh, stop_rx)),
                )
                .map_err(|e| format!("spawn clean DNS UDP worker: {e}"))?;
                threads.push(handle);
            }

            // UDP listener thread
            {
                let sock = udp
                    .try_clone()
                    .map_err(|e| format!("clone clean DNS UDP listener: {e}"))?;
                let flag = Arc::clone(&running);
                let shared = Arc::clone(&self.shared);
                let tx = udp_tx_slot
                    .take()
                    .ok_or_else(|| "UDP job sender already moved".to_string())?;
                let handle = spawn(
                    "u60-ts-dns-udp".into(),
                    Box::new(move || udp_listener_loop(sock, flag, tx, shared)),
                )
                .map_err(|e| format!("spawn clean DNS UDP listener: {e}"))?;
                threads.push(handle);
            }

            // TCP worker pool
            for idx in 0..TCP_WORKERS {
                let queue = Arc::clone(&tcp_queue);
                let shared = Arc::clone(&self.shared);
                let flag = Arc::clone(&running);
                let doh = doh_handle.clone();
                let stop_rx = shutdown_rx.clone();
                let handle = spawn(
                    format!("u60-ts-dns-t{idx}"),
                    Box::new(move || tcp_worker_loop(queue, shared, flag, doh, stop_rx)),
                )
                .map_err(|e| format!("spawn clean DNS TCP worker: {e}"))?;
                threads.push(handle);
            }

            // TCP listener thread
            {
                let flag = Arc::clone(&running);
                let listener = tcp_listener_slot
                    .take()
                    .ok_or_else(|| "TCP listener already moved".to_string())?;
                let queue = Arc::clone(&tcp_queue);
                let shared = Arc::clone(&self.shared);
                let handle = spawn(
                    "u60-ts-dns-tcp".into(),
                    Box::new(move || tcp_listener_loop(listener, flag, queue, shared)),
                )
                .map_err(|e| format!("spawn clean DNS TCP listener: {e}"))?;
                threads.push(handle);
            }

            Ok(())
        })();

        if let Err(error) = startup {
            drop(udp_tx_slot);
            drop(tcp_listener_slot);
            drop(doh_rt_slot);
            stop_runtime(Runtime {
                binding,
                running,
                shutdown: shutdown_tx,
                tcp_queue,
                udp_socket: udp,
                threads,
            });
            self.shared
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .last_error = Some(error.clone());
            return Err(error);
        }

        let result = binding.clone();
        *rt = Some(Runtime {
            binding,
            running,
            shutdown: shutdown_tx,
            tcp_queue,
            udp_socket: udp,
            threads,
        });
        Ok(result)
    }

    /// Stop the UDP and TCP listeners and join worker threads cleanly.
    pub fn stop(&self) {
        let rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(rt) = rt {
            stop_runtime(rt);
        }
    }

    pub fn is_running(&self) -> bool {
        self.runtime
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(Runtime::is_alive)
    }

    pub fn dnat_port(&self) -> Option<u16> {
        self.runtime
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|rt| rt.is_alive())
            .and_then(|rt| rt.binding.dnat_port)
    }

    /// Switch upstream mode (`Direct` vs `Proxy`). Whenever the mode or proxy
    /// credentials change, immediately clears the DNS cache and advances the
    /// generation so every worker drops pooled HTTP/proxy connections.
    pub fn set_mode(&self, next: UpstreamMode) -> bool {
        let mut s = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        if s.mode == next {
            return false;
        }
        s.mode = next;
        s.generation = s.generation.wrapping_add(1);
        s.cache.clear();
        true
    }

    /// Flush cached answers and drop all pooled HTTP/proxy sockets immediately
    /// after an uplink switch (Wi-Fi relay <-> cellular or WAN reconnect).
    pub fn uplink_changed(&self) {
        let mut s = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        s.generation = s.generation.wrapping_add(1);
        s.cache.clear();
    }

    pub fn snapshot(&self) -> CleanDnsSnapshot {
        let (running, listen, dnat_port) = {
            let rt = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
            match rt.as_ref() {
                Some(rt) if rt.is_alive() => {
                    (true, Some(rt.binding.addr.to_string()), rt.binding.dnat_port)
                }
                _ => (false, None, None),
            }
        };
        let s = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        CleanDnsSnapshot {
            running,
            listen,
            dnat_port,
            mode: s.mode.label(),
            error: s.last_error.clone(),
        }
    }

    #[cfg(test)]
    fn cache_len(&self) -> usize {
        self.shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cache
            .len()
    }
}

impl Drop for CleanDns {
    fn drop(&mut self) {
        self.stop();
    }
}

fn bind_pair(ip: Ipv4Addr, port: u16) -> io::Result<(UdpSocket, TcpListener, SocketAddr)> {
    let attempts = if port == 0 { 8 } else { 1 };
    let mut last_err = None;
    for _ in 0..attempts {
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
        let udp = match UdpSocket::bind(addr) {
            Ok(sock) => sock,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        let actual_port = udp.local_addr()?.port();
        let tcp_addr = SocketAddr::V4(SocketAddrV4::new(ip, actual_port));
        match TcpListener::bind(tcp_addr) {
            Ok(tcp) => {
                let _ = udp.set_read_timeout(Some(Duration::from_millis(250)));
                let _ = tcp.set_nonblocking(true);
                let local = tcp.local_addr()?;
                return Ok((udp, tcp, local));
            }
            Err(e) if port == 0 && e.kind() == io::ErrorKind::AddrInUse => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "bind failed")))
}

fn bind_dual_stack(
    ip: Ipv4Addr,
    primary_port: u16,
    fallback_port: Option<u16>,
) -> Result<(UdpSocket, TcpListener, CleanDnsBinding), String> {
    match bind_pair(ip, primary_port) {
        Ok((udp, tcp, addr)) => Ok((
            udp,
            tcp,
            CleanDnsBinding {
                addr,
                dnat_port: None,
            },
        )),
        Err(first_err) => {
            if let Some(fb) = fallback_port.filter(|&p| p != primary_port) {
                match bind_pair(ip, fb) {
                    Ok((udp, tcp, addr)) => {
                        let dnat_port = Some(addr.port());
                        eprintln!(
                            "[tailscale] clean DNS {ip}:{primary_port} unavailable ({first_err}); using fallback {addr} with DNAT"
                        );
                        return Ok((udp, tcp, CleanDnsBinding { addr, dnat_port }));
                    }
                    Err(fb_err) => {
                        return Err(format!(
                            "clean DNS bind failed on {ip}:{primary_port} ({first_err}) and fallback :{fb} ({fb_err})"
                        ));
                    }
                }
            }
            Err(format!("clean DNS bind failed on {ip}:{primary_port}: {first_err}"))
        }
    }
}

fn stop_runtime(rt: Runtime) {
    rt.running.store(false, Ordering::Release);
    let _ = rt.shutdown.send(true);
    rt.tcp_queue.close();
    // Wake the UDP listener if blocked in recv_from.
    if let Ok(waker) = UdpSocket::bind("127.0.0.1:0") {
        let _ = waker.send_to(&[0u8], rt.binding.addr);
    }
    // Wake TCP listener via one non-blocking connect attempt.
    let _ = TcpStream::connect_timeout(&rt.binding.addr, Duration::from_millis(50));
    drop(rt.udp_socket);
    for _ in 0..STOP_WAKE_ATTEMPTS {
        if rt.threads.iter().all(|h| h.is_finished()) {
            break;
        }
        thread::sleep(STOP_WAKE_INTERVAL);
    }
    for handle in rt.threads {
        let _ = handle.join();
    }
}

fn udp_listener_loop(
    socket: UdpSocket,
    running: Arc<AtomicBool>,
    tx: SyncSender<UdpJob>,
    shared: Arc<Mutex<SharedState>>,
) {
    let _guard = RunningDropGuard(Arc::clone(&running));
    let mut buf = [0u8; MAX_DNS_MSG];
    let mut consecutive_errors = 0u32;
    while running.load(Ordering::Acquire) {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                consecutive_errors = 0;
                if !running.load(Ordering::Acquire) {
                    break;
                }
                let query = buf[..len].to_vec();
                if !dns_packet::is_valid_query(&query) {
                    continue;
                }
                let job = UdpJob {
                    query,
                    peer,
                    received: Instant::now(),
                };
                if let Err(TrySendError::Full(dropped)) = tx.try_send(job) {
                    let servfail = build_servfail(&dropped.query);
                    let _ = socket.send_to(&servfail, dropped.peer);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ) =>
            {
                consecutive_errors = 0;
                continue;
            }
            Err(e) => {
                if !running.load(Ordering::Acquire) {
                    break;
                }
                consecutive_errors += 1;
                if consecutive_errors >= LISTENER_MAX_CONSECUTIVE_ERRORS {
                    shared
                        .lock()
                        .unwrap_or_else(|err| err.into_inner())
                        .last_error = Some(format!("clean DNS UDP listener failed: {e}"));
                    running.store(false, Ordering::Release);
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn tcp_listener_loop(
    listener: TcpListener,
    running: Arc<AtomicBool>,
    queue: Arc<TcpQueue>,
    shared: Arc<Mutex<SharedState>>,
) {
    let _guard = RunningDropGuard(Arc::clone(&running));
    let mut consecutive_errors = 0u32;
    while running.load(Ordering::Acquire) {
        let budget = shared.lock().unwrap_or_else(|e| e.into_inner()).budget;
        queue.reap_expired(budget);
        match listener.accept() {
            Ok((stream, _peer)) => {
                consecutive_errors = 0;
                if !running.load(Ordering::Acquire) {
                    break;
                }
                let _ = stream.set_nonblocking(false);
                let job = TcpJob {
                    stream,
                    accepted: Instant::now(),
                };
                if let Err(rejected) = queue.push(job, budget) {
                    let _ = rejected.stream.shutdown(std::net::Shutdown::Both);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                consecutive_errors = 0;
                thread::sleep(Duration::from_millis(15));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                consecutive_errors = 0;
                continue;
            }
            Err(e) => {
                if !running.load(Ordering::Acquire) {
                    break;
                }
                consecutive_errors += 1;
                if consecutive_errors >= LISTENER_MAX_CONSECUTIVE_ERRORS {
                    shared
                        .lock()
                        .unwrap_or_else(|err| err.into_inner())
                        .last_error = Some(format!("clean DNS TCP listener failed: {e}"));
                    running.store(false, Ordering::Release);
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
    queue.close();
}

struct WorkerClient {
    generation: u64,
    last_used: Instant,
    client: Option<Client>,
}

impl WorkerClient {
    fn new() -> Self {
        Self {
            generation: 0,
            last_used: Instant::now(),
            client: None,
        }
    }

    fn checkout(
        &mut self,
        generation: u64,
        mode: &UpstreamMode,
        #[cfg(test)] allow_http_for_test: bool,
    ) -> Result<Client, String> {
        let now = Instant::now();
        if self.client.is_none()
            || self.generation != generation
            || now.saturating_duration_since(self.last_used) > AGENT_IDLE_MAX
        {
            self.client = Some(build_doh_client(
                mode,
                #[cfg(test)]
                allow_http_for_test,
            )?);
            self.generation = generation;
        }
        self.last_used = now;
        self.client
            .clone()
            .ok_or_else(|| "clean DNS HTTP client unavailable".into())
    }
}

fn build_doh_client(
    mode: &UpstreamMode,
    #[cfg(test)] allow_http_for_test: bool,
) -> Result<Client, String> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_idle_timeout(Some(AGENT_IDLE_MAX));
    #[cfg(test)]
    let https_only = !allow_http_for_test;
    #[cfg(not(test))]
    let https_only = true;
    if https_only {
        builder = builder.https_only(true);
    }
    if let UpstreamMode::Proxy {
        addr,
        username,
        secret,
    } = mode
    {
        let proxy_url = format!("http://{addr}");
        let proxy = if https_only {
            reqwest::Proxy::https(&proxy_url)
        } else {
            reqwest::Proxy::all(&proxy_url)
        }
        .map_err(|e| format!("clean DNS proxy setup failed: {e}"))?
        .basic_auth(username, secret);
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| format!("clean DNS HTTP client build failed: {e}"))
}

fn udp_worker_loop(
    rx: Arc<Mutex<Receiver<UdpJob>>>,
    shared: Arc<Mutex<SharedState>>,
    socket: UdpSocket,
    running: Arc<AtomicBool>,
    doh_handle: tokio::runtime::Handle,
    shutdown: watch::Receiver<bool>,
) {
    let mut worker = WorkerClient::new();
    loop {
        let job = {
            let guard = rx.lock().unwrap_or_else(|e| e.into_inner());
            guard.recv()
        };
        let Ok(job) = job else {
            break;
        };
        if !running.load(Ordering::Acquire) {
            break;
        }
        let budget = shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .budget;
        let deadline = job.received + budget;
        let max_udp = query_udp_payload_size(&job.query);
        let response = match resolve_query(
            &shared,
            &mut worker,
            &job.query,
            deadline,
            &running,
            &doh_handle,
            &shutdown,
        ) {
            Ok(resp) => truncate_for_udp(&job.query, &resp, max_udp),
            Err(_) => {
                if !running.load(Ordering::Acquire) {
                    break;
                }
                build_servfail(&job.query)
            }
        };
        let _ = socket.send_to(&response, job.peer);
    }
}

fn tcp_worker_loop(
    queue: Arc<TcpQueue>,
    shared: Arc<Mutex<SharedState>>,
    running: Arc<AtomicBool>,
    doh_handle: tokio::runtime::Handle,
    shutdown: watch::Receiver<bool>,
) {
    let mut worker = WorkerClient::new();
    while let Some(job) = queue.pop(&running) {
        if !running.load(Ordering::Acquire) {
            break;
        }
        handle_tcp_connection(job, &queue, &shared, &mut worker, &running, &doh_handle, &shutdown);
    }
}

fn read_exact_until(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
    running: &AtomicBool,
) -> Result<(), ()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        if !running.load(Ordering::Acquire) {
            return Err(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(());
        }
        let _ = stream.set_read_timeout(Some(remaining.min(TCP_POLL_SLICE)));
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(()),
            Ok(n) => filled += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

fn write_all_until(
    stream: &mut TcpStream,
    buf: &[u8],
    deadline: Instant,
    running: &AtomicBool,
) -> Result<(), ()> {
    let mut written = 0usize;
    while written < buf.len() {
        if !running.load(Ordering::Acquire) {
            return Err(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(());
        }
        let _ = stream.set_write_timeout(Some(remaining.min(TCP_POLL_SLICE)));
        match stream.write(&buf[written..]) {
            Ok(0) => return Err(()),
            Ok(n) => written += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return Err(()),
        }
    }
    let _ = stream.flush();
    Ok(())
}

fn handle_tcp_connection(
    job: TcpJob,
    queue: &TcpQueue,
    shared: &Arc<Mutex<SharedState>>,
    worker: &mut WorkerClient,
    running: &AtomicBool,
    doh_handle: &tokio::runtime::Handle,
    shutdown: &watch::Receiver<bool>,
) {
    let TcpJob {
        mut stream,
        accepted,
    } = job;
    let _ = stream.set_nodelay(true);
    let budget = shared
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .budget;
    for query_idx in 0..MAX_TCP_QUERIES_PER_CONN {
        if !running.load(Ordering::Acquire) {
            break;
        }
        let (len_buf, deadline) = if query_idx == 0 {
            // First query shares the absolute total budget starting from accept()
            // so queue wait + frame reads + DoH + response write never exceed 5s.
            let deadline = accepted + budget;
            let mut len_buf = [0u8; 2];
            if read_exact_until(&mut stream, &mut len_buf, deadline, running).is_err() {
                break;
            }
            (len_buf, deadline)
        } else {
            // If another accepted client is waiting in the queue, do not keep a
            // worker parked idle on a keep-alive connection.
            if queue.has_waiting() {
                break;
            }
            let idle_deadline = Instant::now() + TCP_IDLE_TIMEOUT.min(budget);
            let mut first = [0u8; 1];
            let mut got_first = false;
            loop {
                if !running.load(Ordering::Acquire) || queue.has_waiting() {
                    break;
                }
                let remaining = idle_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let _ = stream.set_read_timeout(Some(remaining.min(TCP_POLL_SLICE)));
                match stream.read(&mut first) {
                    Ok(0) => break,
                    Ok(_) => {
                        got_first = true;
                        break;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            if !got_first {
                break;
            }
            let deadline = Instant::now() + budget;
            let mut second = [0u8; 1];
            if read_exact_until(&mut stream, &mut second, deadline, running).is_err() {
                break;
            }
            ([first[0], second[0]], deadline)
        };
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if !(12..=MAX_DNS_MSG).contains(&msg_len) {
            break;
        }
        let mut query = vec![0u8; msg_len];
        if read_exact_until(&mut stream, &mut query, deadline, running).is_err() {
            break;
        }
        if !dns_packet::is_valid_query(&query) {
            break;
        }
        let response = match resolve_query(shared, worker, &query, deadline, running, doh_handle, shutdown) {
            Ok(resp) if resp.len() <= u16::MAX as usize => resp,
            _ => {
                if !running.load(Ordering::Acquire) || Instant::now() >= deadline {
                    break;
                }
                build_servfail(&query)
            }
        };
        let mut frame = Vec::with_capacity(2 + response.len());
        frame.extend_from_slice(&(response.len() as u16).to_be_bytes());
        frame.extend_from_slice(&response);
        if write_all_until(&mut stream, &frame, deadline, running).is_err() {
            break;
        }
    }
}

fn resolve_query(
    shared: &Arc<Mutex<SharedState>>,
    worker: &mut WorkerClient,
    query: &[u8],
    deadline: Instant,
    running: &AtomicBool,
    doh_handle: &tokio::runtime::Handle,
    shutdown: &watch::Receiver<bool>,
) -> Result<Vec<u8>, String> {
    if !running.load(Ordering::Acquire) {
        return Err("clean DNS shutting down".into());
    }
    if query.len() < 12 {
        return Err("query too short".into());
    }
    if Instant::now() >= deadline {
        return Err("clean DNS query timed out".into());
    }
    let client_id = u16::from_be_bytes([query[0], query[1]]);
    let question = dns_packet::parse_question(query);

    struct QueryPlan {
        mode: UpstreamMode,
        generation: u64,
        urls: Vec<String>,
        #[cfg(test)]
        allow_http_for_test: bool,
    }

    let plan = {
        let s = shared.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((ref qname, qtype, _)) = question {
            if let Some(cached) = s.cache.get(qname, qtype, client_id) {
                return Ok(cached);
            }
        }
        let urls = match &s.mode {
            UpstreamMode::Direct => s.endpoints.direct.clone(),
            UpstreamMode::Proxy { .. } => s.endpoints.proxy.clone(),
        };
        QueryPlan {
            mode: s.mode.clone(),
            generation: s.generation,
            urls,
            #[cfg(test)]
            allow_http_for_test: s.endpoints.allow_http_for_test,
        }
    };
    let QueryPlan {
        mode,
        generation,
        urls,
        #[cfg(test)]
        allow_http_for_test,
    } = plan;

    if urls.is_empty() {
        return Err("no clean DNS upstream configured".into());
    }
    let client = worker.checkout(
        generation,
        &mode,
        #[cfg(test)]
        allow_http_for_test,
    )?;

    let mut last_err = String::from("clean DNS query timed out");
    for (idx, url) in urls.iter().enumerate() {
        if !running.load(Ordering::Acquire) {
            return Err("clean DNS shutting down".into());
        }
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            break;
        }
        let attempt_timeout = if idx + 1 < urls.len() {
            (remaining * 3 / 5)
                .max(Duration::from_millis(200))
                .min(Duration::from_millis(2800))
                .min(remaining)
        } else {
            remaining
        };
        match post_doh(doh_handle, shutdown, &client, url, query, attempt_timeout) {
            Ok(mut response) if response.len() >= 12 && (response[2] & 0x80) != 0 => {
                dns_packet::rewrite_id(&mut response, client_id);
                if let Some((qname, qtype, _)) = question {
                    let ttl = dns_packet::extract_min_ttl(&response);
                    if ttl > 0 {
                        let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
                        if s.generation == generation {
                            s.cache.insert(qname, qtype, &response, ttl);
                        }
                    }
                }
                return Ok(response);
            }
            Ok(_) => {
                last_err = format!("invalid DNS response from {url}");
            }
            Err(err) => {
                if !running.load(Ordering::Acquire) {
                    return Err("clean DNS shutting down".into());
                }
                last_err = err;
            }
        }
    }
    Err(last_err)
}

fn post_doh(
    doh_handle: &tokio::runtime::Handle,
    shutdown: &watch::Receiver<bool>,
    client: &Client,
    url: &str,
    dns_query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut stop = shutdown.clone();
    if *stop.borrow() {
        return Err("clean DNS shutting down".into());
    }
    let client = client.clone();
    let url = url.to_string();
    let body = dns_query.to_vec();
    let (tx, rx) = tokio::sync::oneshot::channel();
    doh_handle.spawn(async move {
        let req_fut = pin!(async move {
            let response = client
                .post(&url)
                .timeout(timeout)
                .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
                .header(reqwest::header::ACCEPT, "application/dns-message")
                .body(body)
                .send()
                .await
                .map_err(|e| format!("clean DoH request failed: {e}"))?;
            let bytes = response
                .error_for_status()
                .map_err(|e| format!("clean DoH HTTP error: {e}"))?
                .bytes()
                .await
                .map_err(|e| format!("clean DoH read failed: {e}"))?;
            Ok(bytes.to_vec())
        });
        let stop_fut = pin!(async move {
            let _ = stop.wait_for(|&stopped| stopped).await;
        });
        let res = match future::select(stop_fut, req_fut).await {
            Either::Left(_) => Err("clean DNS shutting down".to_string()),
            Either::Right((res, _)) => res,
        };
        let _ = tx.send(res);
    });
    rx.blocking_recv()
        .unwrap_or_else(|_| Err("clean DNS shutting down".into()))
}

fn build_servfail(query: &[u8]) -> Vec<u8> {
    let mut resp = if query.len() >= 12 {
        let q_end = dns_packet::parse_question(query)
            .map(|(_, _, end)| end)
            .unwrap_or(12);
        query[..q_end].to_vec()
    } else {
        vec![0u8; 12]
    };
    let rd = resp[2] & 0x01;
    resp[2] = 0x80 | rd; // QR=1, preserve RD
    resp[3] = 0x82; // RA=1, RCODE=2 (SERVFAIL)
    let qd: u16 = if resp.len() > 12 { 1 } else { 0 };
    resp[4..6].copy_from_slice(&qd.to_be_bytes());
    resp[6..12].fill(0);
    resp
}

/// Inspect EDNS0 OPT record in additional section for the client's advertised
/// UDP payload size, clamped to `[512, MAX_DNS_MSG]`. Defaults to 512.
fn query_udp_payload_size(query: &[u8]) -> usize {
    if query.len() < 12 {
        return 512;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]) as usize;
    let ancount = u16::from_be_bytes([query[6], query[7]]) as usize;
    let nscount = u16::from_be_bytes([query[8], query[9]]) as usize;
    let arcount = u16::from_be_bytes([query[10], query[11]]) as usize;
    if arcount == 0 {
        return 512;
    }
    let mut pos = 12usize;
    for _ in 0..qdcount {
        let Some(next) = skip_dns_name(query, pos) else {
            return 512;
        };
        pos = next + 4;
        if pos > query.len() {
            return 512;
        }
    }
    for _ in 0..(ancount + nscount) {
        let Some(next) = skip_dns_name(query, pos) else {
            return 512;
        };
        if next + 10 > query.len() {
            return 512;
        }
        let rdlen = u16::from_be_bytes([query[next + 8], query[next + 9]]) as usize;
        pos = next + 10 + rdlen;
        if pos > query.len() {
            return 512;
        }
    }
    for _ in 0..arcount {
        let Some(next) = skip_dns_name(query, pos) else {
            return 512;
        };
        if next + 10 > query.len() {
            return 512;
        }
        let rtype = u16::from_be_bytes([query[next], query[next + 1]]);
        let rclass = u16::from_be_bytes([query[next + 2], query[next + 3]]);
        let rdlen = u16::from_be_bytes([query[next + 8], query[next + 9]]) as usize;
        if rtype == 41 {
            return (rclass as usize).clamp(512, MAX_DNS_MSG);
        }
        pos = next + 10 + rdlen;
        if pos > query.len() {
            return 512;
        }
    }
    512
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..128 {
        if pos >= buf.len() {
            return None;
        }
        let b = buf[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            return (pos + 2 <= buf.len()).then_some(pos + 2);
        }
        pos += 1 + (b as usize);
    }
    None
}

/// If an upstream DNS answer exceeds the UDP client's payload limit, return a
/// truncated (TC=1) header + question so clients (such as Tailscale PeerAPI)
/// cleanly retry over TCP.
fn truncate_for_udp(query: &[u8], response: &[u8], max_len: usize) -> Vec<u8> {
    if response.len() <= max_len {
        return response.to_vec();
    }
    let q_end = dns_packet::parse_question(query)
        .map(|(_, _, end)| end)
        .filter(|&end| end <= max_len)
        .unwrap_or(12);
    let mut out = if query.len() >= q_end {
        query[..q_end].to_vec()
    } else {
        vec![0u8; 12]
    };
    if response.len() >= 12 {
        out[0] = query[0];
        out[1] = query[1];
        out[2] = (response[2] & !0x02) | 0x82; // QR=1, TC=1
        out[3] = response[3];
    } else {
        out[2] = 0x82;
        out[3] = 0x80;
    }
    let qd: u16 = if out.len() > 12 { 1 } else { 0 };
    out[4..6].copy_from_slice(&qd.to_be_bytes());
    out[6..12].fill(0);
    out
}

// --- Private mount namespace & `/proc/<pid>/mountinfo` verification ---

/// Prepare the private directory containing a single `resolv.conf.auto` with
/// ONLY `nameserver 127.0.0.54\n` (no second host line).
pub fn prepare_resolv_dir(dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("create clean DNS resolv dir {}: {e}", dir.display()))?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    let tmp = dir.join(".resolv.conf.auto.tmp");
    let final_path = dir.join(RESOLV_FILE_NAME);
    fs::write(&tmp, RESOLV_CONTENT)
        .map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &final_path)
        .map_err(|e| format!("install {}: {e}", final_path.display()))?;
    verify_resolv_file(dir)?;
    Ok(final_path)
}

/// Confirm the private `resolv.conf.auto` holds exclusively `nameserver 127.0.0.54\n`.
pub fn verify_resolv_file(dir: &Path) -> Result<(), String> {
    let path = dir.join(RESOLV_FILE_NAME);
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    if content != RESOLV_CONTENT {
        return Err(format!(
            "{} drifted from clean DNS loopback entry",
            path.display()
        ));
    }
    Ok(())
}

fn unescape_mountinfo_field(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let d0 = bytes[i + 1];
            let d1 = bytes[i + 2];
            let d2 = bytes[i + 3];
            if (b'0'..=b'3').contains(&d0)
                && (b'0'..=b'7').contains(&d1)
                && (b'0'..=b'7').contains(&d2)
            {
                let val = ((d0 - b'0') << 6) | ((d1 - b'0') << 3) | (d2 - b'0');
                out.push(val);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `/proc/<pid>/mountinfo` and verify the topmost mount at `target_dir`
/// is a read-only bind mount from a source root ending with
/// `expected_root_suffix` (e.g. `"/tailscale-resolv"`).
pub fn parse_mountinfo_isolated(
    mountinfo: &str,
    target_dir: &str,
    expected_root_suffix: &str,
) -> Result<(), String> {
    let mut matched: Option<(String, String)> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 7 {
            continue;
        }
        let root = unescape_mountinfo_field(fields[3]);
        let mount_point = unescape_mountinfo_field(fields[4]);
        let options = fields[5].to_string();
        if mount_point == target_dir {
            matched = Some((root, options));
        }
    }
    let Some((root, options)) = matched else {
        return Err(format!(
            "mountinfo has no bind mount at {target_dir}"
        ));
    };
    let root_ok = root == expected_root_suffix
        || root.ends_with(expected_root_suffix)
        || (expected_root_suffix.starts_with('/') && root == &expected_root_suffix[1..]);
    if !root_ok {
        return Err(format!(
            "mount at {target_dir} has unexpected source root {root}"
        ));
    }
    if !options.split(',').any(|opt| opt == "ro") {
        return Err(format!(
            "mount at {target_dir} is not read-only ({options})"
        ));
    }
    Ok(())
}

/// Resolve `start` (e.g. `/etc/resolv.conf`) strictly inside `root` (e.g.
/// `/proc/<pid>/root` or `/`), following all intermediate and leaf symlinks
/// relative to `root` without escaping into the caller's mount namespace.
///
/// When `allow_missing_managed_auto` is true (pre-mount inspection before
/// `/tmp/resolv.conf.d` is bind-mounted), a dangling leaf at
/// `/tmp/resolv.conf.d/resolv.conf.auto` is accepted because the read-only
/// directory bind mount will provide that exact file inside the child.
pub fn resolve_in_root(
    root: &Path,
    start: &Path,
    allow_missing_managed_auto: bool,
) -> Result<(PathBuf, PathBuf), String> {
    let managed_auto = Path::new(TARGET_RESOLV_DIR).join(RESOLV_FILE_NAME);
    let mut pending: VecDeque<std::ffi::OsString> = VecDeque::new();
    for comp in start.components() {
        match comp {
            Component::RootDir | Component::CurDir | Component::ParentDir => {}
            Component::Normal(s) => pending.push_back(s.to_os_string()),
            Component::Prefix(_) => return Err("unsupported path prefix".into()),
        }
    }
    let mut resolved: Vec<std::ffi::OsString> = Vec::new();
    let mut symlinks = 0usize;
    while let Some(part) = pending.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            resolved.pop();
            continue;
        }
        resolved.push(part);
        let mut effective = PathBuf::from("/");
        let mut cur = root.to_path_buf();
        for seg in &resolved {
            effective.push(seg);
            cur.push(seg);
        }
        let meta = match fs::symlink_metadata(&cur) {
            Ok(meta) => meta,
            Err(e)
                if allow_missing_managed_auto
                    && e.kind() == io::ErrorKind::NotFound
                    && pending.is_empty()
                    && effective == managed_auto =>
            {
                return Ok((effective, cur));
            }
            Err(e) => return Err(format!("inspect {}: {e}", cur.display())),
        };
        if meta.file_type().is_symlink() {
            symlinks += 1;
            if symlinks > MAX_SYMLINK_HOPS {
                return Err(format!(
                    "too many symlink hops while resolving {}",
                    start.display()
                ));
            }
            let target = fs::read_link(&cur)
                .map_err(|e| format!("readlink {}: {e}", cur.display()))?;
            resolved.pop();
            let mut next_parts: Vec<std::ffi::OsString> = Vec::new();
            for comp in target.components() {
                match comp {
                    Component::RootDir => {
                        resolved.clear();
                    }
                    Component::CurDir => {}
                    Component::ParentDir => next_parts.push(std::ffi::OsString::from("..")),
                    Component::Normal(s) => next_parts.push(s.to_os_string()),
                    Component::Prefix(_) => return Err("unsupported symlink prefix".into()),
                }
            }
            for seg in next_parts.into_iter().rev() {
                pending.push_front(seg);
            }
        } else if !pending.is_empty() && !meta.is_dir() {
            return Err(format!("{} is not a directory", effective.display()));
        }
    }
    let mut effective = PathBuf::from("/");
    let mut host_view = root.to_path_buf();
    for seg in &resolved {
        effective.push(seg);
        host_view.push(seg);
    }
    let final_meta = fs::symlink_metadata(&host_view)
        .map_err(|e| format!("inspect {}: {e}", host_view.display()))?;
    if !final_meta.is_file() {
        return Err(format!("{} is not a regular file", effective.display()));
    }
    Ok((effective, host_view))
}

/// Pure, testable verifier for a child's effective `/etc/resolv.conf` view
/// inside `child_root` (production: `/proc/<pid>/root`) together with its
/// `/proc/<pid>/mountinfo`.
pub fn verify_mount_isolation_in(
    child_root: &Path,
    mountinfo: &str,
    resolv_dir: &Path,
) -> Result<(), String> {
    verify_resolv_file(resolv_dir)?;
    let suffix = resolv_dir
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| format!("/{n}"))
        .unwrap_or_else(|| "/tailscale-resolv".into());
    parse_mountinfo_isolated(mountinfo, TARGET_RESOLV_DIR, &suffix)?;

    let (effective, host_view) =
        resolve_in_root(child_root, Path::new("/etc/resolv.conf"), false)?;
    let managed_auto = Path::new(TARGET_RESOLV_DIR).join(RESOLV_FILE_NAME);
    if effective == managed_auto {
        // Covered by the read-only directory bind mount at `/tmp/resolv.conf.d`.
    } else if effective.starts_with(TARGET_RESOLV_DIR) {
        return Err(format!(
            "/etc/resolv.conf resolves to unexpected file {} inside {TARGET_RESOLV_DIR}",
            effective.display()
        ));
    } else {
        let target_str = effective
            .to_str()
            .ok_or_else(|| "non-UTF-8 /etc/resolv.conf target".to_string())?;
        parse_mountinfo_isolated(
            mountinfo,
            target_str,
            &format!("{suffix}/{RESOLV_FILE_NAME}"),
        )?;
    }

    let seen = fs::read_to_string(&host_view)
        .map_err(|e| format!("read child /etc/resolv.conf ({}): {e}", host_view.display()))?;
    if seen != RESOLV_CONTENT {
        return Err(format!(
            "child /etc/resolv.conf ({}) drifted from clean DNS loopback entry",
            effective.display()
        ));
    }
    Ok(())
}

/// Verify that `pid`'s mount namespace still holds the read-only bind mount
/// covering the child's effective `/etc/resolv.conf` and that the child sees
/// exclusively `nameserver 127.0.0.54\n`.
pub fn verify_pid_mount_isolation(pid: u32, resolv_dir: &Path) -> Result<(), String> {
    verify_resolv_file(resolv_dir)?;
    #[cfg(target_os = "linux")]
    {
        let mountinfo_path = format!("/proc/{pid}/mountinfo");
        let mountinfo = fs::read_to_string(&mountinfo_path)
            .map_err(|e| format!("read {mountinfo_path}: {e}"))?;
        let child_root = PathBuf::from(format!("/proc/{pid}/root"));
        verify_mount_isolation_in(&child_root, &mountinfo, resolv_dir)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Ok(())
    }
}

/// Configure `cmd` (via `pre_exec` on Linux) to spawn inside a private mount
/// namespace (`unshare(CLONE_NEWNS)` + `MS_REC | MS_SLAVE`) with
/// `/tmp/resolv.conf.d` read-only directory-bind-mounted from `resolv_dir`,
/// plus a read-only file bind mount if `/etc/resolv.conf` resolves to a regular
/// file outside `/tmp/resolv.conf.d`, and a child-view `/etc/resolv.conf`
/// verification before `execve`.
pub fn apply_mount_namespace(
    cmd: &mut std::process::Command,
    resolv_dir: &Path,
) -> Result<(), String> {
    let resolv_file = prepare_resolv_dir(resolv_dir)?;
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt;

        fs::create_dir_all(TARGET_RESOLV_DIR)
            .map_err(|e| format!("create {TARGET_RESOLV_DIR}: {e}"))?;
        let (effective_resolv, _) =
            resolve_in_root(Path::new("/"), Path::new("/etc/resolv.conf"), true)?;
        let managed_auto = Path::new(TARGET_RESOLV_DIR).join(RESOLV_FILE_NAME);
        if effective_resolv != managed_auto && effective_resolv.starts_with(TARGET_RESOLV_DIR) {
            return Err(format!(
                "/etc/resolv.conf resolves to unexpected file {} inside {TARGET_RESOLV_DIR}",
                effective_resolv.display()
            ));
        }

        let root_c = CString::new("/").map_err(|_| "invalid root path")?;
        let src_dir_c = CString::new(resolv_dir.as_os_str().as_bytes())
            .map_err(|_| "invalid resolv dir path")?;
        let dst_dir_c = CString::new(TARGET_RESOLV_DIR).map_err(|_| "invalid target resolv dir")?;
        let etc_resolv_c = CString::new("/etc/resolv.conf").map_err(|_| "invalid etc resolv")?;
        let dst_flags = preserved_mount_flags(&dst_dir_c);

        // On B31 OpenWrt `/etc/resolv.conf -> /tmp/resolv.conf ->
        // /tmp/resolv.conf.d/resolv.conf.auto`; bind the effective regular file
        // directly only when `/etc/resolv.conf` resolves outside `/tmp/resolv.conf.d`.
        let file_fallback = if effective_resolv != managed_auto {
            let src_file_c = CString::new(resolv_file.as_os_str().as_bytes())
                .map_err(|_| "invalid resolv file path")?;
            let dst_file_c = CString::new(effective_resolv.as_os_str().as_bytes())
                .map_err(|_| "invalid dst file")?;
            let file_flags = preserved_mount_flags(&dst_file_c);
            Some((src_file_c, dst_file_c, file_flags))
        } else {
            None
        };

        // SAFETY: closure invokes only async-signal-safe libc syscalls
        // (`unshare`, `mount`, `open`, `read`, `close`) with pre-allocated
        // NUL-terminated paths and a stack buffer (no heap allocation).
        unsafe {
            cmd.pre_exec(move || {
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::mount(
                    std::ptr::null(),
                    root_c.as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_SLAVE,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::mount(
                    src_dir_c.as_ptr(),
                    dst_dir_c.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::mount(
                    std::ptr::null(),
                    dst_dir_c.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | dst_flags,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if let Some((ref src_file_c, ref dst_file_c, file_flags)) = file_fallback {
                    if libc::mount(
                        src_file_c.as_ptr(),
                        dst_file_c.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    ) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::mount(
                        std::ptr::null(),
                        dst_file_c.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | file_flags,
                        std::ptr::null(),
                    ) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                // Confirm `/etc/resolv.conf` as seen inside this child's own
                // mount namespace reads exclusively `nameserver 127.0.0.54\n`.
                let fd = libc::open(etc_resolv_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut buf = [0u8; 64];
                let mut filled = 0usize;
                while filled < buf.len() {
                    let n = libc::read(
                        fd,
                        buf.as_mut_ptr().add(filled) as *mut libc::c_void,
                        buf.len() - filled,
                    );
                    if n < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        libc::close(fd);
                        return Err(err);
                    }
                    if n == 0 {
                        break;
                    }
                    filled += n as usize;
                }
                libc::close(fd);
                if &buf[..filled] != RESOLV_CONTENT.as_bytes() {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
                Ok(())
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cmd, resolv_file);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn preserved_mount_flags(path: &std::ffi::CString) -> libc::c_ulong {
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return 0;
    }
    let mut flags: libc::c_ulong = 0;
    let f = stat.f_flag;
    if f & libc::ST_NOSUID != 0 {
        flags |= libc::MS_NOSUID;
    }
    if f & libc::ST_NODEV != 0 {
        flags |= libc::MS_NODEV;
    }
    if f & libc::ST_NOEXEC != 0 {
        flags |= libc::MS_NOEXEC;
    }
    if f & libc::ST_NOATIME != 0 {
        flags |= libc::MS_NOATIME;
    }
    if f & libc::ST_NODIRATIME != 0 {
        flags |= libc::MS_NODIRATIME;
    }
    // Linux `include/linux/statfs.h` defines `ST_RELATIME = 0x1000` (not
    // re-exported by musl's `libc` bindings).
    const ST_RELATIME: libc::c_ulong = 0x1000;
    if f & ST_RELATIME != 0 {
        flags |= libc::MS_RELATIME;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn build_a_response(query: &[u8], ip: [u8; 4], ttl: u32, extra_answers: usize) -> Vec<u8> {
        let q_end = dns_packet::parse_question(query).unwrap().2;
        let mut resp = query[..q_end].to_vec();
        resp[2] = 0x81; // QR=1, RD=1
        resp[3] = 0x80; // RA=1, NOERROR
        let count = (1 + extra_answers) as u16;
        resp[6..8].copy_from_slice(&count.to_be_bytes());
        for i in 0..count {
            resp.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
            resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
            resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            let mut octets = ip;
            octets[3] = octets[3].wrapping_add(i as u8);
            resp.extend_from_slice(&octets);
        }
        resp
    }

    fn extract_first_a(resp: &[u8]) -> Option<[u8; 4]> {
        let q_end = dns_packet::parse_question(resp)?.2;
        if resp.len() < q_end + 16 {
            return None;
        }
        Some([
            resp[q_end + 12],
            resp[q_end + 13],
            resp[q_end + 14],
            resp[q_end + 15],
        ])
    }

    struct MockDohServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        hits: Arc<AtomicUsize>,
        handle: Option<JoinHandle<()>>,
    }

    impl MockDohServer {
        fn start(
            answer_ip: [u8; 4],
            delay: Duration,
            extra_answers: usize,
            require_proxy_auth: Option<&str>,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let hits = Arc::new(AtomicUsize::new(0));
            let stop_c = Arc::clone(&stop);
            let hits_c = Arc::clone(&hits);
            let expected_auth = require_proxy_auth.map(|s| s.to_string());
            let handle = thread::spawn(move || {
                while !stop_c.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let mut buf = Vec::new();
                            let mut chunk = [0u8; 4096];
                            let mut header_end = None;
                            let mut content_len = 0usize;
                            while buf.len() < 16384 {
                                let Ok(n) = stream.read(&mut chunk) else {
                                    break;
                                };
                                if n == 0 {
                                    break;
                                }
                                buf.extend_from_slice(&chunk[..n]);
                                if header_end.is_none() {
                                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                                    {
                                        let hdrs = String::from_utf8_lossy(&buf[..pos]);
                                        for line in hdrs.lines() {
                                            if let Some((k, v)) = line.split_once(':') {
                                                if k.eq_ignore_ascii_case("content-length") {
                                                    content_len = v.trim().parse().unwrap_or(0);
                                                }
                                            }
                                        }
                                        header_end = Some(pos + 4);
                                    }
                                }
                                if let Some(start) = header_end {
                                    if buf.len() >= start + content_len {
                                        break;
                                    }
                                }
                            }
                            let Some(start) = header_end else { continue };
                            let headers = String::from_utf8_lossy(&buf[..start]);
                            if let Some(ref auth) = expected_auth {
                                let ok = headers.lines().any(|l| {
                                    l.to_ascii_lowercase().starts_with("proxy-authorization:")
                                        && l.contains(auth)
                                });
                                if !ok {
                                    let _ = stream.write_all(
                                        b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                    );
                                    continue;
                                }
                            }
                            let body = &buf[start..buf.len().min(start + content_len)];
                            if body.len() >= 12 {
                                hits_c.fetch_add(1, Ordering::SeqCst);
                                if !delay.is_zero() {
                                    let until = Instant::now() + delay;
                                    while !stop_c.load(Ordering::Acquire) && Instant::now() < until
                                    {
                                        thread::sleep(Duration::from_millis(20));
                                    }
                                    if stop_c.load(Ordering::Acquire) {
                                        break;
                                    }
                                }
                                let dns_resp =
                                    build_a_response(body, answer_ip, 300, extra_answers);
                                let reply = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    dns_resp.len()
                                );
                                let _ = stream.write_all(reply.as_bytes());
                                let _ = stream.write_all(&dns_resp);
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                addr,
                stop,
                hits,
                handle: Some(handle),
            }
        }
    }

    impl Drop for MockDohServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn udp_query(server: SocketAddr, query: &[u8]) -> Vec<u8> {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        client.send_to(query, server).unwrap();
        let mut buf = [0u8; MAX_DNS_MSG];
        let (n, _) = client.recv_from(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    fn tcp_query(server: SocketAddr, query: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect_timeout(&server, Duration::from_secs(2)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(query).unwrap();
        stream.flush().unwrap();
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; len];
        stream.read_exact(&mut resp).unwrap();
        resp
    }

    #[test]
    fn udp_and_tcp_queries_resolve_across_direct_and_proxy_modes_and_flush_cache() {
        let direct_srv = MockDohServer::start([93, 184, 216, 34], Duration::ZERO, 0, None);
        // Basic auth base64("u60-download:s3cr3t") == "dTYwLWRvd25sb2FkOnMzY3IzdA=="
        let proxy_srv = MockDohServer::start(
            [142, 250, 190, 78],
            Duration::ZERO,
            0,
            Some("Basic dTYwLWRvd25sb2FkOnMzY3IzdA=="),
        );
        let dns = CleanDns::with_bind(
            Ipv4Addr::LOCALHOST,
            0,
            None,
            Endpoints {
                direct: vec![format!("http://{}/dns-query", direct_srv.addr)],
                proxy: vec!["http://doh.example.test/dns-query".into()],
                allow_http_for_test: true,
            },
            QUERY_BUDGET,
        );
        let binding = dns.ensure_running().unwrap();
        assert_eq!(binding.dnat_port, None);

        // 1. Direct mode via UDP
        let q1 = dns_packet::build_query(0x1111, "example.com", 1).unwrap();
        let r1 = udp_query(binding.addr, &q1);
        assert!(dns_packet::successful_response(&r1, 0x1111));
        assert_eq!(extract_first_a(&r1), Some([93, 184, 216, 34]));
        assert_eq!(direct_srv.hits.load(Ordering::SeqCst), 1);

        // 2. TCP hits cache with rewritten transaction ID
        let q2 = dns_packet::build_query(0x2222, "example.com", 1).unwrap();
        let r2 = tcp_query(binding.addr, &q2);
        assert!(dns_packet::successful_response(&r2, 0x2222));
        assert_eq!(extract_first_a(&r2), Some([93, 184, 216, 34]));
        assert_eq!(direct_srv.hits.load(Ordering::SeqCst), 1, "TCP should reuse cache");

        // 3. Switch to Proxy mode -> immediately flushes cache and routes through authenticated proxy
        assert!(dns.set_mode(UpstreamMode::Proxy {
            addr: proxy_srv.addr.to_string(),
            username: "u60-download".into(),
            secret: "s3cr3t".into(),
        }));
        assert_eq!(dns.cache_len(), 0);
        let q3 = dns_packet::build_query(0x3333, "example.com", 1).unwrap();
        let r3 = tcp_query(binding.addr, &q3);
        assert!(dns_packet::successful_response(&r3, 0x3333));
        assert_eq!(extract_first_a(&r3), Some([142, 250, 190, 78]));
        assert_eq!(proxy_srv.hits.load(Ordering::SeqCst), 1);

        // 4. Uplink change flushes cache so the next UDP query hits upstream again
        dns.uplink_changed();
        assert_eq!(dns.cache_len(), 0);
        let q4 = dns_packet::build_query(0x4444, "example.com", 1).unwrap();
        let r4 = udp_query(binding.addr, &q4);
        assert_eq!(extract_first_a(&r4), Some([142, 250, 190, 78]));
        assert_eq!(proxy_srv.hits.load(Ordering::SeqCst), 2);

        // 5. Switch back to Direct (e.g. Mihomo stopped / D3 backoff)
        assert!(dns.set_mode(UpstreamMode::Direct));
        let q5 = dns_packet::build_query(0x5555, "example.com", 1).unwrap();
        let r5 = udp_query(binding.addr, &q5);
        assert_eq!(extract_first_a(&r5), Some([93, 184, 216, 34]));
        assert_eq!(direct_srv.hits.load(Ordering::SeqCst), 2);

        // Secret is never leaked in Debug output or status JSON
        let debug_str = format!(
            "{:?}",
            UpstreamMode::Proxy {
                addr: "127.0.0.1:17893".into(),
                username: "u60-download".into(),
                secret: "super-secret-value".into(),
            }
        );
        assert!(!debug_str.contains("super-secret-value"));
        dns.stop();
    }

    #[test]
    fn occupied_primary_port_falls_back_and_reports_dnat_port() {
        let blocker = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy_port = blocker.local_addr().unwrap().port();
        let dns = CleanDns::with_bind(
            Ipv4Addr::LOCALHOST,
            busy_port,
            Some(0),
            Endpoints::default(),
            QUERY_BUDGET,
        );
        let binding = dns.ensure_running().unwrap();
        assert_ne!(binding.addr.port(), busy_port);
        assert_eq!(binding.dnat_port, Some(binding.addr.port()));
        dns.stop();
        drop(blocker);
    }

    #[test]
    fn oversized_udp_response_sets_tc_bit_and_tcp_returns_full_answer() {
        // 40 A records (~640 bytes) > 512-byte classic UDP payload limit
        let srv = MockDohServer::start([1, 2, 3, 0], Duration::ZERO, 39, None);
        let dns = CleanDns::with_bind(
            Ipv4Addr::LOCALHOST,
            0,
            None,
            Endpoints {
                direct: vec![format!("http://{}/dns-query", srv.addr)],
                proxy: Vec::new(),
                allow_http_for_test: true,
            },
            QUERY_BUDGET,
        );
        let binding = dns.ensure_running().unwrap();
        let q = dns_packet::build_query(0xABCD, "many.example.com", 1).unwrap();
        let udp_resp = udp_query(binding.addr, &q);
        assert!(udp_resp.len() <= 512);
        assert_ne!(udp_resp[2] & 0x02, 0, "UDP response >512B must set TC bit");
        let tcp_resp = tcp_query(binding.addr, &q);
        assert!(tcp_resp.len() > 512, "TCP response must return full payload");
        assert_eq!(tcp_resp[2] & 0x02, 0);
        assert_eq!(u16::from_be_bytes([tcp_resp[6], tcp_resp[7]]), 40);
        dns.stop();
    }

    #[test]
    fn slow_upstream_respects_budget_and_returns_servfail() {
        let slow = MockDohServer::start([1, 1, 1, 1], Duration::from_secs(2), 0, None);
        let dns = CleanDns::with_bind(
            Ipv4Addr::LOCALHOST,
            0,
            None,
            Endpoints {
                direct: vec![format!("http://{}/dns-query", slow.addr)],
                proxy: Vec::new(),
                allow_http_for_test: true,
            },
            Duration::from_millis(400),
        );
        let binding = dns.ensure_running().unwrap();
        let q = dns_packet::build_query(0x9999, "slow.example.com", 1).unwrap();
        let started = Instant::now();
        let resp = udp_query(binding.addr, &q);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x9999);
        assert_eq!(resp[3] & 0x0F, 2, "timed-out query must return SERVFAIL");
        dns.stop();
    }

    #[test]
    fn mountinfo_parser_validates_readonly_directory_bind_mount() {
        let valid = "\
22 1 0:20 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=65536k\n\
41 22 0:20 /zte-agent-run/tailscale-resolv /tmp/resolv.conf.d ro,nosuid,nodev,relatime - tmpfs tmpfs rw,size=65536k\n";
        assert!(parse_mountinfo_isolated(valid, TARGET_RESOLV_DIR, "/tailscale-resolv").is_ok());

        let rw = "\
41 22 0:20 /zte-agent-run/tailscale-resolv /tmp/resolv.conf.d rw,nosuid,nodev - tmpfs tmpfs rw\n";
        assert!(parse_mountinfo_isolated(rw, TARGET_RESOLV_DIR, "/tailscale-resolv").is_err());

        let wrong_root = "\
41 22 0:20 /other/dir /tmp/resolv.conf.d ro,nosuid - tmpfs tmpfs rw\n";
        assert!(parse_mountinfo_isolated(wrong_root, TARGET_RESOLV_DIR, "/tailscale-resolv").is_err());

        let missing = "22 1 0:20 / /tmp rw,nosuid - tmpfs tmpfs rw\n";
        assert!(parse_mountinfo_isolated(missing, TARGET_RESOLV_DIR, "/tailscale-resolv").is_err());

        // Stacked mount: topmost mount decides validity
        let stacked_bad = "\
41 22 0:20 /zte-agent-run/tailscale-resolv /tmp/resolv.conf.d ro,nosuid - tmpfs tmpfs rw\n\
42 41 0:20 /host-override /tmp/resolv.conf.d rw,nosuid - tmpfs tmpfs rw\n";
        assert!(parse_mountinfo_isolated(stacked_bad, TARGET_RESOLV_DIR, "/tailscale-resolv").is_err());
    }

    #[test]
    fn resolv_dir_contains_only_clean_dns_loopback_and_status_json_maps_states() {
        let dir = std::env::temp_dir().join(format!(
            "u60-clean-dns-resolv-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let resolv = prepare_resolv_dir(&dir).unwrap();
        assert_eq!(fs::read_to_string(&resolv).unwrap(), "nameserver 127.0.0.54\n");
        assert!(verify_resolv_file(&dir).is_ok());

        // Appending a second host nameserver must fail verification
        fs::write(&resolv, "nameserver 127.0.0.54\nnameserver 8.8.8.8\n").unwrap();
        assert!(verify_resolv_file(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);

        let snap = CleanDnsSnapshot {
            running: true,
            listen: Some("127.0.0.54:53".into()),
            dnat_port: None,
            mode: "proxy",
            error: None,
        };
        assert_eq!(snap.to_status_json(false, false, Ok(false))["state"], "disabled");
        assert_eq!(snap.to_status_json(true, false, Ok(false))["state"], "inactive");
        assert_eq!(snap.to_status_json(true, true, Ok(true))["state"], "active");
        assert_eq!(snap.to_status_json(true, true, Ok(true))["mode"], "proxy");
        assert_eq!(snap.to_status_json(true, true, Err("unmounted"))["state"], "degraded");
    }

    fn pick_non_ephemeral_port() -> u16 {
        let base = 22_000u16 + ((std::process::id() as u16) % 4_000);
        for offset in 0..2_000u16 {
            let port = base + offset;
            let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
            if let (Ok(u), Ok(t)) = (UdpSocket::bind(addr), TcpListener::bind(addr)) {
                drop((u, t));
                return port;
            }
        }
        panic!("no free non-ephemeral loopback port found");
    }

    #[test]
    fn partial_startup_failure_rolls_back_listeners_and_releases_port() {
        for (fail_thread, expected_spawns) in [
            ("u60-ts-dns-t0", UDP_WORKERS + 3),
            ("u60-ts-dns-tcp", UDP_WORKERS + TCP_WORKERS + 3),
        ] {
            let port = pick_non_ephemeral_port();
            let dns = CleanDns::with_bind(
                Ipv4Addr::LOCALHOST,
                port,
                None,
                Endpoints::default(),
                QUERY_BUDGET,
            );
            let mut spawned = 0usize;
            let err = dns
                .ensure_running_with_spawner(|name, f| {
                    spawned += 1;
                    if name == fail_thread {
                        return Err(io::Error::other("simulated spawn failure"));
                    }
                    thread::Builder::new().name(name).spawn(f)
                })
                .unwrap_err();
            assert!(err.contains("simulated spawn failure"), "unexpected error: {err}");
            assert_eq!(spawned, expected_spawns);
            assert!(!dns.is_running());

            // Both UDP and TCP ports MUST have been released cleanly by rollback.
            let rebound_udp = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
                .expect("UDP port must be released after partial startup rollback");
            let rebound_tcp = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
                .expect("TCP port must be released after partial startup rollback");
            drop((rebound_udp, rebound_tcp));
        }
    }

    #[test]
    fn tcp_trickled_partial_frame_obeys_absolute_budget_and_exits_quickly_on_stop() {
        let srv = MockDohServer::start([1, 1, 1, 1], Duration::ZERO, 0, None);
        let dns = CleanDns::with_bind(
            Ipv4Addr::LOCALHOST,
            0,
            None,
            Endpoints {
                direct: vec![format!("http://{}/dns-query", srv.addr)],
                proxy: Vec::new(),
                allow_http_for_test: true,
            },
            Duration::from_millis(350),
        );
        let binding = dns.ensure_running().unwrap();

        // 1. Send only the 2-byte length prefix (20 bytes promised) and trickle
        //    1 byte every 80ms: per-read timeouts would never fire, so only an
        //    absolute deadline closes the connection within the 350ms budget.
        let mut s1 = TcpStream::connect(binding.addr).unwrap();
        s1.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s1.write_all(&20u16.to_be_bytes()).unwrap();
        let started = Instant::now();
        let mut closed = false;
        for _ in 0..15 {
            thread::sleep(Duration::from_millis(80));
            if s1.write_all(&[0u8]).is_err() {
                closed = true;
                break;
            }
            let mut probe = [0u8; 1];
            let _ = s1.set_nonblocking(true);
            match s1.read(&mut probe) {
                Ok(0) => {
                    closed = true;
                    break;
                }
                _ => {}
            }
            let _ = s1.set_nonblocking(false);
            if started.elapsed() > Duration::from_secs(1) {
                break;
            }
        }
        assert!(closed, "trickled partial TCP query must be closed at absolute budget");
        assert!(
            started.elapsed() < Duration::from_millis(1200),
            "absolute budget took too long: {:?}",
            started.elapsed()
        );

        // 2. Shutdown while a partial frame is open must return promptly.
        let mut s2 = TcpStream::connect(binding.addr).unwrap();
        s2.write_all(&[0x00, 0x20, 0x01]).unwrap();
        let stop_started = Instant::now();
        dns.stop();
        assert!(
            stop_started.elapsed() < Duration::from_secs(1),
            "stop() blocked on partial TCP frame: {:?}",
            stop_started.elapsed()
        );
        drop(s2);
    }

    #[test]
    fn tcp_queued_socket_expires_while_all_workers_are_busy_and_stop_aborts_hung_doh() {
        // 0. Direct listener-reaper proof with ZERO worker threads dequeuing:
        //    a socket sitting in `TcpQueue` MUST be closed by `tcp_listener_loop`'s
        //    expiry reaper at the budget even when no worker ever calls `pop()`.
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let queue = Arc::new(TcpQueue::new(4));
            let running = Arc::new(AtomicBool::new(true));
            let budget = Duration::from_millis(200);
            let shared = Arc::new(Mutex::new(SharedState {
                mode: UpstreamMode::Direct,
                generation: 0,
                cache: DnsCache::new(64),
                endpoints: Endpoints::default(),
                budget,
                last_error: None,
            }));
            let l_queue = Arc::clone(&queue);
            let l_running = Arc::clone(&running);
            let l_shared = Arc::clone(&shared);
            let handle = thread::spawn(move || {
                tcp_listener_loop(listener, l_running, l_queue, l_shared);
            });
            let mut client = TcpStream::connect(addr).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let started = Instant::now();
            let mut buf = [0u8; 4];
            let n = client.read(&mut buf).unwrap_or(0);
            assert_eq!(n, 0, "listener expiry reaper must close un-dequeued socket at budget");
            assert!(
                started.elapsed() >= Duration::from_millis(140)
                    && started.elapsed() < Duration::from_millis(900),
                "unexpected reaper latency: {:?}",
                started.elapsed()
            );
            running.store(false, Ordering::Release);
            let _ = TcpStream::connect(addr);
            queue.close();
            let _ = handle.join();
        }

        // 1. All 4 TCP workers pinned on a single slow DoH upstream (no fast
        //    fallback) -> a 5th queued TCP socket MUST be closed within budget!
        let slow1 = MockDohServer::start([9, 9, 9, 9], Duration::from_secs(5), 0, None);
        let dns = CleanDns::with_bind(
            Ipv4Addr::LOCALHOST,
            0,
            None,
            Endpoints {
                direct: vec![format!("http://{}/dns-query", slow1.addr)],
                proxy: Vec::new(),
                allow_http_for_test: true,
            },
            Duration::from_millis(450),
        );
        let binding = dns.ensure_running().unwrap();
        let q = dns_packet::build_query(0x5151, "queued.example.com", 1).unwrap();
        let mut frame = Vec::with_capacity(2 + q.len());
        frame.extend_from_slice(&(q.len() as u16).to_be_bytes());
        frame.extend_from_slice(&q);

        // Pin all TCP_WORKERS on live connections sending slow queries.
        let mut pinned = Vec::new();
        for _ in 0..TCP_WORKERS {
            let mut s = TcpStream::connect(binding.addr).unwrap();
            s.write_all(&frame).unwrap();
            pinned.push(s);
        }
        // Connect a 5th socket that sits queued behind the busy workers.
        let mut queued = TcpStream::connect(binding.addr).unwrap();
        queued
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 4];
        let n = queued.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "queued TCP socket must be closed once budget expires");
        assert!(
            started.elapsed() < Duration::from_millis(1200),
            "queued TCP socket waited too long: {:?}",
            started.elapsed()
        );
        drop(pinned);
        dns.stop();

        // 2. Shutdown while a worker is blocked inside a 5-second hung DoH
        //    upstream MUST cancel immediately (<1s) and NEVER hit the 2nd upstream!
        let hung = MockDohServer::start([7, 7, 7, 7], Duration::from_secs(5), 0, None);
        let second = MockDohServer::start([6, 6, 6, 6], Duration::ZERO, 0, None);
        let dns2 = CleanDns::with_bind(
            Ipv4Addr::LOCALHOST,
            0,
            None,
            Endpoints {
                direct: vec![
                    format!("http://{}/dns-query", hung.addr),
                    format!("http://{}/dns-query", second.addr),
                ],
                proxy: Vec::new(),
                allow_http_for_test: true,
            },
            Duration::from_secs(5),
        );
        let binding2 = dns2.ensure_running().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(&q, binding2.addr).unwrap();
        // Wait until the hung upstream has accepted the DoH request.
        let wait_hit = Instant::now();
        while hung.hits.load(Ordering::SeqCst) == 0 && wait_hit.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(hung.hits.load(Ordering::SeqCst) >= 1);

        let stop_started = Instant::now();
        dns2.stop();
        assert!(
            stop_started.elapsed() < Duration::from_secs(1),
            "stop() must cancel in-flight DoH instead of waiting for 5s budget: {:?}",
            stop_started.elapsed()
        );
        assert_eq!(
            second.hits.load(Ordering::SeqCst),
            0,
            "shutdown must never try the second DoH upstream"
        );
    }

    #[test]
    fn mount_isolation_verifier_checks_effective_etc_resolv_conf_and_detached_file_mount() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "u60-clean-dns-root-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let resolv_dir = base.join("tailscale-resolv");
        prepare_resolv_dir(&resolv_dir).unwrap();

        // Case 1: Standard OpenWrt symlink chain `/etc/resolv.conf -> /tmp/resolv.conf -> /tmp/resolv.conf.d/resolv.conf.auto`
        let root1 = base.join("root1");
        fs::create_dir_all(root1.join("etc")).unwrap();
        fs::create_dir_all(root1.join("tmp/resolv.conf.d")).unwrap();
        fs::write(root1.join("tmp/resolv.conf.d/resolv.conf.auto"), RESOLV_CONTENT).unwrap();
        symlink("/tmp/resolv.conf", root1.join("etc/resolv.conf")).unwrap();
        symlink(
            "/tmp/resolv.conf.d/resolv.conf.auto",
            root1.join("tmp/resolv.conf"),
        )
        .unwrap();
        let mi_dir = "41 22 0:20 /zte-agent-run/tailscale-resolv /tmp/resolv.conf.d ro,nosuid - tmpfs tmpfs rw\n";
        assert!(verify_mount_isolation_in(&root1, mi_dir, &resolv_dir).is_ok());

        // Case 2: `/etc/resolv.conf` resolves to regular file `/tmp/resolv.conf`
        let root2 = base.join("root2");
        fs::create_dir_all(root2.join("etc")).unwrap();
        fs::create_dir_all(root2.join("tmp/resolv.conf.d")).unwrap();
        symlink("/tmp/resolv.conf", root2.join("etc/resolv.conf")).unwrap();
        fs::write(root2.join("tmp/resolv.conf"), RESOLV_CONTENT).unwrap();
        let mi_file = "\
41 22 0:20 /zte-agent-run/tailscale-resolv /tmp/resolv.conf.d ro,nosuid - tmpfs tmpfs rw\n\
42 22 0:20 /zte-agent-run/tailscale-resolv/resolv.conf.auto /tmp/resolv.conf ro,nosuid - tmpfs tmpfs rw\n";
        assert!(verify_mount_isolation_in(&root2, mi_file, &resolv_dir).is_ok());

        // Detached file mount (e.g. relay atomically replaced `/tmp/resolv.conf`) fails!
        assert!(verify_mount_isolation_in(&root2, mi_dir, &resolv_dir).is_err());

        // Host ISP content visible through `/etc/resolv.conf` fails even if mountinfo line looks valid!
        fs::write(root2.join("tmp/resolv.conf"), "nameserver 8.8.8.8\n").unwrap();
        assert!(verify_mount_isolation_in(&root2, mi_file, &resolv_dir).is_err());

        // Case 3: `/etc/resolv.conf` directly is a regular file with host DNS -> rejected!
        let root3 = base.join("root3");
        fs::create_dir_all(root3.join("etc")).unwrap();
        fs::write(root3.join("etc/resolv.conf"), "nameserver 1.1.1.1\n").unwrap();
        assert!(verify_mount_isolation_in(&root3, mi_dir, &resolv_dir).is_err());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn dead_listener_thread_marks_clean_dns_unhealthy_and_ensure_running_recovers() {
        let dns = CleanDns::with_bind(
            Ipv4Addr::LOCALHOST,
            0,
            None,
            Endpoints::default(),
            Duration::from_millis(300),
        );
        // Simulate the TCP listener thread dying immediately after startup while
        // the `running` AtomicBool was never cleared externally.
        let binding = dns
            .ensure_running_with_spawner(|name, f| {
                if name == "u60-ts-dns-tcp" {
                    thread::Builder::new().name(name).spawn(|| {})
                } else {
                    thread::Builder::new().name(name).spawn(f)
                }
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while dns.is_running() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !dns.is_running(),
            "exited listener thread must make is_running() return false"
        );
        assert!(dns.dnat_port().is_none());

        // `ensure_running()` MUST tear down the dead runtime and spawn a fresh
        // healthy listener rather than returning the stale binding.
        let recovered = dns.ensure_running().unwrap();
        assert!(dns.is_running());
        assert_ne!(recovered.addr, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let _ = binding;
        dns.stop();
    }
}
