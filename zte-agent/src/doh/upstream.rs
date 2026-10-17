use std::time::{Duration, Instant};

/// Longest idle gap after which the shared Agent is thrown away.
///
/// ureq 3.2.0 never expires pooled connections on its own: `Connection::age()`
/// returns `now.duration_since(now)` (pool.rs), so `max_idle_age` is a no-op.
/// Rebuilding the Agent is the only way to drop a pooled TLS connection whose
/// NAT mapping may have expired while the router sat idle.
pub const AGENT_IDLE_MAX: Duration = Duration::from_secs(15);

/// Build the upstream agent. The timeout stays at agent level (`timeout_global`)
/// rather than per request so ureq reuses its rustls ClientConfig cache.
pub fn build_agent(timeout_ms: u32) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_millis(timeout_ms as u64)))
        .build()
        .into()
}

/// One `ureq::Agent` reused across upstream queries.
///
/// Rebuilt when `timeout_ms` changes or when it has not been handed out for
/// more than [`AGENT_IDLE_MAX`]. Callers clone the Agent out (it is Arc-backed)
/// and release the surrounding lock before sending the request.
pub struct SharedAgent {
    agent: ureq::Agent,
    timeout_ms: u32,
    /// Last time the Agent was handed out (or rebuilt by `checkout`).
    last_used: Instant,
}

impl SharedAgent {
    pub fn new(timeout_ms: u32) -> Self {
        Self::new_at(timeout_ms, Instant::now())
    }

    fn new_at(timeout_ms: u32, now: Instant) -> Self {
        Self {
            agent: build_agent(timeout_ms),
            timeout_ms,
            last_used: now,
        }
    }

    /// Hand out the Agent for one request, rebuilding it first if it has been
    /// idle for longer than [`AGENT_IDLE_MAX`].
    pub fn checkout(&mut self) -> ureq::Agent {
        self.checkout_at(Instant::now())
    }

    fn checkout_at(&mut self, now: Instant) -> ureq::Agent {
        if now.saturating_duration_since(self.last_used) > AGENT_IDLE_MAX {
            self.agent = build_agent(self.timeout_ms);
        }
        self.last_used = now;
        self.agent.clone()
    }

    /// Apply a new per-request timeout; the Agent is rebuilt only when it changed.
    pub fn set_timeout(&mut self, timeout_ms: u32) {
        if self.timeout_ms == timeout_ms {
            return;
        }
        self.timeout_ms = timeout_ms;
        self.agent = build_agent(timeout_ms);
    }
}

pub fn query_doh(agent: &ureq::Agent, dns_query: &[u8], url: &str) -> Result<Vec<u8>, String> {
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .send(dns_query)
        .map_err(|e| format!("DoH request failed: {e}"))?;

    let body = response
        .body_mut()
        .read_to_vec()
        .map_err(|e| format!("DoH read failed: {e}"))?;
    Ok(body)
}

#[cfg(test)]
mod agent_tests {
    use super::*;

    /// Clones of one Agent share its `Arc<Config>`; a rebuilt Agent has a new one.
    fn same_agent(a: &ureq::Agent, b: &ureq::Agent) -> bool {
        std::ptr::eq(a.config(), b.config())
    }

    fn global_timeout(agent: &ureq::Agent) -> Option<Duration> {
        agent.config().timeouts().global
    }

    #[test]
    fn build_agent_sets_global_timeout() {
        let agent = build_agent(2500);
        assert_eq!(global_timeout(&agent), Some(Duration::from_millis(2500)));
    }

    #[test]
    fn checkout_reuses_agent_within_idle_window() {
        let t0 = Instant::now();
        let mut shared = SharedAgent::new_at(3000, t0);
        let a = shared.checkout_at(t0 + Duration::from_secs(1));
        let b = shared.checkout_at(t0 + Duration::from_secs(1) + AGENT_IDLE_MAX);
        assert!(same_agent(&a, &b), "agent must be reused when idle <= 15 s");
    }

    #[test]
    fn checkout_rebuilds_agent_after_idle_window() {
        let t0 = Instant::now();
        let mut shared = SharedAgent::new_at(3000, t0);
        let a = shared.checkout_at(t0);
        let t1 = t0 + AGENT_IDLE_MAX + Duration::from_millis(1);
        let b = shared.checkout_at(t1);
        assert!(
            !same_agent(&a, &b),
            "agent must be rebuilt when idle > 15 s"
        );
        assert_eq!(global_timeout(&b), Some(Duration::from_millis(3000)));
        // The rebuild restarts the idle clock.
        let c = shared.checkout_at(t1 + Duration::from_secs(10));
        assert!(same_agent(&b, &c));
    }

    #[test]
    fn checkout_tolerates_clock_going_backwards() {
        let t0 = Instant::now();
        let mut shared = SharedAgent::new_at(3000, t0 + Duration::from_secs(60));
        let a = shared.checkout_at(t0 + Duration::from_secs(60));
        let b = shared.checkout_at(t0);
        assert!(same_agent(&a, &b));
    }

    #[test]
    fn set_timeout_rebuilds_only_on_change() {
        let t0 = Instant::now();
        let mut shared = SharedAgent::new_at(3000, t0);
        let a = shared.checkout_at(t0);
        shared.set_timeout(3000);
        let b = shared.checkout_at(t0);
        assert!(same_agent(&a, &b), "unchanged timeout must not rebuild");
        shared.set_timeout(5000);
        let c = shared.checkout_at(t0);
        assert!(!same_agent(&b, &c), "changed timeout must rebuild");
        assert_eq!(global_timeout(&c), Some(Duration::from_millis(5000)));
    }
}
