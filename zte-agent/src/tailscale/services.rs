//! Tailscale Services (`svc:*`) management backed directly by `tailscaled`'s
//! own `ServeConfig` (`/localapi/v0/serve-config`), `Prefs.AdvertiseServices`,
//! and live `Self.CapMap` / `Self.PrimaryRoutes` state.
//!
//! No shadow copy is stored in `tailscale.json`: `tailscaled.state` remains the
//! single source of truth across router reboots, agent restarts, and upgrades.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::handlers::AppState;
use crate::httpd::mobile::{interfaces, IfAddr};

use super::localapi::{
    daemon_prefs_at_until, daemon_serve_config_at_until, daemon_set_serve_config_at_until,
    LocalApiWriteError, Prefs, Status,
};
use super::{
    config, handler_error, lan_subnets, require_password, CLI_TIMEOUT_SECS, SOCK,
    STATUS_CLI_TIMEOUT_SECS,
};

pub(crate) const MAX_RULES_PER_SERVICE: usize = 32;
const MAX_PATH_LEN: usize = 256;
const ADMIN_SERVICES_URL: &str = "https://console.tailscale.com/admin/services";
const ADMIN_SERVICE_BASE_URL: &str = "https://console.tailscale.com/admin/services/";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RuleProtocol {
    Https,
    Tcp,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub(crate) struct ServiceRuleInput {
    pub protocol: RuleProtocol,
    pub port: u16,
    #[serde(default)]
    pub path: Option<String>,
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct PutServiceRequest {
    rules: Vec<ServiceRuleInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HttpsBackend {
    Proxy(String),
    FilePath(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NormalizedRule {
    pub protocol: RuleProtocol,
    pub port: u16,
    /// Present for `Https` rules (default `"/"`), `None` for `Tcp`.
    pub path: Option<String>,
    /// Canonical target string shown in API/UI:
    /// - HTTPS proxy: `http://...`, `https://...`, `https+insecure://...`, `unix:/...`
    /// - HTTPS local file/dir: `file:///...`
    /// - TCP forward: `<host>:<port>`, `[<ipv6>]:<port>`, `unix:/...`
    pub target: String,
    https_backend: Option<HttpsBackend>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedServiceConfig {
    pub rules: Vec<NormalizedRule>,
    pub configured_ports: Vec<u16>,
    pub editable: bool,
    pub unsupported_reasons: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct CapServiceInfo {
    vips: Vec<String>,
    ports: Vec<String>,
    has_service_def: bool,
}

/// Validate a service short name or `svc:<name>` identifier and return
/// `(short_name, "svc:<short_name>")`.
pub(crate) fn parse_service_name(raw: &str) -> Result<(String, String), String> {
    if raw.is_empty() || raw != raw.trim() {
        return Err("service name must not be empty or contain surrounding spaces".into());
    }
    let short = raw.strip_prefix("svc:").unwrap_or(raw);
    if short.is_empty() || short.len() > 63 {
        return Err("service name must be 1–63 characters".into());
    }
    let bytes = short.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return Err(
            "service name must start and end with a lowercase ASCII letter or digit".into(),
        );
    }
    if !bytes.iter().all(|&b| is_alnum(b) || b == b'-') {
        return Err(
            "service name may contain only lowercase ASCII letters, digits and hyphens".into(),
        );
    }
    Ok((short.to_string(), format!("svc:{short}")))
}

fn has_control_or_nul(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Parse `host` or `[ipv6]` and optional `:port`, returning `(canonical_host, port)`.
fn parse_authority(authority: &str, require_port: bool) -> Result<(String, Option<u16>), String> {
    if authority.is_empty()
        || has_control_or_nul(authority)
        || authority.chars().any(char::is_whitespace)
        || authority.contains('@')
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err("invalid backend host or port".into());
    }

    let (host_part, port_str) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((addr_str, after)) = rest.split_once(']') else {
            return Err("unclosed IPv6 bracket in backend target".into());
        };
        let ip: Ipv6Addr = addr_str
            .parse()
            .map_err(|_| "invalid IPv6 address in backend target".to_string())?;
        let port = if after.is_empty() {
            None
        } else if let Some(p) = after.strip_prefix(':') {
            Some(p)
        } else {
            return Err("invalid port syntax after IPv6 address".into());
        };
        (format!("[{ip}]"), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return Err("wrap IPv6 addresses in brackets, e.g. [::1]:8080".into());
        }
        (h.to_ascii_lowercase(), Some(p))
    } else {
        (authority.to_ascii_lowercase(), None)
    };

    if !host_part.starts_with('[') {
        if let Ok(v4) = host_part.parse::<Ipv4Addr>() {
            let _ = v4;
        } else if !is_valid_hostname(&host_part) {
            return Err(format!("invalid backend host '{host_part}'"));
        }
    }

    let port = match port_str {
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("backend port must be a number between 1 and 65535".into());
            }
            let num: u16 = p
                .parse()
                .map_err(|_| "backend port must be between 1 and 65535".to_string())?;
            if num == 0 {
                return Err("backend port must be between 1 and 65535".into());
            }
            Some(num)
        }
        None => None,
    };

    if require_port && port.is_none() {
        return Err("TCP backend target must include a port (e.g. 192.168.0.10:22)".into());
    }
    Ok((host_part, port))
}

fn normalize_unix_target(raw: &str) -> Result<String, String> {
    let rest = raw
        .strip_prefix("unix://")
        .or_else(|| raw.strip_prefix("unix:"))
        .ok_or_else(|| "invalid unix socket target".to_string())?;
    if !rest.starts_with('/')
        || rest.len() < 2
        || has_control_or_nul(rest)
        || rest.chars().any(char::is_whitespace)
    {
        return Err("unix socket target must be an absolute path (e.g. unix:/tmp/app.sock)".into());
    }
    Ok(format!("unix:{rest}"))
}

fn normalize_https_path(raw: Option<&str>, is_file: bool) -> Result<(String, String), String> {
    let text = raw.map(str::trim).unwrap_or("");
    let path = if text.is_empty() { "/" } else { text };
    if !path.starts_with('/') {
        return Err("HTTPS URL path must start with '/'".into());
    }
    if path.len() > MAX_PATH_LEN {
        return Err(format!("HTTPS URL path must be at most {MAX_PATH_LEN} characters"));
    }
    if has_control_or_nul(path)
        || path.chars().any(char::is_whitespace)
        || path.contains('?')
        || path.contains('#')
        || path.contains("//")
    {
        return Err(
            "HTTPS URL path must not contain spaces, query strings, fragments or '//'".into(),
        );
    }
    let normalized = if path == "/" {
        "/".to_string()
    } else if is_file {
        path.to_string()
    } else {
        path.trim_end_matches('/').to_string()
    };
    let dedup_key = if normalized == "/" {
        "/".to_string()
    } else {
        normalized.trim_end_matches('/').to_string()
    };
    Ok((normalized, dedup_key))
}

fn validate_https_target(raw: &str) -> Result<(String, HttpsBackend), String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("backend target must not be empty".into());
    }
    if has_control_or_nul(t) {
        return Err("backend target must not contain control characters".into());
    }

    // Local file / directory serving (`file:///path` or `/path`).
    if let Some(fs_path) = t.strip_prefix("file://").or_else(|| {
        if t.starts_with('/') {
            Some(t)
        } else {
            None
        }
    }) {
        if !fs_path.starts_with('/') || fs_path.is_empty() {
            return Err("file target must use an absolute path (e.g. file:///data/share)".into());
        }
        return Ok((
            format!("file://{fs_path}"),
            HttpsBackend::FilePath(fs_path.to_string()),
        ));
    }

    // Unix domain socket (`unix:/path` or `unix:///path`).
    if t.len() >= 5 && t[..5].eq_ignore_ascii_case("unix:") {
        let canonical = normalize_unix_target(&format!("unix:{}", &t[5..]))?;
        return Ok((canonical.clone(), HttpsBackend::Proxy(canonical)));
    }

    let (scheme, rest) = if let Some((s, r)) = t.split_once("://") {
        let lower = s.to_ascii_lowercase();
        match lower.as_str() {
            "http" | "https" | "https+insecure" => (lower, r),
            _ => {
                return Err(format!(
                    "unsupported HTTPS backend scheme '{s}://' (use http://, https://, https+insecure://, unix:, or file://)"
                ))
            }
        }
    } else {
        return Err(
            "HTTPS backend target must start with http://, https://, https+insecure://, unix:, or file://"
                .into(),
        );
    };

    if rest.chars().any(char::is_whitespace) || rest.contains('?') || rest.contains('#') {
        return Err(
            "HTTPS backend URL must not contain spaces, query strings or fragments".into(),
        );
    }
    let (authority, suffix_path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    let (host, port) = parse_authority(authority, false)?;
    let canonical = match port {
        Some(p) => format!("{scheme}://{host}:{p}{suffix_path}"),
        None => format!("{scheme}://{host}{suffix_path}"),
    };
    Ok((canonical.clone(), HttpsBackend::Proxy(canonical)))
}

fn validate_tcp_target(raw: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("TCP backend target must not be empty".into());
    }
    if has_control_or_nul(t) || t.chars().any(char::is_whitespace) {
        return Err("TCP backend target must not contain spaces or control characters".into());
    }
    if t.len() >= 5 && t[..5].eq_ignore_ascii_case("unix:") {
        return normalize_unix_target(&format!("unix:{}", &t[5..]));
    }
    if t.starts_with('/') || (t.len() >= 7 && t[..7].eq_ignore_ascii_case("file://")) {
        return Err("file:// targets are only supported for HTTPS rules, not raw TCP".into());
    }
    let authority = if let Some((scheme, rest)) = t.split_once("://") {
        if scheme.eq_ignore_ascii_case("tcp") {
            rest
        } else {
            return Err(format!(
                "TCP backend target does not accept '{scheme}://' (use host:port, tcp://host:port, or unix:/path)"
            ));
        }
    } else {
        t
    };
    let (host, port) = parse_authority(authority, true)?;
    Ok(format!("{host}:{}", port.unwrap()))
}

pub(crate) fn validate_and_normalize_rules(
    raw_rules: &[ServiceRuleInput],
) -> Result<Vec<NormalizedRule>, String> {
    if raw_rules.is_empty() {
        return Err("add at least one rule, or delete the service to clear it".into());
    }
    if raw_rules.len() > MAX_RULES_PER_SERVICE {
        return Err(format!(
            "a service may configure at most {MAX_RULES_PER_SERVICE} rules"
        ));
    }

    let mut port_protocols: BTreeMap<u16, RuleProtocol> = BTreeMap::new();
    let mut tcp_ports: BTreeSet<u16> = BTreeSet::new();
    let mut https_paths: BTreeSet<(u16, String)> = BTreeSet::new();
    let mut out = Vec::with_capacity(raw_rules.len());

    for rule in raw_rules {
        if rule.port == 0 {
            return Err("external port must be between 1 and 65535".into());
        }
        if let Some(&prev) = port_protocols.get(&rule.port) {
            if prev != rule.protocol {
                return Err(format!(
                    "port {} cannot be used by both HTTPS and TCP rules",
                    rule.port
                ));
            }
        } else {
            port_protocols.insert(rule.port, rule.protocol);
        }

        match rule.protocol {
            RuleProtocol::Https => {
                let (target, backend) = validate_https_target(&rule.target)?;
                let is_file = matches!(backend, HttpsBackend::FilePath(_));
                let (path, dedup_key) = normalize_https_path(rule.path.as_deref(), is_file)?;
                if !https_paths.insert((rule.port, dedup_key)) {
                    return Err(format!(
                        "duplicate HTTPS path '{path}' on port {}",
                        rule.port
                    ));
                }
                out.push(NormalizedRule {
                    protocol: RuleProtocol::Https,
                    port: rule.port,
                    path: Some(path),
                    target,
                    https_backend: Some(backend),
                });
            }
            RuleProtocol::Tcp => {
                if rule
                    .path
                    .as_deref()
                    .is_some_and(|p| !p.trim().is_empty())
                {
                    return Err("URL path prefix is only supported for HTTPS rules".into());
                }
                if !tcp_ports.insert(rule.port) {
                    return Err(format!("duplicate TCP rule on port {}", rule.port));
                }
                let target = validate_tcp_target(&rule.target)?;
                out.push(NormalizedRule {
                    protocol: RuleProtocol::Tcp,
                    port: rule.port,
                    path: None,
                    target,
                    https_backend: None,
                });
            }
        }
    }

    out.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(out)
}

/// Build the `ServeConfig.Services["svc:<name>"]` JSON object from validated rules.
pub(crate) fn build_service_config(
    short_name: &str,
    magic_dns_suffix: Option<&str>,
    rules: &[NormalizedRule],
) -> Result<Value, String> {
    let mut tcp = Map::new();
    let mut web: BTreeMap<String, Map<String, Value>> = BTreeMap::new();

    for rule in rules {
        match rule.protocol {
            RuleProtocol::Tcp => {
                tcp.insert(
                    rule.port.to_string(),
                    json!({"TCPForward": rule.target}),
                );
            }
            RuleProtocol::Https => {
                let suffix = magic_dns_suffix
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        "MagicDNS suffix is unavailable — enable MagicDNS in your tailnet to use HTTPS rules"
                            .to_string()
                    })?;
                tcp.insert(rule.port.to_string(), json!({"HTTPS": true}));
                let host_port = format!("{short_name}.{suffix}:{}", rule.port);
                let path = rule.path.clone().unwrap_or_else(|| "/".to_string());
                let handler = match rule.https_backend.as_ref() {
                    Some(HttpsBackend::FilePath(fs_path)) => json!({"Path": fs_path}),
                    Some(HttpsBackend::Proxy(proxy)) => json!({"Proxy": proxy}),
                    None => json!({"Proxy": rule.target}),
                };
                web.entry(host_port).or_default().insert(path, handler);
            }
        }
    }

    let mut obj = Map::new();
    if !tcp.is_empty() {
        obj.insert("TCP".into(), Value::Object(tcp));
    }
    if !web.is_empty() {
        let mut web_map = Map::new();
        for (host_port, handlers) in web {
            web_map.insert(host_port, json!({"Handlers": Value::Object(handlers)}));
        }
        obj.insert("Web".into(), Value::Object(web_map));
    }
    Ok(Value::Object(obj))
}

/// Atomically replace ONLY `Services[svc_key]` inside a full `ServeConfig`,
/// preserving all node-level fields (`TCP`, `Web`, `AllowFunnel`, `Foreground`,
/// etc.) and every other `svc:*` entry verbatim.
pub(crate) fn apply_service_update(
    raw_config: &Value,
    svc_key: &str,
    service_obj: Value,
) -> Result<Value, String> {
    let mut root = match raw_config {
        Value::Null => Map::new(),
        Value::Object(map) => map.clone(),
        _ => return Err("unexpected tailscale serve-config shape".into()),
    };
    let services = match root.get_mut("Services") {
        Some(Value::Object(map)) => map,
        Some(Value::Null) | None => {
            root.insert("Services".into(), Value::Object(Map::new()));
            root.get_mut("Services")
                .and_then(Value::as_object_mut)
                .unwrap()
        }
        Some(_) => return Err("unexpected Services field in tailscale serve-config".into()),
    };
    services.insert(svc_key.to_string(), service_obj);
    Ok(Value::Object(root))
}

/// Parse an existing `ServeConfig.Services["svc:<name>"]` entry into editable
/// rules plus any CLI-only advanced handlers that prevent safe form overwrites.
pub(crate) fn parse_service_config(
    svc_val: &Value,
    expected_fqdn: Option<&str>,
) -> ParsedServiceConfig {
    let mut rules = Vec::new();
    let mut configured_ports = BTreeSet::new();
    let mut reasons = Vec::new();
    let mut push_reason = |msg: String| {
        if !reasons.contains(&msg) {
            reasons.push(msg);
        }
    };

    let Some(obj) = svc_val.as_object() else {
        if !svc_val.is_null() {
            push_reason("unexpected service configuration structure".into());
        }
        return ParsedServiceConfig {
            rules,
            configured_ports: Vec::new(),
            editable: reasons.is_empty(),
            unsupported_reasons: reasons,
        };
    };

    for (key, val) in obj {
        match key.as_str() {
            "TCP" | "Web" => {}
            "Tun" => {
                if val.as_bool() == Some(true) {
                    push_reason(
                        "L3 TUN service mode (--tun) is configured via CLI and cannot be edited here"
                            .into(),
                    );
                }
            }
            other => {
                if !val.is_null()
                    && val.as_object().is_none_or(|m| !m.is_empty())
                    && val.as_array().is_none_or(|a| !a.is_empty())
                {
                    push_reason(format!("unsupported service option '{other}'"));
                }
            }
        }
    }

    let mut https_ports = BTreeSet::new();
    if let Some(tcp_val) = obj.get("TCP") {
        if let Some(tcp_map) = tcp_val.as_object() {
            for (port_str, handler_val) in tcp_map {
                let Some(port) = port_str.parse::<u16>().ok().filter(|&p| p > 0) else {
                    push_reason(format!("unrecognized TCP port '{port_str}'"));
                    continue;
                };
                configured_ports.insert(port);
                let Some(h) = handler_val.as_object() else {
                    push_reason(format!("unsupported TCP handler shape on port {port}"));
                    continue;
                };
                let mut is_https = false;
                let mut tcp_forward: Option<&str> = None;
                let mut port_unsupported = false;
                for (k, v) in h {
                    match k.as_str() {
                        "HTTPS" => {
                            if v.as_bool() == Some(true) {
                                is_https = true;
                            }
                        }
                        "HTTP" => {
                            if v.as_bool() == Some(true) {
                                port_unsupported = true;
                                push_reason(format!(
                                    "plaintext HTTP listener on port {port} is CLI-only"
                                ));
                            }
                        }
                        "TCPForward" => {
                            if let Some(s) = v.as_str().filter(|s| !s.is_empty()) {
                                tcp_forward = Some(s);
                            }
                        }
                        "TerminateTLS" => {
                            if v.as_str().is_some_and(|s| !s.is_empty()) {
                                port_unsupported = true;
                                push_reason(format!(
                                    "TLS-terminated TCP on port {port} is CLI-only"
                                ));
                            }
                        }
                        "ProxyProtocol" => {
                            if v.as_u64().is_some_and(|n| n > 0) {
                                port_unsupported = true;
                                push_reason(format!(
                                    "PROXY protocol on port {port} is CLI-only"
                                ));
                            }
                        }
                        other => {
                            if !v.is_null() && v.as_bool() != Some(false) {
                                port_unsupported = true;
                                push_reason(format!(
                                    "unsupported TCP option '{other}' on port {port}"
                                ));
                            }
                        }
                    }
                }
                if is_https && tcp_forward.is_some() {
                    port_unsupported = true;
                    push_reason(format!("mixed HTTPS and TCPForward on port {port}"));
                }
                if !port_unsupported {
                    if let Some(target_raw) = tcp_forward {
                        match validate_tcp_target(target_raw) {
                            Ok(target) => rules.push(NormalizedRule {
                                protocol: RuleProtocol::Tcp,
                                port,
                                path: None,
                                target,
                                https_backend: None,
                            }),
                            Err(_) => push_reason(format!(
                                "unrecognized TCP target '{target_raw}' on port {port}"
                            )),
                        }
                    } else if is_https {
                        https_ports.insert(port);
                    } else {
                        push_reason(format!("empty TCP handler on port {port}"));
                    }
                }
            }
        } else if !tcp_val.is_null() {
            push_reason("unexpected TCP map in service config".into());
        }
    }

    let mut web_ports_seen = BTreeSet::new();
    if let Some(web_val) = obj.get("Web") {
        if let Some(web_map) = web_val.as_object() {
            for (host_port, server_val) in web_map {
                let Some((host, port_str)) = host_port.rsplit_once(':') else {
                    push_reason(format!("unrecognized Web endpoint '{host_port}'"));
                    continue;
                };
                let Some(port) = port_str.parse::<u16>().ok().filter(|&p| p > 0) else {
                    push_reason(format!("unrecognized Web port in '{host_port}'"));
                    continue;
                };
                configured_ports.insert(port);
                if let Some(fqdn) = expected_fqdn {
                    if !host.eq_ignore_ascii_case(fqdn) {
                        push_reason(format!(
                            "custom Web hostname '{host}' on port {port} does not match '{fqdn}'"
                        ));
                    }
                }
                if !https_ports.contains(&port) {
                    push_reason(format!(
                        "Web handler on port {port} is not paired with an HTTPS TCP listener"
                    ));
                }
                let Some(server_obj) = server_val.as_object() else {
                    push_reason(format!("unsupported Web config shape on port {port}"));
                    continue;
                };
                for (k, v) in server_obj {
                    if k != "Handlers" && !v.is_null() {
                        push_reason(format!(
                            "unsupported Web option '{k}' on port {port}"
                        ));
                    }
                }
                let Some(handlers) = server_obj.get("Handlers").and_then(Value::as_object) else {
                    push_reason(format!("HTTPS port {port} has no Web handlers"));
                    continue;
                };
                if handlers.is_empty() {
                    push_reason(format!("HTTPS port {port} has no Web handlers"));
                    continue;
                }
                web_ports_seen.insert(port);
                for (mount_path, h_val) in handlers {
                    let Some(h_obj) = h_val.as_object() else {
                        push_reason(format!(
                            "unsupported handler shape on port {port} {mount_path}"
                        ));
                        continue;
                    };
                    let mut proxy: Option<&str> = None;
                    let mut file_path: Option<&str> = None;
                    let mut h_unsupported = false;
                    for (hk, hv) in h_obj {
                        match hk.as_str() {
                            "Proxy" => {
                                if let Some(s) = hv.as_str().filter(|s| !s.is_empty()) {
                                    proxy = Some(s);
                                }
                            }
                            "Path" => {
                                if let Some(s) = hv.as_str().filter(|s| !s.is_empty()) {
                                    file_path = Some(s);
                                }
                            }
                            "Text" => {
                                if hv.as_str().is_some_and(|s| !s.is_empty()) {
                                    h_unsupported = true;
                                    push_reason(format!(
                                        "plain text handler on port {port} {mount_path} is CLI-only"
                                    ));
                                }
                            }
                            "AcceptAppCaps" => {
                                if hv.as_array().is_some_and(|a| !a.is_empty()) {
                                    h_unsupported = true;
                                    push_reason(format!(
                                        "AcceptAppCaps on port {port} {mount_path} is CLI-only"
                                    ));
                                }
                            }
                            other => {
                                if !hv.is_null()
                                    && hv.as_str() != Some("")
                                    && hv.as_array().is_none_or(|a| !a.is_empty())
                                {
                                    h_unsupported = true;
                                    push_reason(format!(
                                        "unsupported handler field '{other}' on port {port} {mount_path}"
                                    ));
                                }
                            }
                        }
                    }
                    if h_unsupported {
                        continue;
                    }
                    match (proxy, file_path) {
                        (Some(p), None) => match validate_https_target(p) {
                            Ok((canonical, backend)) => {
                                let normalized_path =
                                    normalize_https_path(Some(mount_path), false)
                                        .map(|(np, _)| np)
                                        .unwrap_or_else(|_| mount_path.clone());
                                rules.push(NormalizedRule {
                                    protocol: RuleProtocol::Https,
                                    port,
                                    path: Some(normalized_path),
                                    target: canonical,
                                    https_backend: Some(backend),
                                });
                            }
                            Err(_) => push_reason(format!(
                                "unrecognized HTTPS proxy target '{p}' on port {port} {mount_path}"
                            )),
                        },
                        (None, Some(fp)) => match validate_https_target(fp) {
                            Ok((canonical, backend)) => {
                                let normalized_path =
                                    normalize_https_path(Some(mount_path), true)
                                        .map(|(np, _)| np)
                                        .unwrap_or_else(|_| mount_path.clone());
                                rules.push(NormalizedRule {
                                    protocol: RuleProtocol::Https,
                                    port,
                                    path: Some(normalized_path),
                                    target: canonical,
                                    https_backend: Some(backend),
                                });
                            }
                            Err(_) => push_reason(format!(
                                "unrecognized file path target '{fp}' on port {port} {mount_path}"
                            )),
                        },
                        _ => push_reason(format!(
                            "empty or ambiguous handler on port {port} {mount_path}"
                        )),
                    }
                }
            }
        } else if !web_val.is_null() {
            push_reason("unexpected Web map in service config".into());
        }
    }

    for port in &https_ports {
        if !web_ports_seen.contains(port) {
            push_reason(format!("HTTPS port {port} has no matching Web handlers"));
        }
    }

    rules.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.protocol.cmp(&b.protocol))
            .then_with(|| a.path.cmp(&b.path))
    });

    ParsedServiceConfig {
        rules,
        configured_ports: configured_ports.into_iter().collect(),
        editable: reasons.is_empty(),
        unsupported_reasons: reasons,
    }
}

fn magic_dns_suffix_from_status(status: &Status) -> Option<String> {
    let clean = |raw: &str| {
        let s = raw.trim().trim_end_matches('.');
        (!s.is_empty()).then(|| s.to_string())
    };
    if let Some(s) = status.magic_dns_suffix.as_deref().and_then(clean) {
        return Some(s);
    }
    if let Some(s) = status
        .current_tailnet
        .as_ref()
        .and_then(|ct| ct.magic_dns_suffix.as_deref())
        .and_then(clean)
    {
        return Some(s);
    }
    let dns = status
        .self_status
        .as_ref()
        .and_then(|s| s.dns_name.as_deref())
        .and_then(clean)?;
    let (_, rest) = dns.split_once('.')?;
    clean(rest)
}

fn parse_cap_services(cap_map: &BTreeMap<String, Value>) -> BTreeMap<String, CapServiceInfo> {
    let mut map: BTreeMap<String, CapServiceInfo> = BTreeMap::new();
    let push_unique = |vec: &mut Vec<String>, item: String| {
        if !item.is_empty() && !vec.contains(&item) {
            vec.push(item);
        }
    };

    if let Some(entries) = cap_map.get("service-host").and_then(Value::as_array) {
        for entry in entries {
            let Some(obj) = entry.as_object() else {
                continue;
            };
            for (svc_raw, addrs_val) in obj {
                let Ok((short, _)) = parse_service_name(svc_raw) else {
                    continue;
                };
                let info = map.entry(short).or_default();
                if let Some(addrs) = addrs_val.as_array() {
                    for addr in addrs.iter().filter_map(Value::as_str) {
                        push_unique(&mut info.vips, addr.trim().to_string());
                    }
                }
            }
        }
    }

    for (key, val) in cap_map {
        let Some(short_from_key) = key.strip_prefix("services/") else {
            continue;
        };
        let Some(entries) = val.as_array() else {
            continue;
        };
        for entry in entries {
            let Some(obj) = entry.as_object() else {
                continue;
            };
            let raw_name = obj
                .get("Name")
                .and_then(Value::as_str)
                .unwrap_or(short_from_key);
            let Ok((short, _)) = parse_service_name(raw_name) else {
                continue;
            };
            let info = map.entry(short).or_default();
            info.has_service_def = true;
            if let Some(addrs) = obj.get("Addrs").and_then(Value::as_array) {
                for addr in addrs.iter().filter_map(Value::as_str) {
                    push_unique(&mut info.vips, addr.trim().to_string());
                }
            }
            if let Some(ports) = obj.get("Ports").and_then(Value::as_array) {
                for p in ports.iter().filter_map(Value::as_str) {
                    push_unique(&mut info.ports, p.trim().to_string());
                }
            }
        }
    }
    map
}

/// Check whether `port` is allowed by Tailscale's `CapMap["services/<name>"][*].Ports`
/// entries (e.g. `"tcp:443"`, `"tcp:8000-8010"`, `"tcp:*"`, `"*"`).
pub(crate) fn port_allowed_by_tailnet(port: u16, tailnet_ports: &[String]) -> bool {
    for raw in tailnet_ports {
        let spec = raw.trim().to_ascii_lowercase();
        if spec == "*" || spec == "tcp:*" || spec == "tcp:all" {
            return true;
        }
        let range = if let Some(rest) = spec.strip_prefix("tcp:") {
            rest
        } else if !spec.contains(':') {
            spec.as_str()
        } else {
            continue;
        };
        if let Some((start_s, end_s)) = range.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_s.parse::<u16>(), end_s.parse::<u16>()) {
                if start <= end && (start..=end).contains(&port) {
                    return true;
                }
            }
        } else if let Ok(exact) = range.parse::<u16>() {
            if exact == port {
                return true;
            }
        }
    }
    false
}

fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let net: Ipv4Net = "100.64.0.0/10".parse().unwrap();
    net.contains(&ip)
}

fn is_tailscale_ula(ip: Ipv6Addr) -> bool {
    let net: Ipv6Net = "fd7a:115c:a1e0::/48".parse().unwrap();
    net.contains(&ip)
}

fn is_ula(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Classify a validated target for UI hints (non-blocking).
pub(crate) fn classify_target(target: &str, router_ips: &[IpAddr]) -> (Option<IpAddr>, &'static str) {
    if target.starts_with("unix:") {
        return (None, "unix");
    }
    if target.starts_with("file://") {
        return (None, "file");
    }
    let rest = target
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(target);
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = if let Some(r) = authority.strip_prefix('[') {
        r.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map(|(h, _)| h).unwrap_or(authority)
    };
    if host.eq_ignore_ascii_case("localhost") {
        return (None, "loopback");
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        return (None, "hostname");
    };
    if ip.is_loopback() {
        return (Some(ip), "loopback");
    }
    if router_ips.contains(&ip) {
        return (Some(ip), "router_self");
    }
    let kind = match ip {
        IpAddr::V4(v4) => {
            if is_cgnat(v4) {
                "tailnet"
            } else if is_rfc1918(v4) {
                "lan_private"
            } else if v4.is_link_local() {
                "link_local"
            } else if v4.is_multicast() || v4.is_unspecified() {
                "special"
            } else {
                "public"
            }
        }
        IpAddr::V6(v6) => {
            if is_tailscale_ula(v6) {
                "tailnet"
            } else if is_ula(v6) {
                "lan_private"
            } else if v6.is_unicast_link_local() {
                "link_local"
            } else if v6.is_multicast() || v6.is_unspecified() {
                "special"
            } else {
                "public"
            }
        }
    };
    (Some(ip), kind)
}

fn subnet_route_state(
    target_ip: Option<IpAddr>,
    target_kind: &str,
    advertised_routes: &[IpNet],
    approved_routes: &[IpNet],
) -> &'static str {
    if target_kind != "lan_private" {
        return "not_applicable";
    }
    let Some(ip) = target_ip else {
        return "not_applicable";
    };
    if approved_routes.iter().any(|net| net.contains(&ip)) {
        "approved"
    } else if advertised_routes.iter().any(|net| net.contains(&ip)) {
        "pending"
    } else {
        "not_advertised"
    }
}

fn format_rule_access_url(rule: &NormalizedRule, fqdn: Option<&str>) -> Option<String> {
    let host = fqdn?;
    match rule.protocol {
        RuleProtocol::Https => {
            let path = rule.path.as_deref().unwrap_or("/");
            let port_part = if rule.port == 443 {
                String::new()
            } else {
                format!(":{}", rule.port)
            };
            let path_part = if path == "/" { "" } else { path };
            Some(format!("https://{host}{port_part}{path_part}"))
        }
        RuleProtocol::Tcp => Some(format!("tcp://{host}:{}", rule.port)),
    }
}

fn parse_host_route_ips(routes: &[String]) -> BTreeSet<IpAddr> {
    let mut ips = BTreeSet::new();
    for raw in routes {
        if let Ok(ip) = raw.trim().parse::<IpAddr>() {
            ips.insert(ip);
        } else if let Ok(net) = raw.trim().parse::<IpNet>() {
            let is_host = match net {
                IpNet::V4(v4) => v4.prefix_len() == 32,
                IpNet::V6(v6) => v6.prefix_len() == 128,
            };
            if is_host {
                ips.insert(net.addr());
            }
        }
    }
    ips
}

fn extract_router_ips(addrs: &[IfAddr]) -> Vec<IpAddr> {
    let mut ips = BTreeSet::new();
    for entry in addrs {
        if !entry.addr.is_loopback()
            && !matches!(entry.addr, IpAddr::V6(v6) if v6.is_unicast_link_local())
        {
            ips.insert(entry.addr);
        }
    }
    ips.into_iter().collect()
}

fn parse_non_default_routes(routes: &[String]) -> Vec<IpNet> {
    let mut nets = BTreeSet::new();
    for raw in routes {
        if let Ok(net) = raw.trim().parse::<IpNet>() {
            if net.prefix_len() > 0 {
                nets.insert(net.trunc());
            }
        }
    }
    nets.into_iter().collect()
}

pub(crate) fn aggregate_services(
    status: &Status,
    prefs: Option<&Prefs>,
    serve_config: &Value,
    cfg: &config::TsConfig,
    if_addrs: &[IfAddr],
) -> Value {
    let suffix = magic_dns_suffix_from_status(status);
    let self_st = status.self_status.as_ref();
    let https_enabled = self_st.is_some_and(|s| s.cap_map.contains_key("https"));
    let tags = self_st.map(|s| s.tags.clone()).unwrap_or_default();
    let primary_host_ips = self_st
        .map(|s| parse_host_route_ips(&s.primary_routes))
        .unwrap_or_default();
    let allowed_host_ips = self_st
        .map(|s| parse_host_route_ips(&s.allowed_ips))
        .unwrap_or_default();
    let cap_services = self_st
        .map(|s| parse_cap_services(&s.cap_map))
        .unwrap_or_default();

    let advertised_set: Option<BTreeSet<String>> = prefs.map(|p| {
        p.advertise_services
            .iter()
            .filter_map(|s| parse_service_name(s).ok().map(|(short, _)| short))
            .collect()
    });

    let router_ips = extract_router_ips(if_addrs);
    let local_lan_subnets = lan_subnets(if_addrs);

    let advertised_routes = parse_non_default_routes(
        prefs
            .map(|p| p.advertise_routes.as_slice())
            .filter(|r| !r.is_empty())
            .unwrap_or(&cfg.advertise_routes),
    );
    let approved_struct = super::netplane::approved_routes(cfg, Some(status));
    let mut approved_routes: Vec<IpNet> = approved_struct
        .subnets_v4
        .into_iter()
        .map(IpNet::V4)
        .chain(approved_struct.subnets_v6.into_iter().map(IpNet::V6))
        .collect();
    approved_routes.sort();

    let config_services = serve_config
        .get("Services")
        .and_then(Value::as_object);

    let mut all_names: BTreeSet<String> = cap_services.keys().cloned().collect();
    let mut raw_service_map: BTreeMap<String, &Value> = BTreeMap::new();
    if let Some(svcs) = config_services {
        for (raw_key, val) in svcs {
            if let Ok((short, _)) = parse_service_name(raw_key) {
                all_names.insert(short.clone());
                raw_service_map.insert(short, val);
            }
        }
    }

    let mut service_views = Vec::with_capacity(all_names.len());
    for short in all_names {
        let svc_key = format!("svc:{short}");
        let fqdn = suffix.as_ref().map(|s| format!("{short}.{s}"));
        let cap = cap_services.get(&short);
        let vips = cap.map(|c| c.vips.clone()).unwrap_or_default();
        let tailnet_ports = cap.map(|c| c.ports.clone()).unwrap_or_default();
        let has_service_def = cap.is_some_and(|c| c.has_service_def);
        let defined_in_tailnet = has_service_def || !vips.is_empty();
        let admin_url = if defined_in_tailnet {
            format!("{ADMIN_SERVICE_BASE_URL}{svc_key}")
        } else {
            ADMIN_SERVICES_URL.to_string()
        };

        let primary_vips: Vec<String> = vips
            .iter()
            .filter(|v| v.parse::<IpAddr>().is_ok_and(|ip| primary_host_ips.contains(&ip)))
            .cloned()
            .collect();
        let allowed_vips: Vec<String> = vips
            .iter()
            .filter(|v| v.parse::<IpAddr>().is_ok_and(|ip| allowed_host_ips.contains(&ip)))
            .cloned()
            .collect();
        let approved = !primary_vips.is_empty();

        let raw_val = raw_service_map.get(&short).copied();
        let parsed = raw_val.map(|v| parse_service_config(v, fqdn.as_deref()));
        let configured = parsed.as_ref().is_some_and(|p| {
            !p.rules.is_empty()
                || !p.configured_ports.is_empty()
                || !p.unsupported_reasons.is_empty()
        });
        let advertised = advertised_set
            .as_ref()
            .is_none_or(|set| set.contains(&short));
        let drained = configured && !advertised;

        let configured_ports = parsed
            .as_ref()
            .map(|p| p.configured_ports.clone())
            .unwrap_or_default();
        let unallowed_ports: Vec<u16> = if has_service_def {
            configured_ports
                .iter()
                .copied()
                .filter(|&port| !port_allowed_by_tailnet(port, &tailnet_ports))
                .collect()
        } else {
            Vec::new()
        };

        let state = if !configured {
            "unconfigured"
        } else if drained {
            "drained"
        } else if !approved {
            "pending"
        } else if !unallowed_ports.is_empty() {
            "port_mismatch"
        } else {
            "active"
        };

        let editable = parsed.as_ref().is_none_or(|p| p.editable);
        let unsupported_reasons = parsed
            .as_ref()
            .map(|p| p.unsupported_reasons.clone())
            .unwrap_or_default();

        let mut access_urls = Vec::new();
        let rules_json: Vec<Value> = parsed
            .as_ref()
            .map(|p| {
                p.rules
                    .iter()
                    .map(|r| {
                        let url = format_rule_access_url(r, fqdn.as_deref());
                        if let Some(u) = &url {
                            if !access_urls.contains(u) {
                                access_urls.push(u.clone());
                            }
                        }
                        let port_allowed = has_service_def
                            .then(|| port_allowed_by_tailnet(r.port, &tailnet_ports));
                        let (target_ip, target_kind) = classify_target(&r.target, &router_ips);
                        let route_state = subnet_route_state(
                            target_ip,
                            target_kind,
                            &advertised_routes,
                            &approved_routes,
                        );
                        let mut item = json!({
                            "protocol": r.protocol,
                            "port": r.port,
                            "target": r.target,
                            "access_url": url,
                            "port_allowed": port_allowed,
                            "target_ip": target_ip.map(|ip| ip.to_string()),
                            "target_kind": target_kind,
                            "subnet_route_state": route_state,
                        });
                        if let Some(path) = &r.path {
                            item["path"] = json!(path);
                        }
                        item
                    })
                    .collect()
            })
            .unwrap_or_default();

        service_views.push(json!({
            "name": short,
            "service": svc_key,
            "fqdn": fqdn,
            "admin_url": admin_url,
            "state": state,
            "configured": configured,
            "advertised": advertised,
            "drained": drained,
            "defined_in_tailnet": defined_in_tailnet,
            "approved": approved,
            "editable": editable,
            "unsupported_reasons": unsupported_reasons,
            "vips": vips,
            "primary_vips": primary_vips,
            "allowed_vips": allowed_vips,
            "tailnet_ports": tailnet_ports,
            "configured_ports": configured_ports,
            "unallowed_ports": unallowed_ports,
            "access_urls": access_urls,
            "rules": rules_json,
        }));
    }

    json!({
        "available": true,
        "reason": Value::Null,
        "backend_state": status.backend_state,
        "magic_dns_suffix": suffix,
        "https_enabled": https_enabled,
        "tags": tags,
        "advertised_routes": advertised_routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "approved_routes": approved_routes.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "lan_subnets": local_lan_subnets.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "router_ips": router_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "services": service_views,
    })
}

fn unavailable_payload(reason: &str, backend_state: Option<&str>) -> Value {
    json!({
        "available": false,
        "reason": reason,
        "backend_state": backend_state,
        "magic_dns_suffix": Value::Null,
        "https_enabled": false,
        "tags": [],
        "advertised_routes": [],
        "approved_routes": [],
        "lan_subnets": [],
        "router_ips": [],
        "services": [],
    })
}

fn read_services_snapshot(state: &AppState) -> Result<Value, (u16, Value)> {
    let mgr = &state.tailscale;
    let cfg = mgr.config.lock().unwrap().clone();
    if !mgr.is_installed() {
        return Ok(unavailable_payload("Tailscale is not installed.", None));
    }
    if mgr.updating.load(Ordering::Acquire) {
        return Ok(unavailable_payload("Tailscale update is in progress.", None));
    }
    let daemon_up = mgr.active_child.lock().unwrap().is_some();
    if !daemon_up {
        let reason = if cfg.enabled {
            "Tailscale daemon is starting."
        } else {
            "Tailscale is disabled. Enable and sign in to manage Services."
        };
        return Ok(unavailable_payload(reason, None));
    }

    let deadline = Instant::now() + Duration::from_secs(STATUS_CLI_TIMEOUT_SECS);
    let status: Status = match mgr.probe_status(deadline) {
        Ok(s) => s,
        Err(e) => {
            return Ok(unavailable_payload(
                &format!("Tailscale daemon is not ready ({e})."),
                None,
            ));
        }
    };
    if status.backend_state != "Running" {
        return Ok(unavailable_payload(
            "Sign in and connect Tailscale before managing Services.",
            Some(status.backend_state.as_str()),
        ));
    }

    let sock = mgr.device_path(SOCK);
    let serve = daemon_serve_config_at_until(&sock, deadline).map_err(|e| {
        (
            502,
            json!({"ok": false, "error": format!("read tailscale serve config: {e}")}),
        )
    })?;
    let prefs = daemon_prefs_at_until(&sock, deadline);
    let addrs = interfaces().unwrap_or_default();
    Ok(aggregate_services(
        &status,
        prefs.as_ref(),
        &serve.body,
        &cfg,
        &addrs,
    ))
}

fn ensure_running_for_mutation(state: &AppState) -> Result<Status, (u16, Value)> {
    let mgr = &state.tailscale;
    if !mgr.is_installed() {
        return Err((409, json!({"ok": false, "error": "Tailscale is not installed"})));
    }
    if mgr.active_child.lock().unwrap().is_none() {
        return Err((
            409,
            json!({"ok": false, "error": "Tailscale daemon is not running"}),
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(STATUS_CLI_TIMEOUT_SECS);
    let status: Status = mgr.probe_status(deadline).map_err(|e| {
        (
            502,
            json!({"ok": false, "error": format!("tailscale status: {e}")}),
        )
    })?;
    if status.backend_state != "Running" {
        return Err((
            409,
            json!({"ok": false, "error": format!("Tailscale is not connected ({})", status.backend_state)}),
        ));
    }
    Ok(status)
}

/// GET /api/tailscale/services
pub fn services_list(state: &AppState) -> (u16, Value) {
    match read_services_snapshot(state) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(resp) => resp,
    }
}

/// PUT /api/tailscale/services/:name
pub fn service_put(state: &AppState, raw_name: &str, body: &[u8]) -> (u16, Value) {
    if let Some(resp) = require_password(state) {
        return resp;
    }
    let (short_name, svc_key) = match parse_service_name(raw_name) {
        Ok(pair) => pair,
        Err(e) => return (400, json!({"ok": false, "error": e})),
    };
    let req: PutServiceRequest = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => {
            return (
                400,
                json!({"ok": false, "error": format!("invalid service JSON: {e}")}),
            )
        }
    };
    let rules = match validate_and_normalize_rules(&req.rules) {
        Ok(r) => r,
        Err(e) => return (400, json!({"ok": false, "error": e})),
    };

    let mgr = &state.tailscale;
    let Ok(_prefs_guard) = mgr.prefs_lock.try_lock() else {
        return handler_error((409, "tailscale configuration is busy".into()));
    };
    if mgr.updating.load(Ordering::Acquire) {
        return handler_error((409, "update in progress".into()));
    }
    if mgr.slot_change_blocked() {
        return handler_error((409, "OTA slot change or health trial in progress".into()));
    }

    let status = match ensure_running_for_mutation(state) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let suffix = magic_dns_suffix_from_status(&status);
    let expected_fqdn = suffix.as_ref().map(|s| format!("{short_name}.{s}"));

    let sock = mgr.device_path(SOCK);
    let deadline = Instant::now() + Duration::from_secs(CLI_TIMEOUT_SECS);
    let current = match daemon_serve_config_at_until(&sock, deadline) {
        Ok(c) => c,
        Err(e) => {
            return (
                502,
                json!({"ok": false, "error": format!("read tailscale serve config: {e}")}),
            )
        }
    };
    let prefs = daemon_prefs_at_until(&sock, deadline);

    let existing_val = current
        .body
        .get("Services")
        .and_then(Value::as_object)
        .and_then(|svcs| svcs.get(&svc_key));
    let mut was_configured = false;
    if let Some(existing) = existing_val {
        let parsed = parse_service_config(existing, expected_fqdn.as_deref());
        was_configured = !parsed.rules.is_empty()
            || !parsed.configured_ports.is_empty()
            || !parsed.unsupported_reasons.is_empty();
        if !parsed.editable {
            return (
                409,
                json!({
                    "ok": false,
                    "error": format!(
                        "{svc_key} contains CLI-only handlers ({}) and cannot be overwritten from this form — clear it first or edit via CLI",
                        parsed.unsupported_reasons.join("; ")
                    )
                }),
            );
        }
    }

    let service_obj = match build_service_config(&short_name, suffix.as_deref(), &rules) {
        Ok(v) => v,
        Err(e) => return (400, json!({"ok": false, "error": e})),
    };
    let updated_config = match apply_service_update(&current.body, &svc_key, service_obj) {
        Ok(v) => v,
        Err(e) => return (502, json!({"ok": false, "error": e})),
    };

    if let Err(err) = daemon_set_serve_config_at_until(
        &sock,
        &updated_config,
        current.etag.as_deref(),
        Instant::now() + Duration::from_secs(CLI_TIMEOUT_SECS),
    ) {
        return match err {
            LocalApiWriteError::PreconditionFailed => (
                409,
                json!({"ok": false, "error": "Tailscale serve config changed concurrently — reload and retry"}),
            ),
            LocalApiWriteError::Timeout => (
                504,
                json!({"ok": false, "error": "tailscale serve-config update timed out"}),
            ),
            LocalApiWriteError::HttpStatus(code, msg) => (
                if (400..500).contains(&code) { 400 } else { 502 },
                json!({"ok": false, "error": if msg.is_empty() { format!("tailscaled rejected serve config (HTTP {code})") } else { msg }}),
            ),
            LocalApiWriteError::Other(e) => (
                502,
                json!({"ok": false, "error": format!("write tailscale serve config: {e}")}),
            ),
        };
    }

    // Newly configured services are not automatically added to
    // Prefs.AdvertiseServices by POST /localapi/v0/serve-config. Advertise new
    // services immediately while preserving intentional drain state on edits.
    let already_advertised = prefs.as_ref().is_some_and(|p| {
        p.advertise_services
            .iter()
            .any(|s| parse_service_name(s).ok().is_some_and(|(n, _)| n == short_name))
    });
    if !was_configured && !already_advertised {
        if let Err(e) = mgr.run_cli(&["serve", "advertise", &svc_key], CLI_TIMEOUT_SECS) {
            return (
                502,
                json!({"ok": false, "error": format!("service saved, but failed to advertise {svc_key}: {e}")}),
            );
        }
    }

    match read_services_snapshot(state) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(resp) => resp,
    }
}

/// POST /api/tailscale/services/:name/drain
pub fn service_drain(state: &AppState, raw_name: &str) -> (u16, Value) {
    service_cli_action(state, raw_name, "drain", true)
}

/// POST /api/tailscale/services/:name/advertise
pub fn service_advertise(state: &AppState, raw_name: &str) -> (u16, Value) {
    service_cli_action(state, raw_name, "advertise", true)
}

/// DELETE /api/tailscale/services/:name
pub fn service_delete(state: &AppState, raw_name: &str) -> (u16, Value) {
    service_cli_action(state, raw_name, "clear", false)
}

fn service_cli_action(
    state: &AppState,
    raw_name: &str,
    subcmd: &str,
    require_configured: bool,
) -> (u16, Value) {
    if let Some(resp) = require_password(state) {
        return resp;
    }
    let (_, svc_key) = match parse_service_name(raw_name) {
        Ok(pair) => pair,
        Err(e) => return (400, json!({"ok": false, "error": e})),
    };

    let mgr = &state.tailscale;
    let Ok(_prefs_guard) = mgr.prefs_lock.try_lock() else {
        return handler_error((409, "tailscale configuration is busy".into()));
    };
    if mgr.updating.load(Ordering::Acquire) {
        return handler_error((409, "update in progress".into()));
    }
    if mgr.slot_change_blocked() {
        return handler_error((409, "OTA slot change or health trial in progress".into()));
    }
    if let Err(resp) = ensure_running_for_mutation(state) {
        return resp;
    }

    if require_configured {
        let sock = mgr.device_path(SOCK);
        let deadline = Instant::now() + Duration::from_secs(STATUS_CLI_TIMEOUT_SECS);
        let current = match daemon_serve_config_at_until(&sock, deadline) {
            Ok(c) => c,
            Err(e) => {
                return (
                    502,
                    json!({"ok": false, "error": format!("read tailscale serve config: {e}")}),
                )
            }
        };
        let exists = current
            .body
            .get("Services")
            .and_then(Value::as_object)
            .and_then(|svcs| svcs.get(&svc_key))
            .is_some_and(|v| !v.is_null() && v.as_object().is_none_or(|m| !m.is_empty()));
        if !exists {
            return (
                404,
                json!({"ok": false, "error": format!("{svc_key} is not configured on this router")}),
            );
        }
    }

    if let Err(e) = mgr.run_cli(&["serve", subcmd, &svc_key], CLI_TIMEOUT_SECS) {
        return (
            502,
            json!({"ok": false, "error": format!("tailscale serve {subcmd} {svc_key}: {e}")}),
        );
    }

    match read_services_snapshot(state) {
        Ok(data) => (200, json!({"ok": true, "data": data})),
        Err(resp) => resp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale::{ChildIdentity, TailscaleManager, TestIo};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn sample_status(cap_map: Value, primary: &[&str], allowed: &[&str]) -> Status {
        serde_json::from_value(json!({
            "BackendState": "Running",
            "TUN": true,
            "MagicDNSSuffix": "tail.ts.net",
            "Self": {
                "Online": true,
                "DNSName": "u60-pro.tail.ts.net.",
                "TailscaleIPs": ["100.122.45.40", "fd7a:115c:a1e0::1"],
                "PrimaryRoutes": primary,
                "AllowedIPs": allowed,
                "Tags": ["tag:router"],
                "CapMap": cap_map,
            }
        }))
        .unwrap()
    }

    fn ifa(name: &str, ip: &str, prefix: u8) -> IfAddr {
        IfAddr {
            name: name.into(),
            addr: ip.parse().unwrap(),
            prefix,
            scope: 0,
        }
    }

    #[test]
    fn service_name_validation_accepts_and_rejects_strictly() {
        assert_eq!(parse_service_name("t3code").unwrap(), ("t3code".into(), "svc:t3code".into()));
        assert_eq!(parse_service_name("svc:my-app-1").unwrap(), ("my-app-1".into(), "svc:my-app-1".into()));
        assert_eq!(parse_service_name("a").unwrap(), ("a".into(), "svc:a".into()));
        assert_eq!(parse_service_name(&"a".repeat(63)).unwrap().0.len(), 63);

        for bad in [
            "",
            "svc:",
            " t3code",
            "t3code ",
            "MyApp",
            "-lead",
            "trail-",
            "a_b",
            "a.b",
            "a/b",
            "../etc",
            "a%2fb",
            "svc:svc:dup",
            &"a".repeat(64),
        ] {
            assert!(parse_service_name(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rules_allow_all_target_classes_including_loopback_router_tailnet_public_file_and_unix() {
        let input = vec![
            ServiceRuleInput {
                protocol: RuleProtocol::Https,
                port: 443,
                path: None,
                target: "http://192.168.0.124:3773".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Https,
                port: 443,
                path: Some("/self/".into()),
                target: "http://127.0.0.1:9090".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Https,
                port: 443,
                path: Some("/router".into()),
                target: "https+insecure://192.168.0.1:9443".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Https,
                port: 443,
                path: Some("/v6".into()),
                target: "https://[::1]:8443".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Https,
                port: 443,
                path: Some("/ts".into()),
                target: "http://100.64.0.10:8080".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Https,
                port: 443,
                path: Some("/pub".into()),
                target: "https://1.1.1.1:443".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Https,
                port: 443,
                path: Some("/sock".into()),
                target: "unix:/tmp/demo.sock".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Https,
                port: 443,
                path: Some("/files/".into()),
                target: "file:///data/share".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Tcp,
                port: 2222,
                path: None,
                target: "tcp://127.0.0.1:2222".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Tcp,
                port: 3306,
                path: None,
                target: "[fd7a:115c:a1e0::10]:3306".into(),
            },
            ServiceRuleInput {
                protocol: RuleProtocol::Tcp,
                port: 9001,
                path: None,
                target: "unix:///tmp/raw.sock".into(),
            },
        ];

        let rules = validate_and_normalize_rules(&input).unwrap();
        assert_eq!(rules.len(), 11);
        assert!(rules.iter().any(|r| r.path.as_deref() == Some("/self") && r.target == "http://127.0.0.1:9090"));
        assert!(rules.iter().any(|r| r.path.as_deref() == Some("/files/") && r.target == "file:///data/share"));
        assert!(rules.iter().any(|r| r.port == 2222 && r.target == "127.0.0.1:2222"));
        assert!(rules.iter().any(|r| r.port == 9001 && r.target == "unix:/tmp/raw.sock"));

        let cfg = build_service_config("demo", Some("tail.ts.net"), &rules).unwrap();
        assert_eq!(cfg["TCP"]["443"]["HTTPS"], true);
        assert_eq!(cfg["TCP"]["2222"]["TCPForward"], "127.0.0.1:2222");
        assert_eq!(cfg["TCP"]["9001"]["TCPForward"], "unix:/tmp/raw.sock");
        let handlers = &cfg["Web"]["demo.tail.ts.net:443"]["Handlers"];
        assert_eq!(handlers["/"]["Proxy"], "http://192.168.0.124:3773");
        assert_eq!(handlers["/files/"]["Path"], "/data/share");
        assert_eq!(handlers["/sock"]["Proxy"], "unix:/tmp/demo.sock");
    }

    #[test]
    fn rules_reject_malformed_targets_and_port_or_path_conflicts() {
        // Empty rules.
        assert!(validate_and_normalize_rules(&[]).is_err());

        // Port conflict HTTPS vs TCP.
        assert!(validate_and_normalize_rules(&[
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: None, target: "http://192.168.0.2:80".into() },
            ServiceRuleInput { protocol: RuleProtocol::Tcp, port: 443, path: None, target: "192.168.0.2:443".into() },
        ]).is_err());

        // Duplicate HTTPS path after trailing-slash normalization.
        assert!(validate_and_normalize_rules(&[
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: Some("/api".into()), target: "http://192.168.0.2:80".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: Some("/api/".into()), target: "http://192.168.0.3:80".into() },
        ]).is_err());

        // Duplicate TCP port.
        assert!(validate_and_normalize_rules(&[
            ServiceRuleInput { protocol: RuleProtocol::Tcp, port: 22, path: None, target: "192.168.0.2:22".into() },
            ServiceRuleInput { protocol: RuleProtocol::Tcp, port: 22, path: None, target: "192.168.0.3:22".into() },
        ]).is_err());

        // file:// rejected on TCP, path rejected on TCP, bad schemes/ports/paths rejected.
        for bad in [
            ServiceRuleInput { protocol: RuleProtocol::Tcp, port: 80, path: None, target: "file:///etc/hosts".into() },
            ServiceRuleInput { protocol: RuleProtocol::Tcp, port: 80, path: Some("/x".into()), target: "192.168.0.2:80".into() },
            ServiceRuleInput { protocol: RuleProtocol::Tcp, port: 80, path: None, target: "192.168.0.2".into() },
            ServiceRuleInput { protocol: RuleProtocol::Tcp, port: 80, path: None, target: "http://192.168.0.2:80".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 0, path: None, target: "http://192.168.0.2:80".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: Some("no-slash".into()), target: "http://192.168.0.2:80".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: Some("/a?b=1".into()), target: "http://192.168.0.2:80".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: None, target: "ftp://192.168.0.2:21".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: None, target: "http://user@192.168.0.2:80".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: None, target: "unix:relative.sock".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: None, target: "file://relative/path".into() },
            ServiceRuleInput { protocol: RuleProtocol::Https, port: 443, path: None, target: "http://192.168.0.2:0".into() },
        ] {
            assert!(validate_and_normalize_rules(&[bad.clone()]).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn target_classification_and_subnet_route_coverage() {
        let router_ips: Vec<IpAddr> = vec!["192.168.0.1".parse().unwrap()];
        let advertised: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap(), "10.20.0.0/24".parse().unwrap()];
        let approved: Vec<IpNet> = vec!["192.168.0.0/24".parse().unwrap()];

        let (ip, kind) = classify_target("http://192.168.0.124:3773", &router_ips);
        assert_eq!(kind, "lan_private");
        assert_eq!(subnet_route_state(ip, kind, &advertised, &approved), "approved");

        let (ip, kind) = classify_target("http://10.20.0.5:8080", &router_ips);
        assert_eq!(kind, "lan_private");
        assert_eq!(subnet_route_state(ip, kind, &advertised, &approved), "pending");

        let (ip, kind) = classify_target("http://10.99.0.5:8080", &router_ips);
        assert_eq!(kind, "lan_private");
        assert_eq!(subnet_route_state(ip, kind, &advertised, &approved), "not_advertised");

        assert_eq!(classify_target("http://192.168.0.1:9090", &router_ips).1, "router_self");
        assert_eq!(classify_target("http://127.0.0.1:9090", &router_ips).1, "loopback");
        assert_eq!(classify_target("http://100.64.1.2:80", &router_ips).1, "tailnet");
        assert_eq!(classify_target("http://[fd7a:115c:a1e0::9]:80", &router_ips).1, "tailnet");
        assert_eq!(classify_target("http://[fd00:12::5]:80", &router_ips).1, "lan_private");
        assert_eq!(classify_target("https://1.1.1.1:443", &router_ips).1, "public");
        assert_eq!(classify_target("unix:/tmp/a.sock", &router_ips).1, "unix");
        assert_eq!(classify_target("file:///data/share", &router_ips).1, "file");
    }

    #[test]
    fn aggregate_merges_serve_config_and_capmap_and_computes_all_five_states() {
        let status = sample_status(
            json!({
                "https": null,
                "service-host": [{
                    "svc:active-app": ["100.75.1.1"],
                    "svc:mismatch-app": ["100.75.1.2"],
                    "svc:drained-app": ["100.75.1.3"],
                    "svc:unconf-app": ["100.75.1.4"],
                }],
                "services/active-app": [{"Name": "svc:active-app", "Addrs": ["100.75.1.1"], "Ports": ["tcp:443", "tcp:3000-3010"]}],
                "services/mismatch-app": [{"Name": "svc:mismatch-app", "Addrs": ["100.75.1.2"], "Ports": ["tcp:443"]}],
                "services/drained-app": [{"Name": "svc:drained-app", "Addrs": ["100.75.1.3"], "Ports": ["tcp:443"]}],
                "services/unconf-app": [{"Name": "svc:unconf-app", "Addrs": ["100.75.1.4"], "Ports": ["tcp:443"]}],
            }),
            &["100.75.1.1/32", "100.75.1.2/32", "100.75.1.3/32", "192.168.0.0/24"],
            &["100.75.1.1/32", "100.75.1.2/32", "100.75.1.3/32", "192.168.0.0/24"],
        );
        let prefs = Prefs {
            advertise_routes: vec!["192.168.0.0/24".into()],
            advertise_services: vec![
                "svc:active-app".into(),
                "svc:mismatch-app".into(),
                "svc:pending-app".into(),
            ],
            ..Prefs::default()
        };
        let serve = json!({
            "Services": {
                "svc:active-app": {
                    "TCP": {"443": {"HTTPS": true}, "3005": {"TCPForward": "192.168.0.10:3005"}},
                    "Web": {"active-app.tail.ts.net:443": {"Handlers": {"/": {"Proxy": "http://192.168.0.10:8080"}}}}
                },
                "svc:mismatch-app": {
                    "TCP": {"443": {"HTTPS": true}, "8443": {"TCPForward": "192.168.0.10:8443"}},
                    "Web": {"mismatch-app.tail.ts.net:443": {"Handlers": {"/": {"Proxy": "http://192.168.0.10:8080"}}}}
                },
                "svc:drained-app": {
                    "TCP": {"443": {"HTTPS": true}},
                    "Web": {"drained-app.tail.ts.net:443": {"Handlers": {"/": {"Proxy": "http://192.168.0.10:8080"}}}}
                },
                "svc:pending-app": {
                    "TCP": {"443": {"HTTPS": true}},
                    "Web": {"pending-app.tail.ts.net:443": {"Handlers": {"/": {"Proxy": "http://10.88.0.5:8080"}}}}
                }
            }
        });
        let mut cfg = config::TsConfig::default();
        cfg.advertise_routes = vec!["192.168.0.0/24".into()];
        let addrs = vec![ifa("br-lan", "192.168.0.1", 24)];

        let out = aggregate_services(&status, Some(&prefs), &serve, &cfg, &addrs);
        assert_eq!(out["available"], true);
        assert_eq!(out["https_enabled"], true);
        assert_eq!(out["tags"], json!(["tag:router"]));

        let by_name: BTreeMap<String, &Value> = out["services"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| (s["name"].as_str().unwrap().to_string(), s))
            .collect();
        assert_eq!(by_name["active-app"]["state"], "active");
        assert_eq!(by_name["active-app"]["defined_in_tailnet"], true);
        assert_eq!(by_name["active-app"]["admin_url"], "https://console.tailscale.com/admin/services/svc:active-app");
        assert_eq!(by_name["active-app"]["unallowed_ports"], json!([]));
        assert_eq!(by_name["active-app"]["rules"][0]["subnet_route_state"], "approved");

        assert_eq!(by_name["mismatch-app"]["state"], "port_mismatch");
        assert_eq!(by_name["mismatch-app"]["unallowed_ports"], json!([8443]));

        assert_eq!(by_name["drained-app"]["state"], "drained");
        assert_eq!(by_name["drained-app"]["drained"], true);

        assert_eq!(by_name["pending-app"]["state"], "pending");
        assert_eq!(by_name["pending-app"]["defined_in_tailnet"], false);
        assert_eq!(by_name["pending-app"]["admin_url"], "https://console.tailscale.com/admin/services");
        assert_eq!(by_name["pending-app"]["rules"][0]["subnet_route_state"], "not_advertised");

        assert_eq!(by_name["unconf-app"]["state"], "unconfigured");
        assert_eq!(by_name["unconf-app"]["configured"], false);
        assert_eq!(by_name["unconf-app"]["vips"], json!(["100.75.1.4"]));
    }

    #[test]
    fn unsupported_cli_handlers_are_readonly_and_updates_preserve_other_services_and_node_config() {
        let cli_only = json!({
            "Tun": true,
            "TCP": {
                "80": {"HTTP": true},
                "443": {"HTTPS": true},
                "8443": {"TerminateTLS": "demo.tail.ts.net", "TCPForward": "192.168.0.5:8443", "ProxyProtocol": 1}
            },
            "Web": {
                "demo.tail.ts.net:443": {
                    "Handlers": {
                        "/txt": {"Text": "hello"},
                        "/cap": {"Proxy": "http://192.168.0.5:8080", "AcceptAppCaps": ["example.com/cap"]}
                    }
                }
            }
        });
        let parsed = parse_service_config(&cli_only, Some("demo.tail.ts.net"));
        assert!(!parsed.editable);
        assert!(parsed.unsupported_reasons.len() >= 5, "{:?}", parsed.unsupported_reasons);

        let full = json!({
            "TCP": {"8080": {"HTTPS": true}},
            "Web": {"u60-pro.tail.ts.net:8080": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:9090"}}}},
            "AllowFunnel": {"u60-pro.tail.ts.net:8080": false},
            "Services": {
                "svc:keep": {
                    "TCP": {"443": {"HTTPS": true}},
                    "Web": {"keep.tail.ts.net:443": {"Handlers": {"/": {"Proxy": "http://192.168.0.2:80"}}}}
                }
            }
        });
        let rules = validate_and_normalize_rules(&[ServiceRuleInput {
            protocol: RuleProtocol::Tcp,
            port: 5432,
            path: None,
            target: "192.168.0.50:5432".into(),
        }])
        .unwrap();
        let svc_obj = build_service_config("db", Some("tail.ts.net"), &rules).unwrap();
        let merged = apply_service_update(&full, "svc:db", svc_obj).unwrap();
        assert_eq!(merged["TCP"], full["TCP"]);
        assert_eq!(merged["Web"], full["Web"]);
        assert_eq!(merged["AllowFunnel"], full["AllowFunnel"]);
        assert_eq!(merged["Services"]["svc:keep"], full["Services"]["svc:keep"]);
        assert_eq!(merged["Services"]["svc:db"]["TCP"]["5432"]["TCPForward"], "192.168.0.50:5432");
    }

    /// Mock LocalAPI Unix socket server backing end-to-end handler tests.
    struct MockLocalApi {
        serve_config: Arc<Mutex<Value>>,
        advertise_services: Arc<Mutex<Vec<String>>>,
        force_412: Arc<Mutex<bool>>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        sock: std::path::PathBuf,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl MockLocalApi {
        fn start(sock: std::path::PathBuf, initial_serve: Value, initial_adv: Vec<String>) -> Self {
            let _ = std::fs::remove_file(&sock);
            let listener = UnixListener::bind(&sock).unwrap();
            listener.set_nonblocking(true).unwrap();
            let serve_config = Arc::new(Mutex::new(initial_serve));
            let etag = Arc::new(Mutex::new("etag-1".to_string()));
            let advertise_services = Arc::new(Mutex::new(initial_adv));
            let force_412 = Arc::new(Mutex::new(false));
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

            let sc = Arc::clone(&serve_config);
            let et = Arc::clone(&etag);
            let adv = Arc::clone(&advertise_services);
            let f412 = Arc::clone(&force_412);
            let stop = Arc::clone(&shutdown);

            let handle = thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let Ok((mut stream, _)) = listener.accept() else {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    };
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut raw = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let mut expected_total = None;
                    loop {
                        match stream.read(&mut tmp) {
                            Ok(0) => break,
                            Ok(n) => {
                                raw.extend_from_slice(&tmp[..n]);
                                if expected_total.is_none() {
                                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                                        let head = String::from_utf8_lossy(&raw[..pos]);
                                        let cl = head
                                            .lines()
                                            .find_map(|l| {
                                                let (k, v) = l.split_once(':')?;
                                                k.trim().eq_ignore_ascii_case("content-length")
                                                    .then(|| v.trim().parse::<usize>().ok())
                                                    .flatten()
                                            })
                                            .unwrap_or(0);
                                        expected_total = Some(pos + 4 + cl);
                                    }
                                }
                                if let Some(total) = expected_total {
                                    if raw.len() >= total {
                                        break;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(raw.len());
                    let head = String::from_utf8_lossy(&raw[..split]).to_string();
                    let body = if split + 4 <= raw.len() { &raw[split + 4..] } else { &[] };
                    let first = head.lines().next().unwrap_or("");
                    let resp = if first.starts_with("GET /localapi/v0/serve-config ") {
                        let data = sc.lock().unwrap().to_string();
                        let cur_etag = et.lock().unwrap().clone();
                        format!(
                            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nEtag: {cur_etag}\r\n\r\n{data}"
                        )
                    } else if first.starts_with("POST /localapi/v0/serve-config ") {
                        if *f412.lock().unwrap() {
                            "HTTP/1.0 412 Precondition Failed\r\n\r\netag mismatch\n".to_string()
                        } else {
                            let parsed: Value = serde_json::from_slice(body).unwrap();
                            *sc.lock().unwrap() = parsed;
                            *et.lock().unwrap() = "etag-2".to_string();
                            "HTTP/1.0 200 OK\r\n\r\n".to_string()
                        }
                    } else if first.starts_with("GET /localapi/v0/prefs ") {
                        let list = adv.lock().unwrap().clone();
                        let data = json!({
                            "AdvertiseRoutes": ["192.168.0.0/24"],
                            "AdvertiseServices": list
                        })
                        .to_string();
                        format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{data}")
                    } else {
                        "HTTP/1.0 404 Not Found\r\n\r\n".to_string()
                    };
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            });

            Self {
                serve_config,
                advertise_services,
                force_412,
                shutdown,
                sock,
                handle: Some(handle),
            }
        }
    }

    impl Drop for MockLocalApi {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Release);
            let _ = std::os::unix::net::UnixStream::connect(&self.sock);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
            let _ = std::fs::remove_file(&self.sock);
        }
    }

    #[test]
    fn handlers_end_to_end_put_drain_advertise_delete_and_guards() {
        let root = std::env::temp_dir().join(format!("u60-ts-svc-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let sock = root.join("tailscaled.sock");

        let initial_serve = json!({
            "TCP": {"8080": {"HTTPS": true}},
            "Services": {
                "svc:t3code": {
                    "TCP": {"443": {"HTTPS": true}},
                    "Web": {"t3code.tail.ts.net:443": {"Handlers": {"/": {"Proxy": "http://192.168.0.124:3773"}}}}
                },
                "svc:cli-only": {
                    "TCP": {"443": {"HTTPS": true}},
                    "Web": {"cli-only.tail.ts.net:443": {"Handlers": {"/": {"Text": "hello"}}}}
                }
            }
        });
        let mock = MockLocalApi::start(sock, initial_serve, vec!["svc:t3code".into()]);
        let sc_cli = Arc::clone(&mock.serve_config);
        let adv_cli = Arc::clone(&mock.advertise_services);
        let cli_log = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
        let cli_log_ref = Arc::clone(&cli_log);

        let mut mgr = TailscaleManager::new();
        mgr.test_io = Some(TestIo {
            root: root.clone(),
            cli: Box::new(move |args| {
                cli_log_ref
                    .lock()
                    .unwrap()
                    .push(args.iter().map(|s| (*s).to_string()).collect());
                match args {
                    ["serve", "advertise", svc] => {
                        let mut list = adv_cli.lock().unwrap();
                        if !list.iter().any(|x| x == svc) {
                            list.push((*svc).to_string());
                        }
                        Ok(String::new())
                    }
                    ["serve", "drain", svc] => {
                        adv_cli.lock().unwrap().retain(|x| x != svc);
                        Ok(String::new())
                    }
                    ["serve", "clear", svc] => {
                        adv_cli.lock().unwrap().retain(|x| x != svc);
                        if let Some(svcs) = sc_cli
                            .lock()
                            .unwrap()
                            .get_mut("Services")
                            .and_then(Value::as_object_mut)
                        {
                            svcs.remove(*svc);
                        }
                        Ok(String::new())
                    }
                    _ => Err(format!("unexpected cli: {args:?}")),
                }
            }),
            status: Box::new(|| {
                Ok(json!({
                    "BackendState": "Running",
                    "TUN": true,
                    "MagicDNSSuffix": "tail.ts.net",
                    "Self": {
                        "Online": true,
                        "DNSName": "u60-pro.tail.ts.net.",
                        "PrimaryRoutes": ["100.75.1.10/32", "192.168.0.0/24"],
                        "AllowedIPs": ["100.75.1.10/32", "192.168.0.0/24"],
                        "Tags": ["tag:t3"],
                        "CapMap": {
                            "https": null,
                            "service-host": [{"svc:t3code": ["100.75.1.10"]}],
                            "services/t3code": [{"Name": "svc:t3code", "Addrs": ["100.75.1.10"], "Ports": ["tcp:443"]}]
                        }
                    }
                }))
            }),
            up_command: None,
        });
        *mgr.active_child.lock().unwrap() = Some(ChildIdentity { pid: 1, instance: 1 });

        let mut state = AppState::new();
        state.tailscale = Arc::new(mgr);

        // Mutations require agent password.
        let put_body = serde_json::to_vec(&json!({
            "rules": [
                {"protocol": "https", "port": 443, "path": "/", "target": "http://192.168.0.50:8080"},
                {"protocol": "https", "port": 443, "path": "/api", "target": "https+insecure://192.168.0.50:8443"},
                {"protocol": "tcp", "port": 9000, "target": "127.0.0.1:9000"}
            ]
        }))
        .unwrap();
        assert_eq!(service_put(&state, "newapp", &put_body).0, 403);
        state.auth.set_password("secret");

        // GET lists existing t3code + read-only cli-only.
        let (code, body) = services_list(&state);
        assert_eq!(code, 200);
        assert_eq!(body["data"]["available"], true);
        let svcs = body["data"]["services"].as_array().unwrap();
        assert_eq!(svcs.len(), 2);

        // PUT on cli-only is refused with 409.
        assert_eq!(service_put(&state, "cli-only", &put_body).0, 409);

        // PUT creates newapp, preserves t3code & node-level TCP, and auto-advertises it.
        let (code, body) = service_put(&state, "newapp", &put_body);
        assert_eq!(code, 200, "{body}");
        assert!(mock.advertise_services.lock().unwrap().contains(&"svc:newapp".to_string()));
        assert_eq!(mock.serve_config.lock().unwrap()["TCP"]["8080"]["HTTPS"], true);
        assert!(mock.serve_config.lock().unwrap()["Services"]["svc:t3code"].is_object());

        // Drain removes from AdvertiseServices while preserving config.
        let (code, body) = service_drain(&state, "newapp");
        assert_eq!(code, 200);
        let newapp = body["data"]["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "newapp")
            .unwrap();
        assert_eq!(newapp["state"], "drained");

        // Editing a drained service keeps it drained (does NOT auto-advertise!).
        let edit_body = serde_json::to_vec(&json!({
            "rules": [{"protocol": "tcp", "port": 9001, "target": "192.168.0.50:9001"}]
        }))
        .unwrap();
        let (code, body) = service_put(&state, "newapp", &edit_body);
        assert_eq!(code, 200);
        let newapp = body["data"]["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "newapp")
            .unwrap();
        assert_eq!(newapp["state"], "drained");

        // Advertise restores it.
        let (code, body) = service_advertise(&state, "newapp");
        assert_eq!(code, 200);
        let newapp = body["data"]["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "newapp")
            .unwrap();
        assert_eq!(newapp["drained"], false);

        // ETag 412 surfaces as 409 Conflict.
        *mock.force_412.lock().unwrap() = true;
        assert_eq!(service_put(&state, "newapp", &edit_body).0, 409);
        *mock.force_412.lock().unwrap() = false;

        // Concurrent prefs_lock surfaces as 409 Conflict.
        {
            let _lock = state.tailscale.prefs_lock.lock().unwrap();
            assert_eq!(service_drain(&state, "newapp").0, 409);
        }

        // Delete clears newapp cleanly and leaves t3code untouched.
        let (code, body) = service_delete(&state, "newapp");
        assert_eq!(code, 200);
        assert!(body["data"]["services"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["name"] != "newapp"));
        assert!(mock.serve_config.lock().unwrap()["Services"]["svc:t3code"].is_object());

        // Drain on unconfigured service returns 404.
        assert_eq!(service_drain(&state, "nonexistent").0, 404);

        drop(mock);
        let _ = std::fs::remove_dir_all(&root);
    }
}
