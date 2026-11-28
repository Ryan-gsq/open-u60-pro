use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const CONFIG_PATH: &str = "/data/local/tmp/tailscale_config.json";
const MAX_ROUTES: usize = 16;
pub(super) const DEFAULT_V4: &str = "0.0.0.0/0";
pub(super) const DEFAULT_V6: &str = "::/0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsConfig {
    pub enabled: bool,
    /// Set true after a successful enrollment, false on logout. Distinguishes
    /// "never enrolled" from "enrolled but key invalid" — the state file alone
    /// can't (tailscaled creates it before first login).
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default)]
    pub advertise_routes: Vec<String>,
    #[serde(default)]
    pub advertise_exit_node: bool,
    #[serde(default)]
    pub exit_via_mihomo: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) invalid_advertise_routes: Vec<Value>,
    #[serde(default = "default_true")]
    pub hold_wakelock: bool,
    #[serde(default)]
    pub tailscale_ssh: bool,
    #[serde(default)]
    pub pinned_version: String,
}

fn default_hostname() -> String {
    "u60-pro".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for TsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enrolled: false,
            hostname: default_hostname(),
            advertise_routes: Vec::new(),
            advertise_exit_node: false,
            exit_via_mihomo: false,
            invalid_advertise_routes: Vec::new(),
            hold_wakelock: true,
            tailscale_ssh: false,
            pinned_version: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TsConfigPatch {
    pub hostname: Option<String>,
    pub advertise_routes: Option<Vec<String>>,
    pub advertise_exit_node: Option<bool>,
    pub exit_via_mihomo: Option<bool>,
    pub hold_wakelock: Option<bool>,
    pub tailscale_ssh: Option<bool>,
}

impl TsConfig {
    pub fn apply_patch(&mut self, patch: TsConfigPatch) -> Result<(), String> {
        let hostname = if let Some(v) = patch.hostname {
            let v = v.trim().to_string();
            if v.is_empty()
                || v.len() > 63
                || !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Err("hostname must be 1-63 chars, alphanumeric or '-'".into());
            }
            Some(v)
        } else {
            None
        };
        let routes = if let Some(routes) = patch.advertise_routes {
            let mut normalized = Vec::new();
            for route in routes {
                let route = normalize_route(&route)?;
                if !normalized.contains(&route) {
                    normalized.push(route);
                    if normalized.len() > MAX_ROUTES {
                        return Err(format!(
                            "advertise_routes accepts up to {MAX_ROUTES} routes"
                        ));
                    }
                }
            }
            Some(normalized)
        } else {
            None
        };

        if let Some(hostname) = hostname {
            self.hostname = hostname;
        }
        if let Some(routes) = routes {
            self.advertise_routes = routes;
            self.invalid_advertise_routes.clear();
        }
        if let Some(advertise_exit_node) = patch.advertise_exit_node {
            self.advertise_exit_node = advertise_exit_node;
        }
        if let Some(exit_via_mihomo) = patch.exit_via_mihomo {
            self.exit_via_mihomo = exit_via_mihomo;
        }
        if let Some(v) = patch.hold_wakelock {
            self.hold_wakelock = v;
        }
        if let Some(v) = patch.tailscale_ssh {
            self.tailscale_ssh = v;
        }
        Ok(())
    }
}

pub(super) fn normalize_route(route: &str) -> Result<String, String> {
    let invalid = || format!("invalid CIDR route: {route}");
    let (addr, len) = route.trim().split_once('/').ok_or_else(invalid)?;
    let addr = addr.parse::<IpAddr>().map_err(|_| invalid())?;
    let len = len.parse::<u8>().map_err(|_| invalid())?;
    let prefix = IpNet::new(addr, len).map_err(|_| invalid())?;
    if prefix.prefix_len() == 0 {
        return Err(format!(
            "default route {route} requires the Exit Node toggle"
        ));
    }
    if prefix != prefix.trunc() {
        return Err(format!(
            "invalid network prefix {route}: expected {}",
            prefix.trunc()
        ));
    }
    for range in [
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
        "0.0.0.0/32",
        "127.0.0.0/8",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "ff00::/8",
    ] {
        let reserved: IpNet = range.parse().unwrap();
        if reserved.contains(&prefix) || prefix.contains(&reserved) {
            return Err(format!("route {prefix} overlaps reserved range {reserved}"));
        }
    }
    Ok(prefix.to_string())
}

fn legacy_route(route: &Value) -> Option<String> {
    let route = route.as_str()?.trim();
    let net = route.parse::<IpNet>().ok().or_else(|| {
        let (addr, prefix) = route.split_once('/')?;
        let mut octets = addr.split('.');
        let mut parsed = [0; 4];
        for octet in &mut parsed {
            *octet = octets.next()?.parse::<u8>().ok()?;
        }
        if octets.next().is_some() {
            return None;
        }
        IpNet::new(IpAddr::V4(Ipv4Addr::from(parsed)), prefix.parse().ok()?).ok()
    })?;
    if net.prefix_len() == 0 && !net.addr().is_unspecified() {
        return None;
    }
    Some(net.trunc().to_string())
}

fn load_json(json: &str) -> serde_json::Result<TsConfig> {
    let mut raw: Value = serde_json::from_str(json)?;
    let routes = match raw
        .as_object_mut()
        .and_then(|fields| fields.remove("advertise_routes"))
    {
        Some(Value::Array(routes)) => routes,
        Some(value) => vec![value],
        None => Vec::new(),
    };
    let mut config: TsConfig = serde_json::from_value(raw)?;
    let routes: Vec<_> = routes
        .into_iter()
        .map(|raw| (legacy_route(&raw), raw))
        .collect();
    let has = |prefix: &str| {
        routes
            .iter()
            .any(|(route, _)| route.as_deref() == Some(prefix))
    };
    let legacy_exit = has(DEFAULT_V4) && has(DEFAULT_V6);
    config.advertise_exit_node |= legacy_exit;
    for (normalized, original) in routes {
        match normalized.as_deref() {
            Some(DEFAULT_V4 | DEFAULT_V6) if legacy_exit => continue,
            Some(route) if normalize_route(route).is_ok() => {
                if !config.advertise_routes.iter().any(|saved| saved == route) {
                    config.advertise_routes.push(route.to_string());
                }
            }
            _ => {
                eprintln!("[tailscale] isolated an invalid legacy advertise_routes entry");
                config.invalid_advertise_routes.push(original);
            }
        }
    }
    Ok(config)
}

#[cfg(not(test))]
pub fn load() -> TsConfig {
    match std::fs::read_to_string(CONFIG_PATH) {
        Ok(json) => load_json(&json).unwrap_or_else(|_| {
            eprintln!("[tailscale] could not parse {CONFIG_PATH}");
            TsConfig::default()
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TsConfig::default(),
        Err(error) => {
            eprintln!("[tailscale] could not read {CONFIG_PATH}: {error}");
            TsConfig::default()
        }
    }
}

pub fn save(config: &TsConfig) -> Result<(), String> {
    save_at(Path::new(CONFIG_PATH), config)
}

#[cfg(not(test))]
pub(super) fn exists() -> bool {
    Path::new(CONFIG_PATH).exists()
}

pub(super) fn save_at(path: &Path, config: &TsConfig) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(config).map_err(|e| format!("serialize: {e}"))?;
    crate::ota::storage::atomic_write_preserving_parent(path, &json, 0o600)
        .map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_nonzero_default_addresses_cannot_enable_exit_node() {
        for routes in [
            ["192.0.2.7/0", "2001:db8::1/0"],
            ["192.0.2.7/0", "::/0"],
            ["0.0.0.0/0", "2001:db8::1/0"],
        ] {
            let cfg = load_json(
                &json!({
                    "enabled": true,
                    "enrolled": true,
                    "hostname": "old-router",
                    "advertise_routes": routes,
                })
                .to_string(),
            )
            .unwrap();
            assert!(!cfg.advertise_exit_node);
            assert!(cfg.enabled && cfg.enrolled);
            assert_eq!(cfg.hostname, "old-router");
            assert!(cfg.advertise_routes.is_empty());
            assert_eq!(cfg.invalid_advertise_routes, routes.map(Value::from));
        }
        let cfg = load_json(
            r#"{"enabled":true,"advertise_routes":["000.000.000.000/0","::/0","010.0.0.0/8"]}"#,
        )
        .unwrap();
        assert!(cfg.advertise_exit_node);
        assert_eq!(cfg.advertise_routes, ["10.0.0.0/8"]);
    }

    #[test]
    fn hostname_trims_and_accepts_only_one_to_63_ascii_alphanumerics_or_hyphens() {
        let longest = "a".repeat(63);
        for (input, expected) in [
            (String::new(), None),
            (" \t ".into(), None),
            ("-".into(), Some("-")),
            ("  Router-42\t".into(), Some("Router-42")),
            (longest.clone(), Some(longest.as_str())),
            ("a".repeat(64), None),
            ("router_name".into(), None),
            ("router.name".into(), None),
            ("röuter".into(), None),
        ] {
            let mut config = TsConfig::default();
            let result =
                config.apply_patch(serde_json::from_value(json!({"hostname": input})).unwrap());
            match expected {
                Some(hostname) => {
                    assert_eq!(result, Ok(()));
                    assert_eq!(config.hostname, hostname);
                }
                None => {
                    assert_eq!(
                        result,
                        Err("hostname must be 1-63 chars, alphanumeric or '-'".into())
                    );
                    assert_eq!(config.hostname, "u60-pro");
                }
            }
        }
    }

    #[test]
    fn strict_cidr_validates_both_families_and_reserved_ranges() {
        for (input, expected) in [
            ("192.168.0.0/24", "192.168.0.0/24"),
            (" 2001:0DB8:0000::/48 ", "2001:db8::/48"),
            ("fd01::/64", "fd01::/64"),
        ] {
            assert_eq!(normalize_route(input).unwrap(), expected);
        }
        for (input, reason) in [
            ("192.168.0.2/24", "expected 192.168.0.0/24"),
            ("2001:db8::1/48", "expected 2001:db8::/48"),
            (DEFAULT_V4, "Exit Node toggle"),
            (DEFAULT_V6, "Exit Node toggle"),
            ("100.64.0.0/10", "reserved range 100.64.0.0/10"),
            ("100.75.1.1/32", "reserved range 100.64.0.0/10"),
            ("100.0.0.0/8", "reserved range 100.64.0.0/10"),
            (
                "fd7a:115c:a1e0:12::/64",
                "reserved range fd7a:115c:a1e0::/48",
            ),
            ("fd00::/8", "reserved range fd7a:115c:a1e0::/48"),
            ("127.2.0.0/16", "reserved range 127.0.0.0/8"),
            ("::1/128", "reserved range ::1/128"),
            ("224.0.0.0/24", "reserved range 224.0.0.0/4"),
            ("ff02::/16", "reserved range ff00::/8"),
            ("0.0.0.0/32", "reserved range 0.0.0.0/32"),
            ("010.0.0.0/8", "invalid CIDR route"),
            ("192.0.2.0/33", "invalid CIDR route"),
            ("192.0.2.0", "invalid CIDR route"),
        ] {
            assert!(
                normalize_route(input).unwrap_err().contains(reason),
                "{input}"
            );
        }
    }

    #[test]
    fn legacy_routes_migrate_without_discarding_identity_or_isolated_entries() {
        let config = load_json(
            r#"{
            "enabled": true,
            "enrolled": true,
            "hostname": "existing",
            "advertise_routes": ["010.0.0.0/8", "10.0.0.1/8", "0.0.0.0/0", "::/0",
              "malformed", 123, "fd7a:115c:a1e0::/48", "2001:0DB8::/48"]
        }"#,
        )
        .unwrap();
        assert!(config.enabled);
        assert!(config.enrolled);
        assert_eq!(config.hostname, "existing");
        assert!(config.advertise_exit_node);
        assert_eq!(config.advertise_routes, ["10.0.0.0/8", "2001:db8::/48"]);
        assert_eq!(
            config.invalid_advertise_routes,
            [json!("malformed"), json!(123), json!("fd7a:115c:a1e0::/48")]
        );

        let reloaded = load_json(&serde_json::to_string(&config).unwrap()).unwrap();
        assert_eq!(
            reloaded.invalid_advertise_routes,
            config.invalid_advertise_routes
        );
        assert_eq!(reloaded.advertise_routes, config.advertise_routes);
        assert!(reloaded.advertise_exit_node);
    }

    #[test]
    fn lone_legacy_default_is_isolated_and_non_array_preserves_identity() {
        let config =
            load_json(r#"{"enabled": true, "enrolled": true, "advertise_routes": ["0.0.0.0/0"]}"#)
                .unwrap();
        assert!(config.enabled && config.enrolled);
        assert!(!config.advertise_exit_node);
        assert!(config.advertise_routes.is_empty());
        assert_eq!(config.invalid_advertise_routes, [json!("0.0.0.0/0")]);

        let config =
            load_json(r#"{"enabled": true, "enrolled": true, "advertise_routes": "bad"}"#).unwrap();
        assert!(config.enabled && config.enrolled);
        assert_eq!(config.invalid_advertise_routes, [json!("bad")]);
    }

    #[test]
    fn route_patch_deduplicates_in_order_and_limits_unique_prefixes() {
        let mut config = TsConfig::default();
        let patch = serde_json::from_value(json!({
            "advertise_routes": ["2001:0DB8::/32", "192.168.0.0/24", "2001:db8::/32"],
            "advertise_exit_node": true,
            "exit_via_mihomo": true,
        }))
        .unwrap();
        config.apply_patch(patch).unwrap();
        assert_eq!(config.advertise_routes, ["2001:db8::/32", "192.168.0.0/24"]);
        let patch = serde_json::from_value(json!({"advertise_exit_node": false})).unwrap();
        config.apply_patch(patch).unwrap();
        assert!(!config.advertise_exit_node);
        assert!(config.exit_via_mihomo);

        let routes: Vec<_> = (0..MAX_ROUTES)
            .map(|subnet| format!("10.0.{subnet}.0/24"))
            .collect();
        let patch = serde_json::from_value(json!({"advertise_routes": routes})).unwrap();
        config.apply_patch(patch).unwrap();
        let mut too_many = routes.clone();
        too_many.push("192.168.0.0/24".into());
        let patch = serde_json::from_value(json!({"advertise_routes": too_many})).unwrap();
        assert!(config.apply_patch(patch).unwrap_err().contains("up to 16"));
        assert_eq!(config.advertise_routes, routes);
    }

    #[test]
    fn atomic_save_keeps_existing_file_if_staging_fails() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("u60-ts-config-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        let path = dir.join("config.json");
        let mut config = TsConfig {
            enabled: true,
            ..TsConfig::default()
        };
        save_at(&path, &config).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o750
        );
        let original = fs::read(&path).unwrap();

        let staging = dir.join(format!(".config.json.{}.tmp", std::process::id()));
        fs::create_dir(&staging).unwrap();
        config.hostname = "another-host".into();
        assert!(save_at(&path, &config).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn partial_patch_preserves_omitted_fields() {
        let original = json!({
            "enabled": true,
            "enrolled": true,
            "hostname": "router-1",
            "advertise_routes": ["192.0.2.0/24"],
            "advertise_exit_node": false,
            "exit_via_mihomo": false,
            "hold_wakelock": false,
            "tailscale_ssh": true,
            "pinned_version": "1.104.7",
        });
        let mut config: TsConfig = serde_json::from_value(original.clone()).unwrap();
        let patch = serde_json::from_value(json!({"hostname": "router-2"})).unwrap();
        config.apply_patch(patch).unwrap();
        let mut expected = original;
        expected["hostname"] = json!("router-2");
        assert_eq!(serde_json::to_value(config).unwrap(), expected);
    }

    #[test]
    fn invalid_cidr_leaves_all_fields_unchanged() {
        let mut config = TsConfig::default();
        let patch = serde_json::from_value(json!({
            "hostname": "new-hostname",
            "advertise_routes": ["192.0.2.0/24", "192.0.2.0/33"],
            "hold_wakelock": false,
            "tailscale_ssh": true,
        }))
        .unwrap();
        assert_eq!(
            config.apply_patch(patch),
            Err("invalid CIDR route: 192.0.2.0/33".into())
        );
        assert_eq!(config.hostname, default_hostname());
        assert!(config.advertise_routes.is_empty());
        assert!(config.hold_wakelock);
        assert!(!config.tailscale_ssh);
    }
}
