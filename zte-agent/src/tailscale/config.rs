use serde::{Deserialize, Serialize};

const CONFIG_PATH: &str = "/data/local/tmp/tailscale_config.json";

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
    pub hold_wakelock: Option<bool>,
    pub tailscale_ssh: Option<bool>,
}

impl TsConfig {
    pub fn apply_patch(&mut self, patch: TsConfigPatch) -> Result<(), String> {
        if let Some(v) = patch.hostname {
            let v = v.trim().to_string();
            if v.is_empty() || v.len() > 63 || !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err("hostname must be 1-63 chars, alphanumeric or '-'".into());
            }
            self.hostname = v;
        }
        if let Some(v) = patch.advertise_routes {
            for route in &v {
                if !valid_cidr(route) {
                    return Err(format!("invalid CIDR route: {route}"));
                }
            }
            self.advertise_routes = v;
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

/// Minimal IPv4 CIDR validation (e.g. "192.168.0.0/24").
fn valid_cidr(s: &str) -> bool {
    let mut parts = s.splitn(2, '/');
    let (addr, prefix) = match (parts.next(), parts.next()) {
        (Some(a), Some(p)) => (a, p),
        _ => return false,
    };
    let prefix_ok = prefix.parse::<u8>().map(|p| p <= 32).unwrap_or(false);
    let octets: Vec<&str> = addr.split('.').collect();
    let addr_ok = octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok());
    prefix_ok && addr_ok
}

#[cfg(not(test))]
pub fn load() -> TsConfig {
    std::fs::read_to_string(CONFIG_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(config: &TsConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(config).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(CONFIG_PATH, json).map_err(|e| format!("write {CONFIG_PATH}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn cidr_requires_four_ipv4_octets_and_a_prefix_from_zero_to_32() {
        for (input, expected) in [
            ("0.0.0.0/0", true),
            ("255.255.255.255/32", true),
            ("192.0.2.0/24", true),
            ("192.0.2.0/33", false),
            ("192.0.2.0", false),
            ("192.0.2.256/32", false),
            ("192..2.0/24", false),
            ("2001:db8::/32", false),
        ] {
            assert_eq!(valid_cidr(input), expected, "{input}");
        }
    }

    #[test]
    fn partial_patch_preserves_omitted_fields() {
        let original = json!({
            "enabled": true,
            "enrolled": true,
            "hostname": "router-1",
            "advertise_routes": ["192.0.2.0/24"],
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
    fn invalid_cidr_stops_patch_after_hostname_assignment() {
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
        assert_eq!(config.hostname, "new-hostname");
        assert!(config.advertise_routes.is_empty());
        assert!(config.hold_wakelock);
        assert!(!config.tailscale_ssh);
    }
}
