//! Configuration facts used to choose between a live reload and a restart.
//! Preparation keeps these fields for checking the running core after reload
//! and for identifying the databases that validation needs.

use serde_yaml_ng::Value;

/// Only fields needed after the YAML tree is dropped. In particular this
/// excludes node payloads, rules, provider bodies and DNS filter lists.
#[derive(Clone, Debug, Default)]
pub(super) struct Facts {
    pub startup: Value,
    pub runtime: Value,
    pub groups: Vec<(String, bool)>,
    pub providers: Vec<String>,
    pub assets: Vec<super::geodata::Asset>,
    pub sniffing: bool,
}

impl Facts {
    pub fn from(config: &Value) -> Self {
        let keys = [
        "port", "socks-port", "redir-port", "tproxy-port", "mixed-port", "ss-config", "vmess-config", "tuic-server",
        "allow-lan", "bind-address", "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips",
        "inbound-tfo", "inbound-mptcp",
        "external-controller", "external-controller-tls", "external-controller-unix", "external-controller-pipe",
        "external-controller-routing-mark", "external-controller-cors", "external-doh-server", "secret",
        "external-ui", "external-ui-url", "external-ui-name",
    ];
        let mut startup = serde_yaml_ng::Mapping::new();
        for key in keys { if let Some(value) = config.get(key) { startup.insert(key.into(), value.clone()); } }
        for (section, keys) in [("tls", &["certificate", "private-key", "client-auth-type", "client-auth-cert", "ech-key"][..]), ("experimental", &["quic-go-disable-gso", "quic-go-disable-ecn"][..])] {
            for key in keys { if let Some(value) = config[section].get(*key) { startup.insert(format!("{section}.{key}").into(), value.clone()); } }
        }
        let mut runtime = serde_yaml_ng::Mapping::new();
        for key in ["interface-name", "mode", "log-level", "geodata-mode"] { if let Some(v) = config.get(key) { runtime.insert(key.into(), v.clone()); } }
        let groups = config["proxy-groups"].as_sequence().into_iter().flatten().map(|g| (g["name"].as_str().unwrap_or_default().into(), g["type"].as_str() == Some("select"))).collect();
        let providers = config["rule-providers"].as_mapping().into_iter().flat_map(|m| m.keys()).filter_map(|k| k.as_str().map(str::to_owned)).collect();
        let sniffing = config["sniffer"]["enable"].as_bool().unwrap_or(false);
        Self { startup: Value::Mapping(startup), runtime: Value::Mapping(runtime), groups, providers, assets: super::geodata::required(config), sniffing }
    }

    pub fn needs_restart(&self, next: &Self) -> bool {
        self.startup != next.startup || (self.runtime["geodata-mode"].as_bool() == Some(true) && next.runtime.get("geodata-mode").is_none())
    }
}

#[cfg(test)]
fn needs_restart(previous: &str, next: &str) -> bool {
    let (Ok(previous), Ok(next)) = (serde_yaml_ng::from_str(previous), serde_yaml_ng::from_str(next)) else { return true };
    Facts::from(&previous).needs_restart(&Facts::from(&next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_and_force_only_settings_require_a_restart() {
        for setting in ["tproxy-port: 1234", "lan-allowed-ips: [10.0.0.0/8]", "lan-disallowed-ips: [1.2.3.4/32]", "secret: different", "external-controller-routing-mark: 3", "tls: {certificate: new}", "experimental: {quic-go-disable-gso: true}", "experimental: {quic-go-disable-ecn: true}"] {
            assert!(needs_restart("{}", setting), "{setting}");
            assert!(needs_restart(setting, "{}"), "{setting}");
        }
        assert!(needs_restart("geodata-mode: true", "{}"));
        assert!(needs_restart("invalid: [", "{}"));
    }

    #[test]
    fn proxies_rules_dns_and_live_general_settings_reload() {
        for setting in ["proxies: [{name: changed}]", "rules: ['MATCH,REJECT']", "dns: {nameserver: [1.1.1.1]}", "listeners: [{name: download}]", "geodata-mode: true", "keep-alive-idle: 120", "tls: {custom-certifactes: [new]}", "experimental: {dialer-ip4p-convert: true}"] {
            assert!(!needs_restart("{}", setting), "{setting}");
        }
        assert!(!needs_restart("rules: []\nmode: rule", "mode: rule\nrules: []"));
    }
}
