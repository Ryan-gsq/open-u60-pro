use serde_yaml_ng::Value;

pub(super) fn needs_restart(previous: &str, next: &str) -> bool {
    let (Ok(previous), Ok(next)) = (serde_yaml_ng::from_str::<Value>(previous), serde_yaml_ng::from_str::<Value>(next)) else { return true };
    let keys = [
        "port", "socks-port", "redir-port", "tproxy-port", "mixed-port", "ss-config", "vmess-config", "tuic-server",
        "allow-lan", "bind-address", "skip-auth-prefixes", "lan-allowed-ips", "lan-disallowed-ips",
        "inbound-tfo", "inbound-mptcp",
        "external-controller", "external-controller-tls", "external-controller-unix", "external-controller-pipe",
        "external-controller-routing-mark", "external-controller-cors", "external-doh-server", "secret",
        "external-ui", "external-ui-url", "external-ui-name",
    ];
    keys.iter().any(|key| previous.get(*key) != next.get(*key))
        || ["certificate", "private-key", "client-auth-type", "client-auth-cert", "ech-key"].iter().any(|key| previous["tls"].get(*key) != next["tls"].get(*key))
        || ["quic-go-disable-gso", "quic-go-disable-ecn"].iter().any(|key| previous["experimental"].get(*key) != next["experimental"].get(*key))
        || (previous["geodata-mode"].as_bool() == Some(true) && next.get("geodata-mode").is_none())
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
