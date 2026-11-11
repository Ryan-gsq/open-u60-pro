//! The agent's single writer of router network state
//! (`zte-agent/docs/relay-mihomo-architecture.md`, section 4): bounded tool
//! runs (`exec`), private files (`files`), the registry of every name and
//! number the network features use (`ids`), the only conntrack writer
//! (`conntrack`), owned nftables tables (`effect`) and admission of
//! conflicting owner writes (`admission`).

pub mod admission;
pub mod conntrack;
pub mod effect;
pub mod exec;
pub mod files;
pub mod ids;

use crate::boottime::{BootClock, Clock};

/// Seconds since boot (`CLOCK_BOOTTIME`, millisecond precision) for the
/// network owners' log lines: B31 has no `logread`, so the agent's log is the
/// only timeline of ZTE's rewrites and the agent's repairs.
pub fn uptime() -> String {
    let millis = BootClock.now().as_millis();
    format!("{}.{:03}", millis / 1000, millis % 1000)
}

/// `eprintln!` behind the boot-clock time (`[12345.678] [relay] …`).
#[macro_export]
macro_rules! netlog {
    ($($arg:tt)*) => {
        eprintln!("[{}] {}", $crate::netfx::uptime(), format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_boot_time_has_milliseconds() {
        let stamp = super::uptime();
        let (seconds, millis) = stamp.split_once('.').unwrap();
        assert!(seconds.parse::<u64>().is_ok());
        assert_eq!(millis.len(), 3);
    }
}

/// I1 (`relay-mihomo-architecture.md` section 4): the relay and Mihomo
/// write legacy iptables, nftables, addresses, routes, policy rules, kernel
/// settings and conntrack only through journaled `Transaction` steps and
/// `netfx` (owned tables, conntrack). A source scan of their non-test code,
/// run with every `cargo test`: a direct write fails it. Reads are not
/// writes. WireGuard and TTL keep their own legacy chains (`ids`) and are
/// not scanned.
#[cfg(test)]
mod boundary {
    use std::path::{Path, PathBuf};

    /// Network tools that only `netfx`/`net_tools` start as processes.
    const TOOLS: [&str; 8] = ["iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "nft", "conntrack", "ip", "sysctl"];

    /// Writes that stay where they are, with the reason: (file, the line's
    /// text or the command's argument that marks it).
    const ALLOWED: [(&str, &str, &str); 2] = [
        ("wifi_relay/steering.rs", "fs::write(BACKLOG", "the journaled `@u60-relay-steer` step's own command (apply/check/undo)"),
        (
            "wifi_relay/ipv6.rs",
            "change",
            "the session refreshes the lease lifetimes of addresses and routes its journal already holds (section 4.2); `change` creates nothing",
        ),
    ];

    fn allowed(file: &str, text: &str) -> bool {
        ALLOWED.iter().any(|(f, marker, _)| file.ends_with(f) && text.contains(marker))
    }

    /// The code before the file's test module.
    fn code(text: &str) -> &str {
        let end = ["\n#[cfg(test)]\nmod tests", "\n#[cfg(test)]\npub mod tests"].iter().filter_map(|m| text.find(m)).min();
        &text[..end.unwrap_or(text.len())]
    }

    /// The string literals of a call's arguments and whether `.run()`
    /// follows the call directly.
    fn call(text: &str, open: usize) -> (Vec<String>, bool) {
        let bytes = text.as_bytes();
        let (mut depth, mut at, mut literals) = (0usize, open, Vec::new());
        while at < bytes.len() {
            match bytes[at] {
                b'"' => {
                    let end = at + 1 + text[at + 1..].find('"').unwrap_or(0);
                    literals.push(text[at + 1..end].to_owned());
                    at = end;
                }
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            at += 1;
        }
        let after = text.get(at + 1..).unwrap_or("").trim_start();
        (literals, after.starts_with(".run()"))
    }

    fn violations(file: &str, text: &str) -> Vec<String> {
        let text = code(text);
        let mut found = Vec::new();
        let line_of = |at: usize| text[..at].lines().count();
        for tool in TOOLS {
            let needle = format!("Command::new(\"{tool}\")");
            for (at, _) in text.match_indices(&needle).filter(|(at, _)| !text[..*at].ends_with("Cmd::")) {
                found.push(format!("{file}:{} starts {tool} itself", line_of(at)));
            }
        }
        for (at, _) in text.match_indices("Cmd::new(") {
            let (literals, runs) = call(text, at + "Cmd::new".len());
            let Some((tool, args)) = literals.split_first() else { continue };
            let has = |words: &[&str]| args.iter().any(|a| words.contains(&a.as_str()));
            let write = match tool.as_str() {
                "conntrack" => true,
                "nft" => !has(&["list"]),
                "iptables" | "ip6tables" => runs && has(&["-A", "-I", "-D", "-N", "-X", "-F", "-R", "-P", "-Z", "-E"]),
                "ip" => {
                    let verbs = ["add", "del", "delete", "change", "replace", "flush", "append"];
                    let verb = args.iter().find(|a| verbs.contains(&a.as_str())).map_or("", String::as_str);
                    runs && has(&["addr", "address", "route", "rule"]) && !verb.is_empty() && !allowed(file, verb)
                }
                "sysctl" => runs && has(&["-w"]),
                _ => false,
            };
            if write {
                found.push(format!("{file}:{} writes with {tool} outside a journaled step or netfx", line_of(at)));
            }
        }
        let consts: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("\"/proc/sys/net"))
            .filter_map(|l| l.trim().strip_prefix("const ").or_else(|| l.trim().strip_prefix("pub const ")))
            .filter_map(|l| l.split(':').next())
            .collect();
        for (n, line) in text.lines().enumerate() {
            let writes = line.contains("fs::write(") || line.contains("File::create(") || line.contains("OpenOptions");
            let kernel = line.contains("/proc/sys/net") || consts.iter().any(|c| line.contains(&format!("({c}")) || line.contains(&format!("(&{c}")));
            if writes && kernel && !allowed(file, line) {
                found.push(format!("{file}:{} writes a kernel setting outside `@u60-sysctl` or a step", n + 1));
            }
        }
        found
    }

    fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") && path.file_name().is_some_and(|n| n != "tests.rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn the_relay_and_mihomo_write_network_state_only_through_netfx() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![src.join("wifi_relay.rs"), src.join("mihomo.rs")];
        sources(&src.join("wifi_relay"), &mut files);
        sources(&src.join("mihomo"), &mut files);
        assert!(files.len() > 20, "{files:?}");
        let mut found = Vec::new();
        for path in files {
            let name = path.strip_prefix(&src).unwrap().to_string_lossy().into_owned();
            found.extend(violations(&name, &std::fs::read_to_string(&path).unwrap()));
        }
        assert!(found.is_empty(), "{found:#?}");
    }

    #[test]
    fn the_scan_catches_each_kind_of_direct_write() {
        let cases = [
            r#"fn f() { Cmd::new("iptables", &["-w", "2", "-t", "filter", "-I", "INPUT", "1", "-j", "DROP"]).run(); }"#,
            r#"fn f() { Cmd::new("ip", &["-4", "route", "add", "default", "dev", "x"]).run(); }"#,
            r#"fn f() { Cmd::new("nft", &["delete", "table", "ip", "x"]); }"#,
            r#"fn f() { Cmd::new("conntrack", &["-D"]); }"#,
            r#"fn f() { Cmd::new("sysctl", &["-w", "net.ipv4.ip_forward=0"]).run(); }"#,
            r#"fn f() { std::process::Command::new("ip6tables"); }"#,
            r#"fn f() { fs::write("/proc/sys/net/ipv4/ip_forward", "0"); }"#,
            "const P: &str = \"/proc/sys/net/core/x\";\nfn f() { fs::write(P, \"1\"); }",
        ];
        for case in cases {
            assert_eq!(violations("case.rs", case).len(), 1, "{case}");
        }
        let fine = [
            r#"fn f() { Step::new(Cmd::new("iptables", &["-w", "2", "-t", "filter", "-N", "U60_X"]), Cmd::new("iptables", &["-X"])); }"#,
            r#"fn f() { Cmd::new("iptables", &["-w", "2", "-t", "nat", "-S", "redirect_chain"]).run(); }"#,
            r#"fn f() { Cmd::new("ip", &["-4", "route", "get", "1.1.1.1"]).run(); }"#,
            r#"fn f() { Cmd::new("nft", &["-t", "list", "table", "ip", "x"]).run(); }"#,
            r#"fn f() { fs::read_to_string("/proc/sys/net/ipv4/ip_forward"); }"#,
            "fn f() {}\n#[cfg(test)]\nmod tests {\n fn g() { Cmd::new(\"conntrack\", &[]); }\n}",
        ];
        for case in fine {
            assert!(violations("case.rs", case).is_empty(), "{case}");
        }
    }
}
