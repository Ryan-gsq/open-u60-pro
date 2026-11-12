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

    const TOOLS: [&str; 8] = ["iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "nft", "conntrack", "ip", "sysctl"];

    // Match file, function AND command prefix; a new write in that file still fails.
    const ALLOWED: &[(&str, &str, &str, &str)] = &[
        ("wifi_relay.rs", "prepare", "ip link set dev {IFACE} address {mac}", "the wireless journal deletes the station interface, so its MAC cannot outlive the session and needs no guard replay"),
        ("wifi_relay.rs", "prepare", "ip link set dev {IFACE} up", "the wireless journal deletes the station interface, so its link state cannot outlive the session and needs no guard replay"),
        ("wifi_relay/steering.rs", "command", "fs::write BACKLOG", "the journaled @u60-relay-steer step implements its backlog apply/undo here"),
        ("wifi_relay/ipv6.rs", "tick_inner", "ip -6 addr change", "refresh only the lifetime of the LAN address already held by the IPv6 journal"),
        ("wifi_relay/ipv6.rs", "refresh_path", "ip -6 addr change", "refresh only the lifetimes of upstream addresses already held by the IPv6 journal"),
        ("wifi_relay/ipv6.rs", "lan_route", "ip -6 route {action}", "this command factory feeds journaled steps and refreshes their existing finite lifetimes"),
        ("wifi_relay/ipv6.rs", "default_route", "ip -6 route {action}", "this command factory feeds journaled steps and refreshes their existing finite lifetimes"),
        ("wifi_relay/ipv6.rs", "address_step", "ip -6 addr del", "replace the undo on the Step returned by this address-step factory"),
        ("wifi_relay/offload/neighbours.rs", "retire_steps", "ip -4 neigh replace", "move each non-gateway MAC to a spare IPv4 address and back so IPACM drops its uplink-stealing WAN rule"),
        ("wifi_relay/offload/neighbours.rs", "retire_steps", "ip -4 neigh del", "remove that spare neighbour after IPACM drops the non-gateway MAC's uplink-stealing WAN rule"),
        ("wifi_relay/offload/clients.rs", "stale", "ip -4 neigh change", "set an existing LAN neighbour STALE after association so IPACM restores the band-switched client's LAN route"),
    ];

    #[derive(Debug)]
    struct Token {
        value: String,
        literal: bool,
        at: usize,
    }

    fn tokens(text: &str) -> Vec<Token> {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let start = at;
            if bytes[at].is_ascii_whitespace() {
                at += 1;
                continue;
            }
            if bytes[at..].starts_with(b"//") {
                at += text[at..].find('\n').unwrap_or(bytes.len() - at);
                continue;
            }
            if bytes[at..].starts_with(b"/*") {
                at += 2;
                let mut depth = 1;
                while at < bytes.len() && depth > 0 {
                    if bytes[at..].starts_with(b"/*") {
                        depth += 1;
                        at += 2;
                    } else if bytes[at..].starts_with(b"*/") {
                        depth -= 1;
                        at += 2;
                    } else {
                        at += 1;
                    }
                }
                continue;
            }
            let raw = if bytes[at] == b'r' {
                let hashes = bytes[at + 1..].iter().take_while(|b| **b == b'#').count();
                (bytes.get(at + hashes + 1) == Some(&b'"')).then_some(hashes)
            } else {
                None
            };
            if let Some(hashes) = raw {
                let content = at + hashes + 2;
                let close = format!("\"{}", "#".repeat(hashes));
                let end = content + text[content..].find(&close).unwrap_or(bytes.len() - content);
                out.push(Token { value: text[content..end].into(), literal: true, at });
                at = (end + close.len()).min(bytes.len());
                continue;
            }
            if bytes[at] == b'"' {
                at += 1;
                let mut value = String::new();
                while at < bytes.len() && bytes[at] != b'"' {
                    let character = text[at..].chars().next().unwrap();
                    at += character.len_utf8();
                    if character != '\\' {
                        value.push(character);
                        continue;
                    }
                    let Some(&escaped) = bytes.get(at) else { break };
                    at += 1;
                    match escaped {
                        b'n' => value.push('\n'),
                        b'r' => value.push('\r'),
                        b't' => value.push('\t'),
                        b'x' if at + 2 <= bytes.len() => {
                            if let Ok(code) = u8::from_str_radix(&text[at..at + 2], 16) {
                                value.push(char::from(code));
                            }
                            at += 2;
                        }
                        b'u' if bytes.get(at) == Some(&b'{') => {
                            if let Some(end) = text[at..].find('}') {
                                let digits = text[at + 1..at + end].replace('_', "");
                                if let Some(character) = u32::from_str_radix(&digits, 16).ok().and_then(char::from_u32) {
                                    value.push(character);
                                }
                                at += end + 1;
                            }
                        }
                        b'\n' => {
                            while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
                                at += 1;
                            }
                        }
                        _ => value.push(char::from(escaped)),
                    }
                }
                out.push(Token { value, literal: true, at: start });
                at = (at + 1).min(bytes.len());
                continue;
            }
            if bytes[at] == b'\'' {
                let mut end = at + 1;
                if bytes.get(end) == Some(&b'\\') {
                    end += 2;
                } else if let Some(character) = text[end..].chars().next() {
                    end += character.len_utf8();
                }
                if bytes.get(end) == Some(&b'\'') {
                    at = end + 1;
                    out.push(Token { value: text[start..at].into(), literal: true, at: start });
                    continue;
                }
            }
            if bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_' {
                at += 1;
                while bytes.get(at).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_') {
                    at += 1;
                }
            } else {
                at += text[at..].chars().next().unwrap().len_utf8();
            }
            out.push(Token { value: text[start..at].into(), literal: false, at: start });
        }
        out
    }

    struct Scan {
        tokens: Vec<Token>,
        close: Vec<usize>,
        tests: Vec<bool>,
        functions: Vec<(String, usize, usize)>,
    }

    impl Scan {
        fn new(text: &str) -> Self {
            let tokens = tokens(text);
            let mut close = vec![0; tokens.len()];
            let mut stack = Vec::new();
            for (index, token) in tokens.iter().enumerate().filter(|(_, token)| !token.literal) {
                match token.value.as_str() {
                    "(" | "[" | "{" => stack.push(index),
                    ")" | "]" | "}" => {
                        if let Some(open) = stack.pop() {
                            close[open] = index;
                        }
                    }
                    _ => {}
                }
            }
            let mut scan = Self { tests: vec![false; tokens.len()], tokens, close, functions: Vec::new() };
            for index in 0..scan.tokens.len() {
                if scan.is(index, "#") && scan.is(index + 1, "[") {
                    let end = scan.close[index + 1];
                    let attribute = scan.join(index + 2, end);
                    if attribute == "cfg(test)" || attribute == "test" {
                        let item_end = scan.body_end(end + 1);
                        scan.tests[index..=item_end].fill(true);
                    }
                }
                if scan.is(index, "fn") && index + 1 < scan.tokens.len() {
                    let end = scan.body_end(index + 2);
                    scan.functions.push((scan.tokens[index + 1].value.clone(), index, end));
                }
            }
            scan
        }

        fn is(&self, index: usize, value: &str) -> bool {
            self.tokens.get(index).is_some_and(|token| !token.literal && token.value == value)
        }

        fn join(&self, start: usize, end: usize) -> String {
            self.tokens[start..end].iter().map(|token| token.value.as_str()).collect()
        }

        fn body_end(&self, mut index: usize) -> usize {
            while index < self.tokens.len() {
                if self.is(index, "{") {
                    return self.close[index];
                }
                if self.is(index, ";") {
                    return index;
                }
                index = self.close[index].max(index) + 1;
            }
            self.tokens.len().saturating_sub(1)
        }

        fn function(&self, at: usize) -> &str {
            self.functions.iter().rev().find(|(_, start, end)| *start < at && at < *end).map_or("", |(name, _, _)| name)
        }

        fn parts(&self, start: usize, end: usize) -> Vec<(usize, usize)> {
            let mut out = Vec::new();
            let mut part = start;
            let mut index = start;
            while index < end {
                if self.is(index, ",") {
                    out.push((part, index));
                    part = index + 1;
                }
                index = self.close[index].max(index) + 1;
            }
            if part < end {
                out.push((part, end));
            }
            out
        }

        fn binding(&self, name: &str, before: usize) -> Option<(usize, usize)> {
            for index in (0..before).rev() {
                if self.tests[index] {
                    continue;
                }
                if !self.is(index, "let") && !self.is(index, "const") && !self.is(index, "static") {
                    continue;
                }
                let name_at = index + 1 + usize::from(self.is(index + 1, "mut"));
                if !self.is(name_at, name) {
                    continue;
                }
                if self.is(index, "let") && self.function(index) != self.function(before) {
                    continue;
                }
                let end = (name_at + 1..before).find(|at| self.is(*at, ";"))?;
                if let Some(equal) = (name_at + 1..end).find(|at| self.is(*at, "=")) {
                    return Some((equal + 1, end));
                }
            }
            None
        }

        fn values(&self, mut start: usize, mut end: usize, depth: usize) -> Vec<String> {
            while self.is(start, "&") {
                start += 1;
            }
            if start >= end || depth > 8 {
                return vec!["{dynamic}".into()];
            }
            if self.is(start, "[") && self.close[start] == end - 1 {
                return self.parts(start + 1, end - 1).into_iter().flat_map(|(start, end)| self.values(start, end, depth + 1)).collect();
            }
            if end == start + 1 {
                if self.tokens[start].literal {
                    return vec![self.tokens[start].value.clone()];
                }
                if let Some((value, finish)) = self.binding(&self.tokens[start].value, start) {
                    let values = self.values(value, finish, depth + 1);
                    if values.iter().all(|value| !value.starts_with('{')) {
                        return values;
                    }
                }
            }
            end = end.min(start + 20);
            vec![format!("{{{}}}", self.join(start, end))]
        }

        fn step_contains(&self, at: usize) -> bool {
            (0..at).rev().any(|index| {
                self.is(index, "Step") && self.is(index + 1, ":") && self.is(index + 2, ":") && self.is(index + 3, "new")
                    && self.is(index + 4, "(") && index + 4 < at && self.close[index + 4] > at
            })
        }

        fn journaled(&self, at: usize, end: usize) -> bool {
            if self.is(end + 1, ".") && !self.is(end + 2, "clone") {
                return false;
            }
            if self.step_contains(at) {
                return true;
            }
            let Some(equal) = at.checked_sub(1).filter(|equal| self.is(*equal, "=")) else { return false };
            let Some(let_at) = (0..equal).rev().take_while(|index| !self.is(*index, ";") && !self.is(*index, "{")).find(|index| self.is(*index, "let")) else { return false };
            let name_at = let_at + 1 + usize::from(self.is(let_at + 1, "mut"));
            let name = &self.tokens[name_at].value;
            let mut used = false;
            for index in end + 1..self.tokens.len() {
                if self.function(index) == self.function(at) && self.is(index, name) {
                    used = true;
                    if !self.step_contains(index) {
                        return false;
                    }
                }
            }
            used
        }
    }

    fn writes(tool: &str, args: &[String]) -> bool {
        let has = |words: &[&str]| args.iter().any(|arg| words.contains(&arg.as_str()));
        let dynamic = || args.iter().any(|arg| arg.starts_with('{'));
        match tool {
            "conntrack" | "iptables-restore" | "ip6tables-restore" => true,
            "iptables" | "ip6tables" => {
                has(&["-A", "-I", "-D", "-N", "-X", "-F", "-R", "-P", "-Z", "-E", "--append", "--insert", "--delete", "--new-chain", "--delete-chain", "--flush", "--replace", "--policy", "--zero", "--rename-chain"])
                    || (!has(&["-S", "-L", "-C", "--list", "--list-rules", "--check"]) && dynamic())
            }
            "nft" => has(&["add", "create", "insert", "replace", "delete", "destroy", "flush", "reset", "rename", "import", "-f", "--file"])
                || !has(&["list", "get", "monitor", "--help", "--version"]),
            "ip" => {
                has(&["add", "del", "delete", "change", "replace", "flush", "append", "set", "restore", "update", "prepend", "create", "destroy", "attach", "detach", "-b", "-batch"])
                    || (!has(&["show", "list", "get", "help", "monitor", "save"]) && dynamic())
            }
            "sysctl" => has(&["-w", "--write", "-p", "--load", "--system"]) || args.iter().any(|arg| arg.contains('=')) || dynamic(),
            _ => false,
        }
    }

    fn violations(file: &str, text: &str) -> Vec<String> {
        scan_writes(file, text, true)
    }

    fn scan_writes(file: &str, text: &str, exemptions: bool) -> Vec<String> {
        let scan = Scan::new(text);
        let mut found = Vec::new();
        for at in 0..scan.tokens.len() {
            if scan.tests[at] {
                continue;
            }
            let constructor = (scan.is(at, "Cmd") || scan.is(at, "Command")) && scan.is(at + 1, ":") && scan.is(at + 2, ":") && scan.is(at + 3, "new") && scan.is(at + 4, "(");
            let mut command = None;
            if constructor {
                let end = scan.close[at + 4];
                let parts = scan.parts(at + 5, end);
                if let Some(&(start, finish)) = parts.first() {
                    let program = scan.values(start, finish, 0).join(" ");
                    let tool = program.rsplit('/').next().unwrap();
                    if TOOLS.contains(&tool) {
                        let args = parts.get(1).map_or_else(Vec::new, |&(start, end)| scan.values(start, end, 0));
                        if scan.is(at, "Command") || (writes(tool, &args) && !scan.journaled(at, end)) {
                            command = Some(std::iter::once(program).chain(args).collect::<Vec<_>>().join(" "));
                        }
                    }
                }
            }
            let write = scan.is(at, "fs") && scan.is(at + 3, "write") || scan.is(at, "File") && scan.is(at + 3, "create");
            let open = scan.is(at, "OpenOptions") && scan.is(at + 3, "new");
            if write && scan.is(at + 4, "(") {
                if let Some(&(start, end)) = scan.parts(at + 5, scan.close[at + 4]).first() {
                    let paths = scan.values(start, end, 0);
                    if paths.iter().any(|path| path.contains("/proc/sys/")) {
                        command = Some(format!("{}::{} {}", scan.tokens[at].value, scan.tokens[at + 3].value, scan.join(start, end)));
                    }
                }
            }
            if open {
                let end = (at..scan.tokens.len()).find(|index| scan.is(*index, ";")).unwrap_or(scan.tokens.len());
                let writing = (at..end).any(|index| (scan.is(index, "write") || scan.is(index, "append") || scan.is(index, "truncate") || scan.is(index, "create")) && scan.is(index + 1, "(") && scan.is(index + 2, "true"));
                for index in at..end {
                    if writing && scan.is(index, "open") && scan.is(index + 1, "(") {
                        let paths = scan.values(index + 2, scan.close[index + 1], 0);
                        if paths.iter().any(|path| path.contains("/proc/sys/")) {
                            command = Some(format!("OpenOptions write {}", paths.join(" ")));
                        }
                    }
                }
            }
            if let Some(command) = command {
                let function = scan.function(at);
                if exemptions && ALLOWED.iter().any(|(path, name, prefix, reason)| file == *path && function == *name && (command == *prefix || (function != "prepare" && command.starts_with(&format!("{prefix} ")))) && !reason.is_empty()) {
                    continue;
                }
                let line = text[..scan.tokens[at].at].bytes().filter(|byte| *byte == b'\n').count() + 1;
                found.push(format!("{file}:{line} ({function}): {command}; use an owner's Transaction Step or netfx effect; intentional exceptions need a function + command and a reason in netfx::boundary::ALLOWED"));
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
            r#"fn f() { Cmd::new("ip6tables", &["--append", "INPUT", "-j", "DROP"]); }"#,
            r#"fn f() { Cmd::new("iptables-restore", &["--noflush"]); }"#,
            r#"fn f() { Cmd::new("ip6tables-restore", &[]); }"#,
            r#"fn f() { Cmd::new("ip", &["-4", "route", "add", "default", "dev", "x"]).run(); }"#,
            r#"fn f() { Cmd::new("ip", &["-6", "addr", "change", "::1/128", "dev", "lo"]); }"#,
            r#"fn f() { Cmd::new("ip", &["rule", "del", "pref", "900"]); }"#,
            r#"fn f() { Cmd::new("ip", &["neigh", "replace", "192.0.2.1", "dev", "x"]); }"#,
            r#"fn f() { Cmd::new("ip", &["neigh", "change", "192.0.2.1", "nud", "stale"]); }"#,
            r#"fn f() { Cmd::new("ip", &["neigh", "del", "192.0.2.1"]); }"#,
            r#"fn f() { Cmd::new("ip", &["link", "set", "dev", "x", "up"]); }"#,
            r#"fn f() { Cmd::new("ip", &["netns", "add", "x"]); }"#,
            r#"fn f() { Cmd::new("ip", &["tunnel", "change", "x"]); }"#,
            r#"fn f() { Cmd::new("nft", &["delete", "table", "ip", "x"]); }"#,
            r#"fn f() { Cmd::new("nft", &["-f", "/data/rules"]); }"#,
            r#"fn f() { Cmd::new("nft", &["list", "ruleset", ";", "flush", "ruleset"]); }"#,
            r#"fn f() { Cmd::new("conntrack", &["-D"]); }"#,
            r#"fn f() { Cmd::new("sysctl", &["-w", "net.ipv4.ip_forward=0"]).run(); }"#,
            r#"fn f() { Cmd::new("sysctl", &["--write", "net.ipv4.ip_forward=0"]); }"#,
            r#"fn f() { std::process::Command::new("ip6tables"); }"#,
            r#"fn f() { fs::write("/proc/sys/net/ipv4/ip_forward", "0"); }"#,
            r#"fn f() { std::fs::write("/proc/sys/kernel/test", "0"); }"#,
            r#"fn f() { File::create("/proc/sys/net/ipv4/ip_forward"); }"#,
            r#"fn f() { OpenOptions::new().write(true).open("/proc/sys/net/ipv4/ip_forward"); }"#,
            "const P: &str = \"/proc/sys/net/core/x\";\nfn f() { fs::write(P, \"1\"); }",
        ];
        for case in cases {
            assert_eq!(violations("case.rs", case).len(), 1, "{case}");
        }
        let fine = [
            r#"fn f() { Step::new(Cmd::new("iptables", &["-w", "2", "-t", "filter", "-N", "U60_X"]), Cmd::new("iptables", &["-X"])); }"#,
            r#"fn f() { Cmd::new("iptables", &["-w", "2", "-t", "nat", "-S", "redirect_chain"]).run(); }"#,
            r#"fn f() { Cmd::new("ip", &["-4", "route", "get", "1.1.1.1"]).run(); }"#,
            r#"fn f() { Cmd::new("ip", &["route", "show"]).run(); }"#,
            r#"fn f() { Cmd::new("ip", &["addr", "show"]); Cmd::new("ip", &["rule", "list"]); }"#,
            r#"fn f() { Cmd::new("ip", &["neigh", "show"]); Cmd::new("ip", &["link", "show"]); }"#,
            r#"fn f() { Cmd::new("ip6tables", &["--check", "INPUT", "-j", "DROP"]); }"#,
            r#"fn f() { Cmd::new("nft", &["-t", "list", "table", "ip", "x"]).run(); }"#,
            r#"fn f() { Cmd::new("sysctl", &["net.ipv4.ip_forward"]); }"#,
            r#"fn f() { fs::read_to_string("/proc/sys/net/ipv4/ip_forward"); }"#,
            r#"fn f() { OpenOptions::new().read(true).open("/proc/sys/net/ipv4/ip_forward"); }"#,
            "fn f() {}\n#[cfg(test)]\nmod tests {\n fn g() { Cmd::new(\"conntrack\", &[]); }\n}",
        ];
        for case in fine {
            assert!(violations("case.rs", case).is_empty(), "{case}");
        }
    }

    #[test]
    fn the_scan_checks_construction_even_when_execution_is_later() {
        for (tool, args) in [
            ("ip", r#"["route", "add", "default"]"#),
            ("ip", r#"["neigh", "change", "192.0.2.1", "nud", "stale"]"#),
            ("iptables", r#"["-A", "INPUT", "-j", "DROP"]"#),
            ("ip6tables", r#"["-F", "INPUT"]"#),
            ("nft", r#"["flush", "ruleset"]"#),
            ("sysctl", r#"["-w", "net.ipv4.ip_forward=1"]"#),
            ("conntrack", r#"["-D"]"#),
        ] {
            let source = format!("fn f() {{\n let command = Cmd::new(\"{tool}\", &{args});\n command.run();\n}}");
            let found = violations("case.rs", &source);
            assert_eq!(found.len(), 1, "{source}: {found:?}");
            assert!(found[0].contains("case.rs:2 (f):"), "{found:?}");
            assert!(found[0].contains(tool) && found[0].contains("Transaction Step"), "{found:?}");
            assert!(violations("case.rs", &format!("// {source}").replace('\n', "\n// ")).is_empty());
            assert!(violations("case.rs", &format!("/* {source} */")).is_empty());
            assert!(violations("case.rs", &format!("const SOURCE: &str = {source:?};")).is_empty());
        }
        for source in [
            r#"fn f() { let args = ["link", "set", "x", "up"]; let c = Cmd::new("ip", &args); c.run(); }"#,
            r#"fn f() { let program = "ip"; Cmd :: new (program, &["route", "add", "default"]); }"#,
            r#"fn f() { let path = "/proc/sys/net/ipv4/ip_forward"; fs::write(&path, "0"); }"#,
        ] {
            assert_eq!(violations("case.rs", source).len(), 1, "{source}");
        }
    }

    #[test]
    fn the_scan_only_accepts_commands_owned_by_a_step() {
        for (tool, args) in [
            ("ip", r#"["link", "set", "x", "up"]"#),
            ("iptables", r#"["-A", "INPUT", "-j", "DROP"]"#),
            ("ip6tables", r#"["-F", "INPUT"]"#),
            ("nft", r#"["flush", "ruleset"]"#),
            ("sysctl", r#"["-w", "net.ipv4.ip_forward=1"]"#),
        ] {
            let source = format!("fn f() {{ tx.apply(Step::new(Cmd::new(\"{tool}\", &{args}), Cmd::new(\"true\", &[]))); }}");
            assert!(violations("case.rs", &source).is_empty(), "{source}");
            let source = format!("fn f() {{ let command = Cmd::new(\"{tool}\", &{args}); tx.apply(Step::new(command, Cmd::new(\"true\", &[]))); }}");
            assert!(violations("case.rs", &source).is_empty(), "{source}");
        }
        for source in [
            r#"fn f() { Step::new(Cmd::new("ip", &["link", "set", "x", "up"]).run(), Cmd::new("true", &[])); }"#,
            r#"fn f() { let c = Cmd::new("ip", &["route", "add", "default"]); c.run(); Step::new(c, Cmd::new("true", &[])); }"#,
        ] {
            assert_eq!(violations("case.rs", source).len(), 1, "{source}");
        }
    }

    #[test]
    fn the_scan_ignores_comments_literals_and_test_items_without_truncating_the_file() {
        let source = r####"
            // Cmd::new("ip", &["route", "add", "default"]);
            /* outer /* Cmd::new("nft", &["flush", "ruleset"]); */ nested */
            const TEXT: &str = "Cmd::new(\"sysctl\", &[\"-w\", \"x=1\"]);";
            const RAW: &str = r###"Cmd::new("ip", &["link", "set"]); /* # [cfg(test)] */"###;
            fn f() { let text = "quote: \" ) } //"; let brace = '}'; }
            #[cfg(test)] pub(crate) mod checks { fn f() { Cmd::new("conntrack", &[]); } }
            #[cfg(test)] fn helper() { Cmd::new("nft", &["flush", "ruleset"]); }
            #[test] fn test() { Cmd::new("iptables", &["-F"]); }
        "####;
        assert!(violations("case.rs", source).is_empty());
        let after = format!("{source}\nfn production() {{ Cmd::new(\"ip\", &[\"route\", \"add\", \"default\"]); }}");
        assert_eq!(violations("case.rs", &after).len(), 1);
        assert!(violations("netfx.rs", include_str!("netfx.rs")).is_empty());
    }

    #[test]
    fn exemptions_match_the_function_and_command_not_the_file_or_comments() {
        let permitted = r#"fn refresh_path() { Cmd::new("ip", &["-6", "addr", "change", "::1/128", "dev", "x"]); }"#;
        assert!(violations("wifi_relay/ipv6.rs", permitted).is_empty());
        assert_eq!(scan_writes("wifi_relay/ipv6.rs", permitted, false).len(), 1);
        for source in [
            permitted.replace("refresh_path", "other"),
            permitted.replace("\"change\"", "\"replace\""),
            permitted.replace("\"addr\"", "\"link\""),
            format!("// fn refresh_path()\n{}", permitted.replace("refresh_path", "other")),
        ] {
            assert_eq!(violations("wifi_relay/ipv6.rs", &source).len(), 1, "{source}");
        }
        for (file, function, verb) in [
            ("wifi_relay/offload/neighbours.rs", "retire_steps", "replace"),
            ("wifi_relay/offload/neighbours.rs", "retire_steps", "del"),
            ("wifi_relay/offload/clients.rs", "stale", "change"),
        ] {
            let source = format!("fn {function}() {{ Cmd::new(\"ip\", &[\"-4\", \"neigh\", \"{verb}\", \"192.0.2.1\"]); }}");
            assert!(violations(file, &source).is_empty(), "{source}");
            assert_eq!(violations(file, &source.replace(function, "other")).len(), 1);
        }
        for args in [r#"["link", "set", "dev", IFACE, "address", &mac]"#, r#"["link", "set", "dev", IFACE, "up"]"#] {
            let source = format!("fn prepare() {{ Cmd::new(\"ip\", &{args}); }}");
            assert!(violations("wifi_relay.rs", &source).is_empty(), "{source}");
            assert!(violations("wifi_relay.rs", &format!("\n\n{source}")).is_empty());
            for bad in [source.replace("prepare", "other"), source.replace("IFACE", "other"), source.replace("\"link\"", "\"route\"")] {
                assert_eq!(violations("wifi_relay.rs", &bad).len(), 1, "{bad}");
            }
        }
    }

    #[test]
    fn every_exception_is_still_needed_and_reports_its_reason() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for (file, function, prefix, reason) in ALLOWED {
            let text = std::fs::read_to_string(src.join(file)).unwrap();
            let raw = scan_writes(file, &text, false);
            let filtered = violations(file, &text);
            let marker = format!("({function}): {prefix}");
            let hits: Vec<_> = raw.iter().filter(|hit| hit.contains(&marker) && !filtered.contains(hit)).collect();
            assert!(!hits.is_empty(), "stale exception: {file} {function} {prefix}: {reason}");
            for hit in hits {
                println!("EXEMPT {hit}\n  reason: {reason}");
            }
        }
    }
}
