//! B31's offline DNS portal follows cellular state, not our Wi-Fi uplink.
//! Suppress it with one volatile UCI delta; never commit or restore a snapshot.
//! LAN web traffic also skips the vendor's offline redirect (`redirect_chain`,
//! both families) through a RETURN that must sit before every vendor rule
//! there: a present rule (`-C`) behind a DNAT proves nothing.

use crate::net_tools::{Cmd, Step};

const KEY: &str = "zwrt_redirect.redirect.switch";
const PACKAGE: &str = "zwrt_redirect";
const CHAIN: &str = "redirect_chain";
const COMMENT: &str = "zte-agent-wifi-relay";
/// The RETURN, as given to iptables.
const BYPASS: [&str; 7] = ["-i", "br-lan", "-m", "comment", "--comment", COMMENT, "-j"];

pub(super) fn plan() -> Result<Option<Step>, String> {
    plan_with(&mut |cmd| cmd.run())
}

fn bypass() -> Vec<&'static str> {
    let mut rule = BYPASS.to_vec();
    rule.push("RETURN");
    rule
}

/// Skips only the vendor's offline-portal chain, not the rest of NAT or any
/// filter policy: direct management and configured port forwards survive.
/// Applied (and re-checked) as `@u60-relay-portal-return`, which places it
/// first; its undo is the plain `-D` every agent version runs.
pub(super) fn web_bypass(tool: &str) -> Step {
    let rule = crate::net_tools::rule(tool, "nat", CHAIN, &bypass(), true);
    Step::new(Cmd::new("@u60-relay-portal-return", &[tool]), rule.undo)
}

/// Where the RETURN is in a `-S redirect_chain` listing.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Place {
    First,
    /// Behind a vendor rule (a DNAT may come first).
    Late,
    Absent,
}

fn place(listing: &str) -> Place {
    let ours = format!("-A {CHAIN} {}", bypass().join(" "));
    let mut vendor = false;
    for line in listing.lines().map(str::trim).filter(|l| l.starts_with(&format!("-A {CHAIN} "))) {
        if line == ours {
            return if vendor { Place::Late } else { Place::First };
        }
        vendor = true;
    }
    Place::Absent
}

fn tool(args: &[String]) -> Result<&'static str, String> {
    match args {
        [tool] if tool == "iptables" => Ok("iptables"),
        [tool] if tool == "ip6tables" => Ok("ip6tables"),
        _ => Err("Invalid relay portal bypass".into()),
    }
}

fn listing(tool: &str) -> Result<String, String> {
    Cmd::new(tool, &["-w", "2", "-t", "nat", "-S", CHAIN]).run()
}

/// `@u60-relay-portal-return <tool>`: puts the RETURN first. One behind a
/// vendor rule is moved in one restore transaction (deleted and inserted
/// first together), so it is never missing and nothing of the vendor's is
/// touched.
pub(crate) fn place_return(args: &[String]) -> Result<(), String> {
    let tool = tool(args)?;
    let input = moves(place(&listing(tool)?));
    match input {
        None => Ok(()),
        Some(input) => crate::net_tools::firewall::restore(&format!("{tool}-restore"), input),
    }
}

/// The restore transaction that puts the RETURN first from `at`.
pub(super) fn moves(at: Place) -> Option<String> {
    let rule = bypass().join(" ");
    match at {
        Place::First => None,
        Place::Absent => Some(format!("*nat\n-I {CHAIN} 1 {rule}\nCOMMIT\n")),
        Place::Late => Some(format!("*nat\n-D {CHAIN} {rule}\n-I {CHAIN} 1 {rule}\nCOMMIT\n")),
    }
}

/// Whether the RETURN is in place: present and ahead of every vendor rule.
pub(crate) fn return_first(args: &[String]) -> Result<bool, String> {
    Ok(place(&listing(tool(args)?)?) == Place::First)
}

fn plan_with(run: &mut impl FnMut(&Cmd) -> Result<String, String>) -> Result<Option<Step>, String> {
    match current(run)?.as_str() {
        "0" => Ok(None),
        "1" if switch_delta(&run(&Cmd::new("uci", &["-q", "changes", PACKAGE]))?).is_none() => {
            Ok(Some(Step::new(
                Cmd::new("@u60-relay-portal", &["disable"]),
                Cmd::new("@u60-relay-portal", &["release"]),
            )))
        }
        _ => Err("Offline redirect setting has pending or unsupported changes; finish those before connecting relay".into()),
    }
}

fn current(run: &mut impl FnMut(&Cmd) -> Result<String, String>) -> Result<String, String> {
    run(&Cmd::new("uci", &["-q", "get", KEY]))
        .map(|value| value.trim().to_owned())
        .map_err(|_| "Cannot read firmware offline redirect setting".into())
}

fn switch_delta(changes: &str) -> Option<&str> {
    changes.lines().find(|line| {
        let line = line.strip_prefix('-').unwrap_or(line);
        line == KEY
            || line
                .strip_prefix(KEY)
                .is_some_and(|rest| rest.starts_with('='))
    })
}

fn owned_delta(changes: &str) -> bool {
    switch_delta(changes) == Some("zwrt_redirect.redirect.switch='0'")
}

pub(crate) fn command(args: &[String]) -> Result<(), String> {
    command_with(args, &mut |cmd| cmd.run())
}

fn command_with(
    args: &[String],
    run: &mut impl FnMut(&Cmd) -> Result<String, String>,
) -> Result<(), String> {
    match args {
        [action] if action == "disable" => {
            let value = current(run)?;
            let changes = run(&Cmd::new("uci", &["-q", "changes", PACKAGE]))?;
            if value == "1" && switch_delta(&changes).is_none() {
                run(&Cmd::new("uci", &["set", &format!("{KEY}=0")]))?;
            } else if value != "0" || !owned_delta(&changes) {
                return Err("Offline redirect changed while connecting relay; retry".into());
            }
        }
        [action] if action == "release" => {
            let changes = run(&Cmd::new("uci", &["-q", "changes", PACKAGE]))?;
            if owned_delta(&changes) && current(run)? == "0" {
                // A vendor/user commit consumes the delta. In that case the
                // current persisted choice wins, including after a reboot.
                run(&Cmd::new("uci", &["revert", KEY]))?;
            }
        }
        _ => return Err("Invalid relay offline redirect command".into()),
    }
    // B31 reads this switch at process start; SIGHUP leaves it unchanged.
    // Repeat on recovery even if revert already succeeded before a crash.
    run(&Cmd::new("/etc/init.d/dnsmasq", &["restart"]))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Firmware {
        persisted: String,
        delta: Option<String>,
        unrelated: String,
        serving_redirect: bool,
        fail_restart: bool,
        calls: Vec<Cmd>,
    }

    impl Firmware {
        fn new() -> Self {
            Self {
                persisted: "1".into(),
                delta: None,
                unrelated: "zwrt_redirect.redirect.each_user_redirect='0'".into(),
                serving_redirect: true,
                fail_restart: false,
                calls: Vec::new(),
            }
        }

        fn run(&mut self, cmd: &Cmd) -> Result<String, String> {
            self.calls.push(cmd.clone());
            let args: Vec<_> = cmd.args.iter().map(String::as_str).collect();
            match (cmd.program.as_str(), args.as_slice()) {
                ("uci", ["-q", "get", KEY]) => {
                    Ok(self.delta.as_ref().unwrap_or(&self.persisted).clone())
                }
                ("uci", ["-q", "changes", PACKAGE]) => Ok(format!(
                    "{}\n{}",
                    self.unrelated,
                    self.delta
                        .as_ref()
                        .map(|d| format!("{KEY}='{d}'"))
                        .unwrap_or_default()
                )),
                ("uci", ["set", "zwrt_redirect.redirect.switch=0"]) => {
                    self.delta = Some("0".into());
                    Ok(String::new())
                }
                ("uci", ["revert", KEY]) => {
                    self.delta = None;
                    Ok(String::new())
                }
                ("/etc/init.d/dnsmasq", ["restart"]) => {
                    if self.fail_restart {
                        return Err("restart failed".into());
                    }
                    self.serving_redirect = self.delta.as_ref().unwrap_or(&self.persisted) == "1";
                    Ok(String::new())
                }
                _ => panic!("unexpected command: {cmd:?}"),
            }
        }

        fn action(&mut self, action: &str) -> Result<(), String> {
            command_with(&[action.into()], &mut |cmd| self.run(cmd))
        }
    }

    #[test]
    fn the_redirect_return_must_come_before_every_vendor_rule() {
        let ours = "-A redirect_chain -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN";
        let dnat = "-A redirect_chain -i br-lan -p tcp -m tcp --dport 80 -j DNAT --to-destination 192.168.0.1:8080";
        assert_eq!(place(&format!("-N redirect_chain\n{ours}\n{dnat}\n")), Place::First);
        assert_eq!(place(&format!("-N redirect_chain\n{dnat}\n{ours}\n")), Place::Late, "present (-C succeeds) but behind the DNAT");
        assert_eq!(place(&format!("-N redirect_chain\n{dnat}\n")), Place::Absent);
        assert_eq!(place("-N redirect_chain\n-A redirect_chain -i br-lan -m comment --comment zte-agent-wifi-relay-old -j RETURN\n"), Place::Absent);
        assert_eq!(moves(Place::First), None);
        assert_eq!(moves(Place::Absent).unwrap(), format!("*nat\n-I redirect_chain 1 {}\nCOMMIT\n", &ours[18..]));
        // Moved in one transaction: delete and insert commit together.
        assert_eq!(moves(Place::Late).unwrap(), format!("*nat\n-D redirect_chain {0}\n-I redirect_chain 1 {0}\nCOMMIT\n", &ours[18..]));
        let step = web_bypass("ip6tables");
        assert_eq!((step.apply.program.as_str(), step.apply.args.as_slice()), ("@u60-relay-portal-return", &["ip6tables".to_owned()][..]));
        assert_eq!(step.undo.args.join(" "), format!("-w 2 -t nat -D redirect_chain {}", &ours[18..]), "an undo the previous agent runs");
        assert!(step.apply.checkable() && tool(&["inet".to_owned()]).is_err());
    }

    #[test]
    fn relay_disables_vendor_dns_portal_and_releases_only_its_delta() {
        let mut fw = Firmware::new();
        let step = plan_with(&mut |cmd| fw.run(cmd)).unwrap().unwrap();
        assert_eq!(step.undo, Cmd::new("@u60-relay-portal", &["release"]));
        fw.action("disable").unwrap();
        assert!(!fw.serving_redirect);
        assert_eq!(fw.persisted, "1");
        fw.action("release").unwrap();
        assert!(fw.serving_redirect);
        assert!(fw.delta.is_none());
        assert!(!fw.unrelated.is_empty());
        assert!(!fw
            .calls
            .iter()
            .any(|c| c.args.iter().any(|a| a == "commit")));
    }

    #[test]
    fn disabled_or_pending_user_settings_are_not_taken_over() {
        let mut fw = Firmware::new();
        fw.persisted = "0".into();
        assert!(plan_with(&mut |cmd| fw.run(cmd)).unwrap().is_none());
        fw.persisted = "1".into();
        fw.delta = Some("1".into());
        assert!(plan_with(&mut |cmd| fw.run(cmd)).is_err());
        assert!(fw.action("disable").is_err());
        assert_eq!(fw.delta.as_deref(), Some("1"));
    }

    #[test]
    fn vendor_commit_or_new_user_value_is_preserved_at_release() {
        for committed in [false, true] {
            let mut fw = Firmware::new();
            fw.action("disable").unwrap();
            if committed {
                fw.persisted = "0".into();
                fw.delta = None;
            } else {
                fw.delta = Some("1".into());
            }
            let before = (fw.persisted.clone(), fw.delta.clone());
            fw.action("release").unwrap();
            assert_eq!((fw.persisted, fw.delta), before);
            assert!(!fw
                .calls
                .iter()
                .any(|c| c.args.first().is_some_and(|a| a == "revert")));
        }
    }

    #[test]
    fn partial_apply_and_release_restart_failures_are_retryable() {
        let mut fw = Firmware::new();
        fw.fail_restart = true;
        assert!(fw.action("disable").is_err());
        assert_eq!(fw.delta.as_deref(), Some("0"));
        fw.fail_restart = false;
        fw.action("disable").unwrap();
        assert!(!fw.serving_redirect);
        fw.fail_restart = true;
        assert!(fw.action("release").is_err());
        assert!(fw.delta.is_none());
        assert!(!fw.serving_redirect);
        fw.fail_restart = false;
        fw.action("release").unwrap();
        assert!(fw.serving_redirect);
        fw.action("release").unwrap();
    }

    #[test]
    fn delta_matching_is_exact_and_commands_are_allowlisted() {
        assert!(!owned_delta("zwrt_redirect.redirect.switch_extra='0'"));
        assert!(!owned_delta("-zwrt_redirect.redirect.switch"));
        assert!(!owned_delta("zwrt_redirect.redirect.switch='1'"));
        assert!(owned_delta(
            "zwrt_redirect.other.switch='1'\nzwrt_redirect.redirect.switch='0'"
        ));
        assert!(command_with(&["commit".into()], &mut |_| panic!("unexpected effect")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Requires a disposable OpenWrt chroot with real UCI"]
    fn isolated_openwrt_portal_lifecycle_preserves_configuration() {
        assert_eq!(std::env::var("U60_IPV6_ISOLATED_QA").as_deref(), Ok("1"));
        assert!(std::path::Path::new("/u60-ipv6-qa-disposable").is_file());
        let config = std::path::Path::new("/etc/config/zwrt_redirect");
        assert!(!config.exists());
        let original =
            "config zredirect 'redirect'\n option switch '1'\n option each_user_redirect '0'\n";
        std::fs::write(config, original).unwrap();
        Cmd::new(
            "uci",
            &["set", "zwrt_redirect.redirect.each_user_redirect=1"],
        )
        .run()
        .unwrap();
        let mut restarts = 0;
        let mut run = |cmd: &Cmd| {
            if cmd.program == "/etc/init.d/dnsmasq" {
                restarts += 1;
                Ok(String::new())
            } else {
                cmd.run()
            }
        };
        let step = plan_with(&mut run).unwrap().unwrap();
        command_with(&step.apply.args, &mut run).unwrap();
        assert_eq!(current(&mut run).unwrap(), "0");
        assert_eq!(std::fs::read_to_string(config).unwrap(), original);
        command_with(&step.undo.args, &mut run).unwrap();
        command_with(&step.undo.args, &mut run).unwrap();
        assert_eq!(current(&mut run).unwrap(), "1");
        assert_eq!(
            Cmd::new("uci", &["-q", "changes", PACKAGE]).run().unwrap(),
            "zwrt_redirect.redirect.each_user_redirect='1'"
        );
        assert_eq!(std::fs::read_to_string(config).unwrap(), original);
        command_with(&step.apply.args, &mut run).unwrap();
        // Simulate a vendor commit: release must not replay an older value.
        Cmd::new("uci", &["commit", PACKAGE]).run().unwrap();
        command_with(&step.undo.args, &mut run).unwrap();
        assert_eq!(current(&mut run).unwrap(), "0");
        assert!(Cmd::new("uci", &["-q", "changes", PACKAGE])
            .run()
            .unwrap()
            .is_empty());
        assert!(restarts >= 4);
        std::fs::remove_file(config).unwrap();
    }
}
