use super::*;
use std::collections::BTreeMap;
use super::super::fake::FakeNft;

#[derive(Default)]
pub(crate) struct Kernel {
    pub tables: BTreeMap<(String, String), Vec<String>>,
    pub writes: Vec<(String, String)>,
    pub reads: Vec<Cmd>,
    commands: Vec<Cmd>,
    undos: Vec<Cmd>,
    error: Option<String>,
    check_error: Option<(i32, String)>,
    stop_before_effect: Option<PathBuf>,
    pub settings: BTreeMap<String, String>,
    ip: BTreeMap<String, String>,
    undo_error: bool,
    normalize: bool,
    fail_after_commit: bool,
}

impl Kernel {
    pub fn seeded() -> Self {
        let mut kernel = Self::default();
        kernel.tables.insert(("iptables".into(), "filter".into()), vec!["-P INPUT ACCEPT".into(), "-A INPUT -j DROP".into()]);
        kernel
    }

    pub fn portal_late() -> Self {
        let mut kernel = Self::seeded();
        let ours = "-A redirect_chain -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN";
        for tool in ["iptables", "ip6tables"] {
            let mut lines = vec!["-N redirect_chain".into()];
            if tool == "iptables" { lines.push("-A redirect_chain -j DNAT".into()); }
            lines.push(ours.into());
            kernel.tables.insert((tool.into(), "nat".into()), lines);
        }
        kernel
    }

    pub fn empty_router() -> Self {
        let mut kernel = Self::default();
        for tool in ["iptables", "ip6tables"] {
            for (table, chains) in [("filter", vec!["INPUT", "OUTPUT", "FORWARD"]), ("nat", vec!["PREROUTING", "POSTROUTING", "OUTPUT", "redirect_chain"])] {
                kernel.tables.insert((tool.into(), table.into()), chains.into_iter().map(|chain| if chain == "redirect_chain" { format!("-N {chain}") } else { format!("-P {chain} ACCEPT") }).collect());
            }
        }
        kernel
    }

    fn lines(&self) -> &Vec<String> {
        &self.tables[&("iptables".into(), "filter".into())]
    }

    fn lines_mut(&mut self) -> &mut Vec<String> {
        self.tables.get_mut(&("iptables".into(), "filter".into())).unwrap()
    }
}

impl Probe for Kernel {
    fn list(&mut self, command: &Cmd) -> Result<String, String> {
        self.reads.push(command.clone());
        if let Some(error) = &self.error { return Err(error.clone()); }
        if command.program == "ip" {
            return Ok(self.ip.get(&command.args.join(" ")).cloned().unwrap_or_default());
        }
        Ok(self.tables.get(&(command.program.clone(), command.args[3].clone())).map(|lines| lines.join("\n")).unwrap_or_default())
    }

    fn status(&mut self, command: &Cmd) -> Result<(i32, String), String> {
        if let Some(error) = &self.check_error { return Ok(error.clone()); }
        let lines = self.tables.entry((command.program.clone(), command.args[3].clone())).or_default();
        let name = &command.args[5];
        let line = firewall::listed(command.program == "ip6tables", name, &command.args[6..]).unwrap_or_else(|| format!("-A {name} {}", command.args[6..].join(" ")));
        let found = lines.iter().position(|candidate| candidate == &line);
        match command.args[4].as_str() {
            "-C" => return Ok(if found.is_some() { (0, String::new()) } else { (1, "No chain/target/match by that name.".into()) }),
            "-D" => if let Some(index) = found { lines.remove(index); } else { return Ok((1, "No chain/target/match by that name.".into())); },
            "-X" => {
                    if lines.iter().any(|line| line.ends_with(&format!("-j {name}"))) { return Ok((1, "Too many links".into())); }
                if lines.iter().any(|line| line.starts_with(&format!("-A {name} "))) { return Ok((1, "Directory not empty".into())); }
                lines.retain(|line| line != &format!("-N {name}"));
            }
            "-F" => lines.retain(|line| !line.starts_with(&format!("-A {name} "))),
            _ => panic!("unexpected command {command:?}"),
        }
        Ok((0, String::new()))
    }

    fn apply(&mut self, command: &Cmd) -> Result<(), String> {
        self.commands.push(command.clone());
        if command.program == "@u60-sysctl" {
            self.settings.insert(command.args[0].clone(), command.args[1].clone());
        }
        Ok(())
    }

    fn restore(&mut self, program: &str, input: String) -> Result<(), String> {
        if let Some(path) = self.stop_before_effect.take() {
            let journal = EffectSet::read(&path).unwrap();
            assert_eq!(journal.undo.len(), 2, "the last undo is durable before restore starts");
            return Err("killed before first effect".into());
        }
        let mut tables = self.tables.clone();
        let tool = program.trim_end_matches("-restore").to_owned();
        let mut table = String::new();
        for line in input.lines() {
            if let Some(name) = line.strip_prefix('*') { table = name.into(); continue; }
            if line == "COMMIT" {
                if self.fail_after_commit {
                    self.fail_after_commit = false;
                    self.tables = tables;
                    return Err("a later table failed after an earlier COMMIT".into());
                }
                continue;
            }
            let lines = tables.entry((tool.clone(), table.clone())).or_default();
            let words: Vec<_> = line.split_whitespace().collect();
            if let Some(name) = words[0].strip_prefix(':') {
                lines.retain(|line| !line.starts_with(&format!("-A {name} ")));
                continue;
            }
            match words[0] {
                "-N" => {
                    if lines.iter().any(|existing| existing == line) { return Err("Chain already exists".into()); }
                    lines.push(line.into());
                }
                "-A" => lines.push(line.into()),
                "-D" => {
                    let wanted = line.replacen("-D ", "-A ", 1);
                    let index = lines.iter().position(|existing| *existing == wanted).ok_or("missing rule")?;
                    lines.remove(index);
                }
                "-I" => {
                    let prefix = format!("-A {} ", words[1]);
                    let index = lines.iter().position(|line| line.starts_with(&prefix)).unwrap_or(lines.len());
                    let wanted = format!("{prefix}{}", words[3..].join(" "));
                    assert!(!lines.contains(&wanted), "the hook never doubles, even inside the repair");
                    lines.insert(index, wanted);
                }
                _ => panic!("unexpected restore line {line}"),
            }
        }
        if self.normalize {
            for lines in tables.values_mut() {
                for line in lines {
                    if line.starts_with("-A U60_") { *line = line.replace("-j ACCEPT", "-m alternate -j ACCEPT"); }
                }
            }
        }
        self.tables = tables;
        self.writes.push((program.into(), input));
        Ok(())
    }

    fn undo(&mut self, command: &Cmd) -> Result<(), String> {
        self.undos.push(command.clone());
        if self.undo_error { return Err("busy".into()); }
        if matches!(command.program.as_str(), "iptables" | "ip6tables") { firewall::undo(command, self) } else { Ok(()) }
    }

    fn sysctl(&mut self, key: &str) -> Result<String, String> {
        Ok(self.settings.get(key).cloned().unwrap_or_else(|| "1".into()))
    }
}

struct TestSet(EffectSet);
impl std::ops::Deref for TestSet {
    type Target = EffectSet;
    fn deref(&self) -> &EffectSet { &self.0 }
}
impl std::ops::DerefMut for TestSet {
    fn deref_mut(&mut self) -> &mut EffectSet { &mut self.0 }
}
impl Drop for TestSet {
    fn drop(&mut self) {
        crate::net_guard::release(&self.path.to_string_lossy(), None);
        let _ = fs::remove_dir_all(self.path.parent().unwrap());
    }
}

fn set(name: &str) -> TestSet {
    TestSet(EffectSet::new("mihomo", std::env::temp_dir().join(format!("u60-effect-{name}-{}", std::process::id())).join("journal.json")))
}

fn chain() -> Resource {
    Resource::LegacyChain(LegacyChain { tool: LegacyTool::V4, table: "filter".into(), name: "U60_TEST".into(), rules: vec![vec!["-j".into(), "ACCEPT".into()], vec!["-j".into(), "RETURN".into()]] })
}

fn hook() -> Resource {
    Resource::LegacyHook(LegacyHook { tool: LegacyTool::V4, table: "filter".into(), chain: "INPUT".into(), rule: vec!["-j".into(), "U60_TEST".into()], position: Position::BeforeVendor })
}

#[test]
fn interrupted_before_first_effect_recovers_without_touching_vendor_rules() {
    let mut set = set("interrupted");
    let mut kernel = Kernel::seeded();
    kernel.stop_before_effect = Some(set.path.clone());
    assert!(set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut FakeNft::default()).is_err());
    assert!(kernel.writes.is_empty());
    EffectSet::recover_with(&set.path, &mut kernel).unwrap();
    assert_eq!(kernel.lines(), &["-P INPUT ACCEPT", "-A INPUT -j DROP"]);
    assert!(!set.path.exists());
}

#[test]
fn an_unheld_chain_is_refused_before_it_can_be_journaled() {
    let mut set = set("foreign");
    let mut kernel = Kernel::seeded();
    kernel.lines_mut().extend(["-N U60_TEST".into(), "-A U60_TEST -j DROP".into()]);
    let before = kernel.tables.clone();
    assert!(set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut FakeNft::default()).is_err());
    assert_eq!(kernel.tables, before);
    assert!(set.undo.is_empty() && kernel.writes.is_empty());
}

#[test]
fn a_chain_replacement_and_each_content_fault_use_one_owned_chain_transaction() {
    let mut set = set("chain");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut nft).unwrap();
    assert_eq!(kernel.writes.len(), 1, "consecutive legacy resources batch together");
    for broken in [vec!["-j DROP"], vec!["-j ACCEPT", "-j RETURN", "-j RETURN"], vec!["-j ACCEPT"], vec!["-j RETURN", "-j ACCEPT"]] {
        kernel.lines_mut().retain(|line| !line.starts_with("-A U60_TEST "));
        kernel.lines_mut().extend(broken.iter().map(|rule| format!("-A U60_TEST {rule}")));
        kernel.writes.clear();
        let result = set.reconcile_with(&mut kernel, &mut nft);
        assert!(result.failed.is_empty(), "{result:?}");
        assert_eq!(kernel.writes, [("iptables-restore".into(), "*filter\n:U60_TEST - [0:0]\n-A U60_TEST -j ACCEPT\n-A U60_TEST -j RETURN\nCOMMIT\n".into())]);
    }
    let Resource::LegacyChain(mut replacement) = chain() else { unreachable!() };
    replacement.rules = vec![vec!["-j".into(), "DROP".into()]];
    kernel.writes.clear();
    set.declare_with(vec![Resource::LegacyChain(replacement)], false, &mut kernel, &mut nft).unwrap();
    assert_eq!(kernel.writes.len(), 1);
    assert_eq!(set.undo.len(), 2, "replacement never adds another chain undo");
    assert!(kernel.lines().contains(&"-A INPUT -j DROP".into()));
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn hooks_are_added_deduplicated_and_moved_without_deleting_a_vendor_rule() {
    let mut set = set("hook");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut nft).unwrap();
    let wanted = "-A INPUT -j U60_TEST".to_owned();
    for copies in [0, 2, 1] {
        kernel.lines_mut().retain(|line| line != &wanted);
        kernel.lines_mut().extend(vec![wanted.clone(); copies]);
        kernel.writes.clear();
        let result = set.reconcile_with(&mut kernel, &mut nft);
        assert!(result.failed.is_empty(), "{result:?}");
        assert_eq!(kernel.writes.len(), 1);
        assert!(!kernel.writes[0].1.contains("-D INPUT -j DROP"));
        assert_eq!(kernel.lines().iter().filter(|line| **line == wanted).count(), 1);
        assert!(kernel.lines().iter().position(|line| line == &wanted) < kernel.lines().iter().position(|line| line == "-A INPUT -j DROP"));
        kernel.writes.clear();
        assert!(set.reconcile_with(&mut kernel, &mut nft).restored.is_empty());
        assert!(kernel.writes.is_empty());
    }
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn failed_listing_lock_and_unknown_errors_wait_for_a_definite_check() {
    let mut set = set("checks");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut nft).unwrap();
    for error in [None, Some((4, "xtables lock".into())), Some((1, "unknown failure".into()))] {
        kernel.lines_mut().retain(|line| line != "-A INPUT -j U60_TEST");
        kernel.writes.clear();
        kernel.error = error.is_none().then(|| "listing failed".into());
        kernel.check_error = error;
        let result = set.reconcile_with(&mut kernel, &mut nft);
        assert!(!result.failed.is_empty() && result.failed.iter().all(|error| error.contains("not checked")));
        assert!(kernel.writes.is_empty());
        kernel.error = None;
        kernel.check_error = None;
        assert_eq!(set.reconcile_with(&mut kernel, &mut nft).restored.len(), 1);
    }
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn withdrawing_uses_journal_reverse_order_and_never_reapplies_released_resources() {
    let mut set = set("withdraw");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut nft).unwrap();
    set.withdraw_with(&[hook().key()], &mut kernel).unwrap();
    assert_eq!(set.undo.len(), 1);
    kernel.writes.clear();
    assert!(set.reconcile_with(&mut kernel, &mut nft).restored.is_empty());
    assert!(kernel.writes.is_empty());
    set.declare_with(vec![hook()], false, &mut kernel, &mut nft).unwrap();
    kernel.undos.clear();
    set.withdraw_with(&[hook().key(), chain().key()], &mut kernel).unwrap();
    assert_eq!(kernel.undos.iter().map(|command| command.args[4].as_str()).collect::<Vec<_>>(), ["-D", "-X"]);
    assert!(set.held.is_empty());
}

#[test]
fn several_sets_share_a_pass_and_writes_and_pass_end_invalidate_it() {
    let mut first = set("pass-first");
    let mut second = set("pass-second");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    first.declare_with(vec![chain()], false, &mut kernel, &mut nft).unwrap();
    second.declare_with(vec![hook()], false, &mut kernel, &mut nft).unwrap();
    kernel.reads.clear();
    {
        let _pass = net::Pass::open();
        first.reconcile_with(&mut kernel, &mut nft);
        second.reconcile_with(&mut kernel, &mut nft);
        assert_eq!(kernel.reads.len(), 1);
        second.withdraw_with(&[hook().key()], &mut kernel).unwrap();
        first.reconcile_with(&mut kernel, &mut nft);
        assert_eq!(kernel.reads.len(), 2);
    }
    first.reconcile_with(&mut kernel, &mut nft);
    assert_eq!(kernel.reads.len(), 3);
    first.release_with(&mut kernel).unwrap();
}

#[test]
fn cleanup_failure_preserves_the_remaining_journal_and_disables_repair() {
    let mut set = set("cleanup");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut nft).unwrap();
    kernel.undo_error = true;
    assert!(set.release_with(&mut kernel).unwrap_err().starts_with("Network cleanup paused:"));
    assert_eq!(EffectSet::read(&set.path).unwrap().undo.len(), 2);
    kernel.writes.clear();
    assert!(set.reconcile_with(&mut kernel, &mut nft).restored.is_empty());
    kernel.undo_error = false;
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn every_typed_resource_writes_only_the_previous_builds_undo_vocabulary() {
    let resources = vec![
        chain(), hook(),
        Resource::NftTable(NftTable { owner: "mihomo", name: "u60_mihomo", file: PathBuf::from("tables.nft"), families: None }),
        Resource::Route(Route::new(Family::V4, RouteType::Throw, "192.0.2.0/24", "60631")),
        Resource::Rule(Rule { family: Family::V6, priority: 18640, table: "60631".into(), mark: None }),
        Resource::Addr(Addr { family: Family::V6, device: "ath20".into(), address: "2001:db8::2/64".into(), broadcast: None, valid_lft: Some(30), preferred_lft: Some(20), noprefixroute: true }),
        Resource::Sysctl(Sysctl { key: "bridge-nf-call-iptables".into(), value: "0".into() }),
        Resource::Internal(Internal::new("@u60-relay-steer", vec!["backlog".into(), "5000".into()], vec!["backlog".into(), "1000".into()])),
    ];
    let expected = [
        Cmd::new("iptables", &["-w", "2", "-t", "filter", "-X", "U60_TEST"]),
        Cmd::new("iptables", &["-w", "2", "-t", "filter", "-D", "INPUT", "-j", "U60_TEST"]),
        Cmd::new("@u60-mihomo-nft", &["remove"]),
        Cmd::new("ip", &["-4", "route", "del", "throw", "192.0.2.0/24", "table", "60631"]),
        Cmd::new("ip", &["-6", "rule", "del", "pref", "18640", "lookup", "60631"]),
        Cmd::new("ip", &["-6", "addr", "del", "2001:db8::2/64", "dev", "ath20"]),
        Cmd::new("@u60-sysctl", &["bridge-nf-call-iptables", "1"]),
        Cmd::new("@u60-relay-steer", &["backlog", "1000"]),
    ];
    for (resource, expected) in resources.iter().zip(&expected) {
        assert_eq!(&resource.undo(|_| Ok("1".into())).unwrap(), expected);
    }
    let mut journaled = set("vocabulary");
    journaled.declare_with(resources, false, &mut Kernel::seeded(), &mut FakeNft::default()).unwrap();
    assert_eq!(EffectSet::read(&journaled.path).unwrap().undo, expected);
    journaled.release_with(&mut Kernel::seeded()).unwrap();
    let mut set = set("unknown-undo");
    set.undo = vec![Cmd::new("@u60-removed-step", &["on"])];
    set.save().unwrap();
    EffectSet::recover(&set.path).unwrap();
    assert!(!set.path.exists());
}

#[test]
fn sysctl_replacement_keeps_the_first_original_and_adoption_restores_only_missing_effects() {
    let mut set = set("sysctl");
    let mut kernel = Kernel::default();
    let mut nft = FakeNft::default();
    let setting = |value: &str| Resource::Sysctl(Sysctl { key: "tcp_pacing_ss_ratio".into(), value: value.into() });
    set.declare_with(vec![setting("1000")], false, &mut kernel, &mut nft).unwrap();
    set.declare_with(vec![setting("900")], false, &mut kernel, &mut nft).unwrap();
    assert_eq!(set.undo, [Cmd::new("@u60-sysctl", &["tcp_pacing_ss_ratio", "1"])]);
    let mut adopted = EffectSet::load("mihomo", &set.path).unwrap();
    kernel.commands.clear();
    adopted.declare_with(vec![setting("900")], true, &mut kernel, &mut nft).unwrap();
    assert!(kernel.commands.is_empty());
    kernel.settings.insert("tcp_pacing_ss_ratio".into(), "1".into());
    assert_eq!(adopted.reconcile_with(&mut kernel, &mut nft).restored.len(), 1);
    adopted.release_with(&mut kernel).unwrap();
}

#[test]
fn routes_use_metric_gateway_and_device_and_rules_refuse_a_foreign_priority() {
    let mut set = set("ip");
    let mut kernel = Kernel::default();
    let mut nft = FakeNft::default();
    let mut route = Route::new(Family::V4, RouteType::Unicast, "default", "main");
    route.device = Some("ath20".into());
    route.gateway = Some("192.0.2.1".into());
    route.metric = Some(60631);
    let rule = Rule { family: Family::V4, priority: 18640, table: "60631".into(), mark: None };
    let address = Addr { family: Family::V4, device: "ath20".into(), address: "192.0.2.2/24".into(), broadcast: Some("192.0.2.255".into()), valid_lft: None, preferred_lft: None, noprefixroute: false };
    set.declare_with(vec![Resource::Route(route), Resource::Rule(rule), Resource::Addr(address)], false, &mut kernel, &mut nft).unwrap();
    kernel.ip.insert("-4 route show table all".into(), "default via 192.0.2.1 dev ath20 metric 60631".into());
    kernel.ip.insert("-4 rule show".into(), "18640: from all lookup 60631".into());
    kernel.ip.insert("-o -4 addr show".into(), "33: ath20 inet 192.0.2.2/24 scope global".into());
    assert!(set.reconcile_with(&mut kernel, &mut nft).restored.is_empty());
    kernel.ip.insert("-4 route show table all".into(), "default via 192.0.2.1 dev ath20 metric 100".into());
    kernel.ip.insert("-4 rule show".into(), "18640: from all lookup main".into());
    let result = set.reconcile_with(&mut kernel, &mut nft);
    assert_eq!(result.restored.len(), 1);
    assert_eq!(result.failed.len(), 1);
    assert!(result.failed[0].contains("not checked"));
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn insert_first_hook_keeps_a_vendor_rule_added_above_it() {
    for position in [Position::InsertFirst] {
        let mut set = set("first");
        let mut kernel = Kernel::seeded();
        let mut nft = FakeNft::default();
        let Resource::LegacyHook(mut hook) = hook() else { unreachable!() };
        hook.position = position;
        set.declare_with(vec![chain(), Resource::LegacyHook(hook)], false, &mut kernel, &mut nft).unwrap();
        kernel.lines_mut().insert(1, "-A INPUT -j REJECT".into());
        kernel.writes.clear();
        assert!(set.reconcile_with(&mut kernel, &mut nft).restored.is_empty());
        assert!(kernel.writes.is_empty());
        set.release_with(&mut kernel).unwrap();
    }
}

#[test]
fn imperative_steps_are_journaled_and_recovery_discards_another_boot() {
    let mut set = set("step");
    set.step(Step::new(Cmd::new("true", &[]), Cmd::new("true", &[]))).unwrap();
    assert_eq!(EffectSet::read(&set.path).unwrap().undo, [Cmd::new("true", &[])]);
    set.release().unwrap();
    net::write_private(&set.path, br#"{"boot":"previous-boot","undo":[{"program":"false","args":[]}]}"#).unwrap();
    EffectSet::recover(&set.path).unwrap();
    assert!(!set.path.exists());
}

#[test]
fn an_owned_route_or_rule_can_be_replaced_under_its_typed_key() {
    let mut set = set("replace-route");
    let mut kernel = Kernel::default();
    let mut nft = FakeNft::default();
    let mut first = Route::new(Family::V4, RouteType::Unicast, "default", "60631");
    first.device = Some("ath20".into());
    first.gateway = Some("192.0.2.1".into());
    let mut next = first.clone();
    next.gateway = Some("192.0.2.3".into());
    set.declare_with(vec![Resource::Route(first.clone())], false, &mut kernel, &mut nft).unwrap();
    set.declare_with(vec![Resource::Route(next.clone())], false, &mut kernel, &mut nft).unwrap();
    assert_eq!(kernel.undos, [first.command("del")]);
    assert_eq!(kernel.commands.last(), Some(&next.command("add")));
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn nft_reads_share_the_pass_and_every_write_invalidates_them() {
    let reads = std::cell::Cell::new(0);
    let read = || { reads.set(reads.get() + 1); Ok("tables".into()) };
    {
        let _pass = net::Pass::open();
        shared::nft_ruleset(read).unwrap();
        net::with_listings(|_| { shared::nft_ruleset(read).unwrap(); });
        assert_eq!(reads.get(), 1);
        net::changed();
        shared::nft_ruleset(read).unwrap();
        assert_eq!(reads.get(), 2);
    }
    shared::nft_ruleset(read).unwrap();
    assert_eq!(reads.get(), 3);
}

#[test]
fn a_held_table_allows_later_routes_in_its_batch_and_nft_targets_survive_failed_loads() {
    let mut set = set("table-extensions");
    let mut kernel = Kernel::default();
    let mut nft = FakeNft::default();
    let first = Resource::Route(Route::new(Family::V4, RouteType::Throw, "192.0.2.0/24", "60631"));
    set.declare_with(vec![first], false, &mut kernel, &mut nft).unwrap();
    kernel.ip.insert("-4 route show table all".into(), "throw 192.0.2.0/24 table 60631".into());
    let next = Resource::Route(Route::new(Family::V4, RouteType::Unreachable, "198.51.100.0/24", "60631"));
    set.declare_with(vec![next], false, &mut kernel, &mut nft).unwrap();
    let table = |rule: &str| Resource::NftTable(NftTable {
        owner: "mihomo", name: "u60_mihomo", file: set.path.with_extension("nft"),
        families: Some(FAMILIES.map(|family| super::super::table(family, "u60_mihomo", &[], &[("input", "", vec![rule.into()])]))),
    });
    let accept = table("accept");
    let drop = table("drop");
    set.declare_with(vec![accept.clone()], false, &mut kernel, &mut nft).unwrap();
    set.declare_with(vec![accept], false, &mut kernel, &mut nft).unwrap();
    assert_eq!(nft.loads, 1);
    nft.fail.push(("timed out".into(), false));
    assert!(set.declare_with(vec![drop], false, &mut kernel, &mut nft).is_err());
    assert!(!set.tables_confirmed("u60_mihomo"));
    assert!(set.reconcile_with(&mut kernel, &mut nft).failed.is_empty());
    assert!(set.tables_confirmed("u60_mihomo"));
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn selected_reconcile_leaves_live_lease_addresses_to_their_session() {
    let mut set = set("selected");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    let route = Resource::Route(Route::new(Family::V4, RouteType::Throw, "192.0.2.0/24", "60631"));
    set.declare_with(vec![chain(), route], false, &mut kernel, &mut nft).unwrap();
    kernel.commands.clear();
    kernel.lines_mut().retain(|line| line != "-A U60_TEST -j ACCEPT");
    let result = set.reconcile_selected(|resource| matches!(resource, Resource::LegacyChain(_)), &mut kernel, &mut nft);
    assert_eq!(result.restored.len(), 1);
    assert!(kernel.commands.is_empty());
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn a_normalized_chain_repairs_once_and_a_changed_chain_repairs_again() {
    let mut set = set("normalized");
    let mut kernel = Kernel::seeded();
    kernel.normalize = true;
    let mut nft = FakeNft::default();
    set.declare_with(vec![chain()], false, &mut kernel, &mut nft).unwrap();
    assert_eq!(set.reconcile_with(&mut kernel, &mut nft).restored, ["iptables -t filter chain U60_TEST"]);
    let writes = kernel.writes.len();
    assert!(set.reconcile_with(&mut kernel, &mut nft).restored.is_empty());
    assert_eq!(kernel.writes.len(), writes);
    kernel.lines_mut().retain(|line| !line.contains("alternate"));
    assert_eq!(set.reconcile_with(&mut kernel, &mut nft).restored.len(), 1);
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn an_unpredicted_hook_found_by_the_tool_is_kept_without_a_repair_loop() {
    let mut set = set("unpredicted-hook");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut nft).unwrap();
    kernel.lines_mut().iter_mut().filter(|line| line.starts_with("-A INPUT -j U60_")).for_each(|line| *line = line.replace("-j", "-m alternate -j"));
    kernel.check_error = Some((0, String::new()));
    kernel.writes.clear();
    for _ in 0..3 {
        let result = set.reconcile_with(&mut kernel, &mut nft);
        assert!(result.failed.is_empty() && result.restored.is_empty());
    }
    assert!(kernel.writes.is_empty());
}

#[test]
fn teardown_saves_once_on_failure_or_partial_success_and_never_after_each_undo() {
    let mut set = set("write-count");
    let mut kernel = Kernel::seeded();
    set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut FakeNft::default()).unwrap();
    set.journal_writes.set(0);
    kernel.undo_error = true;
    assert!(set.release_with(&mut kernel).is_err());
    assert_eq!(set.journal_writes.get(), 1);
    assert_eq!(EffectSet::read(&set.path).unwrap().undo.len(), 2);
    kernel.undo_error = false;
    set.journal_writes.set(0);
    set.withdraw_with(&[hook().key()], &mut kernel).unwrap();
    assert_eq!(set.journal_writes.get(), 1);
    assert_eq!(EffectSet::read(&set.path).unwrap().undo.len(), 1);
    set.journal_writes.set(0);
    set.release_with(&mut kernel).unwrap();
    assert_eq!(set.journal_writes.get(), 0);
    assert!(!set.path.exists());
}

#[test]
fn a_missing_target_never_installs_a_hook_or_takes_its_journal() {
    let mut set = set("missing-target");
    let mut kernel = Kernel::seeded();
    assert!(set.declare_with(vec![hook()], false, &mut kernel, &mut FakeNft::default()).is_err());
    assert!(kernel.writes.is_empty() && !set.path.exists());
}

#[test]
fn nft_load_errors_and_unreadable_checks_have_different_operator_reports() {
    let mut set = set("nft-report");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    let resource = Resource::NftTable(NftTable { owner: "mihomo", name: "u60_mihomo", file: set.path.with_extension("nft"), families: Some(FAMILIES.map(|family| super::super::table(family, "u60_mihomo", &[], &[("input", "", vec!["accept".into()])])))});
    set.declare_with(vec![resource], false, &mut kernel, &mut nft).unwrap();
    nft.unreadable = true;
    assert!(set.reconcile_with(&mut kernel, &mut nft).failed[0].contains("not checked"));
    nft.unreadable = false;
    nft.tables.clear();
    nft.fail.push(("write failed".into(), false));
    let result = set.reconcile_with(&mut kernel, &mut nft);
    assert!(result.failed[0].contains("did not load") && !result.failed[0].contains("not checked"));
}

fn old_ipv6_journals() -> [Vec<Cmd>; 2] {
    let wireless: Vec<Cmd> = serde_json::from_str(r#"[
        {"program":"ip6tables","args":["-w","2","-t","filter","-X","U60_RELAY_IN"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","INPUT","-i","ath20","-j","U60_RELAY_IN"]}
    ]"#).unwrap();
    let setup: Vec<Cmd> = serde_json::from_str(r#"[
        {"program":"true","args":[]}, {"program":"true","args":[]}, {"program":"true","args":[]},
        {"program":"true","args":[]}, {"program":"true","args":[]}, {"program":"true","args":[]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-X","U60_R6_IN"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-m","conntrack","--ctstate","ESTABLISHED,RELATED","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-p","ipv6-icmp","--icmpv6-type","134","-m","hl","--hl-eq","255","-s","fe80::/10","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-p","ipv6-icmp","--icmpv6-type","135","-m","hl","--hl-eq","255","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-p","ipv6-icmp","--icmpv6-type","136","-m","hl","--hl-eq","255","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-p","ipv6-icmp","--icmpv6-type","1","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-p","ipv6-icmp","--icmpv6-type","2","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-p","ipv6-icmp","--icmpv6-type","3","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-p","ipv6-icmp","--icmpv6-type","4","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_R6_IN","-p","udp","--sport","547","--dport","546","-j","ACCEPT"]},
        {"program":"ip6tables","args":["-w","2","-t","filter","-D","U60_RELAY_IN","-j","U60_R6_IN"]}
    ]"#).unwrap();
    [wireless, setup]
}

fn old_ipv6_kernel(journals: &[Vec<Cmd>; 2]) -> Kernel {
    let mut kernel = Kernel::empty_router();
    let lines = kernel.tables.get_mut(&("ip6tables".into(), "filter".into())).unwrap();
    lines.push("-A INPUT -j DROP".into());
    for command in journals.iter().flatten().filter(|command| command.program == "ip6tables") {
        if command.args[4] == "-X" { lines.push(format!("-N {}", command.args[5])); }
        else { lines.push(firewall::listed(true, &command.args[5], &command.args[6..]).unwrap()); }
    }
    kernel
}

#[test]
fn previous_build_literal_journals_recover_with_the_old_intermediate_chain() {
    let journals = old_ipv6_journals();
    let mut kernel = old_ipv6_kernel(&journals);
    for (index, undo) in journals.into_iter().enumerate().rev() {
        let mut set = set(&format!("old-recover-{index}"));
        set.undo = undo;
        set.save().unwrap();
        EffectSet::recover_with(&set.path, &mut kernel).unwrap();
    }
    let lines = &kernel.tables[&("ip6tables".into(), "filter".into())];
    assert!(lines.contains(&"-A INPUT -j DROP".into()));
    assert!(!lines.iter().any(|line| line.contains("U60_")));
}

#[test]
fn previous_build_takeover_keeps_accepts_until_the_new_hook_and_cleans_both_layouts() {
    let [wireless_undo, setup_undo] = old_ipv6_journals();
    let mut kernel = old_ipv6_kernel(&[wireless_undo.clone(), setup_undo.clone()]);
    let mut wireless = set("old-takeover-wireless");
    wireless.undo = wireless_undo;
    wireless.save().unwrap();
    let mut setup = set("old-takeover-setup");
    setup.undo = setup_undo;
    setup.save().unwrap();
    let mut adopted = EffectSet::load("relay", &setup.path).unwrap();
    crate::wifi_relay::adopt::adopt_resources(&mut adopted, crate::wifi_relay::ipv6::setup_plan(), &mut kernel, &mut FakeNft::default()).unwrap();
    assert_eq!(kernel.writes.len(), 1);
    assert_eq!(kernel.writes[0].1, "*filter\n-I INPUT 1 -i ath20 -j U60_R6_IN\nCOMMIT\n");
    let lines = &kernel.tables[&("ip6tables".into(), "filter".into())];
    assert!(lines.contains(&"-A U60_RELAY_IN -j U60_R6_IN".into()));
    assert!(lines.contains(&"-A INPUT -i ath20 -j U60_R6_IN".into()));
    adopted.release_with(&mut kernel).unwrap();
    wireless.release_with(&mut kernel).unwrap();
    assert!(!kernel.tables.values().flatten().any(|line| line.contains("U60_")));
}

#[test]
fn this_build_takeover_of_intact_resources_and_tables_writes_nothing() {
    let mut set = set("same-build");
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    let table = Resource::NftTable(NftTable { owner: "mihomo", name: "u60_mihomo", file: set.path.with_extension("nft"), families: Some(FAMILIES.map(|family| super::super::table(family, "u60_mihomo", &[], &[("input", "", vec!["accept".into()])])))});
    let resources = vec![chain(), hook(), table];
    set.declare_with(resources.clone(), false, &mut kernel, &mut nft).unwrap();
    let mut adopted = EffectSet::load("mihomo", &set.path).unwrap();
    kernel.writes.clear();
    let loads = nft.loads;
    adopted.declare_with(resources, true, &mut kernel, &mut nft).unwrap();
    assert!(kernel.writes.is_empty());
    assert_eq!(nft.loads, loads);
    adopted.release_with(&mut kernel).unwrap();
}

#[test]
fn one_fw3_repair_restores_all_chains_and_unique_hooks_with_portal_before_dnat() {
    let mut set = set("fw3");
    set.owner = "relay";
    let lease: crate::wifi_relay::Lease = serde_json::from_str(r#"{"ip":"10.20.0.7","subnet":"255.255.255.0","gateway":"10.20.0.1","dns":[]}"#).unwrap();
    let mut resources = crate::wifi_relay::input_guards();
    resources.extend(crate::wifi_relay::relay_plan(&lease, 24, "192.168.0.1".parse().unwrap(), "255.255.255.0".parse().unwrap()).into_iter().filter(|resource| matches!(resource, Resource::LegacyChain(_) | Resource::LegacyHook(_))));
    resources.extend(crate::wifi_relay::portal::web_bypasses());
    resources.extend(crate::wifi_relay::ipv6::setup_plan());
    let mut kernel = Kernel::empty_router();
    let mut nft = FakeNft::default();
    set.declare_with(resources, false, &mut kernel, &mut nft).unwrap();
    for lines in kernel.tables.values_mut() { lines.retain(|line| line.starts_with("-P ") || line == "-N redirect_chain"); }
    kernel.tables.get_mut(&("iptables".into(), "nat".into())).unwrap().push("-A redirect_chain -j DNAT".into());
    kernel.writes.clear();
    let result = set.reconcile_with(&mut kernel, &mut nft);
    assert!(result.failed.is_empty(), "{result:?}");
    let portal = &kernel.tables[&("iptables".into(), "nat".into())];
    assert!(portal.iter().position(|line| line.contains("-j RETURN")) < portal.iter().position(|line| line.contains("-j DNAT")));
    assert_eq!(portal.iter().filter(|line| line.contains("MASQUERADE")).count(), 1);
    kernel.writes.clear();
    let result = set.reconcile_with(&mut kernel, &mut nft);
    assert!(result.failed.is_empty() && result.restored.is_empty());
    assert!(kernel.writes.is_empty());
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn a_failed_restore_is_never_retried_as_commands_and_its_whole_journal_recovers() {
    let mut set = set("partial-batch");
    let mut kernel = Kernel::seeded();
    kernel.stop_before_effect = Some(set.path.clone());
    assert!(set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut FakeNft::default()).is_err());
    assert!(kernel.commands.is_empty());
    assert_eq!(EffectSet::read(&set.path).unwrap().undo.len(), 2);
    EffectSet::recover_with(&set.path, &mut kernel).unwrap();
    assert_eq!(kernel.lines(), &["-P INPUT ACCEPT", "-A INPUT -j DROP"]);
    let Resource::LegacyChain(mut later) = chain() else { unreachable!() };
    later.table = "nat".into();
    later.name = "U60_LATER".into();
    kernel.fail_after_commit = true;
    assert!(set.declare_with(vec![chain(), Resource::LegacyChain(later)], false, &mut kernel, &mut FakeNft::default()).is_err());
    assert!(kernel.lines().contains(&"-N U60_TEST".into()));
    assert!(kernel.commands.is_empty());
    EffectSet::recover_with(&set.path, &mut kernel).unwrap();
    assert!(!kernel.tables.values().flatten().any(|line| line.contains("U60_")));
}

#[test]
fn failed_effect_is_journaled_and_recovers_after_restart() {
    let mut set = set("failed-step");
    let file = set.path.with_extension("effect");
    let name = file.to_str().unwrap();
    set.step(Step::new(Cmd::new("touch", &[name]), Cmd::new("rm", &["-f", name]))).unwrap();
    assert!(set.step(Step::new(Cmd::new("false", &[]), Cmd::new("true", &[]))).is_err());
    EffectSet::recover(&set.path).unwrap();
    EffectSet::recover(&set.path).unwrap();
    assert!(!file.exists() && !set.path.exists());
}

#[test]
fn rollback_stops_on_failure_and_keeps_remaining_recovery() {
    let mut set = set("blocked-step");
    let file = set.path.with_extension("effect");
    let blocker = set.path.with_extension("blocker");
    set.step(Step::new(Cmd::new("touch", &[file.to_str().unwrap()]), Cmd::new("rm", &["-f", file.to_str().unwrap()]))).unwrap();
    set.step(Step::new(Cmd::new("mkdir", &[blocker.to_str().unwrap()]), Cmd::new("rmdir", &[blocker.to_str().unwrap()]))).unwrap();
    fs::write(blocker.join("busy"), "busy").unwrap();
    assert!(set.release().is_err());
    assert!(file.exists() && set.path.exists());
    fs::remove_file(blocker.join("busy")).unwrap();
    EffectSet::recover(&set.path).unwrap();
    assert!(!file.exists() && !blocker.exists() && !set.path.exists());
}

#[test]
fn a_reconcile_after_a_release_never_reapplies_the_released_step() {
    let mut set = set("released-sysctl");
    let mut kernel = Kernel::default();
    let mut nft = FakeNft::default();
    let resource = Resource::Sysctl(Sysctl { key: "bridge-nf-call-iptables".into(), value: "0".into() });
    set.declare_with(vec![resource.clone()], false, &mut kernel, &mut nft).unwrap();
    set.withdraw_with(&[resource.key()], &mut kernel).unwrap();
    kernel.settings.insert("bridge-nf-call-iptables".into(), "1".into());
    kernel.commands.clear();
    let result = set.reconcile_with(&mut kernel, &mut nft);
    assert!(result.failed.is_empty() && result.restored.is_empty() && kernel.commands.is_empty());
    assert_eq!(kernel.settings["bridge-nf-call-iptables"], "1");
}

#[test]
fn a_journal_write_failure_never_executes_or_repairs_unjournaled_changes() {
    let mut set = set("save-fails");
    fs::create_dir_all(&set.path).unwrap();
    let mut kernel = Kernel::seeded();
    let mut nft = FakeNft::default();
    assert!(set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut nft).is_err());
    assert!(kernel.writes.is_empty() && kernel.commands.is_empty());
    assert!(set.reconcile_with(&mut kernel, &mut nft).restored.is_empty());
    fs::remove_dir(&set.path).unwrap();
    set.declare_with(vec![chain(), hook()], false, &mut kernel, &mut nft).unwrap();
    assert_eq!(set.undo.len(), 2);
    set.release_with(&mut kernel).unwrap();
}

#[test]
fn a_failed_table_listing_does_not_stop_a_different_tables_repair() {
    let mut set = set("independent");
    let mut kernel = Kernel::empty_router();
    let mut nft = FakeNft::default();
    set.declare_with(vec![chain()], false, &mut kernel, &mut nft).unwrap();
    kernel.tables.get_mut(&("iptables".into(), "filter".into())).unwrap().retain(|line| !line.starts_with("-A U60_TEST"));
    let bad = Resource::Internal(Internal::new("@u60-relay-power-save", vec!["off".into()], vec![]).with_undo(Cmd::new("true", &[])));
    set.assume(vec![bad]);
    let result = set.reconcile_with(&mut kernel, &mut nft);
    assert_eq!(result.restored, ["iptables -t filter chain U60_TEST"]);
    assert_eq!(result.failed.len(), 1);
}
