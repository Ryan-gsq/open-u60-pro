//! Owned network resources an owner declares, keeps and releases
//! (`relay-mihomo-architecture.md` sections 4.1 and 4.2).
//!
//! `NftTables` is one owner's `ip` and `ip6` table of the same name. Every
//! change replaces both tables whole in one `nft -f` batch (stale sets go
//! with them; the kernel commits the batch or nothing), and carries a
//! generation marker: a rule comment in the unhooked chain `state`. Reading
//! the marker back with `nft -t` (no set elements, so a large set never hits
//! a tool's output limit) proves which batch the kernel holds; set elements
//! are proven by the batch being atomic. The target (what should be loaded)
//! and the confirmed generation (what was read back) are kept apart: a batch
//! that failed, timed out or could not be read back stays the target and is
//! tried again by `reconcile`, and nothing treats the previous table, or a
//! table name that exists, as the new one.
//!
//! A declaration whose content equals the confirmed target is not loaded
//! again: the marker (and each chain's rule count) read back from the kernel
//! proves it still holds it. A Mihomo rule-set refresh used to load two
//! 112 KB tables and list them eight times even when nothing changed. Each
//! check reads both families once (`Nft::list_both`; on the router one
//! `nft -t list ruleset`), for the marker and the rule counts alike.
//!
//! Routes, rules, sysctls and internal steps stay in the owner's
//! `Transaction`, journaled before they apply. The tables' undo is one
//! internal step, `@u60-mihomo-nft remove`, which every agent version since
//! the TPROXY release runs, so a journal stays undoable by the agent an
//! update may roll back to.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::net_tools::{self as net, Cmd};

pub const FAMILIES: [&str; 2] = ["ip", "ip6"];
/// The unhooked chain holding the generation marker.
const STATE: &str = "state";
/// A batch with large sets (GeoIP ranges) takes a while on the router.
const LOAD: Duration = Duration::from_secs(20);

/// One family's table as an `nft -f` definition: sets `(name, spec,
/// elements)` and chains `(name, hook, rules)` (an empty hook is a regular
/// chain).
pub fn table(family: &str, name: &str, sets: &[(&str, &str, &[String])], chains: &[(&str, &str, Vec<String>)]) -> String {
    let mut text = format!("table {family} {name} {{\n");
    for (set, spec, elements) in sets {
        if elements.is_empty() {
            text.push_str(&format!("\tset {set} {{ {spec} }}\n"));
        } else {
            text.push_str(&format!("\tset {set} {{ {spec} elements = {{ {} }} }}\n", elements.join(", ")));
        }
    }
    for (chain, hook, rules) in chains {
        text.push_str(&format!("\tchain {chain} {{\n"));
        if !hook.is_empty() {
            text.push_str(&format!("\t\t{hook}\n"));
        }
        for rule in rules {
            text.push_str(&format!("\t\t{rule}\n"));
        }
        text.push_str("\t}\n");
    }
    text.push_str("}\n");
    text
}

/// The kernel's answer to whether a table name is free.
#[derive(Debug, PartialEq, Eq)]
pub enum Presence {
    Absent,
    /// Present and carrying this owner's marker (a previous agent's table).
    Ours,
    /// Present without it: another writer's, never taken over.
    Foreign,
}

/// What the kernel answers, so tests can stand in for `nft`.
pub trait Nft {
    /// `nft -f file`.
    fn load(&mut self, file: &std::path::Path) -> Result<(), String>;
    /// `nft -t list table family name`: `Ok(None)` when it does not exist.
    fn list(&mut self, family: &str, name: &str) -> Result<Option<String>, String>;
    /// Table `name` in each of `FAMILIES` as `nft -t` lists it (`None`:
    /// absent): one read serves the marker and the rule check.
    fn list_both(&mut self, name: &str) -> Result<[Option<String>; 2], String> {
        Ok([self.list(FAMILIES[0], name)?, self.list(FAMILIES[1], name)?])
    }
    #[cfg_attr(not(test), allow(dead_code))]
    fn delete(&mut self, family: &str, name: &str) -> Result<(), String>;
}

pub struct Device;

impl Nft for Device {
    fn load(&mut self, file: &std::path::Path) -> Result<(), String> {
        let mut command = std::process::Command::new("nft");
        command.arg("-f").arg(file);
        super::exec::run(command, LOAD).map(|_| ())
    }

    fn list(&mut self, family: &str, name: &str) -> Result<Option<String>, String> {
        // Which tables exist first: a failing `list table` alone does not
        // tell a missing table from a failing tool.
        let tables = Cmd::new("nft", &["list", "tables", family]).run()?;
        if !tables.lines().any(|l| l.trim() == format!("table {family} {name}")) {
            return Ok(None);
        }
        Cmd::new("nft", &["-t", "list", "table", family, name]).run().map(Some)
    }

    /// One process for both families, instead of a `list tables` and a
    /// `list table` per family: the whole ruleset without set elements (a
    /// few KB on B31; ZTE never writes nftables, so it holds only the
    /// agent's tables). A failing tool fails the whole read, so it is never
    /// taken for a missing table.
    fn list_both(&mut self, name: &str) -> Result<[Option<String>; 2], String> {
        let ruleset = Cmd::new("nft", &["-t", "list", "ruleset"]).run()?;
        Ok(FAMILIES.map(|family| table_in(&ruleset, family, name)))
    }

    fn delete(&mut self, family: &str, name: &str) -> Result<(), String> {
        Cmd::new("nft", &["delete", "table", family, name]).run().map(|_| ())
    }
}

/// Table `family name` in a ruleset listing, header to closing brace, as
/// `nft list table` prints it.
fn table_in(ruleset: &str, family: &str, name: &str) -> Option<String> {
    let header = format!("table {family} {name} {{");
    let mut lines = ruleset.lines().skip_while(|line| line.trim_end() != header);
    let mut text = format!("{}\n", lines.next()?.trim_end());
    for line in lines {
        text.push_str(line.trim_end());
        text.push('\n');
        if line.trim_end() == "}" {
            return Some(text);
        }
    }
    None
}

#[derive(Clone, Debug)]
struct Generation {
    number: u64,
    marker: String,
    /// Both families' definitions, marker included.
    text: String,
    /// The definitions as declared (without the marker).
    digest: [u8; 32],
}

/// One owner's pair of tables.
pub struct NftTables {
    owner: &'static str,
    name: &'static str,
    /// Where the batch is written for `nft -f` (a private file).
    file: PathBuf,
    generation: u64,
    target: Option<Generation>,
    confirmed: Option<u64>,
    error: Option<String>,
}

impl NftTables {
    pub fn new(owner: &'static str, name: &'static str, file: PathBuf) -> Self {
        Self { owner, name, file, generation: 0, target: None, confirmed: None, error: None }
    }

    fn marker_prefix(&self) -> String {
        format!("zte-agent {} ", self.owner)
    }

    /// Whether the table name is free in both families, already ours (a
    /// previous agent's, by its marker) or someone else's. A table without
    /// our marker is never taken over (section 4.1).
    pub fn presence(&self, nft: &mut (impl Nft + ?Sized)) -> Result<Presence, String> {
        let mut found = Presence::Absent;
        for listing in nft.list_both(self.name)? {
            match listing {
                None => {}
                Some(listing) if listing.contains(&format!("comment \"{}", self.marker_prefix())) => found = Presence::Ours,
                Some(_) => return Ok(Presence::Foreign),
            }
        }
        Ok(found)
    }

    /// Makes `families` (one definition per family, `table`) the target and
    /// loads it: a new generation, both families in one batch. `Err` keeps
    /// it the target (`reconcile` tries again); the previous generation may
    /// still be what the kernel holds. The same content as the confirmed
    /// target is not loaded again while the kernel is read to hold it.
    pub fn declare(&mut self, families: [String; 2], nft: &mut (impl Nft + ?Sized)) -> Result<u64, String> {
        let digest: [u8; 32] = Sha256::digest(families.concat()).into();
        if let Some(target) = self.target.clone().filter(|t| t.digest == digest && self.confirmed == Some(t.number)) {
            // An unreadable kernel proves nothing: load it as a new generation.
            if nft.list_both(self.name).is_ok_and(|listings| self.intact(&target, &listings)) {
                self.error = None;
                return Ok(target.number);
            }
        }
        self.generation += 1;
        let (marker, text) = batch(self.owner, self.name, self.generation, families)?;
        self.target = Some(Generation { number: self.generation, marker, text, digest });
        self.load(nft)
    }

    fn load(&mut self, nft: &mut (impl Nft + ?Sized)) -> Result<u64, String> {
        let target = self.target.clone().ok_or("Nothing to load")?;
        let loaded = net::write_private(&self.file, target.text.as_bytes()).and_then(|()| nft.load(&self.file));
        // A tool that failed or timed out may still have committed: the
        // marker decides, never the exit code alone.
        let readback = nft.list_both(self.name).map(|listings| self.marker(&listings));
        match (&loaded, readback) {
            (_, Ok(Some(marker))) if marker == target.marker => {
                self.confirmed = Some(target.number);
                self.error = None;
                Ok(target.number)
            }
            (Err(e), _) => self.failed(format!("nftables did not load generation {}: {e}", target.number)),
            (Ok(()), Err(e)) => self.failed(format!("generation {} is not confirmed: {e}", target.number)),
            (Ok(()), Ok(_)) => self.failed(format!("generation {} did not read back", target.number)),
        }
    }

    fn failed(&mut self, error: String) -> Result<u64, String> {
        self.error = Some(error.clone());
        Err(error)
    }

    /// The marker both families carry, `None` when they differ or one lacks it.
    fn marker(&self, listings: &[Option<String>; 2]) -> Option<String> {
        let mut seen: Option<String> = None;
        for listing in listings {
            let marker = marker_in(listing.as_deref()?, &self.marker_prefix())?;
            if seen.as_ref().is_some_and(|s| *s != marker) {
                return None;
            }
            seen = Some(marker);
        }
        seen
    }

    /// The listings hold `target`: its marker in both families and every
    /// chain's rule count.
    fn intact(&self, target: &Generation, listings: &[Option<String>; 2]) -> bool {
        self.marker(listings).as_ref() == Some(&target.marker) && holds_rules(&target.text, listings)
    }

    /// After another writer may have acted (`net_guard`), or after a failed
    /// load: loads the target again when it is not confirmed, or when the
    /// tables lost their marker or a rule (one read of both families).
    /// `Ok(true)` when it loaded.
    pub fn reconcile(&mut self, nft: &mut (impl Nft + ?Sized)) -> Result<bool, String> {
        let Some(target) = self.target.clone() else { return Ok(false) };
        if self.confirmed == Some(target.number) && self.intact(&target, &nft.list_both(self.name)?) {
            return Ok(false);
        }
        self.load(nft).map(|_| true)
    }

    /// Whether the target is what the kernel was last read to hold.
    pub fn confirmed(&self) -> bool {
        self.target.as_ref().is_some_and(|t| self.confirmed == Some(t.number))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn status(&self) -> Value {
        json!({"target": self.target.as_ref().map(|t| t.number), "confirmed": self.confirmed, "error": self.error})
    }
}

/// Rules per family and chain, over each family's definition or listing.
fn rule_counts<'a>(families: impl Iterator<Item = &'a str>) -> Vec<std::collections::BTreeMap<String, usize>> {
    families.map(net::nft_chain_rules).collect()
}

/// Both families' listings hold as many rules per chain as `text` defines.
fn holds_rules(text: &str, listings: &[Option<String>; 2]) -> bool {
    let Some(listed) = listings.iter().map(Option::as_deref).collect::<Option<Vec<&str>>>() else { return false };
    rule_counts(text.split("delete table ").skip(1)) == rule_counts(listed.into_iter())
}

/// The `nft -f` batch that replaces both families of table `name` with
/// `families` and marks it generation `generation`: the marker and the text.
pub fn batch(owner: &str, name: &str, generation: u64, families: [String; 2]) -> Result<(String, String), String> {
    let marker = format!("zte-agent {owner} {generation} {}", &hex(&Sha256::digest(families.concat()))[..16]);
    let mut text = String::new();
    for (family, definition) in FAMILIES.iter().zip(families) {
        // Create if absent, delete, define: one atomic replacement.
        text.push_str(&format!("table {family} {name} {{}}\ndelete table {family} {name}\n"));
        let close = definition.rfind('}').ok_or("Invalid nftables definition")?;
        text.push_str(&definition[..close]);
        text.push_str(&format!("\tchain {STATE} {{\n\t\treturn comment \"{marker}\"\n\t}}\n}}\n"));
    }
    Ok((marker, text))
}

fn marker_in(listing: &str, prefix: &str) -> Option<String> {
    let start = listing.find(&format!("comment \"{prefix}"))? + "comment \"".len();
    let end = start + listing[start..].find('"')?;
    Some(listing[start..end].to_owned())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
pub mod fake {
    //! An `nft` stand-in: tables are the definitions loaded, rendered back
    //! the way `nft -t` lists them (rules and comments, no set elements).
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct FakeNft {
        pub tables: BTreeMap<(String, String), String>,
        /// Fail the next loads with this error (after committing, when `commit`).
        pub fail: Vec<(String, bool)>,
        /// Fail listings.
        pub unreadable: bool,
        pub loads: usize,
        /// Tables listed (one per family read).
        pub lists: usize,
    }

    impl Nft for FakeNft {
        fn load(&mut self, file: &std::path::Path) -> Result<(), String> {
            self.loads += 1;
            let text = std::fs::read_to_string(file).map_err(|e| e.to_string())?;
            let (error, commit) = if self.fail.is_empty() { (None, true) } else { let (e, c) = self.fail.remove(0); (Some(e), c) };
            if commit {
                for family in FAMILIES {
                    let header = format!("delete table {family} ");
                    let Some(at) = text.find(&header) else { continue };
                    let rest = &text[at + header.len()..];
                    let name = rest.split_whitespace().next().unwrap().to_owned();
                    let body_start = at + header.len() + rest.find('\n').unwrap() + 1;
                    let body = &text[body_start..];
                    let end = body.find("\n}\n").map(|e| e + 3).unwrap_or(body.len());
                    self.tables.insert((family.to_owned(), name), body[..end].to_owned());
                }
            }
            error.map_or(Ok(()), Err)
        }

        fn list(&mut self, family: &str, name: &str) -> Result<Option<String>, String> {
            self.lists += 1;
            if self.unreadable {
                return Err("Device tool failed".into());
            }
            Ok(self.tables.get(&(family.to_owned(), name.to_owned())).map(|text| {
                text.lines().filter(|l| !l.contains("elements = ")).collect::<Vec<_>>().join("\n")
            }))
        }

        fn delete(&mut self, family: &str, name: &str) -> Result<(), String> {
            self.tables.remove(&(family.to_owned(), name.to_owned()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeNft;
    use super::*;

    fn tables(test: &str) -> NftTables {
        let dir = std::env::temp_dir().join(format!("u60-effect-{test}-{}", std::process::id()));
        NftTables::new("test", "u60_t", dir.join("tables.nft"))
    }

    fn definition(rules: &[&str]) -> [String; 2] {
        FAMILIES.map(|family| table(family, "u60_t", &[("s", "type ipv4_addr; flags interval;", &["1.0.0.0/8".to_owned()])], &[("pre", "type filter hook prerouting priority 0; policy accept;", rules.iter().map(|r| (*r).to_owned()).collect())]))
    }

    #[test]
    fn a_batch_replaces_both_families_at_once_and_is_confirmed_by_its_marker() {
        let mut nft = FakeNft::default();
        let mut t = tables("load");
        assert_eq!(t.presence(&mut nft).unwrap(), Presence::Absent);
        assert_eq!(t.declare(definition(&["accept"]), &mut nft).unwrap(), 1);
        assert!(t.confirmed());
        let text = std::fs::read_to_string(&t.file).unwrap();
        assert!(text.starts_with("table ip u60_t {}\ndelete table ip u60_t\ntable ip u60_t {"), "{text}");
        assert_eq!(text.matches("comment \"zte-agent test 1 ").count(), 2, "one marker per family, one batch");
        assert_eq!(t.presence(&mut nft).unwrap(), Presence::Ours);
        assert!(!t.reconcile(&mut nft).unwrap(), "intact: nothing to load");
        let _ = std::fs::remove_dir_all(t.file.parent().unwrap());
    }

    #[test]
    fn a_table_without_our_marker_is_foreign() {
        let mut nft = FakeNft::default();
        nft.tables.insert(("ip6".into(), "u60_t".into()), "table ip6 u60_t {\n}\n".into());
        assert_eq!(tables("foreign").presence(&mut nft).unwrap(), Presence::Foreign);
        nft.unreadable = true;
        assert!(tables("foreign").presence(&mut nft).is_err(), "an unreadable kernel is no evidence of a free name");
    }

    /// Release blocker 4: A→B fails with A intact; B stays the target.
    #[test]
    fn a_failed_target_is_kept_and_tried_again_never_taken_as_loaded() {
        let mut nft = FakeNft::default();
        let mut t = tables("retry");
        t.declare(definition(&["accept"]), &mut nft).unwrap();
        nft.fail.push(("Device tool timed out".into(), false));
        assert!(t.declare(definition(&["drop"]), &mut nft).is_err());
        assert!(!t.confirmed(), "A is still loaded; B is not");
        assert!(t.error().is_some_and(|e| e.contains("did not load generation 2")));
        assert!(nft.tables[&("ip".to_owned(), "u60_t".to_owned())].contains("accept"));
        assert!(t.reconcile(&mut nft).unwrap(), "the reconcile loads B");
        assert!(t.confirmed() && t.error().is_none() && nft.tables[&("ip".to_owned(), "u60_t".to_owned())].contains("drop"));
        // The kernel committed but the tool reported a failure: the marker
        // decides.
        nft.fail.push(("Device tool failed (exit status: 1)".into(), true));
        assert_eq!(t.declare(definition(&["reject"]), &mut nft).unwrap(), 3);
        // Committed, but the readback fails: not confirmed until it reads.
        nft.fail.push(("Device tool timed out".into(), true));
        nft.unreadable = true;
        assert!(t.declare(definition(&["return"]), &mut nft).is_err() && !t.confirmed());
        nft.unreadable = false;
        assert!(t.reconcile(&mut nft).unwrap() && t.confirmed());
        let _ = std::fs::remove_dir_all(t.file.parent().unwrap());
    }

    #[test]
    fn a_flushed_chain_or_a_lost_marker_is_loaded_again() {
        let mut nft = FakeNft::default();
        let mut t = tables("guard");
        t.declare(definition(&["accept", "drop"]), &mut nft).unwrap();
        let key = ("ip".to_owned(), "u60_t".to_owned());
        let flushed = nft.tables[&key].replace("\t\taccept\n\t\tdrop\n", "");
        nft.tables.insert(key.clone(), flushed);
        assert!(t.reconcile(&mut nft).unwrap(), "a flushed chain");
        nft.tables.remove(&key);
        assert!(t.reconcile(&mut nft).unwrap(), "a deleted family");
        assert!(!t.reconcile(&mut nft).unwrap());
        let _ = std::fs::remove_dir_all(t.file.parent().unwrap());
    }

    #[test]
    fn large_sets_are_not_read_back_element_by_element() {
        let mut nft = FakeNft::default();
        let mut t = tables("large");
        let elements: Vec<String> = (0..20_000u32).map(|i| format!("{}.{}.{}.0/24", 1 + i / 65536, (i / 256) % 256, i % 256)).collect();
        let families = FAMILIES.map(|family| table(family, "u60_t", &[("geo", "type ipv4_addr; flags interval;", &elements)], &[("pre", "type filter hook prerouting priority 0;", vec!["ip daddr @geo return".into()])]));
        assert!(families[0].len() > 256 * 1024, "larger than a tool's captured output");
        t.declare(families, &mut nft).unwrap();
        assert!(t.confirmed() && !t.reconcile(&mut nft).unwrap());
        let _ = std::fs::remove_dir_all(t.file.parent().unwrap());
    }

    /// Finding 6: the same content again is proven by its marker, not
    /// loaded; anything else, or a kernel that lost it, is loaded.
    #[test]
    fn the_same_content_is_not_loaded_again_while_the_kernel_holds_it() {
        let mut nft = FakeNft::default();
        let mut t = tables("same");
        assert_eq!(t.declare(definition(&["accept"]), &mut nft).unwrap(), 1);
        assert_eq!(t.declare(definition(&["accept"]), &mut nft).unwrap(), 1, "the confirmed generation stays");
        assert_eq!(nft.loads, 1);
        assert_eq!(t.declare(definition(&["drop"]), &mut nft).unwrap(), 2);
        assert_eq!(t.declare(definition(&["accept"]), &mut nft).unwrap(), 3, "equal to an older one is still a change");
        let key = ("ip".to_owned(), "u60_t".to_owned());
        let flushed = nft.tables[&key].replace("\t\taccept\n", "");
        nft.tables.insert(key, flushed);
        assert_eq!(t.declare(definition(&["accept"]), &mut nft).unwrap(), 4, "a flushed chain is loaded again");
        nft.fail.push(("Device tool timed out".into(), false));
        assert!(t.declare(definition(&["return"]), &mut nft).is_err());
        assert_eq!(t.declare(definition(&["return"]), &mut nft).unwrap(), 6, "an unconfirmed target is loaded again");
        nft.unreadable = true;
        assert!(t.declare(definition(&["return"]), &mut nft).is_err(), "an unreadable kernel proves nothing");
        assert_eq!(nft.loads, 7);
        let _ = std::fs::remove_dir_all(t.file.parent().unwrap());
    }

    /// Finding 7: one read of each family per check, for the marker and the
    /// rule counts alike.
    #[test]
    fn a_reconcile_reads_each_family_once() {
        let mut nft = FakeNft::default();
        let mut t = tables("once");
        t.declare(definition(&["accept"]), &mut nft).unwrap();
        let before = nft.lists;
        assert!(!t.reconcile(&mut nft).unwrap());
        assert_eq!(nft.lists - before, FAMILIES.len());
    }

    #[test]
    fn a_table_is_cut_out_of_a_ruleset_listing() {
        let ruleset = "table ip u60_relay {\n\tchain fwd {\n\t\tdrop\n\t}\n}\ntable ip u60_t {\n\tset s {\n\t\ttype ipv4_addr\n\t}\n\tchain state {\n\t\treturn comment \"zte-agent test 3 ab\"\n\t}\n}\ntable ip6 u60_t {\n\tchain state {\n\t}\n}\n";
        let ip = table_in(ruleset, "ip", "u60_t").unwrap();
        assert!(ip.starts_with("table ip u60_t {\n") && ip.ends_with("\t}\n}\n") && !ip.contains("u60_relay"), "{ip}");
        assert_eq!(marker_in(&ip, "zte-agent test ").as_deref(), Some("zte-agent test 3 ab"));
        assert_eq!(table_in(ruleset, "ip6", "u60_t").as_deref(), Some("table ip6 u60_t {\n\tchain state {\n\t}\n}\n"));
        assert_eq!(table_in(ruleset, "ip6", "u60_relay"), None);
        assert_eq!(table_in("table ip u60_t {\n\tchain state {\n", "ip", "u60_t"), None, "a cut-off listing is no table");
    }

    /// With the real `nft`, in a disposable namespace (`tests/mihomo-qa`'s
    /// container, `U60_MIHOMO_QA_ISOLATED=1`): the one `list ruleset` read
    /// gives each table as `list table` does, beside another table, and the
    /// checks built on it hold (same content not loaded again, a flushed
    /// chain loaded again).
    #[test]
    #[ignore]
    fn isolated_one_ruleset_read_matches_the_per_table_reads() {
        assert_eq!(std::env::var("U60_MIHOMO_QA_ISOLATED").as_deref(), Ok("1"));
        let mut nft = Device;
        let other = std::env::temp_dir().join("u60-effect-other.nft");
        std::fs::write(&other, "table ip u60_other {\n\tchain c {\n\t\ttype filter hook input priority 0; policy accept;\n\t\tcounter\n\t}\n}\n").unwrap();
        nft.load(&other).unwrap();
        let mut t = tables("isolated");
        assert_eq!(t.declare(definition(&["accept", "counter"]), &mut nft).unwrap(), 1);
        assert!(t.confirmed());
        let both = nft.list_both("u60_t").unwrap();
        for (family, read) in FAMILIES.iter().zip(&both) {
            let alone = nft.list(family, "u60_t").unwrap().unwrap();
            let lines = |text: &str| text.lines().map(str::trim_end).filter(|l| !l.is_empty()).map(str::to_owned).collect::<Vec<_>>();
            assert_eq!(lines(read.as_deref().unwrap()), lines(&alone), "{family}");
        }
        assert_eq!(t.declare(definition(&["accept", "counter"]), &mut nft).unwrap(), 1, "the same content: not loaded again");
        Cmd::new("nft", &["flush", "chain", "ip6", "u60_t", "pre"]).run().unwrap();
        assert!(t.reconcile(&mut nft).unwrap(), "a flushed chain is loaded again");
        assert!(!t.reconcile(&mut nft).unwrap());
        for family in FAMILIES {
            nft.delete(family, "u60_t").unwrap();
        }
        assert_eq!(nft.list_both("u60_t").unwrap(), [None, None]);
        nft.delete("ip", "u60_other").unwrap();
    }
}
