//! Qualcomm IPA hardware forwarding of the relay's IPv4 NAT (owner decision
//! 63, `zte-agent/docs/relay-hw-offload.md`). Three things must all hold:
//! IPACM read a `u60sta0` entry from its configuration when it started (at
//! boot; restarting it at runtime loses the driver's earlier Wi-Fi events),
//! the `main` table has a default route through the relay (IPACM's WAN-up
//! trigger, it ignores policy tables), and IPACM runs in hardware mode.
//! Connections that are offloaded skip iptables, tc and parental control.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use serde::Serialize;
use serde_json::{json, Value};

use super::{net, Cmd, Step, Transaction, IFACE};

pub(crate) const CONFIG: &str = "/etc/data/ipa/IPACM_cfg.xml";
/// `/etc` is an overlay: the edit persists, but a QCMAP factory reset copies
/// `factory_IPACM_cfg.xml` over it (status `overwritten`).
const STATE: &str = "/data/zte-agent-relay/ipacm";
/// Kept after a removal too: the only stock copy if the owner needs it back.
const BACKUP: &str = "IPACM_cfg.xml.orig";
/// Boot id of the install: the entry is loaded only after the next boot.
const MARKER: &str = "installed";
const LOADED_BEFORE: &str = "loaded";
const SWITCH: &str = "/sbin/ipacm_switch.sh";
/// Metric of the relay's `main` default and its unreachable guards. Not 0:
/// netifd installs the cellular default with metric 0 and NLM_F_REPLACE, so
/// an equal metric would let either route replace the other.
pub(super) const METRIC: &str = "60631";
/// Ranges the relay table throws to `main` for their specific routes. With a
/// relay default in `main` they would otherwise leave through the hotel.
/// The LAN subnet always has its connected route there.
pub(super) const GUARDED: [&str; 3] = ["100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4"];
const AUDIT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Config {
    NotInstalled,
    RebootRequired,
    Loaded,
    /// Installed by the owner, then replaced (factory reset): install again.
    Overwritten,
    Unavailable,
}

pub(crate) fn config() -> Config {
    let Ok(text) = fs::read_to_string(CONFIG) else {
        return Config::Unavailable;
    };
    let marker = fs::read_to_string(Path::new(STATE).join(MARKER)).ok();
    classify(&text, marker.as_deref().map(str::trim), &net::boot_id(), loaded_before_ipacm)
}

fn classify(text: &str, marker: Option<&str>, boot: &str, loaded: impl FnOnce() -> bool) -> Config {
    match (entry(text).is_some(), marker) {
        (false, Some(_)) => Config::Overwritten,
        (false, None) => Config::NotInstalled,
        (true, Some(installed)) if installed == boot => Config::RebootRequired,
        (true, Some(_)) => Config::Loaded,
        // Present without our marker (added by hand): only the file age tells.
        (true, None) => if loaded() { Config::Loaded } else { Config::RebootRequired },
    }
}

/// Owner action: add the entry (effective after a restart). The file is
/// rewritten in place to keep its owner, mode and SELinux label.
pub(crate) fn install() -> Result<Config, String> {
    let text = fs::read_to_string(CONFIG).map_err(|_| "Cannot read the IPA configuration")?;
    let marker = Path::new(STATE).join(MARKER);
    if entry(&text).is_some() {
        let value = if loaded_before_ipacm() { LOADED_BEFORE.into() } else { net::boot_id() };
        net::write_private(&marker, value.as_bytes())?;
        return Ok(config());
    }
    let updated = insert(&text)?;
    net::write_private(&Path::new(STATE).join(BACKUP), text.as_bytes())?;
    rewrite(Path::new(CONFIG), &updated)?;
    net::write_private(&marker, net::boot_id().as_bytes())?;
    Ok(config())
}

/// Owner action: remove the entry. New relay sessions stop using hardware
/// forwarding at once; IPACM forgets the interface at the next restart. The
/// stock backup stays.
pub(crate) fn remove() -> Result<Config, String> {
    let text = fs::read_to_string(CONFIG).map_err(|_| "Cannot read the IPA configuration")?;
    if let Some(stripped) = strip(&text) {
        rewrite(Path::new(CONFIG), &stripped)?;
    }
    match fs::remove_file(Path::new(STATE).join(MARKER)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err("Cannot clear the hardware forwarding record".into())
        }
        _ => {}
    }
    Ok(config())
}

fn rewrite(path: &Path, text: &str) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|_| "Cannot write the IPA configuration")?;
    file.write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| "Cannot write the IPA configuration")?;
    if fs::read_to_string(path).ok().as_deref() != Some(text) {
        return Err(format!("The IPA configuration did not read back; the original is in {STATE}/{BACKUP}"));
    }
    Ok(())
}

/// Byte range of the `<Iface>` element naming the relay, whole lines.
fn entry(text: &str) -> Option<(usize, usize)> {
    let name = text.find(&format!("<Name>{IFACE}</Name>"))?;
    let open = text[..name].rfind("<Iface>")?;
    if text[open..name].contains("</Iface>") {
        return None;
    }
    let close = name + text[name..].find("</Iface>")? + "</Iface>".len();
    let start = text[..open].rfind('\n').map_or(0, |i| i + 1);
    let end = text[close..].find('\n').map_or(text.len(), |i| close + i + 1);
    Some((start, end))
}

fn strip(text: &str) -> Option<String> {
    let (start, end) = entry(text)?;
    Some(format!("{}{}", &text[..start], &text[end..]))
}

/// The relay entry before `wlan0`'s, in its format: Category UNKNOWN and
/// WlanMode full, like the vendor's own Wi-Fi interfaces.
fn insert(text: &str) -> Result<String, String> {
    const UNRECOGNIZED: &str = "Unrecognized IPA configuration: no wlan0 interface entry";
    let name = text.find("<Name>wlan0</Name>").ok_or(UNRECOGNIZED)?;
    let open = text[..name].rfind("<Iface>").ok_or(UNRECOGNIZED)?;
    let start = text[..open].rfind('\n').map_or(0, |i| i + 1);
    let child = text[..name].rfind('\n').map_or(0, |i| i + 1);
    let (outer, inner) = (&text[start..open], &text[child..name]);
    if !outer.chars().chain(inner.chars()).all(|c| c == ' ' || c == '\t') {
        return Err(UNRECOGNIZED.into());
    }
    let block = format!(
        "{outer}<Iface>\n{inner}<Name>{IFACE}</Name>\n{inner}<Category>UNKNOWN</Category>\n{inner}<WlanMode>full</WlanMode>\n{outer}</Iface>\n"
    );
    Ok(format!("{}{block}{}", &text[..start], &text[start..]))
}

/// Whether the configuration is older than the running IPACM, for an entry
/// added by hand. Unknown counts as not loaded.
fn loaded_before_ipacm() -> bool {
    let Ok(modified) = fs::metadata(CONFIG).and_then(|m| m.modified()) else {
        return false;
    };
    ipacm_started().is_some_and(|started| modified < started)
}

fn ipacm_started() -> Option<SystemTime> {
    let uptime: f64 = fs::read_to_string("/proc/uptime").ok()?.split_whitespace().next()?.parse().ok()?;
    // SAFETY: sysconf has no preconditions.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        return None;
    }
    let started = fs::read_dir("/proc").ok()?.flatten().find_map(|entry| {
        let dir: PathBuf = entry.path();
        if fs::read_to_string(dir.join("comm")).ok()?.trim() != "ipacm" {
            return None;
        }
        let stat = fs::read_to_string(dir.join("stat")).ok()?;
        stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse::<u64>().ok()
    })?;
    let age = uptime - started as f64 / ticks as f64;
    SystemTime::now().checked_sub(Duration::from_secs_f64(age.max(0.0)))
}

/// Settings for which the router keeps forwarding on the CPU on purpose:
/// offloaded connections would bypass them. Smart QoS (`Ai_mode`) also turns
/// IPA off at boot, but that is the vendor default, not an owner limit.
fn owner_limit() -> Option<&'static str> {
    let on = |key: &str| crate::ubus::uci_get(key).is_ok_and(|v| v == "1");
    if on("zwrt_router.other.ipa_disable") {
        Some("Hardware acceleration is turned off in the router settings")
    } else if on("zwrt_zte_mc.power.power_saver_mode") {
        Some("Power saver mode limits speed on the CPU path")
    } else if on("zwrt_router.qos.total_limit_switch") || on("zwrt_router.qos.st_total_limit_switch") {
        Some("A router speed limit is active")
    } else {
        None
    }
}

/// `ipacm_switch.sh` records each switch here (`off` sets 1).
fn hardware_mode() -> Option<bool> {
    crate::ubus::uci_get("zwrt_router.tmp_router.close_ipa_acce").ok().map(|v| v != "1")
}

fn mode_step(was_hardware: bool) -> Step {
    let undo = if was_hardware { Cmd::new("true", &[]) } else { Cmd::new("@u60-relay-ipa", &["sw"]) };
    Step::new(Cmd::new("@u60-relay-ipa", &["hw"]), undo)
}

/// `@u60-relay-ipa hw|sw`, through the vendor switch (it signals IPACM and
/// records the mode). Without the switch or IPACM, SW is already the case.
pub(crate) fn command(args: &[String]) -> Result<(), String> {
    let mode = match args {
        [m] if m == "hw" => "on",
        [m] if m == "sw" => "off",
        _ => return Err("Invalid IPA mode".into()),
    };
    if !Path::new(SWITCH).exists() {
        return if mode == "off" { Ok(()) } else { Err("The vendor IPA switch is missing".into()) };
    }
    Cmd::new("sh", &[SWITCH, mode]).run().map(|_| ())
}

/// One relay session's hardware forwarding.
pub(super) struct Runtime {
    /// The entry was loaded at boot; the session's plan has the `main` route.
    pub(super) route: bool,
    /// This session owns IPACM's hardware mode (journaled undo exists).
    owned: bool,
    hardware: bool,
    reason: Option<String>,
    checked: Option<Instant>,
}

impl Runtime {
    pub(super) fn off() -> Self {
        Self { route: false, owned: false, hardware: false, reason: None, checked: None }
    }

    /// Called with the session's network plan applied.
    pub(super) fn start(tx: &mut Transaction, config: Config) -> Self {
        let mut runtime = Self::off();
        runtime.route = config == Config::Loaded;
        if !runtime.route {
            runtime.reason = Some(match config {
                Config::RebootRequired => "Hardware forwarding is installed; restart the router to load it",
                Config::Overwritten => "Hardware forwarding was removed by a router reset; install it again",
                Config::Unavailable => "The IPA configuration is unavailable",
                _ => "Hardware forwarding is not installed",
            }.into());
            return runtime;
        }
        runtime.audit(tx);
        runtime
    }

    /// Hardware mode while no owner limit needs the CPU path. The vendor
    /// switches IPACM to software at boot and on Smart QoS events; switch it
    /// back, at most every `AUDIT`. Never forces it against an owner limit.
    pub(super) fn audit(&mut self, tx: &mut Transaction) {
        if !self.route || self.checked.is_some_and(|at| at.elapsed() < AUDIT) {
            return;
        }
        self.checked = Some(Instant::now());
        if let Some(limit) = owner_limit() {
            self.hardware = hardware_mode() == Some(true);
            self.reason = Some(limit.into());
            return;
        }
        let current = hardware_mode();
        if current == Some(true) {
            if !self.owned {
                // Found on: ours to keep, but not to switch off afterwards.
                let _ = tx.apply(mode_step(true));
                self.owned = true;
            }
            self.hardware = true;
            self.reason = None;
            return;
        }
        let result = if self.owned { command(&["hw".into()]) } else { tx.apply(mode_step(false)) };
        self.owned = true;
        self.hardware = result.is_ok() && hardware_mode() == Some(true);
        self.reason = match result {
            Ok(()) if self.hardware => {
                eprintln!("[relay] IPACM switched to hardware mode");
                None
            }
            Ok(()) => Some("IPACM did not confirm hardware mode".into()),
            Err(e) => Some(e),
        };
    }

    pub(super) fn status(&self) -> Value {
        json!({"route": self.route, "hardware": self.hardware, "reason": self.reason})
    }

    /// The `main` route failed: IPACM never sees a WAN, so stop auditing.
    pub(super) fn no_route(&mut self, error: String) {
        self.route = false;
        self.hardware = false;
        self.reason = Some(format!("Hardware forwarding route was not added: {error}"));
    }
}

/// `main` default through the relay plus its unreachable guards, for a plan
/// that already has the relay table. Only with the entry loaded.
pub(super) fn route_plan(gateway: &str, subnet: &str) -> Vec<Step> {
    let mut plan: Vec<Step> = GUARDED
        .iter()
        .filter(|dest| **dest != subnet)
        .map(|dest| net::ip_step("-4", "route", &["unreachable", dest, "metric", METRIC, "table", "main"]))
        .collect();
    plan.push(net::ip_step("-4", "route", &["default", "via", gateway, "dev", IFACE, "metric", METRIC, "table", "main"]));
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    const VENDOR: &str = "    <IPACMIface>\n      <Iface>\n        <Name>rmnet_data0</Name>\n        <Category>WAN</Category>\n      </Iface>\n      <Iface>\n        <Name>wlan0</Name>\n        <Category>UNKNOWN</Category>\n        <WlanMode>full</WlanMode>\n      </Iface>\n    </IPACMIface>\n";

    #[test]
    fn the_entry_goes_before_wlan0_in_its_format_and_strips_back_exactly() {
        let installed = insert(VENDOR).unwrap();
        assert_eq!(
            installed,
            VENDOR.replacen(
                "      <Iface>\n        <Name>wlan0",
                "      <Iface>\n        <Name>u60sta0</Name>\n        <Category>UNKNOWN</Category>\n        <WlanMode>full</WlanMode>\n      </Iface>\n      <Iface>\n        <Name>wlan0",
                1
            )
        );
        assert!(entry(VENDOR).is_none());
        assert_eq!(strip(&installed).unwrap(), VENDOR);
        assert!(insert("<Iface><Name>wlan2</Name></Iface>").is_err());
    }

    #[test]
    fn only_a_later_boot_or_an_older_file_counts_as_loaded() {
        let installed = insert(VENDOR).unwrap();
        let never = || panic!("the marker decides");
        assert_eq!(classify(VENDOR, None, "b", never), Config::NotInstalled);
        assert_eq!(classify(VENDOR, Some("a"), "b", never), Config::Overwritten);
        assert_eq!(classify(&installed, Some("b"), "b", never), Config::RebootRequired);
        assert_eq!(classify(&installed, Some("a"), "b", never), Config::Loaded);
        assert_eq!(classify(&installed, Some(LOADED_BEFORE), "b", never), Config::Loaded);
        assert_eq!(classify(&installed, None, "b", || true), Config::Loaded);
        assert_eq!(classify(&installed, None, "b", || false), Config::RebootRequired);
    }

    #[test]
    fn the_main_route_never_shares_the_cellular_metric_and_guards_thrown_ranges() {
        let plan = route_plan("192.168.2.1", "192.168.2.0/24");
        let last = plan.last().unwrap();
        assert_eq!(last.apply.args.join(" "), format!("-4 route add default via 192.168.2.1 dev u60sta0 metric {METRIC} table main"));
        assert_ne!(METRIC, "0");
        for dest in GUARDED {
            assert!(plan.iter().any(|s| s.apply.args.windows(2).any(|w| w == ["unreachable", dest])));
        }
        assert!(plan.iter().all(|s| s.undo.args.windows(2).any(|w| w == ["table", "main"])));
        // An upstream inside a guarded range keeps its own connected route.
        assert_eq!(route_plan("100.64.0.1", "100.64.0.0/10").len(), GUARDED.len());
        assert!(command(&["on".into()]).is_err());
    }
}
