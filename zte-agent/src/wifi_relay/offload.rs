//! Qualcomm IPA hardware forwarding of the relay's IPv4 NAT (owner decision
//! 63, `zte-agent/docs/relay-hw-offload.md`). Three things must all hold:
//! IPACM read a `u60sta0` entry from its configuration when it started (at
//! boot; restarting it at runtime loses the driver's earlier Wi-Fi events),
//! the `main` table has a default route through the relay (IPACM's WAN-up
//! trigger, it ignores policy tables), and IPACM runs in hardware mode.
//! Connections that are offloaded skip iptables, tc and parental control.
//! IPACM also puts a rule for every other upstream host ahead of the
//! gateway's; `neighbours` removes them. It also loses hotspot clients' LAN
//! routes when they change bands; `clients` brings them back. The owner's switch and an install or
//! removal apply to a connected relay at once (owner decision 64): without
//! the `main` route IPACM has no relay WAN, so the relay forwards on the CPU.

mod clients;
mod monitor;
pub(crate) use monitor::Record;
mod neighbours;

use std::{
    fs,
    io::Write,
    net::Ipv4Addr,
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
/// Present while the owner has hardware forwarding turned off.
const OFF: &str = "off";
/// Boot id while the running IPACM knows the relay interface. It keeps it
/// until the next boot, removed entry or not, so a reinstall in the same boot
/// works at once. On tmpfs: gone at the next boot.
const LOADED_NOW: &str = "/tmp/zte-agent-relay/ipacm-loaded";
const LOADED_BEFORE: &str = "loaded";
const SWITCH: &str = "/sbin/ipacm_switch.sh";
/// Metric of the relay's `main` default and its unreachable guards. Not 0:
/// netifd installs the cellular default with metric 0 and NLM_F_REPLACE, so
/// an equal metric would let either route replace the other.
pub(super) const METRIC: &str = crate::netfx::ids::RELAY_METRIC;
/// Ranges the relay table throws to `main` for their specific routes. With a
/// relay default in `main` they would otherwise leave through the hotel.
/// The LAN subnet always has its connected route there.
pub(super) const GUARDED: [&str; 3] = crate::netfx::ids::LOCAL_ROUTES_V4;
const AUDIT: Duration = Duration::from_secs(15);
/// Relayed IPv4 still forwarded by the kernel faster than this, in packets/s
/// back towards the LAN, means IPA is not carrying it (a working offload
/// leaves a few hundred packets per test; a failed one ~12,000/s at 240 Mbit/s).
const CPU_PATH_PPS: f64 = 1500.0;
const REARM_GAP: Duration = Duration::from_secs(60);
const REARMS: u32 = 3;

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
    let boot = net::boot_id();
    let loaded_now = fs::read_to_string(LOADED_NOW).is_ok_and(|b| b.trim() == boot);
    let config = classify(&text, marker.as_deref().map(str::trim), &boot, loaded_now, loaded_before_ipacm);
    if config == Config::Loaded && !loaded_now {
        let _ = net::write_private(Path::new(LOADED_NOW), boot.as_bytes());
    }
    config
}

fn classify(text: &str, marker: Option<&str>, boot: &str, loaded_now: bool, loaded: impl FnOnce() -> bool) -> Config {
    match (entry(text).is_some(), marker) {
        (false, Some(_)) => Config::Overwritten,
        (false, None) => Config::NotInstalled,
        (true, _) if loaded_now => Config::Loaded,
        (true, Some(installed)) if installed == boot => Config::RebootRequired,
        (true, Some(_)) => Config::Loaded,
        // Present without our marker (added by hand): only the file age tells.
        (true, None) => if loaded() { Config::Loaded } else { Config::RebootRequired },
    }
}

/// Owner action: add the entry (effective at once if IPACM loaded it at this
/// boot, else after a restart). The file is rewritten in place to keep its
/// owner, mode and SELinux label.
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

/// Owner action: remove the entry. The relay stops using hardware forwarding
/// at once (`Runtime::sync`); IPACM forgets the interface at the next restart.
/// The stock backup stays.
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

/// Replaces the configuration without ever leaving a partial one (H5): a
/// complete copy is written on the same filesystem, given the original's
/// owner, mode and SELinux label, checked, then renamed over it. A crash
/// leaves either file whole (and at most the copy behind). The copy goes in
/// the parent directory when it is the same filesystem, so the directory
/// IPACM watches sees one rename.
fn rewrite(path: &Path, text: &str) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let failed = |what: &str| format!("Cannot write the IPA configuration ({what}); the original is in {STATE}/{BACKUP}");
    let meta = fs::metadata(path).map_err(|_| failed("metadata"))?;
    let label = selinux_label(path);
    let dir = path.parent().ok_or_else(|| failed("path"))?;
    let outer = dir.parent().filter(|outer| fs::metadata(outer).is_ok_and(|m| m.dev() == meta.dev()));
    let copy = outer.unwrap_or(dir).join(".u60-ipacm-cfg.new");
    let _ = fs::remove_file(&copy);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&copy)
        .map_err(|_| failed("copy"))?;
    let written = (|| {
        file.write_all(text.as_bytes()).map_err(|_| failed("write"))?;
        std::os::unix::fs::fchown(&file, Some(meta.uid()), Some(meta.gid())).map_err(|_| failed("owner"))?;
        file.set_permissions(fs::Permissions::from_mode(meta.mode() & 0o7777)).map_err(|_| failed("mode"))?;
        if let Some(label) = &label {
            set_selinux_label(&copy, label).map_err(|_| failed("SELinux label"))?;
        }
        file.sync_all().map_err(|_| failed("sync"))?;
        let check = fs::metadata(&copy).map_err(|_| failed("check"))?;
        if fs::read_to_string(&copy).ok().as_deref() != Some(text) || (check.uid(), check.gid(), check.mode()) != (meta.uid(), meta.gid(), meta.mode()) || selinux_label(&copy) != label {
            return Err(failed("the copy did not check out"));
        }
        fs::rename(&copy, path).map_err(|_| failed("rename"))?;
        fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|_| failed("directory sync"))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&copy);
    }
    written?;
    if fs::read_to_string(path).ok().as_deref() != Some(text) {
        return Err(format!("The IPA configuration did not read back; the original is in {STATE}/{BACKUP}"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn selinux_label(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = c"security.selinux";
    let mut value = vec![0u8; 256];
    // SAFETY: the buffer is as long as stated; the strings are NUL-terminated.
    let size = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
    (size > 0).then(|| {
        value.truncate(size as usize);
        value
    })
}

#[cfg(target_os = "linux")]
fn set_selinux_label(path: &Path, label: &[u8]) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: as above; `label` is passed with its length.
    let r = unsafe { libc::lsetxattr(path.as_ptr(), c"security.selinux".as_ptr(), label.as_ptr().cast(), label.len(), 0) };
    if r == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

#[cfg(not(target_os = "linux"))]
fn selinux_label(_: &Path) -> Option<Vec<u8>> {
    None
}

#[cfg(not(target_os = "linux"))]
fn set_selinux_label(_: &Path, _: &[u8]) -> std::io::Result<()> {
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

/// The owner's runtime switch (on unless turned off).
pub(crate) fn enabled() -> bool {
    !Path::new(STATE).join(OFF).exists()
}

pub(crate) fn set_enabled(on: bool) -> Result<(), String> {
    let path = Path::new(STATE).join(OFF);
    if !on {
        return net::write_private(&path, b"1\n");
    }
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err("Cannot clear the hardware forwarding switch".into()),
        _ => Ok(()),
    }
}

/// Why a session forwards on the CPU when it does not engage the hardware path.
fn idle_reason(config: Config) -> &'static str {
    match config {
        Config::Loaded => "Hardware forwarding is turned off",
        Config::RebootRequired => "Hardware forwarding is installed; restart the router to load it",
        Config::Overwritten => "Hardware forwarding was removed by a router reset; install it again",
        Config::Unavailable => "The IPA configuration is unavailable",
        Config::NotInstalled => "Hardware forwarding is not installed",
    }
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
    // `net_guard` watches the script: this run's opens count once.
    crate::net_guard::own_run(SWITCH, || Cmd::new("sh", &[SWITCH, mode]).run()).map(|_| ())
}

/// The firmware the B31-specific workarounds were verified on
/// (`relay-mihomo-architecture.md` section 7): the neighbour retirement, the
/// clients' STALE nudge and the SW→HW re-arm. Elsewhere hardware forwarding
/// stays off and the reason shows.
const FIRMWARE: &str = "BD_CNMU5250V1.0.0B31";
const IPACM: &str = "/usr/bin/ipacm";
/// SHA-256 of B31's `/usr/bin/ipacm` (4,129,835 bytes, read 2026-11-10).
const IPACM_SHA256: &str = "95385816da7b2edb9a977cee328c091753463fcd4a70a67fa1676e8b335c11c0";

/// Where the session's hardware path is (section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum State {
    /// Not wanted, or no session.
    Off,
    /// Hardware mode and the `main` route being put in place.
    Engaging,
    /// The path is engaged and audited every 15 s.
    Hardware,
    /// Wanted but on the CPU: an owner limit, another firmware, a failure.
    Software,
    /// The path being taken back (route first, then the mode it switched).
    Releasing,
}

/// The device side of IPACM and the session's journal, so the state machine
/// runs against a fake in tests (I6).
trait IpacmPort {
    fn config(&mut self) -> Config;
    fn enabled(&mut self) -> bool;
    fn owner_limit(&mut self) -> Option<&'static str>;
    fn hardware_mode(&mut self) -> Option<bool>;
    /// The vendor switch, outside the journal (re-arming a mode we own).
    fn switch(&mut self, hardware: bool) -> Result<(), String>;
    /// `U60_RELAY_FWD`'s upstream-to-LAN TCP accept counter.
    fn return_packets(&mut self) -> Option<u64>;
    /// `Err(why)` unless this is the firmware the workarounds were verified on.
    fn fingerprint(&mut self) -> Result<(), String>;
    fn monitors(&mut self, gateway: Ipv4Addr) -> Vec<monitor::Monitor>;
    fn pause(&mut self, wait: Duration);
    fn apply(&mut self, tx: &mut Transaction, step: Step) -> Result<(), String>;
    fn apply_network(&mut self, tx: &mut Transaction, plan: Vec<Step>) -> Result<(), String>;
    fn release(&mut self, tx: &mut Transaction, undos: &[Cmd]) -> Result<(), String>;
    /// The mode before this session took it (what its undo restores).
    fn mode_before(&mut self) -> bool {
        self.hardware_mode() == Some(true)
    }
    /// Whether engaging re-arms IPACM for a new uplink.
    fn rearms(&self) -> bool {
        true
    }
}

/// The router.
struct Device;

impl IpacmPort for Device {
    fn config(&mut self) -> Config {
        config()
    }
    fn enabled(&mut self) -> bool {
        enabled()
    }
    fn owner_limit(&mut self) -> Option<&'static str> {
        owner_limit()
    }
    fn hardware_mode(&mut self) -> Option<bool> {
        hardware_mode()
    }
    fn switch(&mut self, hardware: bool) -> Result<(), String> {
        command(&[if hardware { "hw" } else { "sw" }.into()])
    }
    fn return_packets(&mut self) -> Option<u64> {
        Cmd::new("iptables", &["-w", "2", "-t", "filter", "-L", "U60_RELAY_FWD", "-nvx"]).run().ok().and_then(|t| return_packets(&t))
    }
    fn fingerprint(&mut self) -> Result<(), String> {
        let version = crate::ubus::uci_get("zwrt_common_info.common_config.wa_inner_version").unwrap_or_default();
        let binary = fs::read(IPACM).ok().map(|bytes| {
            use sha2::Digest;
            sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()
        });
        fingerprint(&version, binary.as_deref())
    }
    fn monitors(&mut self, gateway: Ipv4Addr) -> Vec<monitor::Monitor> {
        vec![neighbours::watch(gateway), clients::watch()]
    }
    fn pause(&mut self, wait: Duration) {
        std::thread::sleep(wait);
    }
    fn apply(&mut self, tx: &mut Transaction, step: Step) -> Result<(), String> {
        tx.apply(step)
    }
    fn apply_network(&mut self, tx: &mut Transaction, plan: Vec<Step>) -> Result<(), String> {
        tx.apply_network(plan)
    }
    fn release(&mut self, tx: &mut Transaction, undos: &[Cmd]) -> Result<(), String> {
        tx.release(undos)
    }
}

/// The router, for a hardware path the previous agent engaged in a session
/// this one adopts (`Runtime::adopt`).
struct Adopting {
    device: Device,
    /// The mode before that session took it (its journaled undo).
    mode_before: bool,
}

impl IpacmPort for Adopting {
    fn config(&mut self) -> Config {
        self.device.config()
    }
    fn enabled(&mut self) -> bool {
        self.device.enabled()
    }
    fn owner_limit(&mut self) -> Option<&'static str> {
        self.device.owner_limit()
    }
    fn hardware_mode(&mut self) -> Option<bool> {
        self.device.hardware_mode()
    }
    fn switch(&mut self, hardware: bool) -> Result<(), String> {
        self.device.switch(hardware)
    }
    fn return_packets(&mut self) -> Option<u64> {
        self.device.return_packets()
    }
    fn fingerprint(&mut self) -> Result<(), String> {
        self.device.fingerprint()
    }
    fn monitors(&mut self, gateway: Ipv4Addr) -> Vec<monitor::Monitor> {
        self.device.monitors(gateway)
    }
    fn pause(&mut self, wait: Duration) {
        self.device.pause(wait)
    }
    fn apply(&mut self, tx: &mut Transaction, step: Step) -> Result<(), String> {
        // The mode step reads as in place (`Cmd::present`); ZTE may have
        // switched IPACM back to software meanwhile.
        let mode = step.apply.program == "@u60-relay-ipa";
        tx.adopt(step)?;
        if mode && self.device.hardware_mode() != Some(true) {
            self.device.switch(true)?;
        }
        Ok(())
    }
    fn apply_network(&mut self, tx: &mut Transaction, plan: Vec<Step>) -> Result<(), String> {
        plan.into_iter().try_for_each(|step| tx.adopt(step))
    }
    fn release(&mut self, tx: &mut Transaction, undos: &[Cmd]) -> Result<(), String> {
        self.device.release(tx, undos)
    }
    fn mode_before(&mut self) -> bool {
        self.mode_before
    }
    fn rearms(&self) -> bool {
        false
    }
}

/// `Err(why)` unless the firmware and IPACM are the ones verified (B31).
fn fingerprint(version: &str, ipacm_sha256: Option<&str>) -> Result<(), String> {
    if version != FIRMWARE {
        return Err(format!("Hardware forwarding was verified on firmware {FIRMWARE} only (this router runs {})", if version.is_empty() { "an unknown version" } else { version }));
    }
    if ipacm_sha256 != Some(IPACM_SHA256) {
        return Err("Hardware forwarding was verified with another IPACM build".into());
    }
    Ok(())
}

/// One relay session's hardware forwarding (section 7).
pub(super) struct Runtime {
    state: State,
    /// This session switched IPACM's mode (or found it on and owns it now).
    owned: bool,
    hardware: bool,
    /// No sign that hardware mode leaves relayed connections on the CPU.
    effective: bool,
    /// A load was seen while hardware mode held: offloading is confirmed,
    /// not just switched on (idle traffic proves nothing).
    confirmed: bool,
    forwarded: Option<(u64, Instant)>,
    rearms: u32,
    rearmed: Option<Instant>,
    reason: Option<String>,
    checked: Option<Instant>,
    /// After a release with load: relayed IPv4 seen back on the CPU.
    cpu_verified: Option<bool>,
    /// `neighbours` and `clients`, while the path is engaged.
    monitors: Vec<monitor::Monitor>,
    /// Undo commands of the steps the engaged path added to the session's
    /// plan (hardware mode, the `main` route), for `release`.
    applied: Vec<Cmd>,
    /// The session's gateway and subnet, to engage again later.
    uplink: Option<(Ipv4Addr, String)>,
}

impl Runtime {
    pub(super) fn off() -> Self {
        Self { state: State::Off, owned: false, hardware: false, effective: true, confirmed: false, forwarded: None, rearms: 0, rearmed: None, reason: None, checked: None, cpu_verified: None, monitors: Vec::new(), applied: Vec::new(), uplink: None }
    }

    /// Whether the session's plan has the `main` route.
    pub(super) fn engaged(&self) -> bool {
        matches!(self.state, State::Hardware)
    }

    /// Called with the session's network plan applied.
    pub(super) fn start(tx: &mut Transaction, gateway: Ipv4Addr, subnet: String) -> Self {
        Self::start_with(&mut Device, tx, gateway, subnet)
    }

    /// The previous agent's hardware path, taken over with its session
    /// (`wifi_relay::adopt`): its journaled steps are re-taken, not run
    /// again; the mode's undo is the original one its journal holds; IPACM
    /// is not re-armed (the uplink did not change). New monitors replace
    /// the stopped ones.
    pub(super) fn adopt(tx: &mut Transaction, gateway: Ipv4Addr, subnet: String) -> Self {
        let mode_before = !tx.holds(&mode_step(false).undo);
        Self::start_with(&mut Adopting { device: Device, mode_before }, tx, gateway, subnet)
    }

    fn start_with(port: &mut impl IpacmPort, tx: &mut Transaction, gateway: Ipv4Addr, subnet: String) -> Self {
        let mut runtime = Self::off();
        runtime.uplink = Some((gateway, subnet));
        if let Err(e) = runtime.sync_with(port, tx, false) {
            runtime.reason = Some(e);
        }
        runtime
    }

    /// Follows the installation and the owner's switch on a live session
    /// (`release_now` releases regardless). `Ok(true)` when the path changed
    /// (the caller resets LAN IPv4 connections onto it).
    pub(super) fn sync(&mut self, tx: &mut Transaction, release_now: bool) -> Result<bool, String> {
        self.sync_with(&mut Device, tx, release_now)
    }

    fn sync_with(&mut self, port: &mut impl IpacmPort, tx: &mut Transaction, release_now: bool) -> Result<bool, String> {
        let config = port.config();
        let wanted = !release_now && config == Config::Loaded && port.enabled() && self.uplink.is_some();
        match (wanted, self.state) {
            (false, State::Hardware | State::Releasing) => {
                // A failed release stays Releasing (never Off while the route may hold).
                self.release(port, tx)?;
                self.state = State::Off;
                self.reason = Some(idle_reason(config).into());
                Ok(true)
            }
            (false, _) => {
                self.state = State::Off;
                self.reason = Some(idle_reason(config).into());
                Ok(false)
            }
            (true, State::Hardware) => Ok(false),
            (true, _) => self.engage(port, tx),
        }
    }

    /// Off/Software → Engaging → Hardware, or Software with the reason. A
    /// failure after something was taken takes it back: the snapshot never
    /// says software while the hardware path holds.
    fn engage(&mut self, port: &mut impl IpacmPort, tx: &mut Transaction) -> Result<bool, String> {
        if let Err(why) = port.fingerprint() {
            self.state = State::Software;
            self.reason = Some(why);
            return Ok(false);
        }
        if let Some(limit) = port.owner_limit() {
            self.state = State::Software;
            self.hardware = port.hardware_mode() == Some(true);
            self.reason = Some(limit.into());
            return Ok(false);
        }
        let Some((gateway, subnet)) = self.uplink.clone() else { return Ok(false) };
        self.state = State::Engaging;
        self.checked = None;
        self.reason = None;
        // Hardware mode first, then IPACM's WAN route (the tested order).
        if let Err(e) = self.take_mode(port, tx) {
            self.release(port, tx)?;
            self.state = State::Software;
            self.reason = Some(e);
            return Ok(false);
        }
        let plan = route_plan(&gateway.to_string(), &subnet);
        self.applied.extend(plan.iter().map(|s| s.undo.clone()));
        if let Err(e) = port.apply_network(tx, plan) {
            self.release(port, tx)?;
            self.state = State::Software;
            self.reason = Some(format!("Hardware forwarding route was not added: {e}"));
            return Ok(false);
        }
        self.state = State::Hardware;
        self.cpu_verified = None;
        self.kick(port);
        self.monitors = port.monitors(gateway);
        Ok(true)
    }

    /// Hardware mode now, journaled with the mode found before.
    fn take_mode(&mut self, port: &mut impl IpacmPort, tx: &mut Transaction) -> Result<(), String> {
        let found = port.mode_before();
        if !self.owned {
            let step = mode_step(found);
            self.applied.push(step.undo.clone());
            port.apply(tx, step)?;
            self.owned = true;
        } else if !found {
            port.switch(true)?;
        }
        self.hardware = port.hardware_mode() == Some(true);
        if self.hardware {
            Ok(())
        } else {
            Err("IPACM did not confirm hardware mode".into())
        }
    }

    /// Hardware/Engaging → Releasing → (the caller's next state): the `main`
    /// route goes first (IPACM's relay WAN is down), then the mode this
    /// session switched. The session goes on.
    fn release(&mut self, port: &mut impl IpacmPort, tx: &mut Transaction) -> Result<(), String> {
        self.state = State::Releasing;
        self.monitors.clear();
        let applied = std::mem::take(&mut self.applied);
        let result = port.release(tx, &applied);
        if let Err(e) = &result {
            // Keep what was not undone: recovery still knows it from the journal.
            self.applied = applied;
            self.reason = Some(format!("Hardware forwarding was not fully released: {e}"));
        } else {
            self.owned = false;
            self.hardware = false;
            self.effective = true;
            self.confirmed = false;
            self.forwarded = None;
            self.rearms = 0;
            self.cpu_verified = Some(false);
        }
        result
    }

    /// Every 15 s while engaged (or waiting in Software): hardware mode while
    /// no owner limit needs the CPU path (the vendor switches IPACM to
    /// software at boot and on Smart QoS events); an owner limit releases the
    /// path; a lifted one engages it again.
    pub(super) fn audit(&mut self, tx: &mut Transaction) -> bool {
        self.audit_with(&mut Device, tx)
    }

    /// `true` when the path changed (the caller resets LAN IPv4).
    fn audit_with(&mut self, port: &mut impl IpacmPort, tx: &mut Transaction) -> bool {
        if self.checked.is_some_and(|at| at.elapsed() < AUDIT) {
            return false;
        }
        self.checked = Some(Instant::now());
        match self.state {
            State::Hardware => {
                if let Some(limit) = port.owner_limit() {
                    if self.release(port, tx).is_ok() {
                        self.state = State::Software;
                        self.reason = Some(limit.into());
                    }
                    return true;
                }
                if port.hardware_mode() != Some(true) {
                    // ZTE put it back to software: ours to switch again.
                    self.hardware = port.switch(true).is_ok() && port.hardware_mode() == Some(true);
                    self.reason = (!self.hardware).then(|| "IPACM did not confirm hardware mode".to_owned());
                    if self.hardware {
                        crate::netlog!("[relay] IPACM switched to hardware mode");
                    }
                } else {
                    self.hardware = true;
                }
                self.verify(port);
                false
            }
            State::Software if self.uplink.is_some() && port.config() == Config::Loaded && port.enabled() && port.owner_limit().is_none() && port.fingerprint().is_ok() => {
                crate::netlog!("[relay] the owner limit on hardware forwarding is gone; engaging it");
                self.engage(port, tx).unwrap_or(false)
            }
            State::Off | State::Software if self.cpu_verified == Some(false) => {
                // After a release, with load, relayed IPv4 shows on the CPU.
                self.cpu_check(port);
                false
            }
            _ => false,
        }
    }

    /// After the relay's `main` route exists: a SW→HW switch makes IPACM
    /// take the new WAN over (a reconnect sometimes left every connection on
    /// the CPU while the mode read hardware; re-arming fixed it 3/3).
    fn kick(&mut self, port: &mut impl IpacmPort) {
        if self.engaged() && self.hardware && port.rearms() {
            crate::netlog!("[relay] re-arming IPACM for the new uplink");
            rearm_with(port);
            self.forwarded = None;
        }
    }

    /// Relay teardown, before the interface goes away.
    pub(super) fn stop(&mut self) {
        self.monitors.clear();
    }

    /// Hardware mode is only claimed while relayed IPv4 is not seen on the
    /// CPU path (with load: idle traffic proves nothing); otherwise re-arm
    /// IPACM, at most `REARMS` times per session.
    fn verify(&mut self, port: &mut impl IpacmPort) {
        let Some(rate) = self.rate(port) else { return };
        self.effective = rate < CPU_PATH_PPS;
        if self.effective {
            self.rearms = 0;
            self.reason = None;
            // A few hundred packets back on the CPU while data flows proves
            // the hardware carries it; too little traffic proves nothing.
            self.confirmed |= rate > 0.0;
            return;
        }
        self.confirmed = false;
        if self.rearms >= REARMS {
            self.reason = Some(format!("IPACM is in hardware mode, but relayed connections stay on the CPU (re-armed {REARMS} times); reconnect the relay"));
            return;
        }
        if self.rearmed.is_none_or(|at| at.elapsed() >= REARM_GAP) {
            crate::netlog!("[relay] relayed IPv4 on the CPU path at {rate:.0} packets/s in hardware mode; re-arming IPACM");
            rearm_with(port);
            self.rearms += 1;
            self.rearmed = Some(Instant::now());
            self.forwarded = None;
        }
        self.reason = Some("Hardware mode was not carrying relayed connections; IPACM was re-armed".into());
    }

    fn cpu_check(&mut self, port: &mut impl IpacmPort) {
        if let Some(rate) = self.rate(port) {
            if rate >= CPU_PATH_PPS {
                self.cpu_verified = Some(true);
            }
        }
    }

    /// Return-path packets per second since the last reading.
    fn rate(&mut self, port: &mut impl IpacmPort) -> Option<f64> {
        let packets = port.return_packets()?;
        let now = Instant::now();
        let (before, at) = self.forwarded.replace((packets, now))?;
        Some(packets.saturating_sub(before) as f64 / now.duration_since(at).as_secs_f64().max(1.0))
    }

    pub(super) fn status(&self) -> Value {
        json!({"state": self.state, "route": self.engaged(), "hardware": self.engaged() && self.hardware && self.effective,
            "mode": if self.hardware { "hardware" } else { "software" },
            // Offloading seen working under load, not just switched on.
            "offload_confirmed": self.engaged() && self.hardware && self.effective && self.confirmed,
            "cpu_path": match self.cpu_verified { Some(true) => Some("confirmed"), Some(false) => Some("unverified"), None => None },
            "reason": self.reason})
    }
}

fn rearm_with(port: &mut impl IpacmPort) {
    let _ = port.switch(false);
    port.pause(Duration::from_secs(1));
    if let Err(e) = port.switch(true) {
        crate::netlog!("[relay] IPACM re-arm failed: {e}");
    }
}

/// Packets of `U60_RELAY_FWD`'s upstream-to-LAN TCP accept rule (`iptables
/// -L -nvx`). TCP only: IPA may leave UDP (QUIC) on the CPU by design.
fn return_packets(listing: &str) -> Option<u64> {
    listing.lines().find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        (f.len() > 6 && f[2] == "ACCEPT" && f[3] == "tcp" && f[5] == IFACE && f[6] == "br-lan").then(|| f[0].parse().ok()).flatten()
    })
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
        assert_eq!(classify(VENDOR, None, "b", false, never), Config::NotInstalled);
        assert_eq!(classify(VENDOR, Some("a"), "b", false, never), Config::Overwritten);
        assert_eq!(classify(&installed, Some("b"), "b", false, never), Config::RebootRequired);
        assert_eq!(classify(&installed, Some("a"), "b", false, never), Config::Loaded);
        assert_eq!(classify(&installed, Some(LOADED_BEFORE), "b", false, never), Config::Loaded);
        assert_eq!(classify(&installed, None, "b", false, || true), Config::Loaded);
        assert_eq!(classify(&installed, None, "b", false, || false), Config::RebootRequired);
        // Removed and installed again in the same boot: IPACM still has it.
        assert_eq!(classify(&installed, Some("b"), "b", true, never), Config::Loaded);
        assert_eq!(classify(VENDOR, None, "b", true, never), Config::NotInstalled, "a removed entry is not loaded for new sessions");
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

    /// A fake IPACM and journal: what was applied, released and switched.
    struct Fake {
        config: Config,
        enabled: bool,
        limit: Option<&'static str>,
        fingerprint: Result<(), String>,
        mode: bool,
        packets: u64,
        route_fails: bool,
        release_fails: bool,
        log: Vec<String>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self { config: Config::Loaded, enabled: true, limit: None, fingerprint: Ok(()), mode: false, packets: 0, route_fails: false, release_fails: false, log: Vec::new() }
        }
    }

    impl IpacmPort for Fake {
        fn config(&mut self) -> Config {
            self.config
        }
        fn enabled(&mut self) -> bool {
            self.enabled
        }
        fn owner_limit(&mut self) -> Option<&'static str> {
            self.limit
        }
        fn hardware_mode(&mut self) -> Option<bool> {
            Some(self.mode)
        }
        fn switch(&mut self, hardware: bool) -> Result<(), String> {
            self.log.push(format!("switch {hardware}"));
            self.mode = hardware;
            Ok(())
        }
        fn return_packets(&mut self) -> Option<u64> {
            Some(self.packets)
        }
        fn fingerprint(&mut self) -> Result<(), String> {
            self.fingerprint.clone()
        }
        fn monitors(&mut self, _: Ipv4Addr) -> Vec<monitor::Monitor> {
            self.log.push("monitors".into());
            Vec::new()
        }
        fn pause(&mut self, _: Duration) {}
        fn apply(&mut self, _: &mut Transaction, step: Step) -> Result<(), String> {
            self.log.push(format!("apply {}", step.apply.args.join(" ")));
            if step.apply.program == "@u60-relay-ipa" {
                self.mode = true;
            }
            Ok(())
        }
        fn apply_network(&mut self, _: &mut Transaction, plan: Vec<Step>) -> Result<(), String> {
            self.log.push(format!("routes {}", plan.len()));
            if self.route_fails { Err("RTNETLINK answers: Network is unreachable".into()) } else { Ok(()) }
        }
        fn release(&mut self, _: &mut Transaction, undos: &[Cmd]) -> Result<(), String> {
            if self.release_fails {
                return Err("Network cleanup paused".into());
            }
            // Newest first, as `Transaction::release` runs them.
            for undo in undos.iter().rev() {
                self.log.push(format!("undo {} {}", undo.program, undo.args.first().map(String::as_str).unwrap_or("")));
                if undo.program == "@u60-relay-ipa" {
                    self.mode = false;
                }
            }
            Ok(())
        }
    }

    fn session(fake: &mut Fake) -> (Runtime, Transaction) {
        let mut tx = Transaction::new(std::env::temp_dir().join("u60-ipa-fake-never-written.json"));
        let runtime = Runtime::start_with(fake, &mut tx, Ipv4Addr::new(192, 168, 2, 1), "192.168.2.0/24".into());
        (runtime, tx)
    }

    fn due(runtime: &mut Runtime) {
        runtime.checked = Some(Instant::now() - AUDIT);
    }

    #[test]
    fn engaging_takes_the_mode_then_the_route_and_releasing_undoes_route_first() {
        let mut fake = Fake::default();
        let (mut runtime, mut tx) = session(&mut fake);
        assert_eq!(runtime.state, State::Hardware);
        assert_eq!(fake.log, ["apply hw", "routes 4", "switch false", "switch true", "monitors"], "mode, route, re-arm, monitors");
        assert_eq!(runtime.status()["offload_confirmed"], false, "switched on is not confirmed");
        fake.log.clear();
        fake.enabled = false;
        assert!(runtime.sync_with(&mut fake, &mut tx, false).unwrap(), "the path changed");
        assert_eq!(runtime.state, State::Off);
        assert_eq!(fake.log.first().map(String::as_str), Some("undo ip -4"), "the main route goes before the mode: {:?}", fake.log);
        assert_eq!(fake.log.last().map(String::as_str), Some("undo @u60-relay-ipa sw"));
        assert!(!fake.mode, "the mode found before is back");
        assert_eq!(runtime.status()["cpu_path"], "unverified", "no load seen on the CPU yet");
        fake.packets = 0;
        due(&mut runtime);
        runtime.audit_with(&mut fake, &mut tx);
        fake.packets = 40_000;
        due(&mut runtime);
        runtime.audit_with(&mut fake, &mut tx);
        assert_eq!(runtime.status()["cpu_path"], "confirmed");
    }

    #[test]
    fn another_firmware_or_an_owner_limit_stays_on_the_cpu_and_a_lifted_limit_engages() {
        let mut fake = Fake { fingerprint: Err("verified on B31 only".into()), ..Fake::default() };
        let (runtime, _) = session(&mut fake);
        assert_eq!((runtime.state, runtime.reason.as_deref()), (State::Software, Some("verified on B31 only")));
        assert!(fake.log.is_empty(), "nothing taken");
        let mut fake = Fake { limit: Some("A router speed limit is active"), ..Fake::default() };
        let (mut runtime, mut tx) = session(&mut fake);
        assert_eq!(runtime.state, State::Software);
        assert!(fake.log.is_empty(), "the owner's limit is never overridden");
        fake.limit = None;
        due(&mut runtime);
        assert!(runtime.audit_with(&mut fake, &mut tx), "the limit was lifted: engaged again");
        assert_eq!(runtime.state, State::Hardware);
        // A limit that comes back releases the path.
        fake.limit = Some("Power saver mode limits speed on the CPU path");
        due(&mut runtime);
        assert!(runtime.audit_with(&mut fake, &mut tx));
        assert_eq!((runtime.state, runtime.reason.as_deref()), (State::Software, Some("Power saver mode limits speed on the CPU path")));
        assert!(!fake.mode);
    }

    #[test]
    fn a_route_that_fails_gives_the_mode_back_and_a_failed_release_never_reads_off() {
        let mut fake = Fake { route_fails: true, ..Fake::default() };
        let (runtime, _) = session(&mut fake);
        assert_eq!(runtime.state, State::Software);
        assert!(runtime.reason.as_deref().unwrap().contains("route was not added"));
        assert!(!fake.mode && fake.log.last().unwrap().starts_with("undo @u60-relay-ipa"), "the mode this attempt took is back: {:?}", fake.log);
        let mut fake = Fake::default();
        let (mut runtime, mut tx) = session(&mut fake);
        fake.release_fails = true;
        fake.enabled = false;
        assert!(runtime.sync_with(&mut fake, &mut tx, false).is_err());
        assert_eq!(runtime.state, State::Releasing, "not Off while the route may hold");
        assert!(!runtime.applied.is_empty(), "what is left stays known");
        fake.release_fails = false;
        assert!(runtime.sync_with(&mut fake, &mut tx, false).unwrap());
        assert_eq!(runtime.state, State::Off);
    }

    #[test]
    fn a_mode_zte_put_back_is_switched_again_and_a_cpu_path_under_load_re_arms_three_times() {
        let mut fake = Fake::default();
        let (mut runtime, mut tx) = session(&mut fake);
        fake.mode = false;
        fake.log.clear();
        due(&mut runtime);
        runtime.audit_with(&mut fake, &mut tx);
        assert_eq!(fake.log, ["switch true"], "no new journal step for a mode it owns");
        // 40,000 packets back on the CPU in 15 s: far above 1,500/s.
        // Each re-arm starts a new reading: two audits per measurement.
        let mut packets = 0;
        for _ in 0..12 {
            packets += 40_000;
            fake.packets = packets;
            due(&mut runtime);
            runtime.rearmed = None;
            runtime.audit_with(&mut fake, &mut tx);
        }
        assert_eq!(runtime.rearms, REARMS);
        assert!(runtime.reason.as_deref().unwrap().contains("reconnect the relay"));
        // A light load back on the CPU while hardware holds: confirmed.
        runtime.rearms = 0;
        runtime.forwarded = Some((packets, Instant::now() - AUDIT));
        fake.packets = packets + 200;
        due(&mut runtime);
        runtime.audit_with(&mut fake, &mut tx);
        assert_eq!(runtime.status()["offload_confirmed"], true);
    }

    #[test]
    fn the_firmware_fingerprint_is_b31_and_its_ipacm() {
        assert!(fingerprint(FIRMWARE, Some(IPACM_SHA256)).is_ok());
        assert!(fingerprint("BD_CNMU5250V1.0.0B32", Some(IPACM_SHA256)).unwrap_err().contains("B32"));
        assert!(fingerprint(FIRMWARE, Some("00")).is_err());
        assert!(fingerprint(FIRMWARE, None).is_err());
        assert!(fingerprint("", None).unwrap_err().contains("unknown"));
    }

    /// H5: the configuration is replaced whole, keeping its mode, and a
    /// failure leaves the original and no copy.
    #[test]
    fn the_configuration_is_replaced_whole_and_a_failure_keeps_the_original() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("u60-ipacm-write-{}", std::process::id()));
        let dir = root.join("ipa");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("IPACM_cfg.xml");
        fs::write(&path, VENDOR).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let installed = insert(VENDOR).unwrap();
        rewrite(&path, &installed).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), installed);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o640, "mode kept");
        assert!(!root.join(".u60-ipacm-cfg.new").exists() && !dir.join(".u60-ipacm-cfg.new").exists(), "no copy left");
        // The directory cannot take the rename: the original stays whole.
        // Root ignores directory permissions, so there the target is a
        // directory instead: the write fails before anything is replaced.
        let as_root = unsafe { libc::geteuid() } == 0;
        let blocked = if as_root { dir.join("blocked.xml") } else { path.clone() };
        if as_root {
            fs::create_dir_all(blocked.join("taken")).unwrap();
        } else {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        }
        assert!(rewrite(&blocked, VENDOR).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), installed, "never half written");
        assert!(!root.join(".u60-ipacm-cfg.new").exists() && !dir.join(".u60-ipacm-cfg.new").exists(), "the copy is removed");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn the_cpu_path_counter_is_the_upstream_to_lan_tcp_accept_rule() {
        let listing = "Chain U60_RELAY_FWD (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n      12     1000 ACCEPT     all  --  br-lan u60sta0  0.0.0.0/0            0.0.0.0/0\n  150537 225000000 ACCEPT     tcp  --  u60sta0 br-lan  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED\n   90000 120000000 ACCEPT     all  --  u60sta0 br-lan  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED\n       0        0 DROP       all  --  u60sta0 *       0.0.0.0/0            0.0.0.0/0\n";
        assert_eq!(return_packets(listing), Some(150537), "UDP on the CPU is not a hardware failure");
        assert_eq!(return_packets("Chain U60_RELAY_FWD\n"), None);
    }
}
