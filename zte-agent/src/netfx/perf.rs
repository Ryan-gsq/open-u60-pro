//! Shared Wi-Fi receive steering and TCP performance settings.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{files, ids};
use crate::net_tools::Cmd;

const BACKLOG_FLOOR: u32 = 5000;
const PACING: &str = "1000";
#[cfg(not(test))]
const JOURNAL_PATH: &str = "/tmp/zte-agent-perf/network.json";

#[cfg(test)]
#[path = "../wifi_relay/test_dir.rs"]
mod test_dir;

#[derive(Clone, Copy)]
pub(crate) enum PerfFeature {
    Relay = 1,
    Mihomo = 2,
    Tailscale = 4,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum Wifi {
    Wlan0,
    Wlan2,
    Relay,
}

impl Wifi {
    fn name(self) -> &'static str {
        match self {
            Self::Wlan0 => "wlan0",
            Self::Wlan2 => "wlan2",
            Self::Relay => ids::RELAY_IFACE,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum Setting {
    Backlog,
    SlowStart,
    Avoidance,
    Rps { wifi: Wifi, queue: u32 },
}

impl Setting {
    fn path(self, perf: &Perf) -> PathBuf {
        match self {
            Self::Backlog => perf.proc.join("sys/net/core/netdev_max_backlog"),
            Self::SlowStart => perf.proc.join("sys/net/ipv4/tcp_pacing_ss_ratio"),
            Self::Avoidance => perf.proc.join("sys/net/ipv4/tcp_pacing_ca_ratio"),
            Self::Rps { wifi, queue } => perf
                .net
                .join(wifi.name())
                .join(format!("queues/rx-{queue}/rps_cpus")),
        }
    }

    fn is_queue(self) -> bool {
        matches!(self, Self::Rps { .. })
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
struct QueueIdentity {
    device: u64,
    inode: u64,
}

impl QueueIdentity {
    fn from(metadata: fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct Original {
    setting: Setting,
    value: String,
    queue: Option<QueueIdentity>,
}

#[derive(Deserialize, Serialize)]
struct Journal {
    boot: String,
    originals: Vec<Original>,
}

pub(crate) struct Perf {
    proc: PathBuf,
    net: PathBuf,
    journal: PathBuf,
    legacy_relay: PathBuf,
    legacy_mihomo: PathBuf,
    state: Mutex<State>,
    #[cfg(test)]
    test_boot_raw: Option<Vec<u8>>,
    #[cfg(test)]
    _temp: Option<test_dir::TestDir>,
}

#[derive(Default)]
struct State {
    desired: u8,
    recovered: bool,
    deferred: bool,
    owner: Option<File>,
    slot_change_paused: bool,
    wake: Option<std::sync::mpsc::SyncSender<()>>,
    #[cfg(test)]
    test_ota_trial_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchAction {
    ApplyNow,
    WaitRetry,
    WaitEvent,
}

impl Perf {
    #[cfg(not(test))]
    pub(crate) fn router() -> Arc<Self> {
        static OWNER: OnceLock<Arc<Perf>> = OnceLock::new();
        Arc::clone(OWNER.get_or_init(|| {
            Arc::new(Self {
                proc: "/proc".into(),
                net: "/sys/class/net".into(),
                journal: JOURNAL_PATH.into(),
                legacy_relay: crate::wifi_relay::network_journal(),
                legacy_mihomo: Path::new(crate::mihomo::ROOT).join("network.json"),
                state: Mutex::default(),
            })
        }))
    }

    #[cfg(test)]
    pub(crate) fn router() -> Arc<Self> {
        let temp = test_dir::TestDir::new("u60-perf");
        let mut perf = Self::for_test(temp.path());
        perf._temp = Some(temp);
        Arc::new(perf)
    }

    #[cfg(test)]
    pub(crate) fn for_test(root: &Path) -> Self {
        Self {
            proc: root.join("proc"),
            net: root.join("sys/class/net"),
            journal: root.join("run/network.json"),
            legacy_relay: root.join("relay/network.json"),
            legacy_mihomo: root.join("mihomo/network.json"),
            state: Mutex::default(),
            test_boot_raw: None,
            _temp: None,
        }
    }

    pub(crate) fn journal_path(&self) -> &Path {
        &self.journal
    }

    pub(crate) fn start(&self) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        self.claim(&mut state)?;
        self.report(self.retire_legacy());
        self.report(self.reconcile(&mut state));
        Ok(())
    }

    pub(crate) fn lock_owner(&self) -> Result<(), String> {
        self.claim(&mut self.state.lock().unwrap())
    }

    pub(crate) fn release_owner(&self) {
        self.state.lock().unwrap().owner = None;
    }

    pub(crate) fn watch(self: &Arc<Self>) {
        let (wake, settled) = std::sync::mpsc::sync_channel(1);
        self.state.lock().unwrap().wake = Some(wake.clone());
        crate::net_guard::on_settled(move || {
            let _ = wake.try_send(());
        });
        let owner = Arc::clone(self);
        crate::system::spawn_named("net-perf", move || {
            Self::watch_loop(owner, settled, std::time::Duration::from_secs(3));
        });
    }

    fn watch_loop(
        owner: Arc<Self>,
        settled: std::sync::mpsc::Receiver<()>,
        retry: std::time::Duration,
    ) {
        loop {
            let proceed = match owner.next_watch_action() {
                WatchAction::ApplyNow => true,
                WatchAction::WaitRetry => settled.recv_timeout(retry).map_or_else(
                    |err| matches!(err, std::sync::mpsc::RecvTimeoutError::Timeout),
                    |()| true,
                ),
                WatchAction::WaitEvent => settled.recv().is_ok(),
            };
            if !proceed {
                break;
            }
            owner.report(owner.refresh_interfaces());
        }
    }

    fn next_watch_action(&self) -> WatchAction {
        let state = self.state.lock().unwrap();
        if !state.deferred || state.desired == 0 || state.slot_change_paused {
            WatchAction::WaitEvent
        } else if Self::slot_change_blocked(&state) {
            WatchAction::WaitRetry
        } else {
            WatchAction::ApplyNow
        }
    }

    #[cfg(test)]
    fn trial_deferred(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.deferred && state.desired != 0 && !state.slot_change_paused
    }

    fn slot_change_blocked(state: &State) -> bool {
        #[cfg(test)]
        if state.test_ota_trial_pending {
            return true;
        }
        state.slot_change_paused || crate::ota::slot_change_pending()
    }

    pub(crate) fn set_active(&self, feature: PerfFeature, active: bool) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        let bit = feature as u8;
        state.desired = if active {
            state.desired | bit
        } else {
            state.desired & !bit
        };
        let result = self.reconcile(&mut state);
        if state.deferred {
            if let Some(wake) = &state.wake {
                let _ = wake.try_send(());
            }
        }
        result
    }

    pub(crate) fn refresh_interfaces(&self) -> Result<(), String> {
        self.reconcile(&mut self.state.lock().unwrap())
    }

    /// Restore all owned RPS, backlog, and TCP pacing settings to their saved
    /// originals and hold them restored across an OTA slot handoff so an older
    /// slot without a `/tmp/zte-agent-perf/network.json` reader never inherits
    /// tuned values as its baseline. Re-applies `desired` if the handoff aborts.
    pub(crate) fn before_slot_change<T>(
        &self,
        action: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        {
            let mut state = self.state.lock().unwrap();
            if state.slot_change_paused {
                return Err("OTA slot change is already in progress".into());
            }
            state.slot_change_paused = true;
            if let Err(error) = self.reconcile(&mut state) {
                state.slot_change_paused = false;
                let _ = self.reconcile(&mut state);
                return Err(format!("performance tuning slot-change cleanup failed: {error}"));
            }
            match self.journal.try_exists() {
                Ok(false) => {}
                Ok(true) => {
                    state.slot_change_paused = false;
                    let _ = self.reconcile(&mut state);
                    return Err("performance tuning journal still present after cleanup".into());
                }
                Err(error) => {
                    state.slot_change_paused = false;
                    let _ = self.reconcile(&mut state);
                    return Err(format!("inspect performance journal: {error}"));
                }
            }
        }
        match action() {
            Ok(value) => Ok(value),
            Err(error) => {
                let mut state = self.state.lock().unwrap();
                state.slot_change_paused = false;
                self.report(self.reconcile(&mut state));
                if state.deferred {
                    if let Some(wake) = &state.wake {
                        let _ = wake.try_send(());
                    }
                }
                Err(error)
            }
        }
    }

    pub(crate) fn recover(&self) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        self.claim(&mut state)?;
        if state.desired == 0 {
            self.retire_legacy()?;
        }
        self.reconcile(&mut state)
    }

    fn claim(&self, state: &mut State) -> Result<(), String> {
        if state.owner.is_some() {
            return Ok(());
        }
        let dir = self
            .journal
            .parent()
            .ok_or("Invalid performance journal path")?;
        files::private_dir(dir)?;
        let path = dir.join("owner.lock");
        let owner = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|error| format!("Cannot open {}: {error}", path.display()))?;
        // SAFETY: owner keeps the descriptor open for this Perf's lifetime.
        if unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Err("Network tuning is owned by another zte-agent process".into());
            }
            return Err(format!("Cannot lock {}: {error}", path.display()));
        }
        state.owner = Some(owner);
        Ok(())
    }

    fn reconcile(&self, state: &mut State) -> Result<(), String> {
        self.claim(state)?;
        if !state.recovered {
            self.sync(0)?;
            state.recovered = true;
        }
        if Self::slot_change_blocked(state) {
            state.deferred = state.desired != 0 && !state.slot_change_paused;
            return self.sync(0);
        }
        state.deferred = false;
        self.sync(state.desired)
    }

    fn retire_legacy(&self) -> Result<(), String> {
        let boot = self.boot();
        retire_legacy(
            &self.legacy_relay,
            &boot,
            |undo| undo.program == "@u60-relay-steer",
            |undo| self.legacy_command(&undo.args),
        )?;
        let pacing = |undo: &Cmd| {
            if undo.program != "@u60-sysctl" {
                return None;
            }
            match undo.args.first()?.as_str() {
                "tcp_pacing_ss_ratio" => Some(Setting::SlowStart),
                "tcp_pacing_ca_ratio" => Some(Setting::Avoidance),
                _ => None,
            }
        };
        retire_legacy(
            &self.legacy_mihomo,
            &boot,
            |undo| pacing(undo).is_some(),
            |undo| {
                let [_, value] = undo.args.as_slice() else {
                    return Err("Invalid legacy pacing setting".into());
                };
                if !value.parse::<u32>().is_ok_and(|value| value <= 100_000) {
                    return Err("Invalid legacy pacing setting".into());
                }
                self.write(pacing(undo).unwrap(), None, value)
            },
        )
    }

    pub(crate) fn report(&self, result: Result<(), String>) {
        if let Err(error) = result {
            crate::netlog!("[perf] {error}");
        }
    }

    fn sync(&self, features: u8) -> Result<(), String> {
        let mut journal = self.load()?;
        let relay = features & PerfFeature::Relay as u8 != 0;
        let retain = |setting| {
            features != 0
                && (relay
                    || !matches!(
                        setting,
                        Setting::Rps {
                            wifi: Wifi::Relay,
                            ..
                        }
                    ))
        };
        let mut result = Ok(());
        let previous = journal.originals.len();
        journal.originals.retain(|original| {
            if retain(original.setting) {
                return true;
            }
            match self.restore(original) {
                Ok(()) => false,
                Err(error) => {
                    result = Err(error);
                    true
                }
            }
        });
        if journal.originals.len() != previous
            || (journal.originals.is_empty() && self.journal.try_exists().unwrap_or(true))
        {
            self.save(&journal)?;
        }
        if features == 0 {
            return result;
        }

        for (setting, target) in self.targets(relay)? {
            let Some((current, queue)) = self.read(setting)? else {
                continue;
            };
            let matches = match setting {
                Setting::Backlog => {
                    current
                        .parse::<u32>()
                        .map_err(|_| "Invalid receive backlog")?
                        >= BACKLOG_FLOOR
                }
                Setting::Rps { .. } => parse_mask(&current) == parse_mask(&target),
                _ => current == target,
            };
            if matches {
                continue;
            }
            let original = journal
                .originals
                .iter()
                .find(|original| original.setting == setting);
            if original.is_none_or(|original| original.queue != queue) {
                journal
                    .originals
                    .retain(|original| original.setting != setting);
                journal.originals.push(Original {
                    setting,
                    value: current,
                    queue,
                });
                self.save(&journal)?;
            }
            if let Err(error) = self.write(setting, queue, &target) {
                result = Err(error);
            }
        }
        result
    }

    fn boot(&self) -> String {
        #[cfg(test)]
        {
            if let Some(raw) = &self.test_boot_raw {
                return crate::net_tools::boot_id_from_raw(raw);
            }
            return "perf-test-boot".into();
        }
        #[cfg(not(test))]
        crate::net_tools::boot_id()
    }

    fn load(&self) -> Result<Journal, String> {
        let boot = self.boot();
        match fs::read(&self.journal) {
            Ok(bytes) => {
                let journal: Journal =
                    serde_json::from_slice(&bytes).map_err(|_| "Invalid performance journal")?;
                // Discard the saved originals ONLY when both boot IDs are
                // strict single printable-ASCII tokens and differ (proven
                // reboot); an empty or malformed boot ID fails closed and
                // preserves the saved originals for restoration.
                let other_boot = crate::net_tools::valid_boot_token(boot.as_bytes()).is_some_and(
                    |cur| {
                        crate::net_tools::is_valid_boot_token_str(&journal.boot)
                            && journal.boot != cur
                    },
                );
                if !other_boot {
                    return Ok(journal);
                }
                remove(&self.journal).map_err(|error| error.to_string())?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        Ok(Journal {
            boot,
            originals: Vec::new(),
        })
    }

    fn save(&self, journal: &Journal) -> Result<(), String> {
        if journal.originals.is_empty() {
            return remove(&self.journal).map_err(|error| error.to_string());
        }
        files::write_private(
            &self.journal,
            &serde_json::to_vec(journal).map_err(|error| error.to_string())?,
        )
    }

    fn targets(&self, relay: bool) -> Result<BTreeMap<Setting, String>, String> {
        let mut targets = BTreeMap::from([
            (Setting::Backlog, BACKLOG_FLOOR.to_string()),
            (Setting::SlowStart, PACING.into()),
            (Setting::Avoidance, PACING.into()),
        ]);
        if let Some(mask) = fs::read_to_string(self.proc.join("interrupts"))
            .ok()
            .and_then(|text| spare_cpus(&text))
        {
            for wifi in [Wifi::Wlan0, Wifi::Wlan2]
                .into_iter()
                .chain(relay.then_some(Wifi::Relay))
            {
                for queue in self.queues(wifi)? {
                    targets.insert(Setting::Rps { wifi, queue }, format!("{mask:x}"));
                }
            }
        }
        Ok(targets)
    }

    fn queues(&self, wifi: Wifi) -> Result<Vec<u32>, String> {
        let path = self.net.join(wifi.name()).join("queues");
        let Some(entries) = optional(fs::read_dir(&path))
            .map_err(|error| format!("{}: {error}", path.display()))?
        else {
            return Ok(Vec::new());
        };
        let mut queues = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            if let Some(queue) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("rx-"))
                .and_then(|queue| queue.parse().ok())
            {
                queues.push(queue);
            }
        }
        Ok(queues)
    }

    fn read(&self, setting: Setting) -> Result<Option<(String, Option<QueueIdentity>)>, String> {
        use std::io::Read;

        let path = setting.path(self);
        let read = || -> io::Result<_> {
            let Some(mut file) = optional(fs::File::open(&path))? else {
                return Ok(None);
            };
            let queue = setting
                .is_queue()
                .then(|| file.metadata().map(QueueIdentity::from))
                .transpose()?;
            let mut value = String::new();
            file.read_to_string(&mut value)?;
            Ok(Some((value.trim().into(), queue)))
        };
        read().map_err(|error| format!("{}: {error}", path.display()))
    }

    fn restore(&self, original: &Original) -> Result<(), String> {
        let Some((value, queue)) = self.read(original.setting)? else {
            return Ok(());
        };
        if queue != original.queue || value == original.value {
            return Ok(());
        }
        self.write(original.setting, queue, &original.value)
    }

    fn write(
        &self,
        setting: Setting,
        queue: Option<QueueIdentity>,
        value: &str,
    ) -> Result<(), String> {
        let path = setting.path(self);
        let write = || -> io::Result<()> {
            let Some(mut file) = optional(OpenOptions::new().write(true).open(&path))? else {
                return Ok(());
            };
            if setting.is_queue() && queue != Some(QueueIdentity::from(file.metadata()?)) {
                return Ok(());
            }
            #[cfg(test)]
            file.set_len(0)?;
            file.write_all(value.as_bytes())
        };
        write().map_err(|error| format!("{}: {error}", path.display()))
    }
}

fn retire_legacy(
    path: &Path,
    boot: &str,
    matches: impl Fn(&Cmd) -> bool,
    mut undo: impl FnMut(&Cmd) -> Result<(), String>,
) -> Result<(), String> {
    #[derive(Deserialize, Serialize)]
    struct EffectJournal {
        boot: String,
        undo: Vec<Cmd>,
    }

    let Some(bytes) = optional(fs::read(path)).map_err(|error| error.to_string())? else {
        return Ok(());
    };
    let mut journal: EffectJournal =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid network recovery journal")?;
    let other_boot = crate::net_tools::valid_boot_token(boot.as_bytes()).is_some_and(|cur| {
        crate::net_tools::is_valid_boot_token_str(&journal.boot) && journal.boot != cur
    });
    if other_boot || !journal.undo.iter().any(&matches) {
        return Ok(());
    }
    for command in journal.undo.iter().rev().filter(|command| matches(command)) {
        undo(command)?;
    }
    journal.undo.retain(|undo| !matches(undo));
    files::write_private(
        path,
        &serde_json::to_vec(&journal).map_err(|error| error.to_string())?,
    )
}

pub(crate) fn legacy_command(args: &[String]) -> Result<(), String> {
    Perf::router().legacy_command(args)
}

impl Perf {
    fn legacy_command(&self, args: &[String]) -> Result<(), String> {
        match args {
            [kind, iface, value] if kind == "rps" => {
                let wifi = match iface.as_str() {
                    "wlan2" => Wifi::Wlan2,
                    ids::RELAY_IFACE => Wifi::Relay,
                    _ => return Err("Invalid receive steering interface".into()),
                };
                let value = u32::from_str_radix(value, 16).map_err(|_| "Invalid RPS mask")?;
                for queue in self.queues(wifi)? {
                    let setting = Setting::Rps { wifi, queue };
                    if let Some((_, identity)) = self.read(setting)? {
                        self.write(setting, identity, &format!("{value:x}"))?;
                    }
                }
                Ok(())
            }
            [kind, value] if kind == "backlog" => {
                let value: u32 = value
                    .parse()
                    .ok()
                    .filter(|value| (1..=100_000).contains(value))
                    .ok_or("Invalid backlog")?;
                self.write(Setting::Backlog, None, &value.to_string())
            }
            _ => Err("Invalid receive steering".into()),
        }
    }
}

pub(crate) fn legacy_present(args: &[String]) -> bool {
    let perf = Perf::router();
    match args {
        [kind, iface, mask] if kind == "rps" => {
            let wifi = match iface.as_str() {
                "wlan2" => Wifi::Wlan2,
                ids::RELAY_IFACE => Wifi::Relay,
                _ => return false,
            };
            let Some(mask) = parse_mask(mask) else {
                return false;
            };
            perf.queues(wifi).is_ok_and(|queues| {
                queues.into_iter().all(|queue| {
                    perf.read(Setting::Rps { wifi, queue }).is_ok_and(|value| {
                        value.is_some_and(|(actual, _)| parse_mask(&actual) == Some(mask))
                    })
                })
            })
        }
        [kind, value] if kind == "backlog" => perf
            .read(Setting::Backlog)
            .is_ok_and(|actual| actual.is_some_and(|(actual, _)| actual == *value)),
        _ => false,
    }
}

fn optional<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn remove(path: &Path) -> io::Result<()> {
    optional(fs::remove_file(path)).map(|_| ())
}

fn parse_mask(value: &str) -> Option<u32> {
    u32::from_str_radix(&value.replace(',', ""), 16).ok()
}

fn spare_cpus(interrupts: &str) -> Option<u32> {
    let mut lines = interrupts.lines();
    let cpus = lines
        .next()?
        .split_whitespace()
        .filter(|cpu| cpu.starts_with("CPU"))
        .count();
    if !(2..32).contains(&cpus) {
        return None;
    }
    let mut busy = 0b11;
    for line in lines.filter(|line| line.contains("wlan")) {
        for (cpu, count) in line.split_whitespace().skip(1).take(cpus).enumerate() {
            if count.parse::<u64>().is_ok_and(|count| count > 0) {
                busy |= 1 << cpu;
            }
        }
    }
    Some(((1u32 << cpus) - 1) & !busy).filter(|mask| *mask != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERRUPTS: &str = "           CPU0       CPU1       CPU2       CPU3\n\
        32:        132          0          0          0     GICv3 346 Level     ipa\n\
       159:    5908049    2200202          0          0  gic_msm_pci_msi 524293 Edge      pci0_wlan_ce_2\n\
       168:   22991343   10355904          0          0  gic_msm_pci_msi 524302 Edge      pci0_wlan_grp_dp_0";

    struct Fixture {
        perf: Perf,
        root: test_dir::TestDir,
    }

    impl Fixture {
        fn new() -> Self {
            let root = test_dir::TestDir::new("u60-perf");
            let perf = Self::owner(root.path());
            let fixture = Self { root, perf };
            for (setting, value) in [
                (Setting::Backlog, "1000"),
                (Setting::SlowStart, "200"),
                (Setting::Avoidance, "120"),
            ] {
                fixture.write(&setting.path(&fixture.perf), value);
            }
            fixture.write(&fixture.perf.proc.join("interrupts"), INTERRUPTS);
            for (wifi, queue, mask) in [
                ("wlan0", 0, "0"),
                ("wlan0", 1, "3"),
                ("wlan2", 0, "00000000"),
                ("ecm0", 0, "6"),
                ("rndis0", 0, "7"),
                ("rmnet0", 0, "8"),
            ] {
                fixture.write(&fixture.queue(wifi, queue), mask);
            }
            fixture
        }

        fn owner(root: &Path) -> Perf {
            Perf::for_test(root)
        }

        fn write(&self, path: &Path, value: &str) {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, value).unwrap();
        }

        fn queue(&self, wifi: &str, queue: u32) -> PathBuf {
            self.perf
                .net
                .join(wifi)
                .join(format!("queues/rx-{queue}/rps_cpus"))
        }

        fn active(&self, feature: PerfFeature, active: bool) {
            self.perf.set_active(feature, active).unwrap();
        }

        fn assert_settings(&self, expected: [&str; 6]) {
            let paths = [
                Setting::Backlog.path(&self.perf),
                Setting::SlowStart.path(&self.perf),
                Setting::Avoidance.path(&self.perf),
                self.queue("wlan0", 0),
                self.queue("wlan0", 1),
                self.queue("wlan2", 0),
            ];
            assert_eq!(
                paths.map(|path| fs::read_to_string(path).unwrap()),
                expected
            );
            for (iface, mask) in [("ecm0", "6"), ("rndis0", "7"), ("rmnet0", "8")] {
                assert_eq!(fs::read_to_string(self.queue(iface, 0)).unwrap(), mask);
            }
        }
    }

    const ORIGINAL: [&str; 6] = ["1000", "200", "120", "0", "3", "00000000"];
    const TUNED: [&str; 6] = ["5000", "1000", "1000", "c", "c", "c"];

    #[test]
    fn duplicate_claims_and_overlapping_features_restore_only_after_the_last_release() {
        let fixture = Fixture::new();
        let relay = fixture.queue("ath20", 0);
        fixture.write(&relay, "5");
        fixture.active(PerfFeature::Relay, true);
        fixture.active(PerfFeature::Relay, true);
        fixture.active(PerfFeature::Tailscale, true);
        fixture.active(PerfFeature::Mihomo, true);
        fixture.perf.recover().unwrap();
        fixture.assert_settings(TUNED);
        assert_eq!(fs::read_to_string(&relay).unwrap(), "c");
        fixture.active(PerfFeature::Relay, false);
        fixture.active(PerfFeature::Relay, false);
        assert_eq!(fs::read_to_string(&relay).unwrap(), "5");
        fixture.assert_settings(TUNED);
        fixture.active(PerfFeature::Tailscale, false);
        fixture.assert_settings(TUNED);
        fixture.active(PerfFeature::Mihomo, false);
        fixture.active(PerfFeature::Mihomo, false);
        fixture.assert_settings(ORIGINAL);
        assert!(!fixture.perf.journal.exists());
    }

    #[test]
    fn mihomo_and_tailscale_each_tune_wifi_and_tcp_on_their_own() {
        let fixture = Fixture::new();
        let backlog = Setting::Backlog.path(&fixture.perf);
        fixture.write(&backlog, "7500");
        let relay = fixture.queue("ath20", 0);
        fixture.write(&relay, "5");
        for feature in [PerfFeature::Mihomo, PerfFeature::Tailscale] {
            fixture.active(feature, true);
            fixture.assert_settings(["7500", "1000", "1000", "c", "c", "c"]);
            assert_eq!(fs::read_to_string(&relay).unwrap(), "5");
            fixture.active(feature, false);
            fixture.assert_settings(["7500", "200", "120", "0", "3", "00000000"]);
        }
    }

    #[test]
    fn refresh_captures_new_and_recreated_station_queues() {
        let fixture = Fixture::new();
        fixture.active(PerfFeature::Relay, true);
        let relay = fixture.queue("ath20", 0);
        fixture.write(&relay, "5");
        fixture.perf.refresh_interfaces().unwrap();
        assert_eq!(fs::read_to_string(&relay).unwrap(), "c");
        fs::rename(&relay, relay.with_extension("gone")).unwrap();
        fixture.write(&relay, "f");
        fixture.perf.refresh_interfaces().unwrap();
        assert_eq!(fs::read_to_string(&relay).unwrap(), "c");
        fixture.active(PerfFeature::Relay, false);
        assert_eq!(fs::read_to_string(&relay).unwrap(), "f");
        fixture.assert_settings(ORIGINAL);
    }

    #[test]
    fn restart_uses_the_journal_without_restoring_onto_recreated_queues() {
        let mut fixture = Fixture::new();
        fixture.active(PerfFeature::Relay, true);
        let wlan = fixture.queue("wlan2", 0);
        fs::rename(&wlan, wlan.with_extension("gone")).unwrap();
        fixture.write(&wlan, "7");
        let next = Fixture::owner(fixture.root.path());
        drop(std::mem::replace(&mut fixture.perf, next));
        fixture.perf.recover().unwrap();
        fixture.assert_settings(["1000", "200", "120", "0", "3", "7"]);
        assert!(!fixture.perf.journal.exists());
    }

    #[test]
    fn a_live_owner_blocks_startup_and_recovery_until_it_exits() {
        let mut fixture = Fixture::new();
        fixture.perf.start().unwrap();
        fixture.active(PerfFeature::Relay, true);
        let next = Fixture::owner(fixture.root.path());
        let journal = fs::read(&fixture.perf.journal).unwrap();
        for error in [next.recover().unwrap_err(), next.start().unwrap_err()] {
            assert!(
                error.contains("owned by another zte-agent process"),
                "{error}"
            );
        }
        fixture.assert_settings(TUNED);
        assert_eq!(fs::read(&fixture.perf.journal).unwrap(), journal);

        drop(std::mem::replace(&mut fixture.perf, next));
        fixture.perf.recover().unwrap();
        fixture.assert_settings(ORIGINAL);
        assert!(!fixture.perf.journal.exists());
    }

    #[test]
    fn refresh_retries_initial_recovery_and_applies_the_recorded_claim() {
        let mut fixture = Fixture::new();
        fixture.active(PerfFeature::Relay, true);
        let next = Fixture::owner(fixture.root.path());
        drop(std::mem::replace(&mut fixture.perf, next));
        let saved = fixture.perf.journal.with_extension("saved");
        fs::rename(&fixture.perf.journal, &saved).unwrap();
        fs::create_dir(&fixture.perf.journal).unwrap();
        assert!(fixture.perf.set_active(PerfFeature::Mihomo, true).is_err());

        fs::remove_dir(&fixture.perf.journal).unwrap();
        fs::rename(saved, &fixture.perf.journal).unwrap();
        fixture.perf.refresh_interfaces().unwrap();
        fixture.assert_settings(TUNED);
        fixture.active(PerfFeature::Mihomo, false);
        fixture.assert_settings(ORIGINAL);
    }

    #[test]
    fn runtime_reconcile_never_rewrites_owner_journals_after_start() {
        let fixture = Fixture::new();
        fixture.write(&fixture.perf.legacy_relay, "incomplete");
        fixture.perf.start().unwrap();

        let undo = Cmd::new("@u60-relay-steer", &["backlog", "1000"]);
        let route = Cmd::new("ip", &["route", "del", "default"]);
        let owner_journal = serde_json::json!({"boot": fixture.perf.boot(), "undo": [undo, route]}).to_string();
        fixture.write(&fixture.perf.legacy_relay, &owner_journal);

        fixture.active(PerfFeature::Relay, true);
        fixture.perf.refresh_interfaces().unwrap();
        assert_eq!(fs::read_to_string(&fixture.perf.legacy_relay).unwrap(), owner_journal);
        fixture.assert_settings(TUNED);
        fixture.active(PerfFeature::Relay, false);
        fixture.assert_settings(ORIGINAL);
    }

    #[test]
    fn a_backlog_at_the_floor_is_left_unowned() {
        let fixture = Fixture::new();
        let backlog = Setting::Backlog.path(&fixture.perf);
        fixture.write(&backlog, "5000");
        fixture.active(PerfFeature::Relay, true);
        fixture.write(&backlog, "9000");
        fixture.perf.refresh_interfaces().unwrap();
        fixture.active(PerfFeature::Relay, false);
        assert_eq!(fs::read_to_string(backlog).unwrap(), "9000");
    }

    #[test]
    fn failed_journaling_prevents_kernel_writes() {
        let fixture = Fixture::new();
        fixture.write(fixture.perf.journal.parent().unwrap(), "regular file");
        assert!(fixture.perf.set_active(PerfFeature::Mihomo, true).is_err());
        fixture.assert_settings(ORIGINAL);
    }

    #[test]
    fn legacy_journal_migration_retires_only_the_tuning_undos() {
        let fixture = Fixture::new();
        let path = fixture.root.path().join("legacy/network.json");
        let backlog = Cmd::new("@u60-relay-steer", &["backlog", "1000"]);
        let rps = Cmd::new("@u60-relay-steer", &["rps", "wlan2", "0"]);
        let nft = Cmd::new("@u60-relay-nft", &["remove"]);
        let boot = fixture.perf.boot();
        let journal = serde_json::json!({"boot": boot, "undo": [&rps, &backlog, &nft]});
        fixture.write(&path, &journal.to_string());
        let mut attempted = Vec::new();
        let matches = |undo: &Cmd| undo.program == "@u60-relay-steer";
        let result = retire_legacy(&path, &boot, matches, |undo| {
            attempted.push(undo.clone());
            Err("unavailable".into())
        });
        assert!(result.is_err());
        assert_eq!(attempted, [backlog.clone()]);
        assert_eq!(fs::read_to_string(&path).unwrap(), journal.to_string());
        attempted.clear();
        retire_legacy(&path, &boot, matches, |undo| {
            attempted.push(undo.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(attempted, [backlog, rps]);
        let remaining: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(remaining, serde_json::json!({"boot": boot, "undo": [nft]}));
    }

    #[test]
    fn cpu_mask_avoids_the_hardware_interrupt_cores() {
        assert_eq!(spare_cpus(INTERRUPTS), Some(0xc));
        assert_eq!(spare_cpus("CPU0 CPU1 CPU2 CPU3\n"), Some(0xc));
        assert_eq!(
            spare_cpus("CPU0 CPU1 CPU2 CPU3\n 1: 5 7 10 0 x wlan"),
            Some(0x8)
        );
        assert_eq!(spare_cpus("CPU0 CPU1\n 1: 5 7 x wlan"), None);
        for iface in ["ecm0", "rndis0", "rmnet0", "wlan0", "br-lan"] {
            assert!(legacy_command(&["rps".into(), iface.into(), "c".into()]).is_err());
        }
        assert!(legacy_command(&["backlog".into(), "0".into()]).is_err());
    }

    #[test]
    fn malformed_or_empty_boot_id_preserves_saved_originals_for_restoration() {
        for bad_boot in ["", "perf test", " perf-test-boot", "perf\tboot", "perf\x0cboot"] {
            let mut fixture = Fixture::new();
            fixture.active(PerfFeature::Relay, true);
            fixture.assert_settings(TUNED);
            let mut journal: serde_json::Value =
                serde_json::from_slice(&fs::read(&fixture.perf.journal).unwrap()).unwrap();
            journal["boot"] = serde_json::json!(bad_boot);
            fs::write(&fixture.perf.journal, serde_json::to_vec(&journal).unwrap()).unwrap();

            let next = Fixture::owner(fixture.root.path());
            drop(std::mem::replace(&mut fixture.perf, next));
            fixture.perf.recover().unwrap();
            fixture.assert_settings(ORIGINAL);
            assert!(!fixture.perf.journal.exists());
        }
    }

    #[test]
    fn slot_change_and_pending_trial_restore_and_hold_shared_tuning() {
        let fixture = Fixture::new();
        fixture.active(PerfFeature::Relay, true);
        fixture.assert_settings(TUNED);
        assert!(fixture.perf.journal.exists());

        // 1. Aborted slot change restores originals before callback, then
        //    re-applies desired tuning after callback returns Err.
        let aborted = fixture
            .perf
            .before_slot_change(|| -> Result<(), String> {
                fixture.assert_settings(ORIGINAL);
                assert!(!fixture.perf.journal.exists());
                Err("simulated OTA failure".into())
            })
            .unwrap_err();
        assert_eq!(aborted, "simulated OTA failure");
        fixture.assert_settings(TUNED);
        assert!(fixture.perf.journal.exists());

        // 2. Successful slot change restores originals, deletes the journal,
        //    and holds tuning off against subsequent set_active/refresh calls.
        fixture
            .perf
            .before_slot_change(|| {
                fixture.assert_settings(ORIGINAL);
                assert!(!fixture.perf.journal.exists());
                Ok(())
            })
            .unwrap();
        fixture.perf.set_active(PerfFeature::Mihomo, true).unwrap();
        fixture.perf.refresh_interfaces().unwrap();
        fixture.assert_settings(ORIGINAL);
        assert!(!fixture.perf.journal.exists());

        // 3. During a pending OTA trial on a newly started candidate, tuning is
        //    deferred until commit clears the pending marker.
        let candidate = Fixture::new();
        candidate.perf.state.lock().unwrap().test_ota_trial_pending = true;
        candidate.perf.set_active(PerfFeature::Relay, true).unwrap();
        candidate.assert_settings(ORIGINAL);
        assert!(!candidate.perf.journal.exists());
        assert!(candidate.perf.trial_deferred());

        candidate.perf.state.lock().unwrap().test_ota_trial_pending = false;
        candidate.perf.refresh_interfaces().unwrap();
        candidate.assert_settings(TUNED);
        assert!(candidate.perf.journal.exists());
        assert!(!candidate.perf.trial_deferred());
    }

    #[test]
    fn empty_same_boot_performance_journal_is_removed_on_recover_and_slot_change() {
        let fixture = Fixture::new();
        let empty = format!("{{\"boot\":\"{}\",\"originals\":[]}}\n", fixture.perf.boot());
        fixture.write(&fixture.perf.journal, &empty);
        assert!(fixture.perf.journal.exists());

        fixture.perf.recover().unwrap();
        assert!(
            !fixture.perf.journal.exists(),
            "recover() must retire an existing empty same-boot performance journal"
        );

        fixture.write(&fixture.perf.journal, &empty);
        fixture
            .perf
            .before_slot_change(|| {
                assert!(!fixture.perf.journal.exists());
                Ok(())
            })
            .unwrap();
        assert!(!fixture.perf.journal.exists());
    }

    #[test]
    fn malformed_current_boot_id_raw_bytes_preserve_originals_and_legacy_undo() {
        for bad_raw in [
            b"".as_slice(),
            b"\x0cperf-test-boot\n".as_slice(),
            b"\x0bperf-test-boot\n".as_slice(),
            b"\xc2\xa0perf-test-boot\n".as_slice(),
            b"perf\0boot\n".as_slice(),
            b"perf boot\n".as_slice(),
            b"perf\xffboot\n".as_slice(),
        ] {
            // 1. Perf::load() / recover() must NOT discard a differing saved
            //    boot ID when the raw current boot_id bytes are malformed.
            let mut fixture = Fixture::new();
            fixture.active(PerfFeature::Relay, true);
            fixture.assert_settings(TUNED);
            let mut journal: serde_json::Value =
                serde_json::from_slice(&fs::read(&fixture.perf.journal).unwrap()).unwrap();
            journal["boot"] = serde_json::json!("prior-valid-boot");
            fs::write(&fixture.perf.journal, serde_json::to_vec(&journal).unwrap()).unwrap();

            let mut next = Fixture::owner(fixture.root.path());
            next.test_boot_raw = Some(bad_raw.to_vec());
            drop(std::mem::replace(&mut fixture.perf, next));
            fixture.perf.recover().unwrap();
            fixture.assert_settings(ORIGINAL);
            assert!(!fixture.perf.journal.exists());

            // 2. Perf::retire_legacy() must ALSO fail closed and restore legacy
            //    tuning entries when the raw current boot_id bytes are malformed.
            let mut legacy_fixture = Fixture::new();
            legacy_fixture.write(&Setting::Backlog.path(&legacy_fixture.perf), "5000");
            let undo = Cmd::new("@u60-relay-steer", &["backlog", "1000"]);
            let legacy = serde_json::json!({
                "boot": "prior-valid-boot",
                "undo": [undo],
            });
            legacy_fixture.write(&legacy_fixture.perf.legacy_relay, &legacy.to_string());
            legacy_fixture.perf.test_boot_raw = Some(bad_raw.to_vec());
            legacy_fixture.perf.retire_legacy().unwrap();
            assert_eq!(
                fs::read_to_string(Setting::Backlog.path(&legacy_fixture.perf)).unwrap(),
                "1000"
            );
        }
    }

    #[test]
    fn watcher_applies_deferred_tuning_even_when_trial_commits_before_wait_check() {
        use std::time::{Duration, Instant};

        // Case A: pending disappears AFTER set_active/refresh deferred tuning
        // and BEFORE the watcher inspects next_watch_action(), with NO wake.
        let fixture = Fixture::new();
        let perf = Arc::new(fixture.perf);
        perf.state.lock().unwrap().test_ota_trial_pending = true;
        perf.set_active(PerfFeature::Relay, true).unwrap();
        assert!(perf.trial_deferred());
        assert_eq!(perf.next_watch_action(), WatchAction::WaitRetry);
        assert!(!perf.journal.exists());

        // Commit clears pending before the watcher checks its wait decision.
        perf.state.lock().unwrap().test_ota_trial_pending = false;
        assert_eq!(perf.next_watch_action(), WatchAction::ApplyNow);

        let (wake, settled) = std::sync::mpsc::sync_channel(1);
        perf.state.lock().unwrap().wake = Some(wake);
        let owner = Arc::clone(&perf);
        let handle = std::thread::spawn(move || {
            Perf::watch_loop(owner, settled, Duration::from_secs(60));
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && !perf.journal.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            perf.journal.exists(),
            "watcher must immediately apply deferred tuning when trial committed before wait check"
        );
        assert!(!perf.trial_deferred());
        assert_eq!(perf.next_watch_action(), WatchAction::WaitEvent);
        perf.state.lock().unwrap().wake = None;
        handle.join().unwrap();

        // Case B: watcher enters timed WaitRetry while pending is still active,
        // then pending disappears with NO external wake -> retry timeout applies.
        let fixture2 = Fixture::new();
        let perf2 = Arc::new(fixture2.perf);
        perf2.state.lock().unwrap().test_ota_trial_pending = true;
        perf2.set_active(PerfFeature::Relay, true).unwrap();
        assert!(perf2.trial_deferred());
        let (wake2, settled2) = std::sync::mpsc::sync_channel(1);
        perf2.state.lock().unwrap().wake = Some(wake2);
        let owner2 = Arc::clone(&perf2);
        let handle2 = std::thread::spawn(move || {
            Perf::watch_loop(owner2, settled2, Duration::from_millis(25));
        });
        std::thread::sleep(Duration::from_millis(40));
        assert!(!perf2.journal.exists());
        perf2.state.lock().unwrap().test_ota_trial_pending = false;

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && !perf2.journal.exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            perf2.journal.exists(),
            "watcher retry timeout must apply deferred tuning without external events"
        );
        assert!(!perf2.trial_deferred());
        perf2.state.lock().unwrap().wake = None;
        handle2.join().unwrap();
    }
}
