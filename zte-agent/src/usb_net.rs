//! One USB configuration for Windows RNDIS, macOS ECM and shared ADB.
//! See `zte-agent/docs/usb-network.md` (owner decision 66).
//!
//! ZTE's ADB composition uses RNDIS on every host. Windows' default
//! composite matching requires one configuration, so replace that debug
//! composition with RNDIS + ECM + ADB in `c.1` and migrate our old `c.2`.
//! Both network functions keep the vendor's GSI/IPA data path.
//!
//! ZTE's `usb_switch` rebuilds `c.1` on boot and mode changes. Its inotify
//! events trigger repair after [`SETTLE`] quiet. Use `f1`..`f3` so ZTE can
//! clear our links on the next rebuild, including when the agent is off.
//! Changes hold `adbd` with SIGSTOP while unbinding/editing/rebinding,
//! because FunctionFS otherwise rebinds within milliseconds. On failure,
//! restore the previous links, configuration attributes and descriptors.
//! A bound gadget's first repair waits [`START_DEFER`] for deployment to
//! finish. Agent startup also continues any previously stopped `adbd`.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// ZTE's composition script also runs for each cable attach.
const SCRIPT: &str = "/sbin/usb/compositions/usb_switch";
const SETTLE: Duration = Duration::from_secs(1);
const SWITCH_WAIT: u32 = 30;
const START_DEFER: Duration = Duration::from_secs(60);
const FALLBACK: Duration = Duration::from_secs(60);

const SECOND: &str = "c.2";
const RNDIS: &str = "gsi.rndis";
const ECM: &str = "gsi.ecm";
const ADB: &str = "ffs.adb";
/// Creation order determines interface numbers. RNDIS must come first.
const LINKS: [(&str, &str); 3] = [("f1", RNDIS), ("f2", ECM), ("f3", ADB)];
const OLD_LINKS: [(&str, &str); 2] = [("u60-adb", ADB), ("u60-ecm", ECM)];
const CLASS: [(&str, &str); 3] = [("bDeviceClass", "0xef"), ("bDeviceSubClass", "0x02"), ("bDeviceProtocol", "0x01")];
/// A stable identity for this layout avoids Windows' old parent-driver cache.
const SERIAL_SUFFIX: &str = "-u60net1";
const SERIAL: &str = "strings/0x409/serialnumber";

type Links = Vec<(String, String)>;

struct Paths {
    gadget: PathBuf,
    udcs: PathBuf,
    role: PathBuf,
    switching: PathBuf,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct State {
    first: Links,
    second: Option<Links>,
    others: bool,
    ecm: bool,
    class: [String; 3],
    serial: String,
    udc: String,
    host: bool,
    switching: bool,
}

#[derive(Debug, PartialEq)]
enum Plan {
    Keep,
    /// Maintain RNDIS + ECM + ADB in the sole configuration and bind it.
    Link,
    /// Remove an owned old configuration after ZTE changed compositions.
    Remove {
        bind: bool,
    },
}

fn layout_serial(serial: &str) -> String {
    if serial.ends_with(SERIAL_SUFFIX) {
        serial.to_owned()
    } else {
        format!("{serial}{SERIAL_SUFFIX}")
    }
}

fn plan(s: &State) -> Plan {
    if s.switching || s.host || s.others || s.first.is_empty() {
        return Plan::Keep;
    }
    if s.second
        .as_ref()
        .is_some_and(|links| !links.iter().all(|(name, function)| OLD_LINKS.iter().any(|(n, f)| name == n && function == f)))
    {
        return Plan::Keep;
    }
    let wanted = s.ecm && s.first.iter().any(|(_, f)| f == RNDIS) && s.first.iter().any(|(_, f)| f == ADB);
    if wanted {
        let complete = s.first.len() == LINKS.len()
            && LINKS.iter().zip(&s.first).all(|((n, f), (name, function))| name == n && function == f)
            && CLASS.iter().zip(&s.class).all(|((_, value), actual)| value == actual)
            && s.serial.ends_with(SERIAL_SUFFIX)
            && s.second.is_none();
        return if complete && !s.udc.is_empty() { Plan::Keep } else { Plan::Link };
    }
    match &s.second {
        Some(links) => Plan::Remove { bind: !s.udc.is_empty() || links.is_empty() },
        None => Plan::Keep,
    }
}

fn read_trimmed(path: &Path) -> String {
    fs::read_to_string(path).map(|s| s.trim().to_owned()).unwrap_or_default()
}

/// A configuration's function links as (name, function).
fn links(config: &Path) -> io::Result<Links> {
    let mut links = Vec::new();
    for entry in fs::read_dir(config)? {
        let path = entry?.path();
        let Ok(target) = fs::read_link(&path) else {
            continue;
        };
        let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        links.push((name(&path), name(&target)));
    }
    links.sort();
    Ok(links)
}

impl Paths {
    fn device() -> Paths {
        Paths {
            gadget: "/sys/kernel/config/usb_gadget/g1".into(),
            udcs: "/sys/class/udc".into(),
            role: "/sys/bus/platform/devices/a600000.ssusb/mode".into(),
            switching: "/tmp/usb_bind_in_progress".into(),
        }
    }

    fn configs(&self) -> PathBuf {
        self.gadget.join("configs")
    }

    fn read(&self) -> io::Result<State> {
        let mut state = State::default();
        for entry in fs::read_dir(self.configs())? {
            let entry = entry?;
            match entry.file_name().to_str() {
                Some("c.1") => state.first = links(&entry.path())?,
                Some(SECOND) => state.second = Some(links(&entry.path())?),
                _ => state.others = true,
            }
        }
        for ((attribute, _), value) in CLASS.iter().zip(&mut state.class) {
            *value = fs::read_to_string(self.gadget.join(attribute))?.trim().to_owned();
        }
        state.serial = fs::read_to_string(self.gadget.join(SERIAL))?.trim().to_owned();
        state.ecm = self.gadget.join("functions").join(ECM).is_dir();
        state.udc = fs::read_to_string(self.gadget.join("UDC"))?.trim().to_owned();
        state.host = fs::read_to_string(&self.role)?.trim() == "host";
        state.switching = self.switching();
        Ok(state)
    }

    fn switching(&self) -> bool {
        read_trimmed(&self.switching) == "start"
    }

    fn first_udc(&self) -> Option<String> {
        fs::read_dir(&self.udcs).ok()?.filter_map(Result::ok).filter_map(|e| e.file_name().into_string().ok()).min()
    }

    fn unbind(&self) -> io::Result<()> {
        match fs::write(self.gadget.join("UDC"), "\n") {
            Err(e) if e.raw_os_error() == Some(libc::ENODEV) => Ok(()),
            other => other,
        }
    }

    fn bind(&self, udc: &str) -> io::Result<()> {
        fs::write(self.gadget.join("UDC"), udc)
    }

    fn clear_links(&self, config: &Path) -> io::Result<()> {
        for (name, _) in links(config)? {
            fs::remove_file(config.join(name))?;
        }
        Ok(())
    }

    fn add_links(&self, config: &Path, links: &Links) -> io::Result<()> {
        for (name, function) in links {
            std::os::unix::fs::symlink(self.gadget.join("functions").join(function), config.join(name))?;
        }
        Ok(())
    }

    /// Capture all attributes of the old configuration before removing it.
    fn second_attributes(&self) -> io::Result<Vec<(PathBuf, String)>> {
        let second = self.configs().join(SECOND);
        let mut attributes = Vec::new();
        for attribute in ["bmAttributes", "MaxPower"] {
            attributes.push((PathBuf::from(attribute), fs::read_to_string(second.join(attribute))?));
        }
        for language in fs::read_dir(second.join("strings"))? {
            let relative = PathBuf::from("strings").join(language?.file_name()).join("configuration");
            attributes.push((relative.clone(), fs::read_to_string(second.join(relative))?));
        }
        Ok(attributes)
    }

    fn remove_second(&self) -> io::Result<()> {
        let second = self.configs().join(SECOND);
        if !second.exists() {
            return Ok(());
        }
        self.clear_links(&second)?;
        for language in fs::read_dir(second.join("strings"))? {
            let language = language?.path();
            // Plain-file fixtures need virtual configfs attributes removed.
            #[cfg(test)]
            fs::remove_file(language.join("configuration"))?;
            fs::remove_dir(language)?;
        }
        #[cfg(test)]
        {
            fs::remove_dir(second.join("strings"))?;
            fs::remove_file(second.join("bmAttributes"))?;
            fs::remove_file(second.join("MaxPower"))?;
        }
        fs::remove_dir(second)
    }

    fn link(&self, state: &State) -> io::Result<()> {
        self.remove_second()?;
        let first = self.configs().join("c.1");
        self.clear_links(&first)?;
        let wanted = LINKS.iter().map(|(name, function)| (name.to_string(), function.to_string())).collect();
        self.add_links(&first, &wanted)?;
        for (attribute, value) in CLASS {
            fs::write(self.gadget.join(attribute), value)?;
        }
        fs::write(self.gadget.join(SERIAL), layout_serial(&state.serial))
    }

    fn restore(&self, state: &State, second_attributes: &[(PathBuf, String)]) -> io::Result<()> {
        let first = self.configs().join("c.1");
        self.clear_links(&first)?;
        self.add_links(&first, &state.first)?;
        if let Some(links) = &state.second {
            let second = self.configs().join(SECOND);
            fs::create_dir_all(second.join("strings"))?;
            self.clear_links(&second)?;
            for (relative, value) in second_attributes {
                if let Some(parent) = relative.parent() {
                    fs::create_dir_all(second.join(parent))?;
                }
                fs::write(second.join(relative), value)?;
            }
            self.add_links(&second, links)?;
        }
        for ((attribute, _), value) in CLASS.iter().zip(&state.class) {
            fs::write(self.gadget.join(attribute), value)?;
        }
        fs::write(self.gadget.join(SERIAL), &state.serial)
    }

    fn apply(&self, state: &State, plan: &Plan) -> Result<(), String> {
        self.apply_with_bind(state, plan, |udc| self.bind(udc))
    }

    /// Hold adbd for the whole transaction. The bind callback also lets
    /// tests fail the first UDC bind and verify restoration before retry.
    fn apply_with_bind(&self, state: &State, plan: &Plan, mut bind_udc: impl FnMut(&str) -> io::Result<()>) -> Result<(), String> {
        let bind = match *plan {
            Plan::Keep => return Ok(()),
            Plan::Link => true,
            Plan::Remove { bind } => bind,
        };
        let udc = if state.udc.is_empty() { self.first_udc() } else { Some(state.udc.clone()) };
        if bind && udc.is_none() {
            return Err("no USB device controller".into());
        }
        let attributes = if state.second.is_some() {
            self.second_attributes().map_err(|e| format!("snapshot configuration 2: {e}"))?
        } else {
            Vec::new()
        };
        if !state.udc.is_empty() {
            self.unbind().map_err(|e| format!("unbind: {e}"))?;
        }
        let edited = match plan {
            Plan::Link => self.link(state),
            _ => self.remove_second(),
        };
        let result = edited.map_err(|e| format!("edit USB configuration: {e}")).and_then(|()| {
            if let (true, Some(udc)) = (bind, &udc) {
                bind_udc(udc).map_err(|e| format!("bind {udc}: {e}"))?;
            }
            Ok(())
        });
        if let Err(error) = result {
            let restored = self.unbind().and_then(|()| self.restore(state, &attributes)).and_then(|()| {
                if let (true, Some(udc)) = (bind, &udc) {
                    bind_udc(udc)?;
                }
                Ok(())
            });
            return match restored {
                Ok(()) => Err(format!("{error}; previous USB layout restored")),
                Err(e) => Err(format!("{error}; restoring previous USB layout failed: {e}")),
            };
        }
        Ok(())
    }
}

/// `adbd` stopped while the gadget is edited, continued on drop.
struct Held(Vec<libc::pid_t>);

impl Held {
    fn stop() -> Held {
        let pids = adbd_pids();
        for &pid in &pids {
            // SAFETY: kill(2) on a pid just read from /proc whose comm is adbd.
            unsafe { libc::kill(pid, libc::SIGSTOP) };
        }
        Held(pids)
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        for &pid in &self.0 {
            // SAFETY: continues the process this guard stopped.
            unsafe { libc::kill(pid, libc::SIGCONT) };
        }
    }
}

fn adbd_pids() -> Vec<libc::pid_t> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str()?.parse::<libc::pid_t>().ok())
        .filter(|&pid| pid > 1 && read_trimmed(Path::new(&format!("/proc/{pid}/comm"))) == "adbd")
        .collect()
}

/// Checks the gadget and carries out what it needs. `force` checks even
/// while ZTE's bind-in-progress flag is still set. After a failed link,
/// `gave_up` keeps ZTE's composition alone until the agent restarts.
fn check(paths: &Paths, gave_up: &mut bool, force: bool) {
    let read = || {
        paths.read().map(|mut s| {
            s.switching &= !force;
            s
        })
    };
    let wanted = |plan: &Plan| !(*gave_up && matches!(plan, Plan::Link)) && *plan != Plan::Keep;
    match read() {
        Ok(state) if wanted(&plan(&state)) => {}
        Ok(_) => return,
        Err(e) => return crate::netlog!("[usb] cannot read the USB gadget: {e}"),
    }
    let _held = Held::stop();
    // Read again with adbd held: it may have bound or unbound meanwhile.
    let state = match read() {
        Ok(state) => state,
        Err(e) => return crate::netlog!("[usb] cannot read the USB gadget: {e}"),
    };
    let plan = plan(&state);
    if !wanted(&plan) {
        return;
    }
    let reconnect = if state.udc.is_empty() { "" } else { "; USB reconnected" };
    match (paths.apply(&state, &plan), &plan) {
        (Ok(()), Plan::Link) => {
            crate::netlog!("[usb] configured RNDIS + ECM + ADB in c.1 (EF/02/01){reconnect}")
        }
        (Ok(()), _) => crate::netlog!("[usb] removed legacy configuration 2{reconnect}"),
        (Err(e), Plan::Link) => {
            *gave_up = true;
            crate::netlog!("[usb] {e}; single-configuration setup suspended until the agent restarts")
        }
        (Err(e), _) => crate::netlog!("[usb] {e}"),
    }
}

pub fn start() {
    #[cfg(target_os = "linux")]
    crate::system::spawn_named("usb-net", run);
}

#[cfg(target_os = "linux")]
fn run() {
    use std::time::Instant;
    let paths = Paths::device();
    if !paths.configs().is_dir() {
        return crate::netlog!("[usb] no USB gadget configfs; USB networking for macOS is off");
    }
    // A previous agent may have died while adbd was stopped.
    drop(Held(adbd_pids()));
    let mut gave_up = false;
    // A bound gadget re-enumerates; let the ADB steps of a deploy finish.
    let mut deferred = match paths.read() {
        Ok(state) if plan(&state) != Plan::Keep && !state.udc.is_empty() => {
            crate::netlog!("[usb] configuring RNDIS + ECM + ADB in c.1 in {} s; USB will reconnect", START_DEFER.as_secs());
            Some(Instant::now() + START_DEFER)
        }
        _ => {
            check(&paths, &mut gave_up, false);
            None
        }
    };
    let Some(watch) = Watch::new(SCRIPT) else {
        crate::netlog!("[usb] cannot watch {SCRIPT}; checking the USB layout every minute");
        loop {
            std::thread::sleep(deferred.take().map_or(FALLBACK, |at| at.saturating_duration_since(Instant::now())));
            check(&paths, &mut gave_up, false);
        }
    };
    loop {
        if !watch.wait(deferred.map(|at| at.saturating_duration_since(Instant::now()))) {
            if deferred.is_some_and(|at| Instant::now() >= at) {
                deferred = None;
                check(&paths, &mut gave_up, false);
            }
            continue;
        }
        deferred = None;
        while watch.wait(Some(SETTLE)) {}
        let mut waited = 0;
        while paths.switching() && waited < SWITCH_WAIT {
            watch.wait(Some(SETTLE));
            waited += 1;
        }
        check(&paths, &mut gave_up, true);
    }
}

/// inotify on [`SCRIPT`]: every launcher's shell opens it, and closes it
/// when the run ends.
#[cfg(target_os = "linux")]
struct Watch(libc::c_int);

#[cfg(target_os = "linux")]
impl Watch {
    fn new(path: &str) -> Option<Watch> {
        let path = std::ffi::CString::new(path).ok()?;
        // SAFETY: plain inotify syscalls on a descriptor this thread owns.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        let wd = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_OPEN | libc::IN_CLOSE_NOWRITE) };
        if wd < 0 {
            unsafe { libc::close(fd) };
            return None;
        }
        Some(Watch(fd))
    }

    /// Waits up to `timeout` (`None`: no limit) for the script to be opened
    /// or closed, and drains what came. Whether anything came.
    fn wait(&self, timeout: Option<Duration>) -> bool {
        let mut pfd = libc::pollfd { fd: self.0, events: libc::POLLIN, revents: 0 };
        let ms = timeout.map_or(-1, |t| t.as_millis().min(i32::MAX as u128) as libc::c_int);
        // SAFETY: one pollfd for the descriptor this thread owns.
        let n = unsafe { libc::poll(&mut pfd, 1, ms) };
        if n <= 0 {
            return false;
        }
        if pfd.revents & libc::POLLIN == 0 {
            // Never spin on an error condition.
            std::thread::sleep(SETTLE);
            return false;
        }
        let mut buffer = [0u64; 64];
        // SAFETY: reads into a buffer of the size passed.
        unsafe { libc::read(self.0, buffer.as_mut_ptr().cast(), std::mem::size_of_val(&buffer)) };
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEBUG: [&str; 8] =
        ["gsi.rndis", "ffs.diag", "cser.nmea.1", "cser.dun.0", "mass_storage.0", "ffs.adb", "gsi.dpl", "qdss.qdss_mdm"];

    fn owned(links: &[(&str, &str)]) -> Links {
        links.iter().map(|(name, function)| (name.to_string(), function.to_string())).collect()
    }

    fn debug() -> State {
        State {
            first: DEBUG.iter().enumerate().map(|(i, f)| (format!("f{}", i + 1), f.to_string())).collect(),
            ecm: true,
            class: ["0x00".into(), "0x00".into(), "0x00".into()],
            serial: "0123456789ABCDEF".into(),
            udc: "a600000.dwc3".into(),
            ..State::default()
        }
    }

    struct Fake(PathBuf);

    impl Fake {
        fn new(name: &str) -> (Fake, Paths) {
            let root = std::env::temp_dir().join(format!("zte-agent-usb-net-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let gadget = root.join("g1");
            let first = gadget.join("configs/c.1");
            fs::create_dir_all(first.join("strings/0x409")).unwrap();
            fs::create_dir_all(gadget.join("strings/0x409")).unwrap();
            fs::write(first.join("bmAttributes"), "0x80\n").unwrap();
            fs::write(first.join("MaxPower"), "900\n").unwrap();
            fs::write(first.join("strings/0x409/configuration"), "vendor\n").unwrap();
            for function in DEBUG.iter().chain([&ECM]) {
                fs::create_dir_all(gadget.join("functions").join(function)).unwrap();
            }
            let state = debug();
            for ((attribute, _), value) in CLASS.iter().zip(&state.class) {
                fs::write(gadget.join(attribute), value).unwrap();
            }
            fs::write(gadget.join(SERIAL), &state.serial).unwrap();
            fs::write(gadget.join("UDC"), &state.udc).unwrap();
            fs::create_dir_all(root.join("udc/a600000.dwc3")).unwrap();
            fs::write(root.join("mode"), "peripheral\n").unwrap();
            let paths = Paths { gadget, udcs: root.join("udc"), role: root.join("mode"), switching: root.join("in-progress") };
            paths.add_links(&first, &state.first).unwrap();
            (Fake(root), paths)
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn legacy(paths: &Paths, links: &Links) {
        let second = paths.configs().join(SECOND);
        fs::create_dir_all(second.join("strings/0x409")).unwrap();
        fs::write(second.join("bmAttributes"), "0x80\n").unwrap();
        fs::write(second.join("MaxPower"), "900\n").unwrap();
        fs::write(second.join("strings/0x409/configuration"), "ECM\n").unwrap();
        paths.add_links(&second, links).unwrap();
    }

    #[test]
    fn debug_layout_has_one_configuration_with_both_networks_and_adb() {
        let (_fake, paths) = Fake::new("single");
        let state = paths.read().unwrap();
        assert_eq!(plan(&state), Plan::Link);
        paths.apply(&state, &plan(&state)).unwrap();
        let after = paths.read().unwrap();
        assert!(after.second.is_none(), "Windows needs one configuration for default composite matching");
        assert_eq!(after.first, owned(&LINKS));
        assert_eq!(after.class, CLASS.map(|(_, value)| value.to_string()));
        assert_eq!(after.serial, "0123456789ABCDEF-u60net1");
        assert_eq!(after.udc, state.udc);
        assert_eq!(plan(&after), Plan::Keep);
        paths.apply(&after, &plan(&after)).unwrap();
        assert_eq!(paths.read().unwrap(), after);
        let first = paths.configs().join("c.1");
        assert_eq!(read_trimmed(&first.join("MaxPower")), "900");
        assert_eq!(read_trimmed(&first.join("bmAttributes")), "0x80");
        assert_eq!(read_trimmed(&first.join("strings/0x409/configuration")), "vendor");
    }

    #[test]
    fn migrates_complete_partial_and_empty_legacy_configurations() {
        for (index, old) in [owned(&OLD_LINKS), owned(&OLD_LINKS[..1]), vec![]].into_iter().enumerate() {
            let (_fake, paths) = Fake::new(&format!("migrate-{index}"));
            legacy(&paths, &old);
            paths.unbind().unwrap();
            let state = paths.read().unwrap();
            paths.apply(&state, &plan(&state)).unwrap();
            let after = paths.read().unwrap();
            assert_eq!(after.first, owned(&LINKS));
            assert!(after.second.is_none());
            assert_eq!(after.udc, "a600000.dwc3");
            assert_eq!(plan(&after), Plan::Keep);
        }
    }

    #[test]
    fn repairs_vendor_rebuild_without_growing_the_serial_suffix() {
        let (_fake, paths) = Fake::new("rebuild");
        let initial = paths.read().unwrap();
        paths.apply(&initial, &plan(&initial)).unwrap();
        let complete = paths.read().unwrap();
        let first = paths.configs().join("c.1");
        paths.unbind().unwrap();
        paths.clear_links(&first).unwrap();
        paths.add_links(&first, &initial.first).unwrap();
        fs::write(paths.gadget.join("bDeviceClass"), "0x00").unwrap();
        let rebuilt = paths.read().unwrap();
        paths.apply(&rebuilt, &plan(&rebuilt)).unwrap();
        assert_eq!(paths.read().unwrap(), complete);
        paths.unbind().unwrap();
        let unbound = paths.read().unwrap();
        paths.apply(&unbound, &plan(&unbound)).unwrap();
        assert_eq!(paths.read().unwrap(), complete);
    }

    #[test]
    fn removes_legacy_configuration_for_other_compositions() {
        let (_fake, paths) = Fake::new("user");
        legacy(&paths, &vec![]);
        let first = paths.configs().join("c.1");
        paths.clear_links(&first).unwrap();
        paths.add_links(&first, &owned(&[("f1", ECM), ("f2", "mass_storage.0")])).unwrap();
        paths.unbind().unwrap();
        let state = paths.read().unwrap();
        assert_eq!(plan(&state), Plan::Remove { bind: true });
        paths.apply(&state, &plan(&state)).unwrap();
        let after = paths.read().unwrap();
        assert!(after.second.is_none());
        assert_eq!(after.first, state.first);
        assert_eq!(after.class, state.class);
        assert_eq!(after.serial, state.serial);
        assert_eq!(after.udc, "a600000.dwc3");
        assert_eq!(plan(&after), Plan::Keep);
    }

    #[test]
    fn leaves_host_mode_switches_and_foreign_configurations_alone() {
        for state in [
            State { host: true, ..debug() },
            State { switching: true, ..debug() },
            State { others: true, ..debug() },
            State { ecm: false, ..debug() },
            State { first: vec![], ..debug() },
            State { second: Some(owned(&[("f1", ECM)])), ..debug() },
            State { second: Some(owned(&[("u60-ecm", "ffs.diag")])), ..debug() },
        ] {
            assert_eq!(plan(&state), Plan::Keep, "{state:?}");
        }
    }

    #[test]
    fn failed_bind_restores_links_attributes_descriptors_and_controller() {
        for old in [false, true] {
            let (_fake, paths) = Fake::new(&format!("rollback-{old}"));
            if old {
                legacy(&paths, &owned(&OLD_LINKS));
                let strings = paths.configs().join("c.2/strings/0x804");
                fs::create_dir_all(&strings).unwrap();
                fs::write(strings.join("configuration"), "previous label").unwrap();
            }
            let state = paths.read().unwrap();
            let mut calls = 0;
            let error = paths
                .apply_with_bind(&state, &plan(&state), |udc| {
                    calls += 1;
                    if calls == 1 {
                        assert!(paths.read().unwrap().second.is_none());
                        return Err(io::Error::from_raw_os_error(libc::EINVAL));
                    }
                    assert_eq!(paths.read().unwrap().first, state.first);
                    paths.bind(udc)
                })
                .unwrap_err();
            assert!(error.contains("previous USB layout restored"), "{error}");
            assert_eq!(calls, 2);
            assert_eq!(paths.read().unwrap(), state);
            if old {
                let second = paths.configs().join(SECOND);
                assert_eq!(read_trimmed(&second.join("MaxPower")), "900");
                assert_eq!(read_trimmed(&second.join("bmAttributes")), "0x80");
                assert_eq!(read_trimmed(&second.join("strings/0x409/configuration")), "ECM");
                assert_eq!(read_trimmed(&second.join("strings/0x804/configuration")), "previous label");
            }
        }
    }

    #[test]
    fn reports_failed_recovery_instead_of_claiming_success() {
        let (_fake, paths) = Fake::new("failed-recovery");
        let state = paths.read().unwrap();
        let error = paths.apply_with_bind(&state, &plan(&state), |_| Err(io::Error::from_raw_os_error(libc::ENODEV))).unwrap_err();
        assert!(error.contains("restoring previous USB layout failed"), "{error}");
        let after = paths.read().unwrap();
        assert_eq!(after.first, state.first);
        assert_eq!(after.class, state.class);
        assert_eq!(after.serial, state.serial);
        assert!(after.udc.is_empty());
    }

    #[test]
    fn snapshot_failure_happens_before_unbinding() {
        let (_fake, paths) = Fake::new("snapshot-failure");
        legacy(&paths, &owned(&OLD_LINKS));
        fs::remove_file(paths.configs().join("c.2/MaxPower")).unwrap();
        let state = paths.read().unwrap();
        let error = paths.apply(&state, &plan(&state)).unwrap_err();
        assert!(error.starts_with("snapshot configuration 2"), "{error}");
        assert_eq!(paths.read().unwrap(), state);
    }
}
