//! USB networking for Macs while ADB is on (owner decision 66,
//! `zte-agent/docs/usb-network.md`).
//!
//! ZTE's kernel picks the USB network by host only in its user
//! compositions (RNDIS for Windows, CDC ECM `0x1405` for macOS and Linux).
//! The debug composition that carries ADB (`0x19d2:0x1404`,
//! `rndis_gsi,diag,serial,modem,mass_storage,ffs,dpl,qdss`) is RNDIS for
//! every host, and macOS has no RNDIS driver. While that composition is in
//! place this module adds a second configuration, `c.2`, with CDC ECM and
//! ADB: Windows takes configuration 1 (RNDIS), macOS chooses 2 (tested on
//! macOS 26), and ZTE's `ecm0` is already a `br-lan` port.
//!
//! - ZTE's `usb_switch` rebuilds `c.1` only. It unlinks `configs/c*/f*` but
//!   cannot remove `c.2` (configfs attributes cannot be unlinked, so
//!   BusyBox `rm -rf` never reaches its `rmdir`), and binding with the empty
//!   `c.2` fails: USB is down, ADB included. After every run of the script
//!   (inotify `IN_OPEN`/`IN_CLOSE_NOWRITE`, then [`SETTLE`] quiet) `c.2` is
//!   linked again for the debug composition or removed for any other, and
//!   bound if ZTE's bind failed. While the agent is stopped such a rebuild
//!   leaves USB down until the next agent start or a reboot.
//! - Configurations change only while the gadget is unbound, and `adbd`
//!   binds it again within milliseconds of an unbind. It is stopped
//!   (`SIGSTOP`) for the edit (about 0.1 s) and continued after, and at
//!   every agent start in case an agent died in between.
//! - Editing a bound gadget re-enumerates the device (ADB reconnects within
//!   about a second). At agent start that waits [`START_DEFER`] so the ADB
//!   steps of a deploy finish first; repairing an unbound gadget does not.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// ZTE's composition script: every rebuild (boot, user/debug mode, a host's
/// switch command) and every cable attach (`START_PERIPHERAL`) runs it.
const SCRIPT: &str = "/sbin/usb/compositions/usb_switch";
/// Check once the script has been quiet this long.
const SETTLE: Duration = Duration::from_secs(1);
/// At most this many [`SETTLE`] periods for ZTE's bind in progress.
const SWITCH_WAIT: u32 = 30;
const START_DEFER: Duration = Duration::from_secs(60);
/// Without inotify: check this often.
const FALLBACK: Duration = Duration::from_secs(60);

const SECOND: &str = "c.2";
const LABEL: &str = "ECM";
const RNDIS: &str = "gsi.rndis";
const ECM: &str = "gsi.ecm";
const ADB: &str = "ffs.adb";
/// `c.2`'s links, named apart from ZTE's `f1`..`fN`.
const LINKS: [(&str, &str); 2] = [("u60-adb", ADB), ("u60-ecm", ECM)];

struct Paths {
    gadget: PathBuf,
    udcs: PathBuf,
    role: PathBuf,
    switching: PathBuf,
}

/// What the gadget looks like now.
#[derive(Debug, Default, Clone, PartialEq)]
struct State {
    /// Functions linked in `c.1` (ZTE's composition).
    first: Vec<String>,
    /// `c.2`'s links as (name, function); `None` without `c.2`.
    second: Option<Vec<(String, String)>>,
    /// A configuration other than `c.1` and `c.2`.
    others: bool,
    /// The gadget has the CDC ECM function.
    ecm: bool,
    /// The bound controller, empty while unbound.
    udc: String,
    /// The port is in host role (powerbank, USB Ethernet adapter).
    host: bool,
    /// ZTE's `usb_switch` is between its unlink and its bind.
    switching: bool,
}

#[derive(Debug, PartialEq)]
enum Plan {
    Keep,
    /// Create or complete `c.2`, then bind if `bind`.
    Link { bind: bool },
    /// Remove `c.2`, then bind if `bind`.
    Remove { bind: bool },
}

fn plan(s: &State) -> Plan {
    if s.switching || s.others || s.first.is_empty() {
        return Plan::Keep;
    }
    let wanted = s.ecm && s.first.iter().any(|f| f == RNDIS) && s.first.iter().any(|f| f == ADB);
    let Some(second) = &s.second else {
        return if wanted { Plan::Link { bind: !s.host && !s.udc.is_empty() } } else { Plan::Keep };
    };
    if !second.iter().all(|(name, _)| LINKS.iter().any(|(own, _)| own == name)) {
        return Plan::Keep;
    }
    // An empty `c.2` is what a ZTE rebuild leaves, and its bind failed on it.
    let bind = !s.host && (!s.udc.is_empty() || second.is_empty());
    if !wanted {
        Plan::Remove { bind }
    } else if complete(second) {
        Plan::Keep
    } else {
        Plan::Link { bind }
    }
}

fn complete(links: &[(String, String)]) -> bool {
    links.len() == LINKS.len() && LINKS.iter().all(|(n, f)| links.iter().any(|(ln, lf)| ln == n && lf == f))
}

fn read_trimmed(path: &Path) -> String {
    fs::read_to_string(path).map(|s| s.trim().to_owned()).unwrap_or_default()
}

/// A configuration's function links as (name, function).
fn links(config: &Path) -> io::Result<Vec<(String, String)>> {
    let mut links = Vec::new();
    for entry in fs::read_dir(config)? {
        let path = entry?.path();
        // Attributes and `strings` are not links.
        let Ok(target) = fs::read_link(&path) else { continue };
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
                Some("c.1") => state.first = links(&entry.path())?.into_iter().map(|(_, f)| f).collect(),
                Some(SECOND) => state.second = Some(links(&entry.path())?),
                _ => state.others = true,
            }
        }
        state.ecm = self.gadget.join("functions").join(ECM).is_dir();
        state.udc = read_trimmed(&self.gadget.join("UDC"));
        state.host = read_trimmed(&self.role) == "host";
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

    /// Creates `c.2` or completes it; ZTE's attributes for `c.1` apply too.
    fn link(&self) -> io::Result<()> {
        let first = self.configs().join("c.1");
        let second = self.configs().join(SECOND);
        let strings = second.join("strings/0x409");
        fs::create_dir_all(&strings)?;
        fs::write(strings.join("configuration"), LABEL)?;
        for attribute in ["bmAttributes", "MaxPower"] {
            let value = read_trimmed(&first.join(attribute));
            if !value.is_empty() {
                fs::write(second.join(attribute), value)?;
            }
        }
        for (name, function) in LINKS {
            let link = second.join(name);
            match fs::read_link(&link) {
                Ok(target) if target.file_name() == Some(OsStr::new(function)) => continue,
                Ok(_) => fs::remove_file(&link)?,
                Err(_) => {}
            }
            std::os::unix::fs::symlink(self.gadget.join("functions").join(function), &link)?;
        }
        Ok(())
    }

    /// Removes `c.2` (only ever holding this module's links).
    fn remove(&self) -> io::Result<()> {
        let second = self.configs().join(SECOND);
        if !second.exists() {
            return Ok(());
        }
        for (name, _) in links(&second)? {
            fs::remove_file(second.join(name))?;
        }
        match fs::remove_dir(second.join("strings/0x409")) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        fs::remove_dir(&second)
    }

    /// Carries out `plan` on `s`, with `adbd` held by the caller. A failure
    /// leaves ZTE's composition alone, bound as it was or as ZTE meant.
    fn apply(&self, s: &State, plan: &Plan) -> Result<(), String> {
        let (link, bind) = match *plan {
            Plan::Keep => return Ok(()),
            Plan::Link { bind } => (true, bind),
            Plan::Remove { bind } => (false, bind),
        };
        let udc = if s.udc.is_empty() { self.first_udc() } else { Some(s.udc.clone()) };
        if !s.udc.is_empty() {
            self.unbind().map_err(|e| format!("unbind: {e}"))?;
        }
        let edited = if link { self.link() } else { self.remove() };
        let result = match (edited, &udc) {
            (Err(e), _) => Err(format!("{} configuration 2: {e}", if link { "link" } else { "remove" })),
            (Ok(()), Some(udc)) if bind => self.bind(udc).map_err(|e| format!("bind {udc}: {e}")),
            (Ok(()), _) => Ok(()),
        };
        if result.is_err() {
            let _ = self.unbind();
            let _ = self.remove();
            if let (true, Some(udc)) = (bind || !s.udc.is_empty(), &udc) {
                let _ = self.bind(udc);
            }
        }
        result
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
    let Ok(entries) = fs::read_dir("/proc") else { return Vec::new() };
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
    let wanted = |plan: &Plan| !(*gave_up && matches!(plan, Plan::Link { .. })) && *plan != Plan::Keep;
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
        (Ok(()), Plan::Link { .. }) if state.second.as_ref().is_some_and(Vec::is_empty) => {
            crate::netlog!("[usb] ZTE rebuilt the USB composition; configuration 2 (CDC ECM + ADB) linked again and bound")
        }
        (Ok(()), Plan::Link { .. }) => {
            crate::netlog!("[usb] added configuration 2 (CDC ECM + ADB) for hosts without RNDIS, such as macOS{reconnect}")
        }
        (Ok(()), _) => crate::netlog!("[usb] removed configuration 2: ZTE's composition {:?} is not RNDIS with ADB{reconnect}", state.first),
        (Err(e), Plan::Link { .. }) => {
            *gave_up = true;
            crate::netlog!("[usb] {e}; keeping ZTE's RNDIS composition alone until the agent restarts")
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
            crate::netlog!("[usb] adding configuration 2 (CDC ECM + ADB) in {} s; USB will reconnect", START_DEFER.as_secs());
            Some(Instant::now() + START_DEFER)
        }
        _ => {
            check(&paths, &mut gave_up, false);
            None
        }
    };
    let Some(watch) = Watch::new(SCRIPT) else {
        crate::netlog!("[usb] cannot watch {SCRIPT}; checking USB configuration 2 every minute");
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

    fn ours() -> Vec<(String, String)> {
        LINKS.iter().map(|(n, f)| (n.to_string(), f.to_string())).collect()
    }

    fn debug(second: Option<Vec<(String, String)>>, udc: &str) -> State {
        State {
            first: DEBUG.iter().map(|f| f.to_string()).collect(),
            second,
            ecm: true,
            udc: udc.into(),
            ..State::default()
        }
    }

    #[test]
    fn the_debug_composition_gets_configuration_2() {
        assert_eq!(plan(&debug(None, "a600000.dwc3")), Plan::Link { bind: true });
        assert_eq!(plan(&debug(None, "")), Plan::Link { bind: false }, "edited unbound, bound by ZTE later");
        assert_eq!(plan(&debug(Some(ours()), "a600000.dwc3")), Plan::Keep);
        let partial = vec![("u60-adb".to_owned(), ADB.to_owned())];
        assert_eq!(plan(&debug(Some(partial), "a600000.dwc3")), Plan::Link { bind: true });
    }

    #[test]
    fn after_a_zte_rebuild_the_empty_configuration_is_linked_and_bound() {
        assert_eq!(plan(&debug(Some(vec![]), "")), Plan::Link { bind: true });
        let host = State { host: true, ..debug(Some(vec![]), "") };
        assert_eq!(plan(&host), Plan::Link { bind: false }, "never bind in host role");
    }

    #[test]
    fn other_compositions_lose_configuration_2() {
        let user = |second| State {
            first: vec!["gsi.ecm".into(), "mass_storage.0".into()],
            second,
            ecm: true,
            ..State::default()
        };
        assert_eq!(plan(&user(Some(vec![]))), Plan::Remove { bind: true });
        assert_eq!(plan(&State { udc: "a600000.dwc3".into(), ..user(Some(ours())) }), Plan::Remove { bind: true });
        assert_eq!(plan(&user(None)), Plan::Keep);
        let cdrom = State { first: vec!["mass_storage.0".into()], ..State::default() };
        assert_eq!(plan(&cdrom), Plan::Keep);
    }

    #[test]
    fn leaves_alone_what_it_does_not_own_or_cannot_judge() {
        assert_eq!(plan(&State { switching: true, ..debug(Some(vec![]), "") }), Plan::Keep);
        assert_eq!(plan(&State { others: true, ..debug(None, "a600000.dwc3") }), Plan::Keep);
        assert_eq!(plan(&State { ecm: false, ..debug(None, "a600000.dwc3") }), Plan::Keep);
        assert_eq!(plan(&State { first: vec![], ..debug(Some(vec![]), "") }), Plan::Keep);
        let foreign = vec![("f1".to_owned(), "gsi.ecm".to_owned())];
        assert_eq!(plan(&debug(Some(foreign), "a600000.dwc3")), Plan::Keep);
    }

    struct Fake(PathBuf);

    impl Fake {
        /// configfs as plain files: ZTE's debug composition, bound.
        fn new(name: &str) -> (Fake, Paths) {
            let root = std::env::temp_dir().join(format!("zte-agent-usb-net-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let gadget = root.join("g1");
            let first = gadget.join("configs/c.1");
            fs::create_dir_all(first.join("strings/0x409")).unwrap();
            fs::write(first.join("bmAttributes"), "0x80\n").unwrap();
            fs::write(first.join("MaxPower"), "900\n").unwrap();
            for (i, function) in DEBUG.iter().chain([&ECM]).enumerate() {
                let target = gadget.join("functions").join(function);
                fs::create_dir_all(&target).unwrap();
                if *function != ECM {
                    std::os::unix::fs::symlink(&target, first.join(format!("f{}", i + 1))).unwrap();
                }
            }
            fs::write(gadget.join("UDC"), "a600000.dwc3\n").unwrap();
            fs::create_dir_all(root.join("udc/a600000.dwc3")).unwrap();
            fs::write(root.join("mode"), "peripheral\n").unwrap();
            let paths = Paths { gadget, udcs: root.join("udc"), role: root.join("mode"), switching: root.join("in-progress") };
            (Fake(root), paths)
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reads_links_and_links_configuration_2_with_zte_attributes() {
        let (_fake, paths) = Fake::new("link");
        let state = paths.read().unwrap();
        assert_eq!(state.first.len(), DEBUG.len());
        assert!(state.ecm && state.second.is_none() && !state.host && !state.switching);
        assert_eq!(state.udc, "a600000.dwc3");
        assert_eq!(plan(&state), Plan::Link { bind: true });

        paths.apply(&state, &plan(&state)).unwrap();
        let after = paths.read().unwrap();
        assert_eq!(after.second, Some(ours()));
        assert_eq!(after.udc, "a600000.dwc3", "bound again");
        assert_eq!(plan(&after), Plan::Keep);
        let second = paths.configs().join(SECOND);
        assert_eq!(read_trimmed(&second.join("MaxPower")), "900");
        assert_eq!(read_trimmed(&second.join("bmAttributes")), "0x80");
        assert_eq!(read_trimmed(&second.join("strings/0x409/configuration")), LABEL);
    }

    #[test]
    fn a_failed_edit_binds_zte_composition_again() {
        let (_fake, paths) = Fake::new("fail");
        // A file where the configuration directory goes.
        fs::write(paths.configs().join(SECOND), "").unwrap();
        let error = paths.apply(&debug(None, "a600000.dwc3"), &Plan::Link { bind: true }).unwrap_err();
        assert!(error.starts_with("link configuration 2"), "{error}");
        assert_eq!(read_trimmed(&paths.gadget.join("UDC")), "a600000.dwc3");
    }

    #[test]
    fn an_unbound_gadget_is_bound_to_the_first_controller() {
        let (_fake, paths) = Fake::new("unbound");
        fs::write(paths.gadget.join("UDC"), "\n").unwrap();
        paths.link().unwrap();
        for (name, _) in LINKS {
            fs::remove_file(paths.configs().join(SECOND).join(name)).unwrap();
        }
        let state = paths.read().unwrap();
        assert_eq!(state.second, Some(vec![]));
        paths.apply(&state, &plan(&state)).unwrap();
        let after = paths.read().unwrap();
        assert_eq!((after.udc.as_str(), after.second), ("a600000.dwc3", Some(ours())));
    }
}
