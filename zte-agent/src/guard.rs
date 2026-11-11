//! The agent's own restart guard (owner choice Q1,
//! `relay-mihomo-architecture.md` section 5.2): a separate process the
//! agent starts once, which outlives it. When the agent dies unexpectedly it
//! runs the boot launcher again, without anyone's hand, and the new agent
//! recovers its network by the owner's persistent choices (Mihomo adopts its
//! tables; DNS, routes, brnf and interception come back). Until then the
//! resident drop in Mihomo's `to_core` keeps traffic from going direct.
//!
//! It never makes a second network owner: the launcher holds its lock and
//! exits when an agent already runs (so an install that stopped the agent
//! wins), and an OTA trial (the `pending` marker) belongs to the update
//! helper, which starts the candidate or the previous slot itself. An
//! operator who stops the agent on purpose creates `STOPPED` first. If the
//! agent cannot come back after three attempts, it rolls the network
//! changes back (`network-recover`, direct like D3) and keeps trying, more
//! slowly.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The boot launcher `setup.sh` installs (`scripts/install-agent.py`).
pub const LAUNCHER: &str = "/data/local/tmp/start_zte_agent.sh";
/// Created by an operator before stopping the agent on purpose.
pub const STOPPED: &str = "/tmp/zte-agent-run/stopped";
/// The launcher records the main's process id here.
const PID: &str = "/tmp/zte-agent-run/pid";
const LOG: &str = "/tmp/zte-agent.log";
/// Waits before each start attempt; the last repeats.
const WAITS: [u64; 5] = [0, 5, 15, 60, 300];
/// Attempts before the network changes are rolled back.
const FAIL_OPEN_AFTER: usize = 3;

/// What the guard sees and does (tests stand in for the device).
pub trait Ops {
    /// Whether the agent process (id and start time) still runs.
    fn alive(&mut self, pid: u32, start: u64) -> bool;
    /// An OTA trial or an operator's stop: not ours to restart.
    fn handed_off(&mut self) -> Option<&'static str>;
    /// Runs the launcher; then whether a main agent runs.
    fn start(&mut self) -> bool;
    /// Rolls the network changes back (direct).
    fn fail_open(&mut self);
    fn sleep(&mut self, wait: Duration);
    fn log(&mut self, line: &str);
}

/// Watches agent `pid` (started at `start`) and restarts it once it dies.
pub fn watch(pid: u32, start: u64, ops: &mut impl Ops) {
    while ops.alive(pid, start) {
        ops.sleep(Duration::from_millis(500));
    }
    if let Some(why) = ops.handed_off() {
        return ops.log(&format!("[guard] agent {pid} ended; {why}: not restarting it"));
    }
    ops.log(&format!("[guard] agent {pid} ended unexpectedly; starting it again"));
    let mut opened = false;
    for attempt in 0.. {
        ops.sleep(Duration::from_secs(WAITS[attempt.min(WAITS.len() - 1)]));
        if let Some(why) = ops.handed_off() {
            return ops.log(&format!("[guard] {why}: stopping"));
        }
        if ops.start() {
            // The new agent starts a guard of its own.
            return ops.log(&format!("[guard] the agent runs again after {} attempt(s)", attempt + 1));
        }
        if attempt + 1 == FAIL_OPEN_AFTER && !opened {
            opened = true;
            ops.log("[guard] the agent does not come back; rolling its network changes back until it does");
            ops.fail_open();
        }
    }
}

/// Starts the guard for this agent, detached so it outlives it. Only for the
/// launcher's main agent (`LAUNCHER` exists), never under tests.
pub fn spawn() {
    if cfg!(test) || std::env::var("ZTE_AGENT_GUARD").as_deref() == Ok("0") || !Path::new(&launcher()).is_file() {
        return;
    }
    // A main agent that starts ends an operator's stop: guard it again.
    if std::fs::remove_file(STOPPED).is_ok() {
        eprintln!("[guard] the stop marker was cleared: this agent is guarded");
    }
    let pid = std::process::id();
    let Some(start) = crate::netfx::exec::process_start(pid) else { return };
    let Ok(exe) = std::env::current_exe() else { return };
    let mut command = Command::new(exe);
    command.args(["guard", &pid.to_string(), &start.to_string()]).stdin(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Its own session: no terminal or group signal of the agent reaches it.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    match command.spawn() {
        Ok(child) => eprintln!("[guard] started (pid {})", child.id()),
        Err(e) => eprintln!("[guard] could not start: {e}"),
    }
}

fn launcher() -> String {
    std::env::var("ZTE_AGENT_LAUNCHER").unwrap_or_else(|_| LAUNCHER.into())
}

/// Runs the boot launcher in a session of its own and waits for it to
/// return: whether it succeeded. Not `netfx::exec::run`, which kills a
/// tool's whole process group once it exits: the launcher leaves the agent
/// it started in its group, and that kill took every restarted agent down
/// with it (seen on B31, 2026-11-10). On a timeout only the launcher dies.
fn run_launcher(launcher: &str, timeout: Duration) -> bool {
    let mut command = Command::new("sh");
    command.arg(launcher).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let Ok(mut child) = command.spawn() else { return false };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// `zte-agent guard <pid> <start>`.
pub fn cli(args: &[String]) -> i32 {
    let (Some(pid), Some(start)) = (args.first().and_then(|a| a.parse().ok()), args.get(1).and_then(|a| a.parse().ok())) else { return 2 };
    watch(pid, start, &mut Device);
    0
}

struct Device;

impl Ops for Device {
    fn alive(&mut self, pid: u32, start: u64) -> bool {
        crate::netfx::exec::process_start(pid) == Some(start)
    }

    fn handed_off(&mut self) -> Option<&'static str> {
        if crate::ota::storage::Paths::system().pending.exists() {
            return Some("an update trial owns the handoff");
        }
        Path::new(STOPPED).exists().then_some("it was stopped on purpose")
    }

    fn start(&mut self) -> bool {
        // Keep the ended agent's log for diagnosis; the launcher starts a new one.
        let _ = std::fs::rename(LOG, PathBuf::from(LOG).with_extension("previous.log"));
        if !run_launcher(&launcher(), Duration::from_secs(60)) {
            return false;
        }
        // The launcher returns once the main has exec'd; it must stay up.
        std::thread::sleep(Duration::from_secs(5));
        std::fs::read_to_string(PID).ok().and_then(|p| p.trim().parse::<u32>().ok()).is_some_and(|pid| crate::netfx::exec::process_start(pid).is_some())
    }

    fn fail_open(&mut self) {
        let Ok(exe) = std::env::current_exe() else { return };
        let mut command = Command::new(exe);
        command.arg("network-recover");
        if let Err(e) = crate::netfx::exec::run(command, Duration::from_secs(120)) {
            eprintln!("[guard] network rollback failed: {e}");
        }
    }

    fn sleep(&mut self, wait: Duration) {
        std::thread::sleep(wait);
    }

    fn log(&mut self, line: &str) {
        crate::netlog!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        alive_for: usize,
        handed_off: Option<&'static str>,
        /// Results of the start attempts in order (then success).
        starts: Vec<bool>,
        attempts: usize,
        opened: usize,
        slept: Vec<Duration>,
        lines: Vec<String>,
    }

    impl Ops for Fake {
        fn alive(&mut self, _: u32, _: u64) -> bool {
            if self.alive_for == 0 {
                return false;
            }
            self.alive_for -= 1;
            true
        }
        fn handed_off(&mut self) -> Option<&'static str> {
            self.handed_off
        }
        fn start(&mut self) -> bool {
            self.attempts += 1;
            if self.starts.is_empty() { true } else { self.starts.remove(0) }
        }
        fn fail_open(&mut self) {
            self.opened += 1;
        }
        fn sleep(&mut self, wait: Duration) {
            self.slept.push(wait);
        }
        fn log(&mut self, line: &str) {
            self.lines.push(line.into());
        }
    }

    #[test]
    fn a_dead_agent_is_started_again_once_it_has_gone() {
        let mut fake = Fake { alive_for: 3, ..Fake::default() };
        watch(42, 7, &mut fake);
        assert_eq!((fake.attempts, fake.opened), (1, 0));
        assert_eq!(fake.slept[..3], [Duration::from_millis(500); 3], "polls while it runs");
        assert!(fake.lines.last().unwrap().contains("runs again"));
    }

    /// The agent a launcher leaves running in the background outlives the
    /// launcher's return (B31: a group kill after the launcher exited took
    /// every restarted agent down); a launcher that hangs is given up.
    #[test]
    fn what_the_launcher_starts_outlives_it_and_a_hung_launcher_is_given_up() {
        let dir = std::env::temp_dir().join(format!("u60-guard-launcher-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("start.sh");
        let pid = dir.join("pid");
        std::fs::write(&script, format!("sleep 30 </dev/null >/dev/null 2>&1 &\necho $! > {}\n", pid.display())).unwrap();
        assert!(run_launcher(script.to_str().unwrap(), Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(300));
        let started: i32 = std::fs::read_to_string(&pid).unwrap().trim().parse().unwrap();
        assert_eq!(unsafe { libc::kill(started, 0) }, 0, "the started process still runs");
        unsafe { libc::kill(started, libc::SIGKILL) };
        std::fs::write(&script, "sleep 5\n").unwrap();
        let begun = Instant::now();
        assert!(!run_launcher(script.to_str().unwrap(), Duration::from_millis(300)));
        assert!(begun.elapsed() < Duration::from_secs(3), "a hung launcher is given up at its deadline");
        std::fs::write(&script, "exit 1\n").unwrap();
        assert!(!run_launcher(script.to_str().unwrap(), Duration::from_secs(5)), "a failed launcher is a failed start");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_update_trial_or_an_operator_stop_is_left_alone() {
        for why in ["an update trial owns the handoff", "it was stopped on purpose"] {
            let mut fake = Fake { handed_off: Some(why), ..Fake::default() };
            watch(42, 7, &mut fake);
            assert_eq!(fake.attempts, 0, "{why}");
        }
    }

    #[test]
    fn an_agent_that_does_not_come_back_fails_open_once_and_keeps_being_tried() {
        let mut fake = Fake { starts: vec![false; 6], ..Fake::default() };
        watch(42, 7, &mut fake);
        assert_eq!((fake.attempts, fake.opened), (7, 1));
        let waits: Vec<u64> = fake.slept.iter().map(Duration::as_secs).collect();
        assert_eq!(waits, [0, 5, 15, 60, 300, 300, 300], "slower and slower, never giving up");
    }
}
