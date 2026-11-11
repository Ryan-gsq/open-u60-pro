//! A line monitor (`ip -4 monitor neigh`, `iw event`) for the hardware path's
//! lifetime: restarted if it exits, stopped when dropped. Both tools run in
//! their own SELinux domain on B31 (`ip.subj`, `iw.subj`), so an agent killed
//! meanwhile leaves the child running until its next write. Its identity
//! (process id, start time and boot, `Record`) is recorded so
//! `wifi_relay::stop_strays` ends that one, never an `iw event` someone runs
//! by hand nor a process that reused the id.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::net;

const RESTART: Duration = Duration::from_secs(5);

/// One monitor process, as its record names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub pid: u32,
    pub start: u64,
}

impl Record {
    fn text(self, boot: &str) -> String {
        format!("{} {} {boot}", self.pid, self.start)
    }

    /// A record written in this boot (`boot`); any other is meaningless.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn parse(text: &str, boot: &str) -> Option<Self> {
        let mut words = text.split_whitespace();
        let record = Self { pid: words.next()?.parse().ok()?, start: words.next()?.parse().ok()? };
        (words.next() == Some(boot) && !boot.is_empty() && words.next().is_none()).then_some(record)
    }
}

pub(super) struct Monitor {
    shared: Arc<Shared>,
}

/// For work after a delay: whether the monitor still runs.
#[derive(Clone)]
pub(super) struct Alive(Arc<Shared>);

impl Alive {
    /// Waits `delay`; false when the monitor stopped meanwhile.
    pub(super) fn wait(&self, delay: Duration) -> bool {
        let state = self.0.lock();
        let (state, _) = self.0.stopped.wait_timeout_while(state, delay, |s| !s.stopped).unwrap_or_else(PoisonError::into_inner);
        !state.stopped
    }
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    stopped: Condvar,
    /// Where the running child's process id is recorded.
    pid_file: Option<PathBuf>,
}

#[derive(Default)]
struct State {
    stopped: bool,
    child: Option<Child>,
}

impl Monitor {
    /// Runs `program args` on thread `name`. `handle` gets `None` each time
    /// the command starts (the monitor reports changes only: read the current
    /// state then), then every output line. `what` names it in the log.
    pub(super) fn start(name: &str, what: &'static str, program: &'static str, args: &[&str], pid_file: Option<PathBuf>, mut handle: impl FnMut(Option<&str>, &Alive) + Send + 'static) -> Self {
        let shared = Arc::new(Shared { pid_file, ..Shared::default() });
        let alive = Alive(Arc::clone(&shared));
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        crate::system::spawn_named(name, move || loop {
            match alive.0.spawn(program, &args) {
                Ok(None) => return,
                Ok(Some(output)) => {
                    handle(None, &alive);
                    for line in BufReader::new(output).lines() {
                        let Ok(line) = line else { break };
                        handle(Some(&line), &alive);
                    }
                    let child = alive.0.lock().child.take();
                    if let Some(mut child) = child {
                        let _ = child.kill();
                        let _ = child.wait();
                        alive.0.forget(child.id());
                    }
                }
                Err(e) => crate::netlog!("[relay] {what} did not start: {e}"),
            }
            if !alive.wait(RESTART) {
                return;
            }
            crate::netlog!("[relay] {what} ended; restarting it");
        });
        Self { shared }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.stopped = true;
        if let Some(child) = state.child.as_mut() {
            // Ends the reader's loop; the reader reaps it.
            let _ = child.kill();
        }
        self.shared.stopped.notify_all();
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The command's output, or `None` when the monitor has already stopped.
    fn spawn(&self, program: &str, args: &[String]) -> Result<Option<ChildStdout>, String> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        let mut child = net::owned_reader(cmd)?;
        let output = child.stdout.take();
        let mut state = self.lock();
        if state.stopped || output.is_none() {
            let _ = child.kill();
            let _ = child.wait();
            return if state.stopped { Ok(None) } else { Err("no output pipe".into()) };
        }
        if let Some(path) = &self.pid_file {
            // An unreadable start time (0) matches no process: never stopped.
            let record = Record { pid: child.id(), start: crate::netfx::exec::process_start(child.id()).unwrap_or(0) };
            if let Err(e) = net::write_private(path, record.text(&crate::net_tools::boot_id()).as_bytes()) {
                crate::netlog!("[relay] cannot record a monitor's process: {e}");
            }
        }
        state.child = Some(child);
        Ok(output)
    }

    /// Removes the record of `pid` once it exited (a restart wrote another).
    fn forget(&self, pid: u32) {
        if let Some(path) = &self.pid_file {
            if std::fs::read_to_string(path).is_ok_and(|text| text.split_whitespace().next() == Some(pid.to_string().as_str())) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn lines_follow_a_start_and_dropping_stops_delayed_work() {
        let (tx, rx) = mpsc::channel();
        // Records are private files: never in the shared temporary directory itself.
        let dir = std::env::temp_dir().join(format!("u60-monitor-{}", std::process::id()));
        let pid_file = dir.join("monitor.pid");
        let monitor = Monitor::start("monitor-test", "test monitor", "sh", &["-c", "echo one; echo two; exec sleep 30"], Some(pid_file.clone()), move |line, alive| {
            tx.send((line.map(str::to_owned), alive.clone())).unwrap();
        });
        let wait = Duration::from_secs(5);
        assert_eq!(rx.recv_timeout(wait).unwrap().0, None, "started");
        assert_eq!(rx.recv_timeout(wait).unwrap().0.as_deref(), Some("one"));
        let (line, alive) = rx.recv_timeout(wait).unwrap();
        assert_eq!(line.as_deref(), Some("two"));
        assert!(alive.wait(Duration::from_millis(1)), "still running");
        let text = std::fs::read_to_string(&pid_file).unwrap();
        #[cfg(target_os = "linux")]
        let pid = Record::parse(&text, &crate::net_tools::boot_id()).expect("pid, start time and boot").pid;
        #[cfg(not(target_os = "linux"))]
        let pid: u32 = text.split_whitespace().next().unwrap().parse().unwrap();
        drop(monitor);
        assert!(!alive.wait(Duration::from_secs(5)), "a delayed task sees the stop at once");
        for _ in 0..50 {
            if !pid_file.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!pid_file.exists(), "the record of process {pid} goes with it");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_record_names_one_process_of_this_boot() {
        let record = Record { pid: 4242, start: 98765 };
        assert_eq!(Record::parse(&record.text("boot-a"), "boot-a"), Some(record));
        assert_eq!(Record::parse(&record.text("boot-a"), "boot-b"), None, "another boot's process ids are meaningless");
        assert_eq!(Record::parse("4242", "boot-a"), None, "a bare id from an older agent identifies no process");
        assert_eq!(Record::parse(&record.text(""), ""), None);
    }
}
