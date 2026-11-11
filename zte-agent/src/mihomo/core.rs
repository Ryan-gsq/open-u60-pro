//! The core's process (`relay-mihomo-architecture.md` section 3): one
//! generation per process and exactly one reaper. The reaper waits for the
//! exit without reaping (`waitid` with `WNOWAIT`), then reaps under the same
//! lock a stop takes before it signals: a signal can only reach this process,
//! never one that reused its id. It reports `CoreExited { generation }` once;
//! the controller ignores a generation it no longer runs.

use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::Duration;

struct Reaped {
    done: Mutex<bool>,
    wake: Condvar,
}

pub(super) struct Core {
    pub generation: u64,
    pid: libc::pid_t,
    reaped: Arc<Reaped>,
}

impl Core {
    /// Starts `command` as an owned child (it dies with the agent) and its
    /// reaper, which calls `exited(generation, how)` once it has reaped it.
    pub fn spawn(command: Command, generation: u64, exited: impl FnOnce(u64, String) + Send + 'static) -> Result<Self, String> {
        let child = crate::net_tools::owned_child(command)?;
        Ok(Self::watch(child.id() as libc::pid_t, generation, exited))
    }

    /// The reaper for a child of this process.
    fn watch(pid: libc::pid_t, generation: u64, exited: impl FnOnce(u64, String) + Send + 'static) -> Self {
        let reaped = Arc::new(Reaped { done: Mutex::new(false), wake: Condvar::new() });
        let watcher = Arc::clone(&reaped);
        crate::system::spawn_named("mihomo-core-wait", move || {
            loop {
                // SAFETY: waitid on our own child; `info` is plain data.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
                if r == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            let mut done = watcher.done.lock().unwrap_or_else(PoisonError::into_inner);
            let mut status = 0;
            // SAFETY: reaps the child that just exited; nothing else waits for it.
            let reaped = unsafe { libc::waitpid(pid, &mut status, 0) };
            *done = true;
            watcher.wake.notify_all();
            drop(done);
            exited(generation, if reaped == pid { describe(status) } else { "exit status unknown".into() });
        });
        Self { generation, pid, reaped }
    }

    pub fn pid(&self) -> u32 {
        self.pid as u32
    }

    #[cfg(test)]
    pub fn alive(&self) -> bool {
        !*self.reaped.done.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn signal(&self, signal: libc::c_int) {
        let done = self.reaped.done.lock().unwrap_or_else(PoisonError::into_inner);
        if !*done {
            // SAFETY: the process is not reaped while `done` is held.
            unsafe { libc::kill(self.pid, signal) };
        }
    }

    /// Waits up to `wait` for the reaper; true once reaped.
    fn wait(&self, wait: Duration) -> bool {
        let done = self.reaped.done.lock().unwrap_or_else(PoisonError::into_inner);
        let (done, _) = self.reaped.wake.wait_timeout_while(done, wait, |done| !*done).unwrap_or_else(PoisonError::into_inner);
        *done
    }

    /// Stops it: TERM, then KILL after `grace`. True once it is reaped.
    pub fn stop(&self, grace: Duration) -> bool {
        self.signal(libc::SIGTERM);
        if self.wait(grace) {
            return true;
        }
        self.signal(libc::SIGKILL);
        self.wait(Duration::from_secs(3))
    }
}

fn describe(status: libc::c_int) -> String {
    if libc::WIFEXITED(status) {
        format!("exit code {}", libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        format!("signal {}", libc::WTERMSIG(status))
    } else {
        format!("status {status}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn sleeper(seconds: &str) -> Command {
        let mut command = Command::new("sleep");
        command.arg(seconds);
        command
    }

    #[test]
    fn one_reaper_reports_the_generation_once_and_a_stop_never_signals_after_it() {
        let (tx, rx) = mpsc::channel();
        let core = Core::spawn(sleeper("30"), 7, move |generation, how| tx.send((generation, how)).unwrap()).unwrap();
        assert!(core.alive());
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "still running");
        assert!(core.stop(Duration::from_secs(2)));
        let (generation, how) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!((generation, how.as_str()), (7, "signal 15"));
        assert!(!core.alive());
        core.signal(libc::SIGKILL);
        assert!(core.stop(Duration::from_millis(10)), "reaped: no signal, no wait");
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "reported once");
    }

    #[test]
    fn an_exit_on_its_own_is_reported_with_its_code() {
        let (tx, rx) = mpsc::channel();
        let mut command = Command::new("sh");
        command.args(["-c", "exit 3"]);
        let core = Core::spawn(command, 2, move |generation, how| tx.send((generation, how)).unwrap()).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap(), (2, "exit code 3".to_owned()));
        assert!(!core.alive());
    }
}
