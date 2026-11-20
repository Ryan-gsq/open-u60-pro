//! Bounded device tool runs, no shell: every command has a deadline that
//! kills its whole process group, output is capped, and long-lived children
//! die with the agent.

use std::io::{Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{mpsc, OnceLock};
use std::time::{Duration, Instant};

pub fn run(command: Command, timeout: Duration) -> Result<String, String> {
    succeeded(run_with_input(command, timeout, None, true)?)
}

pub fn run_input(command: Command, timeout: Duration, input: Vec<u8>) -> Result<String, String> {
    succeeded(run_with_input(command, timeout, Some(input), true)?)
}

/// `run` for a tool whose exit code and standard error are the answer
/// (`conntrack -D` exits 1 both when nothing matched and when it failed, and
/// says which on standard error) and whose standard output is unbounded and
/// unneeded (it lists every entry it deletes): the code and the error text
/// (at most 256 KiB), or why the tool did not finish.
pub fn run_report(command: Command, timeout: Duration) -> Result<(i32, String), String> {
    let (status, report) = run_with_input(command, timeout, None, false)?;
    Ok((status.code().ok_or_else(|| format!("Device tool failed ({status})"))?, report))
}

fn succeeded((status, out): (ExitStatus, String)) -> Result<String, String> {
    if !status.success() {
        // Tool output may contain credentials or nearby SSIDs. Do not expose it.
        return Err(format!("Device tool failed ({status})"));
    }
    Ok(out)
}

fn run_with_input(
    mut command: Command,
    timeout: Duration,
    input: Option<Vec<u8>>,
    capture_stdout: bool,
) -> Result<(ExitStatus, String), String> {
    crate::httpd::gate::debug_assert_may_block();
    use std::os::unix::process::CommandExt;
    // Kill the command's whole process group, including descendants that
    // would otherwise keep its output pipes open beyond the deadline.
    command.process_group(0);
    command.stdout(if capture_stdout { Stdio::piped() } else { Stdio::null() }).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("Cannot run device tool: {e}"))?;
    let pid = child.id() as i32;
    let deadline = Instant::now() + timeout;
    let result = pump(&mut child, input.as_deref().unwrap_or_default(), deadline, capture_stdout);
    // A successful tool may leave descendants holding its pipes. Kill the
    // process group on every exit path, including a pipe setup/read error.
    unsafe { libc::kill(-pid, libc::SIGKILL); }
    let _ = child.wait();
    result
}

fn pump(child: &mut Child, mut input: &[u8], deadline: Instant, capture_stdout: bool) -> Result<(ExitStatus, String), String> {
    use std::os::fd::AsRawFd;
    let (mut stdin, mut stdout, mut stderr) = (child.stdin.take(), child.stdout.take(), child.stderr.take());
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input_failed = false;
    let mut exited = None;
    let pid = child.id() as i32;
    let descriptor = |fd, events| libc::pollfd { fd, events, revents: 0 };
    let io_error = |e: std::io::Error| format!("Device tool I/O failed: {e}");
    // pidfds wake poll on process exit even when a grandchild inherited a pipe.
    // Older kernels and the development Mac use a bounded waitpid fallback.
    #[cfg(target_os = "linux")]
    let process = {
        use std::os::fd::{FromRawFd, OwnedFd};
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
    };
    #[cfg(not(target_os = "linux"))]
    let process: Option<std::os::fd::OwnedFd> = None;
    for fd in [stdin.as_ref().map(AsRawFd::as_raw_fd), stdout.as_ref().map(AsRawFd::as_raw_fd), stderr.as_ref().map(AsRawFd::as_raw_fd)].into_iter().flatten() {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 { return Err(io_error(std::io::Error::last_os_error())); }
    }
    loop {
        if exited.is_none() {
            exited = child.try_wait().map_err(io_error)?;
            if exited.is_some() { unsafe { libc::kill(-pid, libc::SIGKILL); } }
        }
        if input.is_empty() || exited.is_some() { stdin.take(); }
        if let Some(status) = exited {
            if stdout.is_none() && stderr.is_none() {
                if status.success() && (input_failed || !input.is_empty()) { return Err("Device tool input failed".into()); }
                let bytes = if capture_stdout { out } else { err };
                return Ok((status, String::from_utf8_lossy(&bytes).trim().to_owned()));
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err("Device tool timed out".into()); }
        let mut fds = [descriptor(stdin.as_ref().map_or(-1, AsRawFd::as_raw_fd), libc::POLLOUT),
            descriptor(stdout.as_ref().map_or(-1, AsRawFd::as_raw_fd), libc::POLLIN),
            descriptor(stderr.as_ref().map_or(-1, AsRawFd::as_raw_fd), libc::POLLIN),
            descriptor(process.as_ref().filter(|_| exited.is_none()).map_or(-1, AsRawFd::as_raw_fd), libc::POLLIN)];
        let wait = if process.is_some() { left } else { left.min(Duration::from_millis(10)) };
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, wait.as_millis().clamp(1, i32::MAX as u128) as i32) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(io_error(error));
        }
        if let Some(pipe) = stdin.as_mut().filter(|_| fds[0].revents != 0) {
            match pipe.write(input) {
                Ok(n) if n > 0 => input = &input[n..],
                Err(e) if transient(&e) => (),
                _ => { stdin.take(); input_failed = true; }
            }
        }
        if fds[1].revents != 0 { read_pipe(&mut stdout, &mut out)?; }
        if fds[2].revents != 0 { read_pipe(&mut stderr, &mut err)?; }
    }
}

fn transient(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted)
}

fn read_pipe(pipe: &mut Option<impl Read>, bytes: &mut Vec<u8>) -> Result<(), String> {
    let mut buffer = [0; 8192];
    match pipe.as_mut().unwrap().read(&mut buffer) {
        Ok(0) => { pipe.take(); }
        Ok(n) if bytes.len() + n <= 256 * 1024 => bytes.extend_from_slice(&buffer[..n]),
        Ok(_) => return Err("Device tool output exceeded its limit".into()),
        Err(e) if transient(&e) => (),
        Err(e) => return Err(format!("Device tool output failed: {e}")),
    }
    Ok(())
}

/// The child cannot outlive the agent on Linux, unless its exec changes the
/// SELinux domain: the kernel then clears the parent-death signal (B31:
/// wpa_supplicant, odhcp6c), and its owner must stop such leftovers when it
/// recovers (`wifi_relay::stop_strays`). The supervisor additionally reaps
/// exits and rolls back its network rules while the agent is running.
pub fn owned_child(cmd: Command) -> Result<Child, String> {
    spawn_owned(cmd, Stdio::null())
}

/// `owned_child` with its standard output piped to the agent, for a monitor
/// read line by line.
pub fn owned_reader(cmd: Command) -> Result<Child, String> {
    spawn_owned(cmd, Stdio::piped())
}

fn spawn_owned(mut cmd: Command, stdout: Stdio) -> Result<Child, String> {
    cmd.stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::null());
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = unsafe { libc::getpid() };
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    // Linux's parent-death signal follows the spawning THREAD. A tokio
    // blocking worker may retire while the agent is still alive, so every
    // long-lived child must be spawned by this one persistent thread.
    type Spawn = (Command, mpsc::SyncSender<Result<Child, String>>);
    static SPAWNER: OnceLock<mpsc::Sender<Spawn>> = OnceLock::new();
    let sender = SPAWNER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Spawn>();
        std::thread::Builder::new()
            .name("net-children".into())
            .spawn(move || {
                while let Ok((mut cmd, reply)) = rx.recv() {
                    let result = cmd
                        .spawn()
                        .map_err(|e| format!("Cannot start network process: {e}"));
                    if let Err(mpsc::SendError(Ok(mut child))) = reply.send(result) {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
            })
            .expect("network child spawner");
        tx
    });
    let (tx, rx) = mpsc::sync_channel(1);
    sender
        .send((cmd, tx))
        .map_err(|_| "Network child spawner stopped")?;
    rx.recv().map_err(|_| "Network child spawner stopped")?
}

pub fn stop_child(child: &mut Option<Child>) {
    if let Some(mut c) = child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// A process's start time since boot (`/proc/<pid>/stat` field 22, clock
/// ticks): with the PID and the boot id it identifies one process, even after
/// the PID is reused.
pub fn process_start(pid: u32) -> Option<u64> {
    stat_start(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn stat_start(stat: &str) -> Option<u64> {
    // The command name in parentheses may hold spaces and parentheses.
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_time_is_read_past_a_command_name_with_spaces_and_parentheses() {
        let stat = "4242 (iw (event) x) S 1 4242 4242 0 -1 4194560 120 0 0 0 1 2 0 0 20 0 1 0 98765 1000 200 18446744073709551615";
        assert_eq!(stat_start(stat), Some(98765));
        assert_eq!(stat_start("4242 (short) S 1"), None);
    }

    #[test]
    fn commands_are_not_shell_interpreted() {
        let mut c = Command::new("printf");
        c.args(["%s", "$(touch /no-such-file); ' &"]);
        assert_eq!(
            run(c, Duration::from_secs(1)).unwrap(),
            "$(touch /no-such-file); ' &"
        );
    }

    #[test]
    fn piped_tool_input_is_bounded_by_the_same_process_deadline() {
        assert_eq!(
            run_input(
                Command::new("cat"),
                Duration::from_secs(1),
                b"test input".to_vec()
            )
            .unwrap(),
            "test input"
        );
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);
        let start = Instant::now();
        assert_eq!(
            run_input(command, Duration::from_millis(50), vec![0; 1024 * 1024]).unwrap_err(),
            "Device tool timed out"
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn short_lived_command_timeout_is_bounded() {
        let mut command = Command::new("sleep");
        command.arg("10");
        let before = Instant::now();
        assert!(run(command, Duration::from_millis(80)).is_err());
        assert!(before.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn an_exit_code_is_an_answer_not_a_failure() {
        let mut command = Command::new("sh");
        command.args(["-c", "head -c 400000 /dev/zero; echo 'none matched' >&2; exit 1"]);
        assert_eq!(run_report(command, Duration::from_secs(2)).unwrap(), (1, "none matched".to_owned()), "standard output beyond the capture limit is discarded");
        let mut command = Command::new("sh");
        command.args(["-c", "exit 1"]);
        assert!(run(command, Duration::from_secs(1)).is_err());
    }
}
