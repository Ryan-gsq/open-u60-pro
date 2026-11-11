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
    let writer = input.map(|bytes| {
        let mut stdin = child.stdin.take().unwrap();
        std::thread::spawn(move || stdin.write_all(&bytes))
    });
    // Drain both pipes while waiting; a verbose tool must not deadlock on a full pipe.
    let read = |pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let r = pipe.take(256 * 1024 + 1).read_to_end(&mut bytes);
            (r, bytes)
        })
    };
    let stdout = child.stdout.take().map(|pipe| read(Box::new(pipe)));
    let stderr = child.stderr.take().map(|pipe| read(Box::new(pipe)));
    let deadline = Instant::now() + timeout;
    // These tools usually finish within a few milliseconds; a fixed 20 ms
    // poll made every one of the hundreds of firewall/route commands wait
    // for it. Back off from 1 ms so long-running tools still poll cheaply.
    let mut pause = Duration::from_millis(1);
    let result = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(20));
            }
            _ => {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                break Err("Device tool timed out".to_owned());
            }
        }
    };
    // A tool can exit successfully while leaving a background child holding
    // stdout/stderr. These tools are synchronous; no descendants are owned.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let collect = |reader: Option<std::thread::JoinHandle<(std::io::Result<usize>, Vec<u8>)>>| {
        reader.map_or(Ok(Vec::new()), |r| r.join().map(|(_, bytes)| bytes).map_err(|_| "Device tool reader failed"))
    };
    let out = collect(stdout)?;
    let err = collect(stderr)?;
    let written = writer.map(|writer| {
        writer
            .join()
            .map_err(|_| "Device tool input failed")
            .and_then(|r| r.map_err(|_| "Device tool input failed"))
    });
    let status = result?;
    if out.len() > 256 * 1024 || err.len() > 256 * 1024 {
        return Err("Device tool output exceeded its limit".into());
    }
    if status.success() {
        if let Some(written) = written {
            written?;
        }
    }
    let answer = if capture_stdout { out } else { err };
    Ok((status, String::from_utf8_lossy(&answer).trim().to_owned()))
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
