# zte-agent power measurement scripts

Companion to [`docs/research/zte_agent_power_plan_2026-10-17.md`](../../docs/research/zte_agent_power_plan_2026-10-17.md). Read-only on the router; nothing here deploys.

| Script | Runs on | Purpose |
|---|---|---|
| `router-measure.sh <label> <secs>` | router (BusyBox ash) | Snapshots every agent thread (`/proc/<pid>/task/*/{stat,schedstat,sched,wchan}`), `/proc/stat` fork and context-switch counters and `:9090` sockets at t0 and t1, and records every fork made by an agent thread via ftrace (`sched_process_fork` filtered on `parent_comm == "zte-agent"`, plus `sched_process_exec` to name the child). Output in `/tmp/measure-<label>/`. |
| `fetch.sh <label>` | Mac | Copies `/tmp/measure-<label>` from the router and runs `analyze.py` on it. |
| `analyze.py <dir>` | Mac | Prints agent CPU, reaped-children CPU, per-thread wakeups/s, forks per command, and socket counts for one capture. |
| `bench-endpoints.sh /api/a /api/b ...` | Mac | For each endpoint: starts a router capture, sends `N` (default 20) requests at 1/s from the Mac with the agent token, then fetches and summarises. Reads the agent password from the router's start script into a shell variable only. |

Upload the router script with `ssh -p 2222 root@192.168.0.1 'cat > /tmp/measure.sh' < router-measure.sh` (the router has no sftp-server, so `scp` fails).

Typical session:

```sh
ssh -p 2222 root@192.168.0.1 'cat > /tmp/measure.sh' < scripts/power/router-measure.sh
ssh -p 2222 root@192.168.0.1 'sh /tmp/measure.sh idle 300'     # apps closed
scripts/power/fetch.sh idle
N=12 scripts/power/bench-endpoints.sh /api/network/signal /api/wifi/status /api/data-usage
```
