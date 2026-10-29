"""Render private install/boot scripts and edit only our rc.local entry."""

import os
import re
import shlex
import sys
from pathlib import Path


STARTUP = "/data/local/tmp/start_zte_agent.sh"
BOOT_LINE = f"sh {STARTUP}"

SHELL_HEADER = """#!/bin/sh
# Managed by open-u60-pro setup.sh.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
ulimit -c 0
"""

def process_identity(include_temporary=False):
    temporary = "|/tmp/u60-panel/agent|'/tmp/u60-panel/agent (deleted)'" if include_temporary else ""
    return r"""# /proc stat field 22 is stable across exec, unlike a PID alone. Strip the
# parenthesized comm first (it can contain spaces and closing parentheses).
process_start() {
    awk '{ sub(/^.*\) /, ""); if ($1 !~ /^[ZX]$/ && $20 ~ /^[0-9]+$/) print $20 }' \
        "$1/stat" 2>/dev/null
}
is_main() {
    start=$(process_start "$1") || return 1
    [ -n "$start" ] || return 1
    [ "$#" -lt 2 ] || [ "$start" = "$2" ] || return 1
    exe=$(readlink "$1/exe" 2>/dev/null) || return 1
    case "$exe" in
        /data/zte-agent|'/data/zte-agent (deleted)'__TEMPORARY__) ;;
        *) return 1 ;;
    esac
    # Both old and new launchers run the service without CLI arguments.
    # Helpers use this same executable; do not mistake them for the service.
    argc=$(tr -cd '\000' 2>/dev/null <"$1/cmdline" | wc -c)
    [ "$argc" -eq 1 ] || return 1
    # Map embedded newlines away before splitting NUL records. Only these
    # exact environment entries select callbacks; never print the environment.
    environment=$(tr '\n\000' '\001\n' 2>/dev/null <"$1/environ") || return 1
    if printf '%s\n' "$environment" | grep -Eq '^U60_RELAY_DHCP6?=1$'; then
        unset environment
        return 1
    fi
    unset environment
    # Reject exit/reuse during inspection, including a replaced executable.
    [ "$(readlink "$1/exe" 2>/dev/null)" = "$exe" ] || return 1
    [ "$(process_start "$1")" = "$start" ]
}
""".replace("__TEMPORARY__", temporary)


START_LOCK = """mkdir -p /tmp/zte-agent-run
chmod 700 /tmp/zte-agent-run
exec 9>/tmp/zte-agent-run/start.lock
flock -x 9
"""


def launcher(password=None):
    auth = "unset ZTE_AGENT_PASSWORD" if password is None else (
        "export ZTE_AGENT_PASSWORD=" + shlex.quote(password)
    )
    return SHELL_HEADER + auth + "\nexport ZTE_AGENT_BIND=0.0.0.0:9090\n" + process_identity() + START_LOCK + r"""# Do not trust a stale pid file, nor compare against the new binary's inode:
# a still-running main may predate an update and have a deleted executable.
for process in /proc/[0-9]*; do
    if is_main "$process"; then
        exit 0
    fi
done
# Inherited callback selectors must not turn our new service into a helper.
unset U60_RELAY_DHCP U60_RELAY_DHCP6
nohup /data/zte-agent </dev/null >/tmp/zte-agent.log 2>&1 9>&- &
pid=$!
started=$(process_start /proc/$pid)
[ -n "$started" ] || exit 1
# Keep the lock until this same child has exec'd into the main service.
count=0
until is_main /proc/$pid "$started"; do
    [ "$(process_start /proc/$pid)" = "$started" ] || exit 1
    kill -0 "$pid" 2>/dev/null || exit 1
    count=$((count + 1))
    [ "$count" -lt 50 ] || exit 1
    sleep 0.1
done
echo "$pid" >/tmp/zte-agent-run/pid
"""


def installer():
    return SHELL_HEADER + process_identity(include_temporary=True) + r"""is_listener() {
    start=$(process_start "$1") || return 1
    [ -n "$start" ] && [ "$start" = "$2" ] || return 1
    [ "$(awk '/^PPid:/ {print $2}' "$1/status" 2>/dev/null)" = "$3" ] || return 1
    [ "$(readlink "$1/exe" 2>/dev/null)" = /bin/ubus ] || return 1
    [ "$(tr '\n\000' '\001\n' 2>/dev/null <"$1/cmdline" | sed -n '2p')" = listen ] || return 1
    [ "$(awk '/^PPid:/ {print $2}' "$1/status" 2>/dev/null)" = "$3" ] || return 1
    [ "$(readlink "$1/exe" 2>/dev/null)" = /bin/ubus ] || return 1
    [ "$(process_start "$1")" = "$start" ]
}
# Check the complete identity immediately before TERM, then wait only for
# this starttime. No escalation and no signal to a replacement PID. POSIX
# shell cannot make the final /proc check + kill atomic (there is no pidfd).
stop_verified() {
    if ! "$3" "$1" "$2" "${4:-}"; then
        [ "$(process_start "$1")" != "$2" ] && return 0
        printf '%s\n' 'Process identity changed; installation stopped.' >&2
        return 1
    fi
    # ESRCH is normal if it exits after inspection; a live unkillable process
    # must time out below, not abort before checking or count as stopped.
    kill -TERM "${1##*/}" 2>/dev/null || true
    count=0
    while [ "$(process_start "$1")" = "$2" ]; do
        count=$((count + 1))
        if [ "$count" -ge 50 ]; then
            printf '%s\n' 'Process did not stop; installation stopped.' >&2
            return 1
        fi
        sleep 0.1
    done
}
stage=$1
expected_rc=$2
""" + START_LOCK + r"""[ "$(sha256sum /etc/rc.local | awk '{print $1}')" = "$expected_rc" ]
[ -s "$stage/agent.new" ]
sh -n "$stage/start.sh"
# Keep the original rollback inputs even if this same stage is retried after
# a partial install. The marker also records an originally absent launcher.
if [ ! -f "$stage/backups.ready" ]; then
    if [ -f /data/zte-agent ]; then
        cp -p /data/zte-agent "$stage/agent.before"
        chmod 600 "$stage/agent.before"
    fi
    if [ -f /data/local/tmp/start_zte_agent.sh ]; then
        cp -p /data/local/tmp/start_zte_agent.sh "$stage/start.before.sh"
        chmod 600 "$stage/start.before.sh"
    fi
    : >"$stage/backups.ready"
fi
# A retry is a no-op only when both artifacts match and the recorded live
# main is executing this inode, not a deleted older binary or a callback.
if cmp -s "$stage/agent.new" /data/zte-agent && \
        cmp -s "$stage/start.sh" /data/local/tmp/start_zte_agent.sh; then
    installed_pid=$(cat /tmp/zte-agent-run/pid 2>/dev/null || true)
    case "$installed_pid" in
        ''|*[!0-9]*) ;;
        *) if is_main /proc/$installed_pid && [ /proc/$installed_pid/exe -ef /data/zte-agent ]; then
               exit 0
           fi ;;
    esac
fi
# Prepare both replacements before stopping anything. Keep upload payloads
# until host verification succeeds so the same stage can be retried safely.
cp "$stage/agent.new" "$stage/agent.ready"
cp "$stage/start.sh" "$stage/start.ready"
chmod 700 "$stage/agent.ready" "$stage/start.ready"
for process in /proc/[0-9]*; do
    main_start=$(process_start "$process") || continue
    is_main "$process" "$main_start" || continue
    main_pid=${process##*/}
    # Only capture listeners while both child and parent identities are
    # verified. A reparented listener is safe to clean up only with this
    # same starttime, never by its PID/executable alone.
    listeners=""
    for child in /proc/[0-9]*; do
        child_start=$(process_start "$child") || continue
        is_listener "$child" "$child_start" "$main_pid" || continue
        is_main "$process" "$main_start" || continue
        listeners="$listeners ${child##*/}:$child_start"
    done
    stop_verified "$process" "$main_start" is_main
    for listener in $listeners; do
        child_pid=${listener%%:*}
        child_start=${listener#*:}
        is_listener /proc/$child_pid "$child_start" 1 || continue
        stop_verified /proc/$child_pid "$child_start" is_listener 1
    done
done
# Never turn PID reuse or an out-of-band restart into a successful install
# while a replacement main still serves the old binary.
for process in /proc/[0-9]*; do
    if is_main "$process"; then
        printf '%s\n' 'A main service is still running; installation stopped.' >&2
        exit 1
    fi
done
mv "$stage/agent.ready" /data/zte-agent
mv "$stage/start.ready" /data/local/tmp/start_zte_agent.sh
flock -u 9
exec 9>&-
sh /data/local/tmp/start_zte_agent.sh
"""


def boot_config(text):
    """Keep all unrelated commands verbatim; add one executable hook."""
    lines = text.splitlines(keepends=True)
    lines = [line for line in lines if line.strip() != BOOT_LINE]
    if any(STARTUP in line and not line.lstrip().startswith("#") for line in lines):
        raise ValueError("Unrecognized existing agent boot command; review rc.local manually")
    position = next(
        (i for i, line in enumerate(lines) if re.fullmatch(r"\s*exit\s+0\s*", line)),
        len(lines),
    )
    before = "".join(lines[:position])
    if before and not before.endswith("\n"):
        before += "\n"
    return before + BOOT_LINE + "\n" + "".join(lines[position:])


def write_private(path, content):
    with open(path, "w", encoding="utf-8") as file:
        os.chmod(path, 0o600)
        file.write(content)


if __name__ == "__main__":
    mode, destination, *args = sys.argv[1:]
    if mode == "launcher":
        override = args == ["override"]
        password = sys.stdin.read() if override else None
        if override and not password:
            raise SystemExit("Empty agent password")
        write_private(destination, launcher(password))
    elif mode == "install":
        write_private(destination, installer())
    elif mode == "boot":
        write_private(destination, boot_config(Path(args[0]).read_text()))
    else:
        raise SystemExit("Unknown installation artifact")
