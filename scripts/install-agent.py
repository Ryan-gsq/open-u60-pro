"""Render private install/boot scripts and edit only our rc.local entry."""

import os
import re
import shlex
import sys
from pathlib import Path


STARTUP = "/data/local/tmp/start_zte_agent.sh"
BOOT_LINE = f"sh {STARTUP}"
LEGACY = "/data/zte-agent"
OTA_ROOT = "/data/open-u60/update"
SUPERVISOR = "/data/local/tmp/zte-agent-supervisor.sh"

OTA_ENVIRONMENT = f"""export ZTE_OTA_ROOT={OTA_ROOT}
export ZTE_OTA_SUPERVISOR={SUPERVISOR}
export ZTE_OTA_LEGACY_LINK={LEGACY}
"""

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
    # The boot supervisor execs the active slot (or the retained last Stable
    # rescue copy), so a running main's executable is that file, not the
    # /data/zte-agent link. Pre-OTA installs still run /data/zte-agent itself.
    slots = (
        f"|{OTA_ROOT}/slot-[ab]/zte-agent|{OTA_ROOT}/slot-[ab]/zte-agent' (deleted)'"
        f"|{OTA_ROOT}/last-stable/zte-agent|{OTA_ROOT}/last-stable/zte-agent' (deleted)'"
    )
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
        /data/zte-agent|'/data/zte-agent (deleted)'__SLOTS____TEMPORARY__) ;;
        *) return 1 ;;
    esac
    # Both old and new launchers run the service without CLI arguments.
    # Helpers use this same executable; do not mistake them for the service.
    argc=$(tr -cd '\000' 2>/dev/null <"$1/cmdline" | wc -c)
    [ "$argc" -eq 1 ] || return 1
    # Map embedded newlines away before splitting NUL records. Exclude relay
    # callbacks and live OTA trial processes; never print the environment.
    environment=$(tr '\n\000' '\001\n' 2>/dev/null <"$1/environ") || return 1
    if printf '%s\n' "$environment" | grep -Eq '^(U60_RELAY_DHCP6?|ZTE_OTA_TRIAL)=1$'; then
        unset environment
        return 1
    fi
    unset environment
    # Reject exit/reuse during inspection, including a replaced executable.
    [ "$(readlink "$1/exe" 2>/dev/null)" = "$exe" ] || return 1
    [ "$(process_start "$1")" = "$start" ]
}
is_trial() {
    start=$(process_start "$1") || return 1
    [ -n "$start" ] || return 1
    environment=$(tr '\n\000' '\001\n' 2>/dev/null <"$1/environ") || return 1
    if ! printf '%s\n' "$environment" | grep -Eq '^ZTE_OTA_TRIAL=1$'; then
        unset environment
        return 1
    fi
    unset environment
    exe=$(readlink "$1/exe" 2>/dev/null) || return 1
    case "$exe" in
        /data/zte-agent|'/data/zte-agent (deleted)'__SLOTS__) ;;
        *) return 1 ;;
    esac
    [ "$(readlink "$1/exe" 2>/dev/null)" = "$exe" ] || return 1
    [ "$(process_start "$1")" = "$start" ]
}
is_supervisor() {
    start=$(process_start "$1") || return 1
    [ -n "$start" ] || return 1
    [ "$#" -lt 2 ] || [ "$start" = "$2" ] || return 1
    tr '\n\000' '\001\n' 2>/dev/null <"$1/cmdline" | grep -Fxq /data/local/tmp/zte-agent-supervisor.sh || return 1
    [ "$(process_start "$1")" = "$start" ]
}
is_ota_helper() {
    start=$(process_start "$1") || return 1
    [ -n "$start" ] || return 1
    [ "$(tr '\n\000' '\001\n' 2>/dev/null <"$1/cmdline" | sed -n '2p')" = ota-helper ] || return 1
    exe=$(readlink "$1/exe" 2>/dev/null) || return 1
    case "$exe" in
        /data/zte-agent|'/data/zte-agent (deleted)'__SLOTS__) ;;
        *) return 1 ;;
    esac
    [ "$(process_start "$1")" = "$start" ]
}
""".replace("__SLOTS__", slots).replace("__TEMPORARY__", temporary)


def shared_supervisor_helpers():
    """Extract the exact shared OTA helper functions from zte-agent-supervisor.sh
    so installer validation, quarantine checks, digest verification, and marker
    parsing can never drift from the boot supervisor."""
    src = (Path(__file__).resolve().parent / "router" / "zte-agent-supervisor.sh").read_text()
    blocks = []
    pos = 0
    begin = "# BEGIN SHARED OTA HELPERS\n"
    end = "# END SHARED OTA HELPERS\n"
    while True:
        start = src.find(begin, pos)
        if start < 0:
            break
        finish = src.find(end, start + len(begin))
        if finish < 0:
            raise ValueError("Unclosed SHARED OTA HELPERS block in zte-agent-supervisor.sh")
        blocks.append(src[start + len(begin):finish])
        pos = finish + len(end)
    if not blocks:
        raise ValueError("Missing SHARED OTA HELPERS blocks in zte-agent-supervisor.sh")
    return "".join(blocks)


START_LOCK = """mkdir -p /tmp/zte-agent-run
chmod 700 /tmp/zte-agent-run
exec 9>/tmp/zte-agent-run/start.lock
flock -x 9
"""


def launcher(password=None):
    auth = "unset ZTE_AGENT_PASSWORD" if password is None else (
        "export ZTE_AGENT_PASSWORD=" + shlex.quote(password)
    )
    return SHELL_HEADER + auth + "\nexport ZTE_AGENT_BIND=0.0.0.0:9090\n" + OTA_ENVIRONMENT + process_identity() + START_LOCK + r"""# First check any tracked supervisor from a previous launcher that hit its
# polling deadline: `(pid, starttime)` is invariant across `exec`, so we never
# miss the shell-to-main transition and publish the verified main PID once ready.
if [ -f /tmp/zte-agent-run/starting ]; then
    st_pid=$(sed -n '1p' /tmp/zte-agent-run/starting 2>/dev/null || true)
    st_start=$(sed -n '2p' /tmp/zte-agent-run/starting 2>/dev/null || true)
    case "$st_pid:$st_start" in
        [0-9]*:[0-9]*)
            if is_main "/proc/$st_pid" "$st_start"; then
                echo "$st_pid" >/tmp/zte-agent-run/pid
                rm -f /tmp/zte-agent-run/starting
                exit 0
            fi
            if [ "$(process_start "/proc/$st_pid")" = "$st_start" ]; then
                exit 1
            fi
            ;;
    esac
    rm -f /tmp/zte-agent-run/starting
fi
# Do not trust a stale pid file, nor compare against the new binary's inode:
# a still-running main may predate an update and have a deleted executable.
# Re-check `is_main` with the same `starttime` after `is_supervisor` so an
# `exec` transition during inspection can never slip through both checks.
for process in /proc/[0-9]*; do
    p_start=$(process_start "$process") || continue
    if is_main "$process" "$p_start"; then
        exit 0
    fi
    if is_supervisor "$process" "$p_start"; then
        exit 1
    fi
    if is_main "$process" "$p_start"; then
        exit 0
    fi
done
# Inherited callback selectors must not turn our new service into a helper.
unset U60_RELAY_DHCP U60_RELAY_DHCP6
# The supervisor picks the verified A/B slot and execs it, keeping this PID.
# If a pending rollback attempt exits early before reaching `is_main`, retry
# once under the lock so cold boot advances to verified Stable rescue without
# requiring external intervention.
launch_try=0
while [ "$launch_try" -lt 2 ]; do
    launch_try=$((launch_try + 1))
    nohup /data/local/tmp/zte-agent-supervisor.sh </dev/null >/tmp/zte-agent.log 2>&1 9>&- &
    pid=$!
    started=$(process_start /proc/$pid)
    if [ -n "$started" ]; then
        printf '%s\n%s\n' "$pid" "$started" >/tmp/zte-agent-run/starting
    fi
    # Keep the lock until this same child has exec'd into the main service. The
    # supervisor hashes and probes the slot first, so allow it 10 s. Only retry
    # if this recorded process is positively observed to have exited (never on
    # poll exhaustion while the first supervisor is still running).
    count=0
    exec_ok=0
    exited=0
    if [ -n "$started" ]; then
        while [ "$count" -lt 100 ]; do
            if is_main /proc/$pid "$started"; then
                exec_ok=1
                break
            fi
            if [ "$(process_start /proc/$pid)" != "$started" ] || ! kill -0 "$pid" 2>/dev/null; then
                exited=1
                break
            fi
            count=$((count + 1))
            sleep 0.1
        done
    else
        kill -0 "$pid" 2>/dev/null || exited=1
    fi
    if [ "$exec_ok" = 1 ]; then
        rm -f /tmp/zte-agent-run/starting
        echo "$pid" >/tmp/zte-agent-run/pid
        exit 0
    fi
    if [ "$exited" = 1 ]; then
        rm -f /tmp/zte-agent-run/starting
    fi
    if [ "$launch_try" -eq 1 ] && [ "$exited" = 1 ] && [ -f /data/open-u60/update/rollback-attempt ]; then
        continue
    fi
    exit 1
done
exit 1
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
agent_sha=${3:-}
agent_version=${4:-}
""" + START_LOCK + r"""[ "$(sha256sum /etc/rc.local | awk '{print $1}')" = "$expected_rc" ]
[ -s "$stage/agent.new" ]
[ -s "$stage/supervisor.new" ]
sh -n "$stage/start.sh"
sh -n "$stage/supervisor.new"
# Everything the supervisor will trust is checked before anything is stopped.
case "$agent_sha" in *[!0-9a-f]*) exit 1 ;; esac
[ "${#agent_sha}" -eq 64 ]
case "$agent_version" in ''|*[!0-9A-Za-z.+-]*) exit 1 ;; esac
[ "$(sha256sum "$stage/agent.new" | awk '{print $1}')" = "$agent_sha" ]
OTA_ROOT=/data/open-u60/update
ACTIVE="$OTA_ROOT/active"
PENDING="$OTA_ROOT/pending"
LAST_STABLE="$OTA_ROOT/last-stable/zte-agent"
LAST_STABLE_META="$OTA_ROOT/last-stable/release.json"
BLOCKED="$OTA_ROOT/blocked.json"
ROLLBACK_BLOCKED="$OTA_ROOT/rollback-blocked"
ROLLBACK_ATTEMPT="$OTA_ROOT/rollback-attempt"
RECOVER_PENDING="$OTA_ROOT/network-recover-pending"
TS_JOURNAL=/data/tailscale/network.json
TS_FLUSH_MARKER=/data/tailscale/clean-dns-dnat-flush-pending
RELAY_CELLULAR_PAUSE=/data/zte-agent-relay/cellular-pause
PERF_JOURNAL=/tmp/zte-agent-perf/network.json
BOOT_ID_PATH=/proc/sys/kernel/random/boot_id
PROC_ROOT=/proc/
PROC_ROOT=${PROC_ROOT%/}
""" + shared_supervisor_helpers() + r"""# Refuse to overwrite working slots with a quarantined version (or unreadable,
# malformed, or dangling `blocked.json`) BEFORE stopping the running main.
if ! blocked_allows_version "$agent_version"; then
    printf '%s\n' 'Target version is quarantined or blocked.json is invalid; installation stopped.' >&2
    exit 1
fi
# Refuse to race a live OTA helper, trial child, or boot supervisor BEFORE
# stopping the main.
for process in /proc/[0-9]*; do
    if is_ota_helper "$process" || is_trial "$process" || is_supervisor "$process"; then
        printf '%s\n' 'An OTA handoff, trial, or boot supervisor is active; installation stopped.' >&2
        exit 1
    fi
done
# A retry is a no-op only when every binary (with executable bits), script,
# exact 2-record bootstrap digest in both slots, `active=a`, absence of stale
# release/handoff markers, and the live main inode all match.
bootstrap_matches() {
    parse_bootstrap_identity "$1" || return 1
    [ "$pbi_sha" = "$agent_sha" ] && [ "$pbi_ver" = "$agent_version" ]
}
if cmp -s "$stage/agent.new" /data/zte-agent && \
        cmp -s "$stage/agent.new" "$OTA_ROOT/slot-a/zte-agent" && \
        cmp -s "$stage/agent.new" "$OTA_ROOT/slot-b/zte-agent" && \
        [ -x "$OTA_ROOT/slot-a/zte-agent" ] && \
        [ -x "$OTA_ROOT/slot-b/zte-agent" ] && \
        cmp -s "$stage/supervisor.new" /data/local/tmp/zte-agent-supervisor.sh && \
        cmp -s "$stage/start.sh" /data/local/tmp/start_zte_agent.sh && \
        [ -f "$ACTIVE" ] && ! has_nul_byte "$ACTIVE" && \
        [ "$(awk 'END { print NR }' "$ACTIVE" 2>/dev/null || echo 0)" -eq 1 ] && \
        [ "$(sed -n '1p' "$ACTIVE" 2>/dev/null || true)" = a ] && \
        bootstrap_matches "$OTA_ROOT/slot-a/bootstrap.sha256" && \
        bootstrap_matches "$OTA_ROOT/slot-b/bootstrap.sha256" && \
        [ ! -e "$OTA_ROOT/slot-a/release.json" ] && [ ! -L "$OTA_ROOT/slot-a/release.json" ] && \
        [ ! -e "$OTA_ROOT/slot-b/release.json" ] && [ ! -L "$OTA_ROOT/slot-b/release.json" ] && \
        [ ! -e "$PENDING" ] && [ ! -L "$PENDING" ] && \
        [ ! -e "$RECOVER_PENDING" ] && [ ! -L "$RECOVER_PENDING" ] && \
        [ ! -e "$ROLLBACK_ATTEMPT" ] && [ ! -L "$ROLLBACK_ATTEMPT" ] && \
        [ ! -e "$ROLLBACK_BLOCKED" ] && [ ! -L "$ROLLBACK_BLOCKED" ]; then
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
cp "$stage/supervisor.new" "$stage/supervisor.ready"
cp "$stage/start.sh" "$stage/start.ready"
chmod 700 "$stage/agent.ready" "$stage/supervisor.ready" "$stage/start.ready"
for process in /proc/[0-9]*; do
    if is_ota_helper "$process" || is_trial "$process" || is_supervisor "$process"; then
        printf '%s\n' 'An OTA handoff, trial, or boot supervisor became active; installation stopped.' >&2
        exit 1
    fi
done
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
# Never turn PID reuse, a concurrent OTA helper/trial, or a live supervisor
# into a successful install while another owner is active.
for process in /proc/[0-9]*; do
    if is_main "$process" || is_ota_helper "$process" || is_trial "$process" || is_supervisor "$process"; then
        printf '%s\n' 'A main service, OTA helper, trial, or supervisor is still running; installation stopped.' >&2
        exit 1
    fi
done
# Resolve any outstanding network, policy-rule, or cellular recovery using the
# supervisor's exact marker parsers, digest verifiers, rescue ownership rules,
# and durable `network-recover-pending` persistence BEFORE overwriting slots or
# retiring handoff/attempt markers.
tailscaled_alive() {
    if [ "$PROC_ROOT" = "/proc" ] && [ ! -r "$PROC_ROOT/self/stat" ]; then
        return 0
    fi
    for tsp in /proc/[0-9]*; do
        [ -e "$tsp" ] || continue
        if [ -r "$tsp/stat" ]; then
            ts_line=$(cat "$tsp/stat" 2>/dev/null || true)
            if [ -z "$ts_line" ]; then
                [ -e "$tsp/stat" ] && return 0
                continue
            fi
            case "${ts_line##*) }" in Z*|X*) continue ;; esac
            case "$ts_line" in *" (tailscaled) "*) return 0 ;; esac
        elif [ -e "$tsp/stat" ]; then
            return 0
        else
            continue
        fi
        if [ -r "$tsp/comm" ]; then
            if [ "$(tr -d '\r\n' <"$tsp/comm" 2>/dev/null || true)" = tailscaled ]; then
                return 0
            fi
        elif [ -e "$tsp/comm" ]; then
            return 0
        fi
        if [ -r "$tsp/cmdline" ]; then
            ts_arg0=$(tr '\000' '\n' <"$tsp/cmdline" 2>/dev/null | sed -n '1p')
            case "${ts_arg0##*/}" in
                tailscaled) return 0 ;;
            esac
        elif [ -e "$tsp/cmdline" ]; then
            return 0
        fi
    done
    return 1
}
network_artifacts_present() {
    tailscale_same_boot_journal_present \
        || tailscale_same_boot_flush_pending \
        || tailscaled_alive \
        || tailscale_policy_rules_present \
        || relay_cellular_pause_present \
        || perf_same_boot_journal_present
}
persist_install_recover_owner() {
    piro_owner=$1
    mkdir -p "$OTA_ROOT"
    chmod 700 "$OTA_ROOT"
    if [ "$piro_owner" = staged ]; then
        [ ! -d "$RECOVER_PENDING" ] || return 1
        piro_boot=$(read_valid_boot_token "$BOOT_ID_PATH") || return 1
        {
            printf '%s\n%s\n' "$piro_boot" staged >"$RECOVER_PENDING.tmp" \
                && chmod 600 "$RECOVER_PENDING.tmp"
        } 2>/dev/null || { rm -f "$RECOVER_PENDING.tmp" 2>/dev/null || true; return 1; }
        sync_path "$RECOVER_PENDING.tmp" || { rm -f "$RECOVER_PENDING.tmp" 2>/dev/null || true; return 1; }
        mv -f "$RECOVER_PENDING.tmp" "$RECOVER_PENDING" 2>/dev/null || { rm -f "$RECOVER_PENDING.tmp" 2>/dev/null || true; return 1; }
        sync_ota_root || return 1
        return 0
    fi
    persist_recover_pending "$piro_owner"
}
cleaner_ready() {
    case "$1" in
        a|b) verified_slot_integrity "$1" ;;
        stable) runnable_stable ;;
        staged) [ -f "$stage/agent.ready" ] && [ -x "$stage/agent.ready" ] ;;
        *) return 1 ;;
    esac
}
run_verified_cleaner() {
    case "$1" in
        a|b)
            verified_slot_integrity "$1" || return 1
            ZTE_TEST_MARKER= "$(slot_binary "$1")" network-recover >/dev/null 2>&1
            ;;
        stable)
            runnable_stable || return 1
            ZTE_TEST_MARKER= "$LAST_STABLE" network-recover >/dev/null 2>&1
            ;;
        staged)
            [ -f "$stage/agent.ready" ] && [ -x "$stage/agent.ready" ] || return 1
            ZTE_TEST_MARKER= "$stage/agent.ready" network-recover >/dev/null 2>&1
            ;;
        *) return 1 ;;
    esac
}
pending_cand=""
pending_prev=""
if [ -e "$PENDING" ] || [ -L "$PENDING" ]; then
    if [ ! -f "$PENDING" ] || [ ! -r "$PENDING" ] || has_nul_byte "$PENDING"; then
        printf '%s\n' 'Unreadable pending marker; original slots preserved and installation stopped.' >&2
        exit 1
    fi
    pending_cand=$(sed -n '1p' "$PENDING" 2>/dev/null || true)
    pending_prev=$(sed -n '2p' "$PENDING" 2>/dev/null || true)
    if ! valid_slot "$pending_cand" || ! valid_slot "$pending_prev" || [ "$pending_cand" = "$pending_prev" ]; then
        printf '%s\n' 'Malformed pending marker (must name two distinct valid slots); original slots preserved and installation stopped.' >&2
        exit 1
    fi
fi
active_slot=""
if [ -f "$ACTIVE" ] && [ -r "$ACTIVE" ] && ! has_nul_byte "$ACTIVE"; then
    active_slot=$(sed -n '1p' "$ACTIVE" 2>/dev/null || true)
fi
if same_boot_recover_pending; then
    rp_target=""
    if [ "$rp_owner" = unknown ] && [ -f "$RECOVER_PENDING" ] && [ -r "$RECOVER_PENDING" ] && ! has_nul_byte "$RECOVER_PENDING"; then
        rp_cur_boot=$(read_valid_boot_token "$BOOT_ID_PATH" 2>/dev/null || true)
        if [ -n "$rp_cur_boot" ] \
            && [ "$(awk 'END { print NR }' "$RECOVER_PENDING" 2>/dev/null || echo 0)" -eq 2 ] \
            && [ "$(sed -n '1p' "$RECOVER_PENDING" 2>/dev/null | tr -d ' \t\r')" = "$rp_cur_boot" ] \
            && [ "$(sed -n '2p' "$RECOVER_PENDING" 2>/dev/null | tr -d ' \t\r')" = staged ]; then
            rp_owner=staged
        fi
    fi
    case "$rp_owner" in
        candidate) if valid_slot "$pending_cand"; then rp_target=$pending_cand; fi ;;
        legacy)
            if valid_slot "$pending_cand"; then rp_target=$pending_cand
            elif valid_slot "$active_slot"; then rp_target=$active_slot
            elif [ "$active_slot" = rescue ]; then rp_target=stable
            fi ;;
        previous) if valid_slot "$pending_prev"; then rp_target=$pending_prev; fi ;;
        stable) rp_target=stable ;;
        staged) rp_target=staged ;;
        a|b) rp_target=$rp_owner ;;
    esac
    if [ -z "$rp_target" ] || ! run_verified_cleaner "$rp_target"; then
        printf '%s\n' 'Pending network recovery failed; original slots preserved and installation stopped.' >&2
        exit 1
    fi
fi
if same_boot_rollback_blocked; then
    if ! valid_slot "$pending_prev" || ! cleaner_ready "$pending_prev"; then
        printf '%s\n' 'Same-boot or malformed rollback-blocked recovery failed; original slots preserved and installation stopped.' >&2
        exit 1
    fi
    if ! persist_install_recover_owner previous || ! run_verified_cleaner "$pending_prev"; then
        printf '%s\n' 'Same-boot or malformed rollback-blocked recovery failed; original slots preserved and installation stopped.' >&2
        exit 1
    fi
fi
if network_artifacts_present; then
    rescue_owned=0
    if [ "$active_slot" = rescue ] && { ! valid_slot "$pending_prev" || ! verified_runnable_slot "$pending_prev"; }; then
        rescue_owned=1
    fi
    cleaner_list=""
    if [ "$rescue_owned" = 1 ]; then
        cleaner_list="stable staged"
    else
        if valid_slot "$pending_cand"; then
            cleaner_list="$cleaner_list $pending_cand"
        fi
        if valid_slot "$active_slot" && [ "$active_slot" != "$pending_cand" ]; then
            cleaner_list="$cleaner_list $active_slot"
        fi
        cleaner_list="$cleaner_list stable staged"
    fi
    extra_ok=0
    for cleaner in $cleaner_list; do
        if ! cleaner_ready "$cleaner"; then
            continue
        fi
        owner_tag=$cleaner
        if [ "$cleaner" = "$pending_cand" ]; then
            owner_tag=candidate
        fi
        if ! persist_install_recover_owner "$owner_tag"; then
            printf '%s\n' 'Could not persist recovery-pending marker; original slots preserved and installation stopped.' >&2
            exit 1
        fi
        if run_verified_cleaner "$cleaner"; then
            if ! network_artifacts_present; then
                extra_ok=1
                break
            fi
        fi
    done
    if [ "$extra_ok" != 1 ] || network_artifacts_present; then
        printf '%s\n' 'Outstanding network, policy-rule, or cellular recovery failed; original slots preserved and installation stopped.' >&2
        exit 1
    fi
fi
# Bootstrap the A/B layout like the OTA design expects: two verified copies
# with a recorded digest each, slot A active, no stale signed metadata or
# trial/recovery/attempt markers. Nothing runs from here on, so the order only
# matters for a power cut: the boot launcher is replaced last, after the
# supervisor and the /data/zte-agent link it relies on exist.
mkdir -p "$OTA_ROOT/slot-a" "$OTA_ROOT/slot-b" "$OTA_ROOT/last-stable"
chmod 700 "$OTA_ROOT" "$OTA_ROOT/slot-a" "$OTA_ROOT/slot-b" "$OTA_ROOT/last-stable"
for slot in a b; do
    cp "$stage/agent.ready" "$OTA_ROOT/slot-$slot/zte-agent.new"
    chmod 700 "$OTA_ROOT/slot-$slot/zte-agent.new"
    rm -f "$OTA_ROOT/slot-$slot/release.json" "$OTA_ROOT/slot-$slot/release.json.download"
    printf '%s\n%s\n' "$agent_sha" "$agent_version" >"$OTA_ROOT/slot-$slot/bootstrap.sha256"
    chmod 600 "$OTA_ROOT/slot-$slot/bootstrap.sha256"
    mv -f "$OTA_ROOT/slot-$slot/zte-agent.new" "$OTA_ROOT/slot-$slot/zte-agent"
done
rm -f "$PENDING" "$OTA_ROOT/state.json" \
    "$RECOVER_PENDING" "$RECOVER_PENDING.tmp" \
    "$ROLLBACK_ATTEMPT" "$ROLLBACK_ATTEMPT.tmp" \
    "$ROLLBACK_BLOCKED"
printf 'a\n' >"$ACTIVE.new"
chmod 600 "$ACTIVE.new"
mv -f "$ACTIVE.new" "$ACTIVE"
mv "$stage/supervisor.ready" /data/local/tmp/zte-agent-supervisor.sh
ln -sfn "$OTA_ROOT/slot-a/zte-agent" /data/zte-agent.next
mv -f /data/zte-agent.next /data/zte-agent
rm -f "$stage/agent.ready"
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
