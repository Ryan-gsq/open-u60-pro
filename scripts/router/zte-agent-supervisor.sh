#!/bin/sh
# Minimal boot supervisor for OpenU60 A/B agent updates. Keep this POSIX and
# independent from the agent so a bad candidate can never replace recovery.
set -u

OTA_ROOT="${ZTE_OTA_ROOT:-/data/open-u60/update}"
ACTIVE="$OTA_ROOT/active"
PENDING="$OTA_ROOT/pending"
LEGACY="${ZTE_OTA_LEGACY_LINK:-/data/zte-agent}"
LAST_STABLE="$OTA_ROOT/last-stable/zte-agent"
LAST_STABLE_META="$OTA_ROOT/last-stable/release.json"
BLOCKED="$OTA_ROOT/blocked.json"
ROLLBACK_BLOCKED="$OTA_ROOT/rollback-blocked"
ROLLBACK_ATTEMPT="$OTA_ROOT/rollback-attempt"
RECOVER_PENDING="$OTA_ROOT/network-recover-pending"
TS_JOURNAL="${ZTE_TAILSCALE_JOURNAL:-/data/tailscale/network.json}"
TS_FLUSH_MARKER="${TS_JOURNAL%/*}/clean-dns-dnat-flush-pending"
RELAY_CELLULAR_PAUSE="${ZTE_RELAY_CELLULAR_PAUSE:-/data/zte-agent-relay/cellular-pause}"
PERF_JOURNAL="${ZTE_PERF_JOURNAL:-/tmp/zte-agent-perf/network.json}"
BOOT_ID_PATH="${ZTE_BOOT_ID_PATH:-/proc/sys/kernel/random/boot_id}"
PROC_ROOT="${ZTE_PROC_ROOT:-/proc}"
SUPERVISOR_SELF="$0"

# BEGIN SHARED OTA HELPERS
# Return 0 if the file contains a NUL byte or cannot be read (fail-closed).
has_nul_byte() {
    [ "$(wc -c < "$1" 2>/dev/null | tr -d '[:space:]')" != "$(LC_ALL=C tr -d '\000' < "$1" 2>/dev/null | wc -c | tr -d '[:space:]')" ]
}
# END SHARED OTA HELPERS

# Return 0 (fail-closed: tailscaled running or process table unreadable/empty)
# unless PROC_ROOT is a usable, populated procfs and no live non-zombie
# tailscaled process is present.
tailscaled_process_running() {
    [ -d "$PROC_ROOT" ] && [ -r "$PROC_ROOT" ] || return 0
    if [ "$PROC_ROOT" = "/proc" ] && [ ! -r "$PROC_ROOT/self/stat" ]; then
        return 0
    fi
    saw_pid=0
    for pid_dir in "$PROC_ROOT"/[0-9]*; do
        [ -e "$pid_dir" ] || continue
        pid=${pid_dir##*/}
        case "$pid" in
            *[!0-9]*|"") continue ;;
        esac
        [ -e "$pid_dir" ] || continue
        if [ -r "$pid_dir/stat" ]; then
            stat_line=$(cat "$pid_dir/stat" 2>/dev/null || true)
            if [ -z "$stat_line" ]; then
                [ -e "$pid_dir/stat" ] && return 0
                continue
            fi
            saw_pid=1
            case "${stat_line##*) }" in
                Z*) continue ;;
            esac
            case "$stat_line" in
                *" (tailscaled) "*) return 0 ;;
            esac
        elif [ -e "$pid_dir/stat" ]; then
            return 0
        else
            continue
        fi
        if [ -r "$pid_dir/comm" ]; then
            comm=$(tr -d '\r\n' < "$pid_dir/comm" 2>/dev/null || true)
            [ "$comm" = "tailscaled" ] && return 0
        elif [ -e "$pid_dir/comm" ]; then
            return 0
        else
            continue
        fi
        if [ -r "$pid_dir/cmdline" ]; then
            arg0=$(tr '\000' '\n' < "$pid_dir/cmdline" 2>/dev/null | sed -n '1p')
            case "${arg0##*/}" in
                tailscaled) return 0 ;;
            esac
        elif [ -e "$pid_dir/cmdline" ]; then
            return 0
        fi
    done
    [ "$saw_pid" = 1 ] || return 0
    return 1
}

# BEGIN SHARED OTA HELPERS
# Read a single strict boot-ID token from file $1 matching Rust's
# `valid_boot_token`: NUL-free readable regular file, trimmed only of leading
# and trailing `[ \t\r\n]`, non-empty, printable non-space ASCII (0x21..0x7E).
read_valid_boot_token() {
    [ -f "$1" ] && [ -r "$1" ] || return 1
    has_nul_byte "$1" && return 1
    LC_ALL=C awk '
        { s = (NR == 1 ? $0 : s "\n" $0) }
        END {
            gsub(/^[ \t\r\n]+|[ \t\r\n]+$/, "", s)
            if (s == "" || s ~ /[^!-~]/) exit 1
            printf "%s", s
        }
    ' "$1" 2>/dev/null
}

# Return 0 (fail-closed: same-boot pending) unless marker $1 is absent OR
# both $1 and $BOOT_ID_PATH carry valid single boot-ID tokens that differ.
same_boot_marker_pending() {
    [ -e "$1" ] || [ -L "$1" ] || return 1
    smp_boot_id=$(read_valid_boot_token "$BOOT_ID_PATH") || return 0
    smp_marker_boot=$(read_valid_boot_token "$1") || return 0
    [ "$smp_marker_boot" != "$smp_boot_id" ] && return 1
    return 0
}

persist_recover_pending() {
    prp_owner=${1:-candidate}
    case "$prp_owner" in
        candidate|previous|stable|a|b) ;;
        *) return 1 ;;
    esac
    [ ! -d "$RECOVER_PENDING" ] || return 1
    prp_boot_id=$(read_valid_boot_token "$BOOT_ID_PATH") || return 1
    {
        printf '%s\n%s\n' "$prp_boot_id" "$prp_owner" > "$RECOVER_PENDING.tmp" \
            && chmod 600 "$RECOVER_PENDING.tmp"
    } 2>/dev/null || {
        rm -f "$RECOVER_PENDING.tmp" 2>/dev/null || true
        return 1
    }
    sync_path "$RECOVER_PENDING.tmp" || {
        rm -f "$RECOVER_PENDING.tmp" 2>/dev/null || true
        return 1
    }
    mv -f "$RECOVER_PENDING.tmp" "$RECOVER_PENDING" 2>/dev/null || {
        rm -f "$RECOVER_PENDING.tmp" 2>/dev/null || true
        return 1
    }
    sync_ota_root || return 1
    same_boot_recover_pending && [ "$rp_owner" = "$prp_owner" ]
}

clear_recover_pending() {
    rm -f "$RECOVER_PENDING.tmp" 2>/dev/null || true
    remove_handoff_marker "$RECOVER_PENDING"
}

# Return 0 (fail-closed: same-boot active) unless JSON journal $1 is absent OR
# is a complete, syntactically valid RFC 8259 JSON object carrying exactly one
# unescaped, printable-ASCII top-level `"boot"` string value strictly different
# from the current boot ID. Any JSON escape in the `"boot"` key or value,
# nested-only or duplicate `"boot"` key, truncation, trailing bytes, invalid
# UTF-8, NUL, or unreadable file fails closed.
same_boot_json_journal_present() {
    [ -e "$1" ] || [ -L "$1" ] || return 1
    [ -f "$1" ] && [ -r "$1" ] || return 0
    has_nul_byte "$1" && return 0
    sbj_boot_id=$(read_valid_boot_token "$BOOT_ID_PATH") || return 0
    sbj_journal_boot=$(LC_ALL=C awk '
        BEGIN {
            for (b = 1; b < 256; b++) ord[sprintf("%c", b)] = b
            hex["0"]=0; hex["1"]=1; hex["2"]=2; hex["3"]=3; hex["4"]=4
            hex["5"]=5; hex["6"]=6; hex["7"]=7; hex["8"]=8; hex["9"]=9
            hex["a"]=10; hex["b"]=11; hex["c"]=12; hex["d"]=13; hex["e"]=14; hex["f"]=15
            hex["A"]=10; hex["B"]=11; hex["C"]=12; hex["D"]=13; hex["E"]=14; hex["F"]=15
        }
        function is_ws(c) { return c == " " || c == "\t" || c == "\r" || c == "\n" }
        function skip_ws() {
            while (i <= len && is_ws(substr(s, i, 1))) i++
        }
        function hex4(pos,    d0, d1, d2, d3) {
            if (pos + 3 > len) return -1
            d0 = substr(s, pos, 1); d1 = substr(s, pos + 1, 1)
            d2 = substr(s, pos + 2, 1); d3 = substr(s, pos + 3, 1)
            if (!(d0 in hex) || !(d1 in hex) || !(d2 in hex) || !(d3 in hex)) return -1
            return hex[d0] * 4096 + hex[d1] * 256 + hex[d2] * 16 + hex[d3]
        }
        function utf8_encode(cp) {
            if (cp == 0) return ""
            if (cp < 128) return sprintf("%c", cp)
            if (cp < 2048) return sprintf("%c%c", 192 + int(cp / 64), 128 + (cp % 64))
            if (cp < 65536) return sprintf("%c%c%c", 224 + int(cp / 4096), 128 + (int(cp / 64) % 64), 128 + (cp % 64))
            return sprintf("%c%c%c%c", 240 + int(cp / 262144), 128 + (int(cp / 4096) % 64), 128 + (int(cp / 64) % 64), 128 + (cp % 64))
        }
        function parse_str(    c, o, b1, b2, b3, cp, lo, out, has_nul, esc) {
            if (i > len || substr(s, i, 1) != "\"") return 0
            i++
            out = ""
            has_nul = 0
            esc = 0
            while (i <= len) {
                c = substr(s, i, 1)
                if (c == "\"") {
                    decoded = out
                    decoded_has_nul = has_nul
                    str_had_escape = esc
                    i++
                    return 1
                }
                if (c == "\\") {
                    esc = 1
                    i++
                    if (i > len) return 0
                    c = substr(s, i, 1)
                    if (c == "\"" || c == "\\" || c == "/") { out = out c; i++ }
                    else if (c == "b") { out = out sprintf("%c", 8); i++ }
                    else if (c == "f") { out = out sprintf("%c", 12); i++ }
                    else if (c == "n") { out = out "\n"; i++ }
                    else if (c == "r") { out = out "\r"; i++ }
                    else if (c == "t") { out = out "\t"; i++ }
                    else if (c == "u") {
                        cp = hex4(i + 1)
                        if (cp < 0) return 0
                        i += 5
                        if (cp >= 55296 && cp <= 56319) {
                            if (i + 5 > len || substr(s, i, 2) != "\\u") return 0
                            lo = hex4(i + 2)
                            if (lo < 56320 || lo > 57343) return 0
                            i += 6
                            cp = 65536 + (cp - 55296) * 1024 + (lo - 56320)
                        } else if (cp >= 56320 && cp <= 57343) {
                            return 0
                        }
                        if (cp == 0) { has_nul = 1 } else { out = out utf8_encode(cp) }
                    } else return 0
                } else {
                    o = ord[c]
                    if (o < 32) return 0
                    if (o < 128) {
                        out = out c
                        i++
                    } else if (o >= 194 && o <= 223) {
                        if (i + 1 > len) return 0
                        b1 = ord[substr(s, i + 1, 1)]
                        if (b1 < 128 || b1 > 191) return 0
                        out = out substr(s, i, 2)
                        i += 2
                    } else if (o >= 224 && o <= 239) {
                        if (i + 2 > len) return 0
                        b1 = ord[substr(s, i + 1, 1)]
                        b2 = ord[substr(s, i + 2, 1)]
                        if (b2 < 128 || b2 > 191) return 0
                        if (o == 224 && (b1 < 160 || b1 > 191)) return 0
                        if (o == 237 && (b1 < 128 || b1 > 159)) return 0
                        if (o != 224 && o != 237 && (b1 < 128 || b1 > 191)) return 0
                        out = out substr(s, i, 3)
                        i += 3
                    } else if (o >= 240 && o <= 244) {
                        if (i + 3 > len) return 0
                        b1 = ord[substr(s, i + 1, 1)]
                        b2 = ord[substr(s, i + 2, 1)]
                        b3 = ord[substr(s, i + 3, 1)]
                        if (b2 < 128 || b2 > 191 || b3 < 128 || b3 > 191) return 0
                        if (o == 240 && (b1 < 144 || b1 > 191)) return 0
                        if (o == 244 && (b1 < 128 || b1 > 143)) return 0
                        if (o != 240 && o != 244 && (b1 < 128 || b1 > 191)) return 0
                        out = out substr(s, i, 4)
                        i += 4
                    } else {
                        return 0
                    }
                }
            }
            return 0
        }
        function is_digit(c,    o) {
            o = ord[c]
            return o >= 48 && o <= 57
        }
        function parse_number(    c, o) {
            if (i > len) return 0
            if (substr(s, i, 1) == "-") {
                i++
                if (i > len) return 0
            }
            c = substr(s, i, 1)
            o = ord[c]
            if (c == "0") {
                i++
            } else if (o >= 49 && o <= 57) {
                i++
                while (i <= len && is_digit(substr(s, i, 1))) i++
            } else {
                return 0
            }
            if (i <= len && substr(s, i, 1) == ".") {
                i++
                if (i > len || !is_digit(substr(s, i, 1))) return 0
                while (i <= len && is_digit(substr(s, i, 1))) i++
            }
            if (i <= len && (substr(s, i, 1) == "e" || substr(s, i, 1) == "E")) {
                i++
                if (i <= len && (substr(s, i, 1) == "+" || substr(s, i, 1) == "-")) i++
                if (i > len || !is_digit(substr(s, i, 1))) return 0
                while (i <= len && is_digit(substr(s, i, 1))) i++
            }
            return 1
        }
        function parse_value(depth,    c) {
            if (depth > 64) return 0
            skip_ws()
            if (i > len) return 0
            c = substr(s, i, 1)
            if (c == "\"") return parse_str()
            if (c == "{") return parse_object(depth + 1)
            if (c == "[") return parse_array(depth + 1)
            if (substr(s, i, 4) == "true") { i += 4; return 1 }
            if (substr(s, i, 5) == "false") { i += 5; return 1 }
            if (substr(s, i, 4) == "null") { i += 4; return 1 }
            return parse_number()
        }
        function parse_array(depth,    c) {
            if (depth > 64) return 0
            if (i > len || substr(s, i, 1) != "[") return 0
            i++
            skip_ws()
            if (i <= len && substr(s, i, 1) == "]") {
                i++
                return 1
            }
            while (1) {
                if (!parse_value(depth)) return 0
                skip_ws()
                if (i > len) return 0
                c = substr(s, i, 1)
                if (c == ",") {
                    i++
                    skip_ws()
                } else if (c == "]") {
                    i++
                    return 1
                } else {
                    return 0
                }
            }
        }
        function parse_object(depth,    k, k_nul, k_esc, c) {
            if (depth > 64) return 0
            if (i > len || substr(s, i, 1) != "{") return 0
            i++
            skip_ws()
            if (i <= len && substr(s, i, 1) == "}") {
                i++
                return 1
            }
            while (1) {
                if (!parse_str()) return 0
                k = decoded
                k_nul = decoded_has_nul
                k_esc = str_had_escape
                skip_ws()
                if (i > len || substr(s, i, 1) != ":") return 0
                i++
                skip_ws()
                if (depth == 1 && !k_nul && k == "boot") {
                    boot_count++
                    if (boot_count > 1 || k_esc) return 0
                    if (!parse_str()) return 0
                    if (decoded_has_nul || str_had_escape || decoded == "" || decoded ~ /[^!-~]/) return 0
                    boot_val = decoded
                } else {
                    if (!parse_value(depth)) return 0
                }
                skip_ws()
                if (i > len) return 0
                c = substr(s, i, 1)
                if (c == ",") {
                    i++
                    skip_ws()
                } else if (c == "}") {
                    i++
                    return 1
                } else {
                    return 0
                }
            }
        }
        { s = (NR == 1 ? $0 : s "\n" $0) }
        END {
            if (NR == 0) exit 1
            len = length(s)
            i = 1
            boot_count = 0
            boot_val = ""
            skip_ws()
            if (i > len || substr(s, i, 1) != "{") exit 1
            if (!parse_object(1)) exit 1
            skip_ws()
            if (i <= len) exit 1
            if (boot_count != 1 || boot_val == "" || boot_val ~ /[^!-~]/) exit 1
            printf "%s", boot_val
        }
    ' "$1" 2>/dev/null) || return 0
    [ -n "$sbj_journal_boot" ] || return 0
    [ "$sbj_journal_boot" != "$sbj_boot_id" ] && return 1
    return 0
}

tailscale_same_boot_journal_present() {
    same_boot_json_journal_present "$TS_JOURNAL"
}

perf_same_boot_journal_present() {
    same_boot_json_journal_present "$PERF_JOURNAL"
}

# Return 0 (fail-closed: residual Tailscale RPDB policy rules present or
# unreadable) when running on real Linux procfs (or `ZTE_IP_BIN` shim) and any
# agent-owned (5110/5130/5131) or tailscaled-owned (5210/5230/5250/5270) rule
# remains in IPv4 or IPv6 policy tables.
tailscale_policy_rules_present() {
    tspr_ip="${ZTE_IP_BIN:-}"
    if [ -z "$tspr_ip" ]; then
        if [ "$PROC_ROOT" = "/proc" ] && [ -r "$PROC_ROOT/self/stat" ]; then
            tspr_ip=$(command -v ip 2>/dev/null || true)
        else
            return 1
        fi
    fi
    [ -n "$tspr_ip" ] || return 0
    for tspr_fam in -4 -6; do
        tspr_out=$("$tspr_ip" "$tspr_fam" rule show 2>/dev/null) || return 0
        if printf '%s\n' "$tspr_out" | LC_ALL=C awk '
            /^[[:space:]]*(5110|5130|5131|5210|5230|5250|5270):/ { found = 1; exit 0 }
            END { exit (found ? 0 : 1) }
        '; then
            return 0
        fi
    done
    return 1
}

# Return 0 (fail-closed: same-boot Clean DNS DNAT flush pending) unless the
# flush marker is absent OR positively carries a valid boot ID different from
# a valid current boot ID.
tailscale_same_boot_flush_pending() {
    same_boot_marker_pending "$TS_FLUSH_MARKER"
}

# Return 0 (fail-closed: blocked for this boot) unless the rollback-blocked
# marker is absent OR positively matches a previous boot's valid ID.
same_boot_rollback_blocked() {
    same_boot_marker_pending "$ROLLBACK_BLOCKED"
}

# Return 0 (fail-closed: interrupted/failed same-boot recovery still pending)
# unless the marker is absent OR positively matches a previous boot's valid ID.
# Sets `rp_owner` to candidate|previous|stable|a|b|legacy|unknown.
same_boot_recover_pending() {
    rp_owner=""
    if [ ! -e "$RECOVER_PENDING" ] && [ ! -L "$RECOVER_PENDING" ]; then
        return 1
    fi
    if [ ! -f "$RECOVER_PENDING" ] || [ ! -r "$RECOVER_PENDING" ] || has_nul_byte "$RECOVER_PENDING"; then
        rp_owner=unknown
        return 0
    fi
    sbrp_boot_id=$(read_valid_boot_token "$BOOT_ID_PATH") || {
        rp_owner=unknown
        return 0
    }
    sbrp_parsed=$(LC_ALL=C awk '
        { lines[NR] = $0 }
        END {
            if (NR < 1 || NR > 2) exit 1
            b = lines[1]
            gsub(/^[ \t\r]+|[ \t\r]+$/, "", b)
            if (b == "" || b ~ /[^!-~]/) exit 1
            if (NR == 1) {
                printf "%s\nlegacy\n", b
                exit 0
            }
            o = lines[2]
            gsub(/^[ \t\r]+|[ \t\r]+$/, "", o)
            if (o != "candidate" && o != "previous" && o != "stable" && o != "a" && o != "b") exit 1
            printf "%s\n%s\n", b, o
        }
    ' "$RECOVER_PENDING" 2>/dev/null) || {
        rp_owner=unknown
        return 0
    }
    sbrp_marker_boot=$(printf '%s\n' "$sbrp_parsed" | sed -n '1p')
    sbrp_marker_owner=$(printf '%s\n' "$sbrp_parsed" | sed -n '2p')
    if [ "$sbrp_marker_boot" != "$sbrp_boot_id" ]; then
        return 1
    fi
    rp_owner=$sbrp_marker_owner
    return 0
}

# Return 0 when the strict zero-cellular pause journal still exists; modem
# enable=0 persists across reboots so older slots lacking a reader must never
# start while this journal survives.
relay_cellular_pause_present() {
    [ -e "$RELAY_CELLULAR_PAUSE" ] || [ -L "$RELAY_CELLULAR_PAUSE" ]
}

parse_bootstrap_identity() {
    pbi_file=$1
    [ -f "$pbi_file" ] && [ -r "$pbi_file" ] || return 1
    has_nul_byte "$pbi_file" && return 1
    pbi_out=$(LC_ALL=C awk '
        function valid_semver(v,    base, pre, build, pos, core, i, n, parts, seg) {
            if (v ~ /[^0-9A-Za-z.+-]/) return 0
            pos = index(v, "+")
            if (pos > 0) {
                build = substr(v, pos + 1)
                v = substr(v, 1, pos - 1)
                if (length(build) == 0 || build ~ /\+/) return 0
                n = split(build, parts, ".")
                for (i = 1; i <= n; i++) {
                    seg = parts[i]
                    if (length(seg) == 0 || seg ~ /[^0-9A-Za-z-]/) return 0
                }
            }
            pos = index(v, "-")
            if (pos > 0) {
                pre = substr(v, pos + 1)
                base = substr(v, 1, pos - 1)
                if (length(pre) == 0) return 0
                n = split(pre, parts, ".")
                for (i = 1; i <= n; i++) {
                    seg = parts[i]
                    if (length(seg) == 0 || seg ~ /[^0-9A-Za-z-]/) return 0
                    if (seg ~ /^[0-9]+$/ && length(seg) > 1 && substr(seg, 1, 1) == "0") return 0
                }
            } else {
                base = v
            }
            n = split(base, core, ".")
            if (n != 3) return 0
            for (i = 1; i <= 3; i++) {
                seg = core[i]
                if (seg !~ /^(0|[1-9][0-9]*)$/) return 0
                if (length(seg) > 20 || (length(seg) == 20 && ("_" seg) > "_18446744073709551615")) return 0
            }
            return 1
        }
        NR == 1 { sha = $0; next }
        NR == 2 { ver = $0; next }
        { bad = 1 }
        END {
            if (bad || NR != 2) exit 1
            if (length(sha) != 64 || sha ~ /[^0-9a-f]/) exit 1
            if (!valid_semver(ver)) exit 1
            printf "%s\n%s\n", sha, ver
        }
    ' "$pbi_file" 2>/dev/null) || return 1
    pbi_sha=$(printf '%s\n' "$pbi_out" | sed -n '1p')
    pbi_ver=$(printf '%s\n' "$pbi_out" | sed -n '2p')
    [ "${#pbi_sha}" -eq 64 ] && [ -n "$pbi_ver" ]
}

verified_slot_integrity() {
    vsi_binary=$(slot_binary "$1")
    vsi_meta=$(slot_meta "$1")
    [ -f "$vsi_binary" ] && [ -x "$vsi_binary" ] || return 1
    if [ -e "$vsi_meta" ] || [ -L "$vsi_meta" ]; then
        parse_release_meta "$vsi_meta" || return 1
        vsi_expected_size=$prm_size
        vsi_expected_sha=$prm_sha
        [ -n "$vsi_expected_size" ] && [ -n "$vsi_expected_sha" ] || return 1
        vsi_actual_size=$(wc -c < "$vsi_binary" | tr -d '[:space:]')
        [ "$vsi_actual_size" = "$vsi_expected_size" ] || return 1
        vsi_actual_sha=$(sha256sum "$vsi_binary" 2>/dev/null | sed -n 's/[[:space:]].*//p')
        [ "$vsi_actual_sha" = "$vsi_expected_sha" ]
        return $?
    fi
    vsi_bootstrap_sha="${vsi_binary%/*}/bootstrap.sha256"
    if [ -e "$vsi_bootstrap_sha" ] || [ -L "$vsi_bootstrap_sha" ]; then
        parse_bootstrap_identity "$vsi_bootstrap_sha" || return 1
        vsi_expected_sha=$pbi_sha
        vsi_bootstrap_version=$pbi_ver
        vsi_actual_sha=$(sha256sum "$vsi_binary" 2>/dev/null | sed -n 's/[[:space:]].*//p')
        [ "$vsi_actual_sha" = "$vsi_expected_sha" ] || return 1
        "$vsi_binary" ota-probe "$vsi_bootstrap_version" >/dev/null 2>&1
        return $?
    fi
    return 1
}

slot_binary() {
    printf '%s/slot-%s/zte-agent' "$OTA_ROOT" "$1"
}

slot_meta() {
    printf '%s/slot-%s/release.json' "$OTA_ROOT" "$1"
}

valid_slot() {
    [ "$1" = a ] || [ "$1" = b ]
}

runnable_binary() {
    rb_binary=$1
    rb_meta=$2
    [ -f "$rb_binary" ] && [ -x "$rb_binary" ] || return 1

    if [ -e "$rb_meta" ] || [ -L "$rb_meta" ]; then
        parse_release_meta "$rb_meta" || return 1
        rb_version=$prm_ver
        rb_expected_size=$prm_size
        rb_expected_sha=$prm_sha
        [ -n "$rb_version" ] && [ -n "$rb_expected_size" ] && [ -n "$rb_expected_sha" ] || return 1
        if ! blocked_allows_version "$rb_version"; then
            return 1
        fi
        rb_actual_size=$(wc -c < "$rb_binary" | tr -d '[:space:]')
        [ "$rb_actual_size" = "$rb_expected_size" ] || return 1
        rb_actual_sha=$(sha256sum "$rb_binary" 2>/dev/null | sed -n 's/[[:space:]].*//p')
        [ "$rb_actual_sha" = "$rb_expected_sha" ] || return 1
        "$rb_binary" ota-probe "$rb_version" >/dev/null 2>&1
        return $?
    fi

    rb_bootstrap_sha="${rb_binary%/*}/bootstrap.sha256"
    if [ -e "$rb_bootstrap_sha" ] || [ -L "$rb_bootstrap_sha" ]; then
        parse_bootstrap_identity "$rb_bootstrap_sha" || return 1
        rb_expected_sha=$pbi_sha
        rb_bootstrap_version=$pbi_ver
        if ! blocked_allows_version "$rb_bootstrap_version"; then
            return 1
        fi
        rb_actual_sha=$(sha256sum "$rb_binary" 2>/dev/null | sed -n 's/[[:space:]].*//p')
        [ "$rb_actual_sha" = "$rb_expected_sha" ] || return 1
        "$rb_binary" ota-probe "$rb_bootstrap_version" >/dev/null 2>&1
        return $?
    fi

    # A manually bootstrapped legacy slot has no signed release metadata, so
    # keep the executable-bit compatibility fallback used before OTA while
    # still failing closed if `blocked.json` is unreadable, malformed, or a
    # dangling symlink.
    blocked_json_valid || return 1
    return 0
}

runnable_slot() {
    runnable_binary "$(slot_binary "$1")" "$(slot_meta "$1")"
}

verified_runnable_slot() {
    verified_slot_integrity "$1" && runnable_slot "$1"
}

runnable_stable() {
    ( [ -e "$LAST_STABLE_META" ] || [ -L "$LAST_STABLE_META" ] ) \
        && parse_release_meta "$LAST_STABLE_META" \
        && [ "$prm_channel" = stable ] \
        && runnable_binary "$LAST_STABLE" "$LAST_STABLE_META"
}

SYNC_PATH_SUPPORTED=""
sync_path() {
    sp_target=$1
    if [ -z "$SYNC_PATH_SUPPORTED" ]; then
        sp_rc=0
        sp_err=$(sync "$sp_target" 2>&1) || sp_rc=$?
        if [ "$sp_rc" -eq 0 ]; then
            SYNC_PATH_SUPPORTED=1
            return 0
        fi
        case "$sp_err" in
            *[Uu]sage:*|*"unrecognized"*|*"invalid option"*|*"too many"*|*"extra operand"*)
                SYNC_PATH_SUPPORTED=0
                sync
                return $?
                ;;
            *)
                return "$sp_rc"
                ;;
        esac
    fi
    if [ "$SYNC_PATH_SUPPORTED" = 1 ]; then
        sync "$sp_target" 2>/dev/null
        return $?
    fi
    sync
}

sync_ota_root() {
    sync_path "$OTA_ROOT"
}

disarm_slot_binary() {
    dsb_bin=$1
    if [ -e "$dsb_bin" ] || [ -L "$dsb_bin" ]; then
        chmod 600 "$dsb_bin" 2>/dev/null || return 1
        [ ! -x "$dsb_bin" ] || return 1
        sync_path "$dsb_bin" || return 1
        sync_path "${dsb_bin%/*}" || return 1
    fi
    return 0
}

remove_handoff_marker() {
    rhm_path=$1
    if [ -e "$rhm_path" ] || [ -L "$rhm_path" ]; then
        rm -f "$rhm_path" 2>/dev/null || return 1
        [ ! -e "$rhm_path" ] && [ ! -L "$rhm_path" ] || return 1
        sync_ota_root || return 1
    fi
    return 0
}
# END SHARED OTA HELPERS

atomic_active() {
    [ ! -d "$ACTIVE" ] || return 1
    {
        printf '%s\n' "$1" > "$ACTIVE.tmp" \
            && chmod 600 "$ACTIVE.tmp"
    } 2>/dev/null || {
        rm -f "$ACTIVE.tmp" 2>/dev/null || true
        return 1
    }
    sync_path "$ACTIVE.tmp" || {
        rm -f "$ACTIVE.tmp" 2>/dev/null || true
        return 1
    }
    mv -f "$ACTIVE.tmp" "$ACTIVE" 2>/dev/null || {
        rm -f "$ACTIVE.tmp" 2>/dev/null || true
        return 1
    }
    sync_ota_root || return 1
    [ -f "$ACTIVE" ] && [ "$(sed -n '1p' "$ACTIVE" 2>/dev/null)" = "$1" ]
}

proc_start_time() {
    awk '{ sub(/^.*\) /, ""); if ($1 !~ /^[ZX]$/ && $20 ~ /^[0-9]+$/) print $20 }' \
        "$1/stat" 2>/dev/null || true
}

write_rollback_attempt() {
    [ ! -d "$ROLLBACK_ATTEMPT" ] || return 1
    {
        printf '%s\n%s\n' "$1" "$2" > "$ROLLBACK_ATTEMPT.tmp" \
            && chmod 600 "$ROLLBACK_ATTEMPT.tmp"
    } 2>/dev/null || {
        rm -f "$ROLLBACK_ATTEMPT.tmp" 2>/dev/null || true
        return 1
    }
    sync_path "$ROLLBACK_ATTEMPT.tmp" || {
        rm -f "$ROLLBACK_ATTEMPT.tmp" 2>/dev/null || true
        return 1
    }
    mv -f "$ROLLBACK_ATTEMPT.tmp" "$ROLLBACK_ATTEMPT" 2>/dev/null || {
        rm -f "$ROLLBACK_ATTEMPT.tmp" 2>/dev/null || true
        return 1
    }
    sync_ota_root || return 1
    [ -f "$ROLLBACK_ATTEMPT" ] \
        && [ "$(sed -n '1p' "$ROLLBACK_ATTEMPT" 2>/dev/null)" = "$1" ] \
        && [ "$(sed -n '2p' "$ROLLBACK_ATTEMPT" 2>/dev/null)" = "$2" ]
}

rollback_attempt_slot() {
    if [ -f "$ROLLBACK_ATTEMPT" ] && [ -r "$ROLLBACK_ATTEMPT" ] && ! has_nul_byte "$ROLLBACK_ATTEMPT"; then
        ras_val=$(sed -n '1p' "$ROLLBACK_ATTEMPT" 2>/dev/null || true)
        if valid_slot "$ras_val"; then
            printf '%s\n' "$ras_val"
        fi
    fi
}

rollback_attempt_matches() {
    [ -f "$ROLLBACK_ATTEMPT" ] && [ -r "$ROLLBACK_ATTEMPT" ] || return 1
    ! has_nul_byte "$ROLLBACK_ATTEMPT" || return 1
    [ "$(sed -n '1p' "$ROLLBACK_ATTEMPT" 2>/dev/null || true)" = "$1" ] || return 1
    [ "$(sed -n '2p' "$ROLLBACK_ATTEMPT" 2>/dev/null || true)" = "$2" ]
}

proc_socket_inodes() {
    psi_dir=$1
    for psi_fd in "$psi_dir"/*; do
        psi_t=$(readlink "$psi_fd" 2>/dev/null || true)
        case "$psi_t" in
            'socket:['*']')
                psi_t=${psi_t#'socket:['}
                printf '%s\n' "${psi_t%']'}"
                ;;
        esac
    done
}

# Own the rollback attempt from launch through readiness, early exit, or an
# enforced startup timeout. If the previous slot confirms readiness (either by
# clearing `rollback-attempt` itself or binding its TCP listener), clear the
# marker and exit. If it exits early OR exceeds the timeout without binding,
# enforce the timeout (TERM -> KILL on the verified process) and automatically
# trigger the boot launcher / supervisor so cold boot advances to Stable rescue
# without external intervention and no slow legacy slot survives with a stale
# marker.
spawn_rollback_attempt_owner() {
    rac_pid=$1
    rac_start=$2
    rac_bin=$3
    rac_slot=$4
    rac_token=$5
    rac_sup=$6
    rac_launcher="${ZTE_AGENT_LAUNCHER:-/data/local/tmp/start_zte_agent.sh}"
    rac_stopped="${ZTE_AGENT_STOPPED:-/tmp/zte-agent-run/stopped}"
    rac_bind=${ZTE_AGENT_BIND:-0.0.0.0:9090}
    rac_port=${rac_bind##*:}
    case "$rac_port" in
        ""|*[!0-9]*) rac_port=9090 ;;
    esac
    rac_hex=$(printf '%04X' "$rac_port")
    rac_max_polls=${ZTE_OTA_ROLLBACK_WAIT_POLLS:-150}
    case "$rac_max_polls" in
        ""|*[!0-9]*) rac_max_polls=150 ;;
    esac
    [ "$rac_max_polls" -ge 1 ] || rac_max_polls=150
    rac_bin_real=$(cd "${rac_bin%/*}" 2>/dev/null && printf '%s/%s' "$(pwd -P)" "${rac_bin##*/}" || printf '%s' "$rac_bin")
    (
        rac_same_process() {
            kill -0 "$rac_pid" 2>/dev/null || return 1
            if [ -n "$rac_start" ]; then
                [ "$(proc_start_time "$PROC_ROOT/$rac_pid")" = "$rac_start" ] || return 1
            elif command -v ps >/dev/null 2>&1; then
                rac_ps=$(ps -o stat= -p "$rac_pid" 2>/dev/null || true)
                case "$rac_ps" in
                    ""|*Z*) return 1 ;;
                esac
            fi
            return 0
        }
        rac_is_listening() {
            if [ -d "$PROC_ROOT/$rac_pid/fd" ] && [ -r "$PROC_ROOT/$rac_pid/net/tcp" ]; then
                rac_exe=$(readlink "$PROC_ROOT/$rac_pid/exe" 2>/dev/null || true)
                if [ -z "$rac_exe" ] || { [ "$rac_exe" != "$rac_bin" ] && [ "$rac_exe" != "$rac_bin_real" ]; }; then
                    return 1
                fi
                rac_inodes=$(proc_socket_inodes "$PROC_ROOT/$rac_pid/fd")
                if [ -n "$rac_inodes" ]; then
                    if awk -v hex=":$rac_hex" -v inodes="$rac_inodes" '
                        BEGIN { n = split(inodes, a, "\n"); for (k = 1; k <= n; k++) if (a[k] != "") want[a[k]] = 1 }
                        NR > 1 && $4 == "0A" && substr($2, length($2) - 4) == hex && ($10 in want) { ok = 1; exit 0 }
                        END { exit (ok ? 0 : 1) }
                    ' "$PROC_ROOT/$rac_pid/net/tcp" "$PROC_ROOT/$rac_pid/net/tcp6" 2>/dev/null; then
                        return 0
                    fi
                fi
                return 1
            elif [ -x /usr/sbin/lsof ]; then
                /usr/sbin/lsof -nP -a -p "$rac_pid" -iTCP:"$rac_port" -sTCP:LISTEN -F p 2>/dev/null | grep -qx "p$rac_pid"
                return $?
            fi
            return 1
        }
        rac_i=0
        rac_alive=1
        while [ "$rac_i" -lt "$rac_max_polls" ]; do
            sleep 0.2
            if ! rac_same_process; then
                rac_alive=0
                break
            fi
            # New agents clear `rollback-attempt` themselves in `confirm_boot_ready()`.
            if [ -e "$PENDING" ] || [ -L "$PENDING" ] || { [ ! -e "$ROLLBACK_ATTEMPT" ] && [ ! -L "$ROLLBACK_ATTEMPT" ]; }; then
                exit 0
            fi
            if ! rollback_attempt_matches "$rac_slot" "$rac_token"; then
                exit 0
            fi
            if rac_is_listening; then
                rac_same_process || { rac_alive=0; break; }
                remove_handoff_marker "$ROLLBACK_ATTEMPT" || true
                exit 0
            fi
            rac_i=$((rac_i + 1))
        done
        if [ "$rac_alive" = 1 ]; then
            if [ -e "$PENDING" ] || [ -L "$PENDING" ] || { [ ! -e "$ROLLBACK_ATTEMPT" ] && [ ! -L "$ROLLBACK_ATTEMPT" ]; }; then
                exit 0
            fi
            if ! rollback_attempt_matches "$rac_slot" "$rac_token"; then
                exit 0
            fi
            if rac_is_listening && rac_same_process; then
                remove_handoff_marker "$ROLLBACK_ATTEMPT" || true
                exit 0
            fi
            # Enforce the startup timeout so a slow/hung legacy agent never
            # keeps running with a stale `rollback-attempt` marker.
            if rac_same_process; then
                kill -TERM "$rac_pid" 2>/dev/null || true
                rac_k=0
                while [ "$rac_k" -lt 10 ] && rac_same_process; do
                    sleep 0.2
                    rac_k=$((rac_k + 1))
                done
                if rac_same_process; then
                    kill -KILL "$rac_pid" 2>/dev/null || true
                    rac_k=0
                    while [ "$rac_k" -lt 5 ] && rac_same_process; do
                        sleep 0.2
                        rac_k=$((rac_k + 1))
                    done
                fi
            fi
        fi
        # Only trigger automatic fallback if this exact attempt is still active,
        # no new pending handoff has started, and the service was not stopped.
        if [ -e "$PENDING" ] || [ -L "$PENDING" ] || [ -e "$rac_stopped" ] || ! rollback_attempt_matches "$rac_slot" "$rac_token"; then
            exit 0
        fi
        ZTE_OTA_SUPERVISOR="$rac_sup"
        ZTE_OTA_REAL_SUPERVISOR="$rac_sup"
        export ZTE_OTA_SUPERVISOR ZTE_OTA_REAL_SUPERVISOR
        if [ -f "$rac_launcher" ]; then
            exec sh "$rac_launcher"
        elif [ -f "$rac_sup" ]; then
            exec sh "$rac_sup"
        fi
        exit 0
    ) </dev/null >/dev/null 2>&1 &
}

# BEGIN SHARED OTA HELPERS
parse_release_meta() {
    prm_file=$1
    [ -f "$prm_file" ] && [ -r "$prm_file" ] || return 1
    prm_out=$(blocked_json_awk release "" "$prm_file") || return 1
    prm_ver=$(printf '%s\n' "$prm_out" | sed -n '1p')
    prm_size=$(printf '%s\n' "$prm_out" | sed -n '2p')
    prm_sha=$(printf '%s\n' "$prm_out" | sed -n '3p')
    prm_channel=$(printf '%s\n' "$prm_out" | sed -n '4p')
    [ -n "$prm_ver" ] && [ -n "$prm_size" ] && [ -n "$prm_sha" ] && [ -n "$prm_channel" ]
}

# Strict RFC 8259 + RFC 3629 POSIX `awk` JSON helper for `blocked.json` and
# `release.json` (enforcing Rust's 256 KiB `storage::read_json` size cap).
# Modes:
#   allows   <ver> -> exit 0 iff valid JSON array of strings AND <ver> is absent
#   contains <ver> -> exit 0 iff valid JSON array of strings AND <ver> is present
#   append   <ver> -> validate entire JSON array of strings; print valid compact
#                     JSON array with <ver> included (or exit non-zero on error)
#   release  ""    -> validate full ReleaseManifest JSON + schema/field rules
blocked_json_awk() {
    [ -f "$3" ] && [ -r "$3" ] || return 1
    bja_bytes=$(wc -c < "$3" 2>/dev/null | tr -d '[:space:]')
    case "$bja_bytes" in
        ""|*[!0-9]*) return 1 ;;
    esac
    [ "$bja_bytes" -le 262144 ] || return 1
    has_nul_byte "$3" && return 1
    LC_ALL=C awk -v mode="$1" -v target="$2" '
        BEGIN {
            for (b = 1; b < 256; b++) ord[sprintf("%c", b)] = b
            hex["0"]=0; hex["1"]=1; hex["2"]=2; hex["3"]=3; hex["4"]=4
            hex["5"]=5; hex["6"]=6; hex["7"]=7; hex["8"]=8; hex["9"]=9
            hex["a"]=10; hex["b"]=11; hex["c"]=12; hex["d"]=13; hex["e"]=14; hex["f"]=15
            hex["A"]=10; hex["B"]=11; hex["C"]=12; hex["D"]=13; hex["E"]=14; hex["F"]=15
        }
        function is_ws(c) { return c == " " || c == "\t" || c == "\r" || c == "\n" }
        function skip_ws() {
            while (i <= len && is_ws(substr(s, i, 1))) i++
        }
        function hex4(pos,    d0, d1, d2, d3) {
            if (pos + 3 > len) return -1
            d0 = substr(s, pos, 1); d1 = substr(s, pos + 1, 1)
            d2 = substr(s, pos + 2, 1); d3 = substr(s, pos + 3, 1)
            if (!(d0 in hex) || !(d1 in hex) || !(d2 in hex) || !(d3 in hex)) return -1
            return hex[d0] * 4096 + hex[d1] * 256 + hex[d2] * 16 + hex[d3]
        }
        function utf8_encode(cp) {
            if (cp == 0) return ""
            if (cp < 128) return sprintf("%c", cp)
            if (cp < 2048) return sprintf("%c%c", 192 + int(cp / 64), 128 + (cp % 64))
            if (cp < 65536) return sprintf("%c%c%c", 224 + int(cp / 4096), 128 + (int(cp / 64) % 64), 128 + (cp % 64))
            return sprintf("%c%c%c%c", 240 + int(cp / 262144), 128 + (int(cp / 4096) % 64), 128 + (int(cp / 64) % 64), 128 + (cp % 64))
        }
        function parse_str(    start, c, o, b1, b2, b3, cp, lo, out, has_nul) {
            if (i > len || substr(s, i, 1) != "\"") return 0
            start = i
            i++
            out = ""
            has_nul = 0
            while (i <= len) {
                c = substr(s, i, 1)
                if (c == "\"") {
                    raw_tok = substr(s, start, i - start + 1)
                    decoded = out
                    decoded_has_nul = has_nul
                    i++
                    return 1
                }
                if (c == "\\") {
                    i++
                    if (i > len) return 0
                    c = substr(s, i, 1)
                    if (c == "\"" || c == "\\" || c == "/") { out = out c; i++ }
                    else if (c == "b") { out = out sprintf("%c", 8); i++ }
                    else if (c == "f") { out = out sprintf("%c", 12); i++ }
                    else if (c == "n") { out = out "\n"; i++ }
                    else if (c == "r") { out = out "\r"; i++ }
                    else if (c == "t") { out = out "\t"; i++ }
                    else if (c == "u") {
                        cp = hex4(i + 1)
                        if (cp < 0) return 0
                        i += 5
                        if (cp >= 55296 && cp <= 56319) {
                            if (i + 5 > len || substr(s, i, 2) != "\\u") return 0
                            lo = hex4(i + 2)
                            if (lo < 56320 || lo > 57343) return 0
                            i += 6
                            cp = 65536 + (cp - 55296) * 1024 + (lo - 56320)
                        } else if (cp >= 56320 && cp <= 57343) {
                            return 0
                        }
                        if (cp == 0) { has_nul = 1 } else { out = out utf8_encode(cp) }
                    } else return 0
                } else {
                    o = ord[c]
                    if (o < 32) return 0
                    if (o < 128) {
                        out = out c
                        i++
                    } else if (o >= 194 && o <= 223) {
                        if (i + 1 > len) return 0
                        b1 = ord[substr(s, i + 1, 1)]
                        if (b1 < 128 || b1 > 191) return 0
                        out = out substr(s, i, 2)
                        i += 2
                    } else if (o >= 224 && o <= 239) {
                        if (i + 2 > len) return 0
                        b1 = ord[substr(s, i + 1, 1)]
                        b2 = ord[substr(s, i + 2, 1)]
                        if (b2 < 128 || b2 > 191) return 0
                        if (o == 224 && (b1 < 160 || b1 > 191)) return 0
                        if (o == 237 && (b1 < 128 || b1 > 159)) return 0
                        if (o != 224 && o != 237 && (b1 < 128 || b1 > 191)) return 0
                        out = out substr(s, i, 3)
                        i += 3
                    } else if (o >= 240 && o <= 244) {
                        if (i + 3 > len) return 0
                        b1 = ord[substr(s, i + 1, 1)]
                        b2 = ord[substr(s, i + 2, 1)]
                        b3 = ord[substr(s, i + 3, 1)]
                        if (b2 < 128 || b2 > 191 || b3 < 128 || b3 > 191) return 0
                        if (o == 240 && (b1 < 144 || b1 > 191)) return 0
                        if (o == 244 && (b1 < 128 || b1 > 143)) return 0
                        if (o != 240 && o != 244 && (b1 < 128 || b1 > 191)) return 0
                        out = out substr(s, i, 4)
                        i += 4
                    } else {
                        return 0
                    }
                }
            }
            return 0
        }
        function valid_semver(v,    base, pre, build, pos, core, k, m, parts, seg) {
            if (v ~ /[^0-9A-Za-z.+-]/) return 0
            pos = index(v, "+")
            if (pos > 0) {
                build = substr(v, pos + 1)
                v = substr(v, 1, pos - 1)
                if (length(build) == 0 || build ~ /\+/) return 0
                m = split(build, parts, ".")
                for (k = 1; k <= m; k++) {
                    seg = parts[k]
                    if (length(seg) == 0 || seg ~ /[^0-9A-Za-z-]/) return 0
                }
            }
            pos = index(v, "-")
            if (pos > 0) {
                pre = substr(v, pos + 1)
                base = substr(v, 1, pos - 1)
                if (length(pre) == 0) return 0
                m = split(pre, parts, ".")
                for (k = 1; k <= m; k++) {
                    seg = parts[k]
                    if (length(seg) == 0 || seg ~ /[^0-9A-Za-z-]/) return 0
                    if (seg ~ /^[0-9]+$/ && length(seg) > 1 && substr(seg, 1, 1) == "0") return 0
                }
            } else {
                base = v
            }
            m = split(base, core, ".")
            if (m != 3) return 0
            for (k = 1; k <= 3; k++) {
                seg = core[k]
                if (seg !~ /^(0|[1-9][0-9]*)$/) return 0
                if (length(seg) > 20 || (length(seg) == 20 && ("_" seg) > "_18446744073709551615")) return 0
            }
            return 1
        }
        function parse_uint(max_str,    start, num) {
            start = i
            while (i <= len && substr(s, i, 1) ~ /[0-9]/) i++
            num = substr(s, start, i - start)
            if (num !~ /^(0|[1-9][0-9]*)$/) return 0
            if (length(num) > length(max_str) || (length(num) == length(max_str) && ("_" num) > ("_" max_str))) return 0
            parsed_num = num
            return 1
        }
        { s = (NR == 1 ? $0 : s "\n" $0) }
        END {
            if (NR == 0) exit 1
            len = length(s)
            i = 1
            n = 0
            found = 0
            skip_ws()
            if (mode == "release") {
                if (i > len || substr(s, i, 1) != "{") exit 1
                i++
                skip_ws()
                if (i > len || substr(s, i, 1) == "}") exit 1
                rcnt = 0
                while (1) {
                    if (!parse_str() || decoded_has_nul) exit 1
                    key = decoded
                    if (key in seen) exit 1
                    seen[key] = 1
                    skip_ws()
                    if (i > len || substr(s, i, 1) != ":") exit 1
                    i++
                    skip_ws()
                    if (key == "schema") {
                        if (!parse_uint("255")) exit 1
                        fld[key] = parsed_num
                    } else if (key == "size") {
                        if (!parse_uint("18446744073709551615")) exit 1
                        fld[key] = parsed_num
                    } else if (key == "channel") {
                        if (!parse_str() || decoded_has_nul) exit 1
                        if (decoded != "stable" && decoded != "beta") exit 1
                        fld[key] = decoded
                    } else if (key == "version" || key == "tag" || key == "commit" || key == "target" || key == "sha256" || key == "binary_url" || key == "notes_url" || key == "published_at" || key == "minimum_updater_version") {
                        if (!parse_str() || decoded_has_nul) exit 1
                        fld[key] = decoded
                    } else {
                        exit 1
                    }
                    rcnt++
                    skip_ws()
                    if (i > len) exit 1
                    c = substr(s, i, 1)
                    if (c == ",") {
                        i++
                        skip_ws()
                    } else if (c == "}") {
                        i++
                        break
                    } else {
                        exit 1
                    }
                }
                skip_ws()
                if (i <= len || rcnt != 12) exit 1
                # Mirror Rust `ReleaseManifest::validate()` identically so
                # boot selection and quarantine decisions never diverge.
                if (fld["schema"] != "1") exit 1
                if (!valid_semver(fld["version"])) exit 1
                if (fld["tag"] != ("v" fld["version"])) exit 1
                ver_no_build = fld["version"]
                bpos = index(ver_no_build, "+")
                if (bpos > 0) ver_no_build = substr(ver_no_build, 1, bpos - 1)
                ppos = index(ver_no_build, "-")
                pre_str = (ppos > 0 ? substr(ver_no_build, ppos + 1) : "")
                split(pre_str, pre_parts, ".")
                if (fld["channel"] == "stable" && length(pre_str) > 0) exit 1
                if (fld["channel"] == "beta" && pre_parts[1] != "beta") exit 1
                if (fld["target"] != "aarch64-unknown-linux-musl") exit 1
                sz = fld["size"]
                if (length(sz) < 4 || length(sz) > 8 || (sz + 0) < 1024 || (sz + 0) > 33554432) exit 1
                if (length(fld["sha256"]) != 64 || fld["sha256"] ~ /[^0-9a-f]/) exit 1
                if (length(fld["commit"]) < 7 || length(fld["commit"]) > 64 || fld["commit"] ~ /[^0-9A-Fa-f]/) exit 1
                if (length(fld["published_at"]) < 1 || length(fld["published_at"]) > 64) exit 1
                if (!valid_semver(fld["minimum_updater_version"])) exit 1
                if (fld["binary_url"] != ("https://github.com/jesther-ai/open-u60-pro/releases/download/" fld["tag"] "/zte-agent")) exit 1
                if (fld["notes_url"] != ("https://github.com/jesther-ai/open-u60-pro/releases/tag/" fld["tag"])) exit 1
                printf "%s\n%s\n%s\n%s\n", fld["version"], fld["size"], fld["sha256"], fld["channel"]
                exit 0
            }
            if (i > len || substr(s, i, 1) != "[") exit 1
            i++
            skip_ws()
            if (i <= len && substr(s, i, 1) == "]") {
                i++
            } else {
                while (1) {
                    if (!parse_str()) exit 1
                    n++
                    toks[n] = raw_tok
                    if (!decoded_has_nul && decoded == target) {
                        found = 1
                        if (mode == "append") toks[n] = "\"" target "\""
                    }
                    skip_ws()
                    if (i > len) exit 1
                    c = substr(s, i, 1)
                    if (c == ",") {
                        i++
                        skip_ws()
                    } else if (c == "]") {
                        i++
                        break
                    } else {
                        exit 1
                    }
                }
            }
            skip_ws()
            if (i <= len) exit 1
            if (mode == "valid") exit 0
            if (mode == "allows") exit (found ? 2 : 0)
            if (mode == "contains") exit (found ? 0 : 2)
            if (mode == "append") {
                if (!found) {
                    n++
                    toks[n] = "\"" target "\""
                }
                printf "["
                for (k = 1; k <= n; k++) {
                    if (k > 1) printf ","
                    printf "%s", toks[k]
                }
                printf "]\n"
                exit 0
            }
            exit 1
        }
    ' "$3" 2>/dev/null
}

blocked_json_valid() {
    [ ! -e "$BLOCKED" ] && [ ! -L "$BLOCKED" ] && return 0
    [ -f "$BLOCKED" ] && [ -r "$BLOCKED" ] || return 1
    blocked_json_awk valid "" "$BLOCKED" >/dev/null
}

blocked_allows_version() {
    [ ! -e "$BLOCKED" ] && [ ! -L "$BLOCKED" ] && return 0
    [ -f "$BLOCKED" ] && [ -r "$BLOCKED" ] || return 1
    blocked_json_awk allows "$1" "$BLOCKED" >/dev/null
}

blocked_contains_version() {
    [ -f "$BLOCKED" ] && [ -r "$BLOCKED" ] || return 1
    blocked_json_awk contains "$1" "$BLOCKED" >/dev/null
}
# END SHARED OTA HELPERS

quarantine_version() {
    qv_ver=$1
    # Reject empty strings, control characters (including raw tabs), spaces,
    # quotes, backslashes, or non-ASCII bytes before touching `blocked.json`.
    case "$qv_ver" in
        ""|*[!0-9A-Za-z._+-]*) return 1 ;;
    esac
    [ ! -d "$BLOCKED" ] || return 1
    if [ -e "$BLOCKED" ] || [ -L "$BLOCKED" ]; then
        [ -f "$BLOCKED" ] && [ -r "$BLOCKED" ] || return 1
        qv_body=$(blocked_json_awk append "$qv_ver" "$BLOCKED") || return 1
        [ -n "$qv_body" ] || return 1
    else
        qv_body="[\"$qv_ver\"]"
    fi
    {
        printf '%s\n' "$qv_body" > "$BLOCKED.tmp" \
            && chmod 600 "$BLOCKED.tmp"
    } 2>/dev/null || {
        rm -f "$BLOCKED.tmp" 2>/dev/null || true
        return 1
    }
    if ! blocked_json_awk contains "$qv_ver" "$BLOCKED.tmp" >/dev/null; then
        rm -f "$BLOCKED.tmp" 2>/dev/null || true
        return 1
    fi
    sync_path "$BLOCKED.tmp" || {
        rm -f "$BLOCKED.tmp" 2>/dev/null || true
        return 1
    }
    mv -f "$BLOCKED.tmp" "$BLOCKED" 2>/dev/null || {
        rm -f "$BLOCKED.tmp" 2>/dev/null || true
        return 1
    }
    sync_ota_root || return 1
    blocked_contains_version "$qv_ver"
}

quarantine_candidate() {
    qc_slot=$1
    qc_pending_ver=$2
    qc_prev_slot=$3
    if [ -e "$PENDING" ] || [ -L "$PENDING" ]; then
        [ -f "$PENDING" ] && [ -r "$PENDING" ] || return 1
        has_nul_byte "$PENDING" && return 1
    fi
    valid_slot "$qc_slot" || return 1
    [ "$qc_slot" != "$qc_prev_slot" ] || return 1
    qc_meta=$(slot_meta "$qc_slot")
    qc_binary=$(slot_binary "$qc_slot")
    qc_stable_ver=""
    qc_stable_unknown=0
    if [ -e "$LAST_STABLE_META" ] || [ -L "$LAST_STABLE_META" ]; then
        if parse_release_meta "$LAST_STABLE_META"; then
            qc_stable_ver=$prm_ver
        else
            qc_stable_unknown=1
        fi
    fi
    qc_prev_ver=""
    qc_prev_unknown=0
    if valid_slot "$qc_prev_slot"; then
        qc_prev_meta=$(slot_meta "$qc_prev_slot")
        if [ -e "$qc_prev_meta" ] || [ -L "$qc_prev_meta" ]; then
            if parse_release_meta "$qc_prev_meta"; then
                qc_prev_ver=$prm_ver
            else
                qc_prev_unknown=1
            fi
        fi
        if [ -z "$qc_prev_ver" ] && [ "$qc_prev_unknown" != 1 ]; then
            qc_prev_boot=$(slot_binary "$qc_prev_slot")
            qc_prev_boot="${qc_prev_boot%/*}/bootstrap.sha256"
            if [ -e "$qc_prev_boot" ] || [ -L "$qc_prev_boot" ]; then
                if parse_bootstrap_identity "$qc_prev_boot"; then
                    qc_prev_ver=$pbi_ver
                else
                    # Previous bootstrap identity is damaged (already disqualifying
                    # previous slot from boot); disarm candidate by slot instead of
                    # blocking a verified Stable rescue with exit 9.
                    qc_prev_unknown=1
                fi
            fi
        fi
    fi
    if ( [ -e "$qc_meta" ] || [ -L "$qc_meta" ] ) && parse_release_meta "$qc_meta"; then
        qc_ver=$prm_ver
        # Only quarantine `qc_ver` in `blocked.json` when previous and Stable
        # versions are known (or absent), `qc_ver` matches the attempted trial
        # version recorded in `pending` (or `pending` had no version), and it
        # does not collide with `last-stable` or `previous`. Otherwise disarm
        # candidate by slot (matching Rust's `quarantine_failed_candidate`).
        if [ "$qc_prev_unknown" != 1 ] \
            && [ "$qc_stable_unknown" != 1 ] \
            && [ -n "$qc_ver" ] \
            && { [ -z "$qc_pending_ver" ] || [ "$qc_ver" = "$qc_pending_ver" ]; } \
            && [ "$qc_ver" != "$qc_stable_ver" ] \
            && [ "$qc_ver" != "$qc_prev_ver" ]; then
            quarantine_version "$qc_ver" || return 1
            return 0
        fi
    fi
    disarm_slot_binary "$qc_binary" || return 1
    return 0
}

mkdir -p "$OTA_ROOT/slot-a" "$OTA_ROOT/slot-b" "$OTA_ROOT/last-stable"
chmod 700 "$OTA_ROOT" "$OTA_ROOT/slot-a" "$OTA_ROOT/slot-b" "$OTA_ROOT/last-stable"

current_active=
if [ -f "$ACTIVE" ] && [ -r "$ACTIVE" ] && ! has_nul_byte "$ACTIVE"; then
    current_active=$(sed -n '1p' "$ACTIVE" 2>/dev/null || true)
fi

# A pending marker exists from before the candidate health trial. If power was
# lost or both processes died, select the recorded previous slot first. On a
# same-boot rollback, refuse to hand off to an older slot while a current-boot
# Tailscale kernel-TUN journal remains active.
excluded=
had_pending=0
preferred=
candidate=
previous=
pending_ver=
if [ -e "$PENDING" ] || [ -L "$PENDING" ]; then
    if [ ! -f "$PENDING" ] || [ ! -r "$PENDING" ] || has_nul_byte "$PENDING"; then
        echo "[ota-supervisor] pending marker is unreadable or contains NUL bytes; refusing rollback handoff" >&2
        exit 9
    fi
    had_pending=1
    candidate=$(sed -n '1p' "$PENDING" 2>/dev/null || true)
    previous=$(sed -n '2p' "$PENDING" 2>/dev/null || true)
    pending_ver=$(sed -n '3p' "$PENDING" 2>/dev/null || true)
    if ! valid_slot "$candidate" || ! valid_slot "$previous" || [ "$candidate" = "$previous" ]; then
        echo "[ota-supervisor] pending marker must name two distinct valid slots; refusing rollback handoff" >&2
        exit 9
    fi
    ts_journal=0
    ts_blocked=0
    cand_recover_pending=0
    prev_recover_pending=0
    stable_recover_pending=0
    unknown_recover_pending=0
    if same_boot_recover_pending; then
        ts_journal=1
        case "$rp_owner" in
            candidate|legacy) cand_recover_pending=1 ;;
            previous) prev_recover_pending=1; ts_blocked=1 ;;
            stable) stable_recover_pending=1 ;;
            a|b)
                if [ "$rp_owner" = "$candidate" ]; then
                    cand_recover_pending=1
                elif [ "$rp_owner" = "$previous" ]; then
                    prev_recover_pending=1
                    ts_blocked=1
                else
                    unknown_recover_pending=1
                fi
                ;;
            *) unknown_recover_pending=1 ;;
        esac
    fi
    if [ "$unknown_recover_pending" = 1 ]; then
        echo "[ota-supervisor] recovery-pending marker is corrupted or names an unknown owner; refusing rollback handoff" >&2
        exit 8
    fi
    if tailscale_same_boot_journal_present || tailscale_same_boot_flush_pending || tailscaled_process_running || tailscale_policy_rules_present || relay_cellular_pause_present || perf_same_boot_journal_present; then ts_journal=1; fi
    if same_boot_rollback_blocked; then ts_blocked=1; fi
    # Track who owns network cleanup independently of which slot will boot
    # after cleanup succeeds: retrying a transient Stable cleanup when
    # candidate B is unavailable must NOT override or disarm a healthy A!
    stable_cleanup_owner=0
    if [ "$stable_recover_pending" = 1 ] \
        || { [ "$current_active" = rescue ] && [ "$cand_recover_pending" != 1 ] && [ "$prev_recover_pending" != 1 ] && ! verified_runnable_slot "$previous"; }; then
        stable_cleanup_owner=1
    fi
    cand_ran=0
    cand_ok=0
    prev_ran=0
    prev_ok=0
    stable_ran=0
    stable_ok=0
    if [ "$stable_cleanup_owner" != 1 ] && [ "$prev_recover_pending" != 1 ] && [ "$ts_journal" = 1 ] && valid_slot "$candidate" && verified_slot_integrity "$candidate"; then
        if ! persist_recover_pending candidate; then
            echo "[ota-supervisor] could not persist recovery-pending marker; refusing rollback handoff" >&2
            exit 8
        fi
        cand_ran=1
        if ZTE_TEST_MARKER= "$(slot_binary "$candidate")" network-recover >/dev/null 2>&1; then
            cand_ok=1
        fi
    fi
    if [ "$cand_ran" = 1 ] && [ "$cand_ok" != 1 ]; then
        echo "[ota-supervisor] candidate network recovery failed; refusing rollback handoff" >&2
        exit 8
    fi
    if [ "$cand_recover_pending" = 1 ] && [ "$cand_ok" != 1 ]; then
        echo "[ota-supervisor] pending candidate network recovery cannot be completed; refusing rollback handoff" >&2
        exit 8
    fi
    if [ "$ts_blocked" = 1 ] && valid_slot "$previous" && verified_slot_integrity "$previous"; then
        if ! persist_recover_pending previous; then
            echo "[ota-supervisor] could not persist previous recovery-pending marker; refusing rollback handoff" >&2
            exit 8
        fi
        prev_ran=1
        if ZTE_TEST_MARKER= "$(slot_binary "$previous")" network-recover >/dev/null 2>&1; then
            prev_ok=1
        fi
    fi
    if [ "$prev_ran" = 1 ] && [ "$prev_ok" != 1 ]; then
        echo "[ota-supervisor] previous-slot network recovery failed; refusing rollback handoff" >&2
        exit 8
    fi
    if [ "$prev_recover_pending" = 1 ] && [ "$prev_ok" != 1 ]; then
        echo "[ota-supervisor] pending previous-slot network recovery cannot be completed; refusing rollback handoff" >&2
        exit 8
    fi
    # Route cleanup to verified Stable rescue when Stable already owns recovery
    # (`active=rescue` with previous unavailable, or `network-recover-pending`
    # names `stable`), OR when candidate/previous cannot clean up and no
    # candidate/previous recovery obligation is pending. Persist `stable`
    # before invoking `network-recover` so a partial failure is remembered on
    # the next attempt without affecting boot slot selection.
    if [ "$ts_journal" = 1 ] && [ "$cand_ran" != 1 ] && [ "$prev_ran" != 1 ] && [ "$cand_recover_pending" != 1 ] && [ "$prev_recover_pending" != 1 ] && runnable_stable; then
        if ! persist_recover_pending stable; then
            echo "[ota-supervisor] could not persist Stable recovery-pending marker; refusing rollback handoff" >&2
            exit 8
        fi
        stable_ran=1
        if ZTE_TEST_MARKER= "$LAST_STABLE" network-recover >/dev/null 2>&1; then
            stable_ok=1
        fi
    fi
    if [ "$stable_ran" = 1 ] && [ "$stable_ok" != 1 ]; then
        echo "[ota-supervisor] Stable rescue network recovery failed; refusing rollback handoff" >&2
        exit 8
    fi
    if [ "$stable_recover_pending" = 1 ] && [ "$stable_ok" != 1 ]; then
        echo "[ota-supervisor] pending Stable rescue network recovery cannot be completed; refusing rollback handoff" >&2
        exit 8
    fi
    if [ "$ts_journal" = 1 ] && [ "$cand_ok" != 1 ] && [ "$prev_ok" != 1 ] && [ "$stable_ok" != 1 ]; then
        echo "[ota-supervisor] tailscale same-boot journal cleanup failed; refusing rollback handoff" >&2
        exit 8
    fi
    if [ "$ts_blocked" = 1 ] && [ "$prev_ok" != 1 ]; then
        echo "[ota-supervisor] tailscale same-boot rollback-blocked cleanup failed; refusing rollback handoff" >&2
        exit 8
    fi
    if tailscale_same_boot_journal_present || tailscale_same_boot_flush_pending || tailscaled_process_running || tailscale_policy_rules_present || relay_cellular_pause_present || perf_same_boot_journal_present; then
        echo "[ota-supervisor] tailscale same-boot cleanup incomplete; refusing rollback handoff" >&2
        exit 8
    fi
    if ! clear_recover_pending; then
        echo "[ota-supervisor] could not clear recovery-pending marker; refusing rollback handoff" >&2
        exit 8
    fi
    if ! blocked_json_valid; then
        echo "[ota-supervisor] quarantine list is unreadable or malformed; refusing rollback handoff" >&2
        exit 9
    fi
    excluded=$candidate
    if [ "$previous" != "$excluded" ] && verified_runnable_slot "$previous"; then
        preferred=$previous
    fi
elif same_boot_rollback_blocked; then
    echo "[ota-supervisor] same-boot rollback-blocked marker present without pending; refusing boot" >&2
    exit 8
else
    rm -f "$ROLLBACK_BLOCKED"
fi

failed_attempt=
if [ "$had_pending" != 1 ]; then
    failed_attempt=$(rollback_attempt_slot)
fi

if [ "$had_pending" = 1 ]; then
    if [ -n "$preferred" ]; then
        active=$preferred
    elif [ "$excluded" != a ] && verified_runnable_slot a; then
        active=a
    elif [ "$excluded" != b ] && verified_runnable_slot b; then
        active=b
    elif runnable_stable; then
        active=stable
    else
        echo "[ota-supervisor] no verified rollback or rescue slot available" >&2
        exit 127
    fi
else
    active=$current_active
    if [ "$active" = rescue ]; then
        if runnable_stable; then
            active=stable
        else
            echo "[ota-supervisor] persisted rescue slot is not runnable; refusing fallback to unverified A/B slots" >&2
            exit 127
        fi
    elif ! valid_slot "$active" || [ "$active" = "$failed_attempt" ] || ! runnable_slot "$active"; then
        if [ "$failed_attempt" != a ] && verified_runnable_slot a; then active=a
        elif [ "$failed_attempt" != b ] && verified_runnable_slot b; then active=b
        elif runnable_stable; then active=stable
        else
            echo "[ota-supervisor] no verified fallback or rescue agent slot" >&2
            exit 127
        fi
    fi
fi

if valid_slot "$active"; then
    target_active=$active
    binary=$(slot_binary "$active")
else
    # The last Stable copy is a read-only rescue path. Keep the invalid slot
    # out of the active marker so the agent refuses another install until an
    # operator repairs A/B storage.
    target_active=rescue
    binary=$LAST_STABLE
fi

# When fallback switches away from the recorded active slot without a pending
# trial (or an earlier same-boot recovery obligation was left pending), enforce
# the same-boot cleanup gate before updating `active` or executing a
# replacement slot. Persist the responsible owner in `network-recover-pending`
# before invoking `network-recover` and clear it only after cleanup succeeds
# and verifies.
fb_recover_needed=0
fb_recover_owner=""
if [ "$had_pending" != 1 ]; then
    if same_boot_recover_pending; then
        fb_recover_needed=1
        fb_recover_owner=$rp_owner
    elif [ "$current_active" != "$target_active" ]; then
        if tailscale_same_boot_journal_present || tailscale_same_boot_flush_pending || tailscaled_process_running || tailscale_policy_rules_present || relay_cellular_pause_present || perf_same_boot_journal_present; then
            fb_recover_needed=1
        fi
    fi
fi
if [ "$fb_recover_needed" = 1 ]; then
    fb_recover_ok=0
    if [ "$fb_recover_owner" = unknown ]; then
        echo "[ota-supervisor] recovery-pending marker is corrupted; refusing boot" >&2
        exit 8
    fi
    if [ -z "$fb_recover_owner" ] || [ "$fb_recover_owner" = legacy ]; then
        if valid_slot "$current_active"; then
            fb_recover_owner=$current_active
        elif [ "$current_active" = rescue ]; then
            fb_recover_owner=stable
        fi
    fi
    if [ "$fb_recover_owner" = stable ]; then
        if runnable_stable; then
            if ! persist_recover_pending stable; then
                echo "[ota-supervisor] could not persist Stable recovery-pending marker; refusing fallback slot switch" >&2
                exit 8
            fi
            if ZTE_TEST_MARKER= "$LAST_STABLE" network-recover >/dev/null 2>&1; then
                fb_recover_ok=1
            fi
        fi
    elif valid_slot "$fb_recover_owner" && verified_slot_integrity "$fb_recover_owner"; then
        if ! persist_recover_pending "$fb_recover_owner"; then
            echo "[ota-supervisor] could not persist recovery-pending marker; refusing fallback slot switch" >&2
            exit 8
        fi
        if ZTE_TEST_MARKER= "$(slot_binary "$fb_recover_owner")" network-recover >/dev/null 2>&1; then
            fb_recover_ok=1
        fi
    fi
    if [ "$fb_recover_ok" != 1 ] || tailscale_same_boot_journal_present || tailscale_same_boot_flush_pending || tailscaled_process_running || tailscale_policy_rules_present || relay_cellular_pause_present || perf_same_boot_journal_present; then
        echo "[ota-supervisor] tailscale same-boot cleanup incomplete; refusing fallback slot switch" >&2
        exit 8
    fi
    if ! clear_recover_pending; then
        echo "[ota-supervisor] could not clear recovery-pending marker; refusing fallback slot switch" >&2
        exit 8
    fi
elif [ "$had_pending" != 1 ]; then
    clear_recover_pending || true
fi

if [ "$had_pending" = 1 ]; then
    if ! quarantine_candidate "$candidate" "$pending_ver" "$previous"; then
        echo "[ota-supervisor] could not quarantine failed candidate $candidate" >&2
        exit 9
    fi
fi
if [ "$target_active" = rescue ]; then
    if [ "$had_pending" = 1 ]; then
        # Same-boot network cleanup is already verified clean above. Durably clear
        # `rollback-blocked` BEFORE disarming rejected slots for rescue so a
        # disarm/sync failure on slot A never strands a same-boot retry with a
        # disarmed `previous` slot and a live `rollback-blocked`.
        if ! remove_handoff_marker "$ROLLBACK_BLOCKED"; then
            echo "[ota-supervisor] could not durably clear rollback-blocked marker; refusing boot" >&2
            exit 9
        fi
    fi
    for ds_slot in a b; do
        if [ "$had_pending" = 1 ] && [ "$ds_slot" = "$candidate" ]; then
            continue
        fi
        ds_bin=$(slot_binary "$ds_slot")
        if ! disarm_slot_binary "$ds_bin"; then
            echo "[ota-supervisor] could not disarm rejected slot $ds_slot before rescue" >&2
            exit 9
        fi
    done
fi

if [ "$had_pending" = 1 ] || [ "$current_active" != "$target_active" ]; then
    if ! atomic_active "$target_active"; then
        echo "[ota-supervisor] could not persist active marker $target_active" >&2
        exit 9
    fi
fi

arm_attempt_owner=0
attempt_start=""
attempt_token=""
if [ "$had_pending" = 1 ] && valid_slot "$target_active" && runnable_stable; then
    # Record that this A/B slot was selected by rollback and has not yet
    # reached its HTTP listener; the rollback attempt owner tracks it through
    # readiness, early exit, or an enforced startup timeout and advances to
    # verified Stable rescue automatically on failure.
    if [ -r "$PROC_ROOT/$$/stat" ]; then
        attempt_start=$(proc_start_time "$PROC_ROOT/$$")
    fi
    attempt_token="$$-${attempt_start:-0}"
    if ! write_rollback_attempt "$target_active" "$attempt_token"; then
        echo "[ota-supervisor] could not persist rollback-attempt marker; refusing boot" >&2
        exit 9
    fi
    arm_attempt_owner=1
elif [ -e "$ROLLBACK_ATTEMPT" ] || [ -L "$ROLLBACK_ATTEMPT" ]; then
    if ! remove_handoff_marker "$ROLLBACK_ATTEMPT"; then
        echo "[ota-supervisor] could not durably clear rollback-attempt marker; refusing boot" >&2
        exit 9
    fi
fi

if [ "$had_pending" = 1 ]; then
    if ! remove_handoff_marker "$ROLLBACK_BLOCKED"; then
        echo "[ota-supervisor] could not durably clear rollback-blocked marker; refusing boot" >&2
        exit 9
    fi
    if ! remove_handoff_marker "$PENDING"; then
        echo "[ota-supervisor] could not durably clear pending marker; refusing boot" >&2
        exit 9
    fi
fi

ln -sfn "$binary" "$LEGACY.next"
mv -f "$LEGACY.next" "$LEGACY"
# Isolate legacy `965ebfe` startup `ensure_supervisor()` writes to a private
# shadow file while carrying the real supervisor path in `ZTE_OTA_REAL_SUPERVISOR`
# for new binaries, matching Rust's direct handoff environment.
real_sup="${ZTE_OTA_REAL_SUPERVISOR:-${ZTE_OTA_SUPERVISOR:-/data/local/tmp/zte-agent-supervisor.sh}}"
owner_sup="$real_sup"
if [ ! -f "$owner_sup" ] && [ -f "$SUPERVISOR_SELF" ]; then
    owner_sup="$SUPERVISOR_SELF"
fi
ZTE_OTA_REAL_SUPERVISOR="$real_sup"
ZTE_OTA_SUPERVISOR="$OTA_ROOT/legacy-supervisor.shadow"
export ZTE_OTA_SUPERVISOR ZTE_OTA_REAL_SUPERVISOR
unset ZTE_OTA_TRIAL ZTE_OTA_PROMOTED
if [ "$arm_attempt_owner" = 1 ]; then
    spawn_rollback_attempt_owner "$$" "$attempt_start" "$binary" "$target_active" "$attempt_token" "$owner_sup"
fi
exec "$binary"
