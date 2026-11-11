#!/usr/bin/env bash
# Side-effect-free admission probe (relay-mihomo-refactor-plan.md, v1
# acceptance). For DURATION seconds it sends owner writes with an invalid JSON
# body to two admission-gated endpoints. A write that is admitted stops at the
# JSON check (400) and changes nothing; the rest are refused before any write.
# Counts "in progress" refusals (the network lock was busy past the 3 s wait)
# apart from real conflicts (the relay or Mihomo owns the network).
#
#   ANDROID_SERIAL=<serial> scripts/probe-admission.sh [seconds] [pause]
#
# Uses the agent's per-start local token over an ADB forward (never printed).
set -euo pipefail
DURATION=${1:-120}
PAUSE=${2:-0.25}
PORT=18091
adb forward "tcp:$PORT" tcp:9090 >/dev/null
trap 'adb forward --remove "tcp:$PORT" >/dev/null 2>&1 || true' EXIT
TOKEN=$(adb shell cat /tmp/zte-agent-run/admin-token | tr -d '\r\n')
[ -n "$TOKEN" ] || { echo "no local token" >&2; exit 1; }
busy=0 conflict=0 admitted=0 gate=0 other=0 total=0
end=$((SECONDS + DURATION))
while [ "$SECONDS" -lt "$end" ]; do
    for path in /api/usb/mode /api/router/lan; do
        reply=$(curl --noproxy '*' -s --max-time 12 -X PUT -H "Authorization: Bearer $TOKEN" \
            -H 'Content-Type: application/json' --data-binary 'not-json' \
            -w '\n%{http_code}' "http://127.0.0.1:$PORT$path" || printf '\n000')
        code=${reply##*$'\n'}
        body=${reply%$'\n'*}
        total=$((total + 1))
        case "$code" in
            409) case "$body" in
                    *"in progress"*) busy=$((busy + 1)) ;;
                    *) conflict=$((conflict + 1)) ;;
                 esac ;;
            400) admitted=$((admitted + 1)) ;;
            503) case "$body" in
                    *"agent busy"*) gate=$((gate + 1)) ;;
                    *) other=$((other + 1)) ;;
                 esac ;;
            *) other=$((other + 1)) ;;
        esac
    done
    sleep "$PAUSE"
done
printf 'requests=%d admitted_400=%d busy_409=%d conflict_409=%d gate_503=%d other=%d\n' \
    "$total" "$admitted" "$busy" "$conflict" "$gate" "$other"
