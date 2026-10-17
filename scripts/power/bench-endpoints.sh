#!/bin/zsh
# Per-endpoint cost: for each endpoint, run a router-side capture while sending N requests at 1/s from the Mac.
set -u
R="root@192.168.0.1"; SSH=(ssh -o BatchMode=yes -o ConnectTimeout=5 -p 2222 $R)
N=${N:-20}; WIN=$((N + 6))
PW=$("${SSH[@]}" "sed -n 's/^export ZTE_AGENT_PASSWORD=//p' /data/local/tmp/start_zte_agent.sh" | tr -d '"'"'")
TOK=$(curl -s -X POST http://192.168.0.1:9090/api/auth/login -H 'Content-Type: application/json' --data-binary "{\"password\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$PW")}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"]["token"])')
unset PW
[[ -n "$TOK" ]] || { echo "login failed"; exit 1; }
for ep in "$@"; do
  name=$(echo "$ep" | tr '/' '_' | sed 's/^_api_//')
  "${SSH[@]}" "sh /tmp/measure.sh ep-$name $WIN" >/dev/null 2>&1 &
  sshpid=$!
  sleep 3
  for i in $(seq 1 $N); do
    curl -s -o /dev/null -w "%{http_code} " -H "Authorization: Bearer $TOK" "http://192.168.0.1:9090$ep"
    sleep 1
  done
  echo " <- $ep"
  wait $sshpid
  "$(dirname "$0")/fetch.sh" "ep-$name" > "${POWER_OUT:-/tmp/u60-perf}/ep-$name.txt" 2>&1
  printf "%-32s " "$ep"; grep -E "agent own CPU|reaped children|agent forks" "${POWER_OUT:-/tmp/u60-perf}/ep-$name.txt" | tr '\n' '|'; echo
done
unset TOK
