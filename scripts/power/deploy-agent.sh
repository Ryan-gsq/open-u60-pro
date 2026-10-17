#!/bin/zsh
# Deploy the working-tree zte-agent to the router with a backup and a smoke test.
# Usage: scripts/power/deploy-agent.sh <tag>      (e.g. power-1)
# Builds from the working tree (never from main: it lacks Live Activity/STK),
# backs up /data/zte-agent to /data/zte-agent.bak-<tag>, uploads via ssh (no
# sftp-server on the router), verifies sha256, restarts with the existing start
# script, and checks a few endpoints.
set -eu
TAG=${1:?tag}
R="root@192.168.0.1"; P=2222
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=5 -p $P $R)
cd "$(dirname "$0")/../.."

cargo build --release --target aarch64-unknown-linux-musl -p zte-agent
BIN=target/aarch64-unknown-linux-musl/release/zte-agent
SHA=$(shasum -a 256 "$BIN" | cut -d' ' -f1)
echo "local sha256 $SHA ($(stat -f %z "$BIN") bytes)"

"${SSH[@]}" "cp /data/zte-agent /data/zte-agent.bak-$TAG && ls -l /data/zte-agent.bak-$TAG"
"${SSH[@]}" "cat > /data/zte-agent.new" < "$BIN"
"${SSH[@]}" "sha256sum /data/zte-agent.new | cut -d' ' -f1" | grep -qx "$SHA" || { echo "sha mismatch after upload"; exit 1; }
echo "upload verified"

"${SSH[@]}" '
  killall zte-agent 2>/dev/null; sleep 1
  for p in $(pidof ubus); do [ "$(awk "{print \$4}" /proc/$p/stat)" = 1 ] && kill $p && echo "killed orphan ubus listen $p"; done
  chmod +x /data/zte-agent.new && mv /data/zte-agent.new /data/zte-agent
  sh /data/local/tmp/start_zte_agent.sh
  sleep 3
  echo "agent pid $(pidof zte-agent) threads $(ls /proc/$(pidof zte-agent)/task | wc -l)"
  sha256sum /data/zte-agent | cut -d" " -f1
'
echo "smoke test:"
for ep in /api/device /api/live-activity /api/stk/session /api/tailscale/status /api/network/signal /api/wifi/status /api/device/system; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://192.168.0.1:9090$ep")
  echo "  $ep -> $code (401 expected without a token)"
done
echo "rollback: ssh -p $P $R 'killall zte-agent; cp /data/zte-agent.bak-$TAG /data/zte-agent; sh /data/local/tmp/start_zte_agent.sh'"
