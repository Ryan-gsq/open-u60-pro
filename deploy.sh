#!/bin/bash
set -e

PASSWORD="${1:?Usage: ./deploy.sh <agent-password>}"
if [[ "$PASSWORD" == *$'\n'* || "$PASSWORD" == *$'\r'* ]]; then
    echo "Agent password cannot contain a line break." >&2
    exit 1
fi
DEVICE="192.168.0.1"
SSH_PORT=2222
TARGET=aarch64-unknown-linux-musl
BINARY=target/$TARGET/release/zte-agent
OTA_ROOT=/data/open-u60/update
REMOTE_SLOT=$OTA_ROOT/slot-a/zte-agent
REMOTE_BIN=/data/zte-agent
SUPERVISOR=/data/local/tmp/zte-agent-supervisor.sh
SUPERVISOR_LOCAL=scripts/router/zte-agent-supervisor.sh
STARTUP_SCRIPT=/data/local/tmp/start_zte_agent.sh
SSH="ssh -p $SSH_PORT -o StrictHostKeyChecking=no root@$DEVICE"

# 1. Build
echo "Building..."
cargo build --locked --release --target $TARGET -p zte-agent

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

WORKDIR=$(mktemp -d)
STAGE=""
cleanup() {
    if [ -n "$STAGE" ]; then
        $SSH "rm -rf '$STAGE'" >/dev/null 2>&1 || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# 2. Size comparison
LOCAL_SIZE=$(wc -c < "$BINARY")
REMOTE_SIZE=$($SSH "wc -c < $REMOTE_SLOT 2>/dev/null" 2>/dev/null || echo 0)
DIFF=$((LOCAL_SIZE - REMOTE_SIZE))
if [ "$REMOTE_SIZE" -eq 0 ]; then
    echo "Binary size: $LOCAL_SIZE bytes (first deploy)"
else
    echo "Binary size: $REMOTE_SIZE -> $LOCAL_SIZE bytes ($( [ $DIFF -ge 0 ] && echo '+' )${DIFF} bytes)"
fi

# 3. Stage and install verified A/B slots via scripts/install-agent.py
#    (matching setup.sh's bootstrap.sha256 layout, lock, and recovery checks).
echo "Staging verified A/B deployment..."
STAGE="/data/zte-agent-deploy-$(date +%Y%m%d-%H%M%S)-$$"
$SSH "umask 077; mkdir '$STAGE'; mkdir -p /data/local/tmp"
LOCAL_SHA=$(sha256_file "$BINARY")
cat "$BINARY" | $SSH "cat > '$STAGE/agent.new' && chmod 700 '$STAGE/agent.new'"
REMOTE_SHA=$($SSH "sha256sum '$STAGE/agent.new'" | awk '{print $1}')
if [ "$LOCAL_SHA" != "$REMOTE_SHA" ]; then
    echo "Staged binary checksum mismatch; current agent is untouched." >&2
    exit 1
fi
REMOTE_VERSION=$($SSH "'$STAGE/agent.new' --version" | awk 'NR == 1 {print $2}')
if [[ ! "$REMOTE_VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$ ]]; then
    echo "The staged agent reported an invalid build version; current agent is untouched." >&2
    exit 1
fi
$SSH "'$STAGE/agent.new' ota-probe '$REMOTE_VERSION' >/dev/null 2>&1"

cat "$SUPERVISOR_LOCAL" | $SSH "cat > '$STAGE/supervisor.new' && chmod 700 '$STAGE/supervisor.new'"
printf '%s' "$PASSWORD" | python3 scripts/install-agent.py launcher "$WORKDIR/start.sh" override
python3 scripts/install-agent.py install "$WORKDIR/install.sh"
cat "$WORKDIR/start.sh" | $SSH "cat > '$STAGE/start.sh' && chmod 700 '$STAGE/start.sh'"
cat "$WORKDIR/install.sh" | $SSH "cat > '$STAGE/install.sh' && chmod 700 '$STAGE/install.sh'"
RC_SHA=$($SSH "sha256sum /etc/rc.local" | awk '{print $1}')

echo "Installing verified A/B slots and restarting agent..."
$SSH "sh '$STAGE/install.sh' '$STAGE' '$RC_SHA' '$LOCAL_SHA' '$REMOTE_VERSION'"
$SSH "rm -rf '$STAGE'"
STAGE=""

# 4. Verify
echo "Verifying..."
sleep 2
printf '%s' "$PASSWORD" | python3 -c 'import json,sys; json.dump({"password":sys.stdin.read()},sys.stdout)' >"$WORKDIR/login.json"
chmod 600 "$WORKDIR/login.json"
TOKEN=$(curl -sf http://$DEVICE:9090/api/auth/login -H 'Content-Type: application/json' --data-binary "@$WORKDIR/login.json" | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["token"])')
curl -sf http://$DEVICE:9090/api/device -H "Authorization: Bearer $TOKEN" > /dev/null
echo "Deploy successful!"
