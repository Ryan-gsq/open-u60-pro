#!/bin/sh
# Copies out/bundle to the router's /data/lpac (where zte-agent looks for lpac), checks it and
# keeps the previous copy as /data/lpac.old.
# Usage: ./install-to-router.sh [user@host] [ssh port]     default: root@192.168.0.1 2222
set -eu
R=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOST=${1:-root@192.168.0.1}
PORT=${2:-2222}
DEST=${LPAC_DEST:-/data/lpac}
[ -f "$R/out/bundle/SHA256SUMS" ] || { echo "no bundle: run ./make-bundle.sh first" >&2; exit 1; }
cd "$R/out/bundle"
COPYFILE_DISABLE=1 tar --no-xattrs -cf - . 2>/dev/null | ssh -p "$PORT" "$HOST" "
  set -e
  rm -rf '$DEST.new' && mkdir -p '$DEST.new' && tar -C '$DEST.new' -xf - 2>/dev/null
  cd '$DEST.new' && sha256sum -c SHA256SUMS >/dev/null
  chown -R root:root . && chmod -R go-w . && chmod 700 .
  ./bounded 10 ./smoke version
  rm -rf '$DEST.old'; [ -d '$DEST' ] && mv '$DEST' '$DEST.old'; mv '$DEST.new' '$DEST'
  echo 'installed to $DEST'"
