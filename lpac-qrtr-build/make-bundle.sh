#!/bin/sh
# Builds the private lpac bundle (out/bundle) for the U60 Pro from the pinned inputs.
# Usage: ./make-bundle.sh [--refresh-pins]
#   --refresh-pins: Alpine has replaced pinned library packages; resolve against the current
#   Alpine v3.22 indexes and update evidence/ (commit the result).
#
# Needs python3, curl, tar, patch and an aarch64 musl cross compiler (aarch64-linux-musl-gcc)
# on PATH or in $CC. macOS: brew install filosottile/musl-cross/musl-cross
# Everything else (cmake, ninja, pkgconf, lpac and cJSON sources, Alpine libraries) is
# downloaded into this directory and checked against the SHA-256 pins in evidence/.
set -eu
R=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REFRESH=
[ "${1:-}" = --refresh-pins ] && REFRESH=--refresh-pins
cd "$R"
step() { printf '\n== %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

CC=${CC:-$(command -v aarch64-linux-musl-gcc || echo /opt/homebrew/opt/musl-cross/bin/aarch64-linux-musl-gcc)}
[ -x "$CC" ] || die "aarch64-linux-musl-gcc not found (set CC or install musl-cross)"
for t in python3 curl tar patch; do command -v "$t" >/dev/null || die "$t not found"; done
export CC

step "1/7 build tools (private venv: cmake, ninja, pkgconf)"
if [ ! -x host-tools/bin/cmake ] || [ ! -x host-tools/bin/ninja ] || ! ls host-tools/lib/python3*/site-packages/pkgconf/.bin/pkgconf >/dev/null 2>&1; then
  python3 -m venv host-tools
  host-tools/bin/pip install --quiet cmake==3.31.10 ninja==1.13.2 pkgconf==3.0.1.post0
fi

step "2/7 pinned downloads"
mkdir -p downloads
REFRESH="$REFRESH" python3 - <<'PY'
import hashlib, json, os, subprocess
from pathlib import Path
refresh = bool(os.environ.get('REFRESH'))
pins_path = Path('evidence/initial-downloads.json')
pins = json.loads(pins_path.read_text())
for d in pins:
    index = d['name'].startswith('alpine-')
    if index and not refresh:
        continue  # only needed to re-resolve packages; the package pins are used directly
    dest = Path('downloads') / d['name']
    if index:
        dest.unlink(missing_ok=True)  # Alpine updates the index in place
    ok = dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == d['sha256']
    if not ok:
        print('fetching', d['name'])
        subprocess.run(['curl', '-fsSL', '--retry', '3', '-o', str(dest), d['url']], check=True)
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        if index:
            d['sha256'] = digest
            d['bytes'] = dest.stat().st_size
        elif digest != d['sha256']:
            dest.unlink()
            raise SystemExit(f"checksum mismatch for {d['name']}")
    print('ok', d['name'])
if refresh:
    pins_path.write_text(json.dumps(pins, indent=2) + '\n')
PY

step "3/7 sources (lpac + hardening patch, cJSON, Alpine indexes)"
if [ -n "$REFRESH" ]; then
  for repo in main community; do
    tar -xzf "downloads/alpine-$repo-index.tar.gz" -O APKINDEX > "downloads/alpine-$repo-APKINDEX"
  done
fi
mkdir -p sources work
LPAC_SRC=sources/lpac-c7c8d4f817ddfeab21d104870b4647439f9cfab7
[ -d "$LPAC_SRC" ] || tar -xzf downloads/lpac-c7c8d4f.tar.gz -C sources
[ -d sources/cJSON-4818f043bda624b5738384eae3a0189b2bd1f5e1 ] || tar -xzf downloads/cjson-4818f043.tar.gz -C sources
rm -rf work/lpac
cp -R "$LPAC_SRC" work/lpac
(cd work/lpac && patch -p1 --quiet < "$R/patches/0001-isolated-qrtr-hardening.patch")

step "4/7 sysroot (pinned Alpine v3.22 aarch64 libraries, no package scripts run)"
python3 scripts/fetch_sysroot.py $REFRESH

step "5/7 build lpac"
sh scripts/build.sh

step "6/7 time-limit helper"
"$CC" -static -Os -Wall -Wextra -o out/bounded tests/bounded.c

step "7/7 bundle"
rm -rf out/bundle
python3 scripts/bundle.py
printf '\nbundle ready: %s (%s)\ninstall it with: ./install-to-router.sh\n' "$R/out/bundle" "$(du -sh out/bundle | cut -f1)"
