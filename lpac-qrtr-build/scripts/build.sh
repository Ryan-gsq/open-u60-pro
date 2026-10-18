#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PATH="$ROOT/host-tools/bin:/opt/homebrew/opt/musl-cross/bin:$PATH"
CC=${CC:-$(command -v aarch64-linux-musl-gcc)}
# The pkgconf binary itself: pip's pkg-config launcher prints nothing under Python 3.15.
PKGCONF=${PKGCONF:-$(ls -d "$ROOT"/host-tools/lib/python3*/site-packages/pkgconf/.bin/pkgconf 2>/dev/null | head -1)}
[ -x "$PKGCONF" ] || { echo 'pkgconf not found: run ./make-bundle.sh or set PKGCONF' >&2; exit 1; }
export PKG_CONFIG_LIBDIR="$ROOT/sysroot/usr/lib/pkgconfig:$ROOT/sysroot/usr/share/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$ROOT/sysroot"
unset PKG_CONFIG_PATH
cat > "$ROOT/toolchain.cmake" <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_C_COMPILER $CC)
set(CMAKE_SYSROOT "$ROOT/sysroot")
set(CMAKE_FIND_ROOT_PATH "$ROOT/sysroot")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
EOF
"$PKGCONF" --modversion qmi-glib qrtr-glib glib-2.0 libcurl | tee "$ROOT/evidence/build-dependency-versions.txt"
cmake --fresh -S "$ROOT/work/lpac" -B "$ROOT/out/build" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$ROOT/toolchain.cmake" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_C_FLAGS='-Wall -Wextra -Wformat=2 -fstack-protector-strong' \
  -DCMAKE_EXE_LINKER_FLAGS='-Wl,-z,relro,-z,now' \
  -DCMAKE_SHARED_LINKER_FLAGS='-Wl,-z,relro,-z,now' \
  -DFETCHCONTENT_SOURCE_DIR_CJSON="$ROOT/sources/cJSON-4818f043bda624b5738384eae3a0189b2bd1f5e1" \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
  -DSTANDALONE_MODE=ON -DBUILD_TESTING=OFF \
  -DLPAC_WITH_APDU_PCSC=OFF -DLPAC_WITH_APDU_QMI=OFF \
  -DLPAC_WITH_APDU_QMI_QRTR=ON -DLPAC_WITH_HTTP_CURL=ON \
  -DPKG_CONFIG_EXECUTABLE="$PKGCONF"
cmake --build "$ROOT/out/build" --parallel 4
DESTDIR="$ROOT/out/stage" cmake --install "$ROOT/out/build"
