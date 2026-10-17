#!/bin/sh
set -eu
R=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PKG_CONFIG_LIBDIR="$R/sysroot/usr/lib/pkgconfig:$R/sysroot/usr/share/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$R/sysroot"
unset PKG_CONFIG_PATH
PC="$R/host-tools/lib/python3.14/site-packages/pkgconf/.bin/pkgconf"
CC=/opt/homebrew/opt/musl-cross/bin/aarch64-linux-musl-gcc
S="$R/work/lpac"
COMMON="--sysroot=$R/sysroot -O0 -g -Wall -Wextra -DLPAC_WITH_DRIVER_APDU_QMI_QRTR -I$S/driver/apdu -I$S/driver -I$S/utils -I$S -I$R/sources/cJSON-4818f043bda624b5738384eae3a0189b2bd1f5e1/.. -I$R/out/stage/include"
# cJSON public header has its cjson/ prefix in the generated build tree.
COMMON="$COMMON -I$R/out/build/_deps/cjson-build/include"
CFLAGS=$($PC --cflags qmi-glib)
LIBS=$($PC --libs qmi-glib)
mkdir -p "$R/out/tests"
$CC $COMMON $CFLAGS "$R/tests/faults.c" "$S/driver/apdu/qmi_qrtr.c" "$S/driver/apdu/qmi_common.c" $LIBS -Wl,--wrap=calloc -o "$R/out/tests/faults"
BASE="$R/sources/lpac-c7c8d4f817ddfeab21d104870b4647439f9cfab7"
$CC $COMMON $CFLAGS -DBASELINE -Dmalloc=poison_malloc -c "$BASE/driver/apdu/qmi_qrtr.c" -o "$R/out/tests/baseline-driver.o"
$CC $COMMON $CFLAGS -DBASELINE -c "$BASE/driver/apdu/qmi_common.c" -o "$R/out/tests/baseline-common.o"
$CC $COMMON $CFLAGS -DBASELINE "$R/tests/faults.c" "$R/out/tests/baseline-driver.o" "$R/out/tests/baseline-common.o" -L"$R/out/stage/executables/lib" -llpac-utils $LIBS -o "$R/out/tests/baseline"
mkdir -p "$R/out/tests/driver"
$CC $COMMON -fPIC -shared -DFAKE_APDU "$R/tests/fake-driver.c" -o "$R/out/tests/driver/driver_apdu_fakeapdu.so"
$CC $COMMON -fPIC -shared "$R/tests/fake-driver.c" -o "$R/out/tests/driver/driver_http_fakehttp.so"
$CC $COMMON "$R/tests/loader-faults.c" -Wl,--export-dynamic -Wl,-rpath,'$ORIGIN' -L"$R/out/stage/executables/lib" -leuicc-driver-loader -o "$R/out/tests/loader-faults"
cp "$R/sysroot/lib/ld-musl-aarch64.so.1" "$R/out/tests/ld-musl-aarch64.so.1"
