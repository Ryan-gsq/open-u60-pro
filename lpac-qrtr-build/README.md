# lpac QMI-over-QRTR build recipe

Cross-build of [lpac](https://github.com/estkme-group/lpac) with only the QMI-over-QRTR APDU backend, as a private bundle for the U60 Pro (aarch64 musl). zte-agent runs it to list, switch, download and delete eSIM profiles (see [`zte-agent/docs/esim.md`](../zte-agent/docs/esim.md)). Background: [`docs/research/U60_Pro_QRTR_lpac_Feasibility.md`](../docs/research/U60_Pro_QRTR_lpac_Feasibility.md).

## Build and install

Needs Python 3, curl, tar, patch and an aarch64 musl cross compiler (`aarch64-linux-musl-gcc`; macOS: `brew install filosottile/musl-cross/musl-cross`), plus SSH access to the router (set up by `setup.sh`).

```sh
cd lpac-qrtr-build
./make-bundle.sh            # downloads the pinned inputs, checks their SHA-256, builds out/bundle (~23 MB)
./install-to-router.sh      # copies it to /data/lpac on root@192.168.0.1:2222 and runs a version check
```

`make-bundle.sh` keeps its build tools (cmake, ninja, pkgconf) in a private Python venv under `host-tools/`; nothing is installed system-wide. Alpine replaces library packages in the v3.22 repository with security updates, after which the pinned files can no longer be downloaded and the build stops with a list of them. `./make-bundle.sh --refresh-pins` then resolves the same package set against the current Alpine index, rebuilds, and rewrites `evidence/alpine-packages.json` and the index pins; test the bundle on the router and commit the new pins. `install-to-router.sh [user@host] [port]` keeps the previous bundle as `/data/lpac.old`. The agent needs no restart.

Only the recipe is committed. The inputs and outputs (`downloads/`, `sources/`, `work/`, `sysroot/`, `host-tools/`, `host-qemu/`, `vm/`, `out/`, `toolchain.cmake`, run logs) are ignored by git; recreate them locally.

| Path | Purpose |
|---|---|
| `evidence/initial-downloads.json` | Pinned inputs (lpac commit `c7c8d4f`, cJSON, Alpine v3.22 aarch64 indexes) with URLs and SHA-256 |
| `evidence/alpine-packages.json`, `qemu-bottles.json`, `kernel-5.15.json` | Pinned Alpine packages, QEMU bottles and test kernel |
| `make-bundle.sh` | One-command build: tools, pinned downloads, patch, sysroot, lpac, `bounded`, bundle |
| `install-to-router.sh` | Copies `out/bundle` to the router's `/data/lpac`, checks the hashes and the version |
| `scripts/fetch_sysroot.py` | Downloads the pinned Alpine packages and extracts them into `sysroot/` (no APK scripts run, nothing installed on the host); `--refresh-pins` re-resolves them from the current index |
| `scripts/fetch_qemu.py` | Extracts QEMU Homebrew bottles into the workspace for VM tests |
| `patches/0001-isolated-qrtr-hardening.patch` | Hardening of lpac's QRTR backend; apply to the lpac source in `work/lpac` |
| `scripts/build.sh` | Configures and builds lpac with `aarch64-linux-musl-gcc` (`$CC`) and the `pkgconf` from `host-tools/` (`$PKGCONF`) |
| `scripts/build_tests.sh`, `tests/` | Fault-injection and loader tests against patched and baseline drivers |
| `scripts/bundle.py`, `scripts/smoke` | Assemble a self-contained bundle with its own musl loader; `smoke` only prints the version |
| `scripts/make_initramfs.py`, `scripts/run_qemu.py` | Run the tests in an aarch64 QEMU VM |

## License

The patch modifies lpac files under `driver/`, which lpac licenses as AGPL-3.0-only (except the QMI files that carry an MIT SPDX header), so `patches/` is distributed under lpac's terms, not this repository's MIT license. The scripts and tests are MIT like the rest of the repository.
