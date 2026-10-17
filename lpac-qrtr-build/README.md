# lpac QMI-over-QRTR build recipe (experimental)

Cross-build of [lpac](https://github.com/estkme-group/lpac) with only the QMI-over-QRTR APDU backend, as a private bundle for the U60 Pro (aarch64 musl). Background and results: [`docs/research/U60_Pro_QRTR_lpac_Feasibility.md`](../docs/research/U60_Pro_QRTR_lpac_Feasibility.md). Nothing here has been used to manage a profile on the router; treat it as research.

Only the recipe is committed. The inputs and outputs (`downloads/`, `sources/`, `work/`, `sysroot/`, `host-tools/`, `host-qemu/`, `vm/`, `out/`, `toolchain.cmake`, run logs) are ignored by git; recreate them locally.

| Path | Purpose |
|---|---|
| `evidence/initial-downloads.json` | Pinned inputs (lpac commit `c7c8d4f`, cJSON, Alpine v3.22 aarch64 indexes) with URLs and SHA-256 |
| `evidence/alpine-packages.json`, `qemu-bottles.json`, `kernel-5.15.json` | Pinned Alpine packages, QEMU bottles and test kernel |
| `scripts/fetch_sysroot.py` | Extracts the pinned Alpine packages into `sysroot/` (no APK scripts run, nothing installed on the host) |
| `scripts/fetch_qemu.py` | Extracts QEMU Homebrew bottles into the workspace for VM tests |
| `patches/0001-isolated-qrtr-hardening.patch` | Hardening of lpac's QRTR backend; apply to the lpac source in `work/lpac` |
| `scripts/build.sh` | Configures and builds lpac with `aarch64-linux-musl-gcc` (Homebrew `musl-cross`) and `pkgconf` from `host-tools/` |
| `scripts/build_tests.sh`, `tests/` | Fault-injection and loader tests against patched and baseline drivers |
| `scripts/bundle.py`, `scripts/smoke` | Assemble a self-contained bundle with its own musl loader; `smoke` only prints the version |
| `scripts/make_initramfs.py`, `scripts/run_qemu.py` | Run the tests in an aarch64 QEMU VM |

## License

The patch modifies lpac files under `driver/`, which lpac licenses as AGPL-3.0-only (except the QMI files that carry an MIT SPDX header), so `patches/` is distributed under lpac's terms, not this repository's MIT license. The scripts and tests are MIT like the rest of the repository.
