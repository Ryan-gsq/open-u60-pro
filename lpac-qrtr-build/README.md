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

The bundle carries a `BUILDINFO` file (lpac commit, patch SHA-256, Alpine pins SHA-256, CA file SHA-256, build time; no host or user names), included in `SHA256SUMS`. zte-agent reports it, with the lpac binary's checksum, in `GET /api/esim/chip` under `lpac`.

## Operator server certificates

The operators' SM-DP+ servers use TLS certificates issued by the GSMA eSIM root CI, not by a web CA. Upstream lpac doesn't check them at all (`CURLOPT_SSL_VERIFYPEER` 0). The patch turns checking on and adds `LPAC_HTTP_CA_FILE`: when it is set, lpac trusts only the roots in that file and ignores the system CA directory. `bundle.py` concatenates `certs/*.pem` into the bundle's `gsma-ci.pem`, and zte-agent passes that file.

`certs/gsma-rsp2-root-ci1.pem` is "GSM Association - RSP2 Root CI1" (valid 2017–2052, SHA-256 fingerprint `5E:3E:91:FD:45:43:27:C3:AF:5D:32:A7:A7:3B:BC:59:FE:43:AA:7D:85:FD:32:D5:DB:44:42:3F:80:A5:6B:B3`). The SHA-1 of its public key, `81370f5125d0b1d408d4c3b232e6d25e795bebfb`, matches the CI key ID that the tested card lists in `chip info` (`euiccCiPKIdListForVerification`), so it is the root the card itself trusts. Add a root here only if a card lists its key ID.

## Running lpac by hand

zte-agent holds a `flock` on `/tmp/lpac.lock` while it runs lpac. When running lpac by hand on the router, take the same lock so the two never talk to the card at once:

```sh
cd /data/lpac && flock -n /tmp/lpac.lock env LPAC_APDU=qmi_qrtr LPAC_APDU_QMI_QRTR_NODE=3 LPAC_APDU_QMI_UIM_SLOT=1 \
  LPAC_HTTP=curl LPAC_HTTP_CA_FILE=/data/lpac/gsma-ci.pem \
  GIO_MODULE_DIR=/data/lpac/no-modules GIO_USE_VFS=local GIO_USE_PROXY_RESOLVER=dummy \
  ./ld-musl-aarch64.so.1 --library-path lib ./lpac chip info
```

BusyBox `flock` on the router has no `-w` (wait) option: use `-n` and retry.

## Files

Only the recipe is committed. The inputs and outputs (`downloads/`, `sources/`, `work/`, `sysroot/`, `host-tools/`, `host-qemu/`, `vm/`, `out/`, `toolchain.cmake`, run logs) are ignored by git; recreate them locally.

| Path | Purpose |
|---|---|
| `evidence/initial-downloads.json` | Pinned inputs (lpac commit `c7c8d4f`, cJSON, Alpine v3.22 aarch64 indexes) with URLs and SHA-256 |
| `evidence/alpine-packages.json`, `qemu-bottles.json`, `kernel-5.15.json` | Pinned Alpine packages, QEMU bottles and test kernel |
| `make-bundle.sh` | One-command build: tools, pinned downloads, patch, sysroot, lpac, `bounded`, bundle |
| `install-to-router.sh` | Copies `out/bundle` to the router's `/data/lpac`, checks the hashes and the version |
| `scripts/fetch_sysroot.py` | Downloads the pinned Alpine packages and extracts them into `sysroot/` (no APK scripts run, nothing installed on the host); `--refresh-pins` re-resolves them from the current index |
| `scripts/fetch_qemu.py` | Extracts QEMU Homebrew bottles into the workspace for VM tests |
| `patches/0001-isolated-qrtr-hardening.patch` | Hardening of lpac's QRTR backend, TLS certificate checking for operator servers, and the card's result codes in profile errors (`cat busy`, `undefined error`, `unknown result N` instead of `unknown`); apply to the lpac source in `work/lpac` |
| `certs/` | Trusted GSMA root CI certificates for the operators' TLS servers (bundled as `gsma-ci.pem`) |
| `scripts/build.sh` | Configures and builds lpac with `aarch64-linux-musl-gcc` (`$CC`) and the `pkgconf` from `host-tools/` (`$PKGCONF`) |
| `scripts/build_tests.sh`, `tests/` | Fault-injection and loader tests against patched and baseline drivers |
| `scripts/bundle.py`, `scripts/smoke` | Assemble a self-contained bundle with its own musl loader; `smoke` only prints the version |
| `scripts/make_initramfs.py`, `scripts/run_qemu.py` | Run the tests in an aarch64 QEMU VM |

## License

The patch modifies lpac files under `driver/` and `src/`, which lpac licenses as AGPL-3.0-only (except the QMI files that carry an MIT SPDX header), so `patches/` is distributed under lpac's terms, not this repository's MIT license. The scripts and tests are MIT like the rest of the repository.
