#!/usr/bin/env python3
"""Check source and optional built iOS app for the foreground BLE configuration."""

import argparse
import pathlib
import plistlib
import subprocess


def verify_plist(path: pathlib.Path) -> dict:
    with path.open("rb") as stream:
        info = plistlib.load(stream)
    usage = info.get("NSBluetoothAlwaysUsageDescription", "")
    if not isinstance(usage, str) or not usage.strip():
        raise SystemExit(f"Missing Bluetooth privacy purpose in {path}")
    background = set(info.get("UIBackgroundModes", []))
    if background & {"bluetooth-central", "bluetooth-peripheral"}:
        raise SystemExit(f"Bluetooth background mode conflicts with foreground-only sensing: {path}")
    # BLE is an optional router companion feature, so it must not restrict installation.
    capabilities = info.get("UIRequiredDeviceCapabilities", [])
    required_ble = capabilities.get("bluetooth-le", False) if isinstance(capabilities, dict) else "bluetooth-le" in capabilities
    if required_ble:
        raise SystemExit(f"Optional BLE feature incorrectly restricts device installation: {path}")
    return info


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", nargs="?", type=pathlib.Path, help="Optional built OpenU60.app path")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent.parent
    source = verify_plist(root / "mobile/ios/OpenU60/Resources/Info.plist")
    if args.app:
        built = verify_plist(args.app / "Info.plist")
        if built["NSBluetoothAlwaysUsageDescription"] != source["NSBluetoothAlwaysUsageDescription"]:
            raise SystemExit("Built Bluetooth privacy description differs from the source configuration")
        executable = args.app / built["CFBundleExecutable"]
        linked = subprocess.run(["xcrun", "otool", "-L", str(executable)],
                                check=True, text=True, capture_output=True).stdout
        # Xcode debug builds load the app implementation from a companion dylib.
        debug_name = built["CFBundleExecutable"] + ".debug.dylib"
        if f"@rpath/{debug_name}" in linked:
            linked += subprocess.run(["xcrun", "otool", "-L", str(args.app / debug_name)],
                                     check=True, text=True, capture_output=True).stdout
        if "/CoreBluetooth.framework/" not in linked:
            raise SystemExit("Built app does not link CoreBluetooth.framework")
    print("iOS BLE setup passed: privacy description, foreground-only mode, optional device support"
          + (", built bundle and CoreBluetooth linkage" if args.app else ""))


if __name__ == "__main__":
    main()
