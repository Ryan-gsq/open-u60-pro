#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/u60-b1-tests.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT
python3 scripts/verify-ios-bluetooth-setup.py
swiftc -module-cache-path "$test_dir/cache" \
    mobile/ios/OpenU60/Core/Bluetooth/B1BluetoothModels.swift \
    mobile/ios/OpenU60/Core/Bluetooth/B1BluetoothController.swift \
    mobile/ios/OpenU60/Core/Bluetooth/B1CoreBluetoothTransport.swift \
    mobile/ios/Tests/B1BluetoothTests.swift -o "$test_dir/b1-tests"
"$test_dir/b1-tests"
