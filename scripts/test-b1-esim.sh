#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/u60-b1-esim-tests.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT
swiftc -module-cache-path "$test_dir/cache" \
    mobile/ios/OpenU60/Core/Bluetooth/B1BluetoothModels.swift \
    mobile/ios/OpenU60/Core/ESim/B1ESimModels.swift \
    mobile/ios/OpenU60/Core/ESim/B1ESimController.swift \
    mobile/ios/Tests/B1ESimTests.swift -o "$test_dir/b1-esim-tests"
"$test_dir/b1-esim-tests"
