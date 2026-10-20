#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/u60-router-esim-tests.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT
swiftc -module-cache-path "$test_dir/cache" \
    mobile/ios/OpenU60/Features/RouterSettings/SIM/ESim/RouterESimModels.swift \
    mobile/ios/Tests/RouterESimTests.swift -o "$test_dir/router-esim-tests"
"$test_dir/router-esim-tests"
swiftc -module-cache-path "$test_dir/cache" \
    mobile/ios/OpenU60/Core/Models/SignalModels.swift \
    mobile/ios/OpenU60/Core/Networking/AgentError.swift \
    mobile/ios/OpenU60/Core/Concurrency/PollingLoop.swift \
    mobile/ios/OpenU60/Features/RouterSettings/SIM/ESim/RouterESimModels.swift \
    mobile/ios/OpenU60/Features/RouterSettings/SIM/ESim/RouterESimViewModel.swift \
    mobile/ios/Tests/RouterESimFlowTests.swift -o "$test_dir/router-esim-flow-tests"
"$test_dir/router-esim-flow-tests"
swiftc -module-cache-path "$test_dir/cache" \
    mobile/ios/OpenU60/Core/Models/RouterSettingsModels.swift \
    mobile/ios/Tests/MobileNetworkTests.swift -o "$test_dir/mobile-network-tests"
"$test_dir/mobile-network-tests"
swiftc -module-cache-path "$test_dir/cache" \
    mobile/ios/OpenU60/Core/Models/SimIdentity.swift \
    mobile/ios/Tests/SimIdentityTests.swift -o "$test_dir/sim-identity-tests"
"$test_dir/sim-identity-tests"
