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
