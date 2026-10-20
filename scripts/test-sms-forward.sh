#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/u60-sms-forward-tests.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT
swiftc -module-cache-path "$test_dir/cache" \
    mobile/ios/OpenU60/Core/Networking/AgentError.swift \
    mobile/ios/OpenU60/Features/SMS/Forward/SMSForwardModels.swift \
    mobile/ios/OpenU60/Features/SMS/Forward/SMSForwardViewModel.swift \
    mobile/ios/Tests/SMSForwardLogTests.swift -o "$test_dir/sms-forward-tests"
"$test_dir/sms-forward-tests"
