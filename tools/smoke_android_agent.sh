#!/usr/bin/env bash
# Exercise the real debug Agent on the disposable Android emulator used by Android CI.
set -euo pipefail
apk=${1:?Pass the debug instrumentation APK path}
serial=${2:-emulator-5554}
[[ -s "$apk" ]] || { echo '::error::Instrumentation APK is missing.' >&2; exit 1; }
[[ "$serial" =~ ^emulator-[0-9]+$ ]] || { echo '::error::Agent tests require a disposable emulator.' >&2; exit 1; }
adb=("${ANDROID_HOME:?}/platform-tools/adb" -s "$serial")
[[ $("${adb[@]}" shell getprop ro.kernel.qemu | tr -d '\r') == 1 ]] || {
    echo '::error::Refusing to change connectivity on a non-emulator device.' >&2
    exit 1
}

"${adb[@]}" install -t "$apk"
"${adb[@]}" shell svc wifi disable
"${adb[@]}" shell svc data disable

result=$(mktemp)
trap 'rm -f "$result"' EXIT
runner=com.adshield.pro.debug.test/androidx.test.runner.AndroidJUnitRunner
classes=com.adshield.pro.AetherAgentDeviceTest,com.adshield.pro.AetherAgentCancellationDeviceTest,com.adshield.pro.EvolutionUpdaterDeviceTest
# am instrument can exit 0 even on a failed test or before running any cases.
timeout 300 "${adb[@]}" shell am instrument -w -e class "$classes" "$runner" | tr -d '\r' | tee "$result"
if ! grep -qx 'OK (6 tests)' "$result"; then
    echo '::error::Expected all 4 Android Agent and 2 evolution updater tests to pass.' >&2
    "${adb[@]}" logcat -b crash -d -t 100 >&2 || true
    exit 1
fi
