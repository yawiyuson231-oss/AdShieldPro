#!/usr/bin/env bash
# Install the exact CI APK on a disposable Android emulator and exercise its launcher.
set -euo pipefail
apk=${1:?Pass the verified debug APK path}
serial=${2:-emulator-5554}
package=${3:-com.adshield.pro.debug}
activity="$package/com.adshield.pro.MainActivity"

[[ -s "$apk" ]] || { echo '::error::APK is missing or empty.' >&2; exit 1; }
[[ "$serial" =~ ^emulator-[0-9]+$ ]] || { echo '::error::Install smoke test requires a disposable emulator.' >&2; exit 1; }
[[ "$package" == com.adshield.pro.debug || "$package" == com.adshield.pro.secure ]] ||
    { echo '::error::Refusing to smoke-test an unrecognized application ID.' >&2; exit 1; }
adb=("${ANDROID_HOME:?}/platform-tools/adb" -s "$serial")

fail() {
    echo "::error::$*" >&2
    "${adb[@]}" logcat -b crash -d -t 100 >&2 || true
    exit 1
}

sdk=$("${adb[@]}" shell getprop ro.build.version.sdk | tr -d '\r')
[[ "$sdk" == 29 ]] || fail 'Expected the Android 10 (API 29) baseline emulator.'
abi=$("${adb[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')
[[ "$abi" == x86_64 ]] || fail 'Expected the x86_64 emulator.'
installed=$("${adb[@]}" shell pm list packages "$package" | tr -d '\r')
[[ "$installed" != *"package:$package"* ]] || fail 'Install smoke test requires a fresh Android environment.'

"${adb[@]}" shell input keyevent 82
"${adb[@]}" logcat -b crash -c
install_result=$("${adb[@]}" install "$apk" 2>&1) || fail "Android Package Manager rejected the debug APK: $install_result"
printf '%s\n' "$install_result"
[[ "${install_result//$'\r'/}" == *$'\nSuccess' || "${install_result//$'\r'/}" == Success ]] || fail 'Install did not report success.'
"${adb[@]}" shell pm path "$package" | grep '^package:' || fail 'Expected debug application ID was not installed.'

# Launchers resolve MAIN/LAUNCHER first, then start the component explicitly. An implicit
# am start additionally needs CATEGORY_DEFAULT, which launcher filters do not normally have.
resolved=$("${adb[@]}" shell cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p "$package" | tr -d '\r') ||
    fail 'Android could not resolve an installed launcher entry.'
grep -Fx "$activity" <<< "$resolved" || fail "No AdShield Pro launcher entry: $resolved"
launch=$("${adb[@]}" shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n "$activity" 2>&1) ||
    fail "Android could not launch the app: $launch"
printf '%s\n' "$launch"
grep -qx 'Status: ok' <<< "${launch//$'\r'/}" || fail 'Android did not report a successful launcher start.'

pid=$("${adb[@]}" shell pidof -s "$package" | tr -d '\r') || fail 'App process stopped after launch.'
[[ "$pid" =~ ^[0-9]+$ ]] || fail 'App process was not found after launch.'
# A process can crash just after am start -W succeeds. Give startup work time to settle.
sleep 8
after=$("${adb[@]}" shell pidof -s "$package" | tr -d '\r') || fail 'App process crashed after launch.'
[[ "$after" == "$pid" ]] || fail 'App process restarted during startup.'
resumed=$("${adb[@]}" shell dumpsys activity activities)
grep -E '(mResumedActivity[:=]|topResumedActivity[:=])' <<< "$resumed" | grep -F "$activity" ||
    fail 'AdShield Pro did not stay in the foreground after startup.'

echo "PASSED: Installed and opened $package on Android 10 (API $sdk, x86_64)."
