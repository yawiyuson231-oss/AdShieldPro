#!/usr/bin/env bash
# Run only on a disposable emulator. Never use on a phone: this uninstalls the app.
set -euo pipefail
CURRENT=/tmp/adshield-apk/current/AdShieldPro-2.10.10-release.apk
PREVIOUS=/tmp/adshield-apk/previous/AdShieldPro-2.10.9-release.apk
install_or_report() {
  local operation="$1"
  shift
  if ! adb install "$@" > /tmp/install-result.txt 2>&1; then
    cat /tmp/install-result.txt
    echo "::error::$operation failed: $(tr '\n' ' ' < /tmp/install-result.txt)"
    exit 1
  fi
  cat /tmp/install-result.txt
}
echo 'Checking a fresh installation of the exact published APK'
install_or_report 'Fresh install' "$CURRENT"
adb shell dumpsys package com.adshield.pro | grep -E 'versionCode=|versionName='
adb uninstall com.adshield.pro
echo 'Checking an in-place upgrade from the previous published release'
install_or_report 'Previous version install' "$PREVIOUS"
install_or_report 'Upgrade' -r "$CURRENT"
adb shell dumpsys package com.adshield.pro | grep -q 'versionCode=21010'
adb shell dumpsys package com.adshield.pro | grep -q 'versionName=2.10.10'
echo 'Fresh install and upgrade both succeeded.'
