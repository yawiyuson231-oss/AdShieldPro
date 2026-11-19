"""Exercise installer and publication gates without Android or release writes."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

TOOLS = Path(__file__).resolve().parents[1]


class AndroidDeliveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {
            'PATH': f'{self.root}/bin:{os.environ["PATH"]}',
            'ANDROID_HOME': str(self.root / 'sdk'),
            'RUNNER_TEMP': str(self.root),
            'GITHUB_STEP_SUMMARY': str(self.root / 'summary'),
        }
        self.apk_rel = Path('app/build/outputs/apk/debug/app-debug.apk')
        self.file(self.apk_rel, 'stand-in bytes for test only')
        self.file('app/build.gradle.kts', '    versionName = "2.11.1"\n')

    def file(self, path, text, executable=False):
        path = self.root / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        if executable:
            path.chmod(0o700)

    def run_script(self, name, *args, **extra_env):
        return subprocess.run(['bash', TOOLS / name, *args], cwd=self.root,
                              env={**self.env, **extra_env}, text=True, capture_output=True, timeout=15)

    def mock_emulator(self):
        self.file('bin/sleep', '#!/bin/sh\nexit 0\n', executable=True)
        self.file('sdk/platform-tools/adb', '''#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -s && "$2" == emulator-5554 ]]
shift 2
case "$*" in
'shell getprop ro.build.version.sdk') echo 29 ;;
'shell getprop ro.product.cpu.abi') echo x86_64 ;;
'shell pm list packages com.adshield.pro.debug'|'shell input keyevent 82'|'logcat -b crash -c'|'logcat -b crash -d -t 100') : ;;
install*)
    if [[ "${REJECT_INSTALL:-0}" == 1 ]]; then echo 'Failure [INSTALL_FAILED_INVALID_APK]' >&2; exit 1; fi
    printf 'Performing Streamed Install\\r\\nSuccess\\r\\n'
    ;;
'shell pm path com.adshield.pro.debug') echo 'package:/data/app/fixture/base.apk' ;;
'shell am start -W '*) printf 'Status: ok\\r\\n'; ;;
'shell pidof -s com.adshield.pro.debug')
    if [[ "${CRASH:-0}" == 1 && -f pid-seen ]]; then exit 1; fi
    touch pid-seen
    echo 1234
    ;;
'shell dumpsys activity activities') echo 'mResumedActivity: ActivityRecord{1 u0 com.adshield.pro.debug/com.adshield.pro.MainActivity t1}' ;;
*) exit 44 ;;
esac
''', executable=True)

    def test_require_install_and_foreground_start(self):
        self.mock_emulator()
        result = self.run_script('smoke_android_install.sh', str(self.apk_rel))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASSED: Installed and opened', result.stdout)

    def test_fail_for_rejected_apk_or_startup_crash(self):
        self.mock_emulator()
        for settings, diagnostic in [({'REJECT_INSTALL': '1'}, 'INSTALL_FAILED_INVALID_APK'),
                                     ({'CRASH': '1'}, 'crashed after launch')]:
            with self.subTest(diagnostic=diagnostic):
                result = self.run_script('smoke_android_install.sh', str(self.apk_rel), **settings)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)

    def test_smoke_refuses_to_install_on_a_non_emulator_target(self):
        result = self.run_script('smoke_android_install.sh', str(self.apk_rel), 'physical-device-serial')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires a disposable emulator', result.stderr)

    def test_preview_does_not_publish_on_push_or_without_manual_opt_in(self):
        for event, requested in [('push', 'true'), ('workflow_dispatch', 'false')]:
            result = self.run_script('publish_android_preview.sh', GITHUB_EVENT_NAME=event,
                                     GITHUB_REF_TYPE='branch', PUBLIC_PREVIEW=requested)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires an explicit manual workflow request', result.stderr)

    def test_preview_publishes_exact_tested_apk_as_non_latest_with_checksum(self):
        self.file('bin/git', '#!/bin/bash\nprintf "%s\\n" "$GITHUB_SHA"\n', executable=True)
        self.file('bin/python3', '#!/bin/bash\n[[ "$2" == --variant && "$3" == debug && -s "$4" ]]\n', executable=True)
        self.file('sdk/build-tools/36.0.0/apksigner', '#!/bin/bash\n[[ "$1" == verify && -s "$2" ]]\n', executable=True)
        self.file('bin/gh', '''#!/usr/bin/env bash
set -euo pipefail
case "$*" in
'api repos/example/repo/releases/latest --jq .tag_name') echo v2.11.0 ;;
'release create preview-v2.11.1-run.123.2 '*)
    cmp "$4" app/build/outputs/apk/debug/app-debug.apk
    [[ "$5" == "$4.sha256" && "$(cat "$5")" == "$(sha256sum "$4" | cut -d ' ' -f 1)" ]]
    [[ " $* " == *' --prerelease --latest=false '* && " $* " == *" --target $GITHUB_SHA "* ]]
    touch published
    ;;
'release view preview-v2.11.1-run.123.2 '*) test -f published; echo true ;;
*) exit 66 ;;
esac
''', executable=True)
        result = self.run_script('publish_android_preview.sh', GITHUB_EVENT_NAME='workflow_dispatch',
                                 GITHUB_REF_TYPE='branch', PUBLIC_PREVIEW='true', GITHUB_REPOSITORY='example/repo',
                                 GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2', GITHUB_SHA='a' * 40)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / 'published').exists())
        self.assertEqual(list(self.root.glob('adshield-preview.*')), [])
        summary = (self.root / 'summary').read_text(encoding='utf-8')
        self.assertIn('AdShieldPro-2.11.1-preview-123.2.apk', summary)
        self.assertIn('Production Latest: `v2.11.0`', summary)


if __name__ == '__main__':
    unittest.main()
