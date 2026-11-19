"""Tests signing policy without private keys or GitHub access."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'release_signing.sh'
EXPOSED = 'a' * 64
PUBLISHED = 'b' * 64
SECURE = hashlib.sha256(b'mock-secure-certificate').hexdigest()


class PublicSigningAuditTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {
            'PATH': f'{self.root}/bin:{os.environ["PATH"]}',
            'ANDROID_HOME': str(self.root / 'sdk'),
            'RUNNER_TEMP': str(self.root),
            'GITHUB_STEP_SUMMARY': str(self.root / 'summary'),
            'EXPOSED_CERT': EXPOSED,
            'PUBLISHED_CERT': PUBLISHED,
            'SECURE_CERT': SECURE,
            'SECURE_VERSION_NAME': '2.11.1',
            'GITHUB_REPOSITORY': 'example/repo',
        }
        self.binary('bin/gh', '''#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == 'release view --json tagName --jq .tagName' ]]; then
    echo v2.11.0
elif [[ "$1" == api && "$2" == --paginate && "$3" == 'repos/example/repo/releases?per_page=100' ]]; then
    printf '%s\\n' v2.11.0 preview-v2.11.1-run.123.1 test-secure-v2.11.1-run.123.1 "${SECURE_TAG:-}"
elif [[ "$1" == release && "$2" == download && "$4" == --pattern && "$6" == --dir && $# == 7 ]]; then
    case "$3:$5" in
        v2.10.9:AdShieldPro-2.10.9-release.apk) printf '%s' "$EXPOSED_CERT" > "$7/$5" ;;
        v2.11.0:AdShieldPro-2.11.0-release.apk) printf '%s' "$PUBLISHED_CERT" > "$7/$5" ;;
        secure-v2.10.0:AdShieldPro-Secure-2.10.0-release.apk) printf '%s' "$SECURE_CERT" > "$7/$5" ;;
        *) exit 4 ;;
    esac
else
    exit 5
fi
''')
        self.binary('sdk/build-tools/36.0.0/apksigner', '''#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == verify && "$2" == --print-certs && $# == 3 ]]
digest=$(cat "$3")
printf 'Signer #1 certificate SHA-256 digest: %s\\n' "$digest"
''')

    def binary(self, path, text):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding='utf-8')
        file.chmod(0o700)

    def run_action(self, command, **extra_env):
        result = subprocess.run(['bash', SCRIPT, command], cwd=self.root,
                                env={**self.env, **extra_env}, text=True, capture_output=True, timeout=10)
        self.assertEqual(list(self.root.glob('adshield-signing.*')), [])
        return result

    def test_audit_compares_verified_apks_without_signing_credentials(self):
        result = self.run_action('audit')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Latest v2.11.0 uses a different signing certificate', result.stdout)
        summary = (self.root / 'summary').read_text(encoding='utf-8')
        self.assertIn(PUBLISHED, summary)
        self.assertIn('does not prove the key is privately held', summary)

    def test_audit_reports_when_latest_is_signed_with_the_exposed_key(self):
        result = self.run_action('audit', PUBLISHED_CERT=EXPOSED)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Latest v2.11.0 uses the exposed v2.10.9 signing certificate', result.stdout)
        self.assertIn('::warning', result.stdout)

    def prepare_mock_key(self):
        self.binary('bin/keytool', '#!/bin/sh\nprintf "mock-secure-certificate"\n')
        self.binary('gradlew', '#!/bin/bash\n[[ -s "$ADSHIELD_KEYSTORE_PATH" && "$GITHUB_UPDATE_REPOSITORY" == example/repo ]] || exit 3\ntouch built\n')
        self.binary('sdk/build-tools/36.0.0/aapt2', """#!/bin/bash
printf "package: name='%s' versionCode='21000'\\n" "${PREDECESSOR_ID:-com.adshield.pro.secure}"
""")

    def build(self, cert=SECURE, **env):
        return self.run_action('build-secure', ADSHIELD_SECURE_APK_CERT_SHA256=cert,
                               KEYSTORE_B64='dGVzdA==', ADSHIELD_STORE_PASSWORD='test-only', **env)

    def test_secure_build_rejects_exposed_and_legacy_pins_before_opening_a_key(self):
        for cert in (EXPOSED, PUBLISHED):
            with self.subTest(cert=cert):
                result = self.build(cert)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('fresh signer', result.stderr)

    def test_first_secure_build_uses_a_different_approved_signer(self):
        self.prepare_mock_key()
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'built').exists())
        self.assertIn('No prior Secure APK', result.stdout)

    def test_secure_updates_require_predecessor_id_newer_version_and_matching_key(self):
        self.prepare_mock_key()
        for settings, diagnostic in [({'SECURE_TAG': 'secure-v2.11.1'}, 'must be newer'),
                                     ({'SECURE_CERT': 'd' * 64}, 'another signer'),
                                     ({'PREDECESSOR_ID': 'com.adshield.pro'}, 'another package identity')]:
            with self.subTest(diagnostic=diagnostic):
                result = self.build(**{'SECURE_TAG': 'secure-v2.10.0', **settings})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(diagnostic, result.stderr)
        result = self.build(SECURE_TAG='secure-v2.10.0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / 'built').exists())

    def test_audit_does_not_report_success_on_unverified_certificate(self):
        result = self.run_action('audit', PUBLISHED_CERT='unreadable')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('::notice', result.stdout)
        self.assertFalse((self.root / 'summary').exists())


if __name__ == '__main__':
    unittest.main()
