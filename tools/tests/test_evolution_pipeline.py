import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.evolution.pipeline import commands, run_checks, validate_module, verify_apk_signer


class EngineeringPipelineTest(unittest.TestCase):
    def test_fixed_plan_has_no_publish_install_or_arbitrary_patch_execution(self):
        plan = commands(android=True)
        self.assertTrue(any(':app:assembleDebug' in argv for argv in plan))
        self.assertTrue(any('tools/check_universal_release.py' in argv for argv in plan))
        for argv in plan:
            self.assertNotIn('shell', argv)
            self.assertFalse(any(word in argv for word in ('install', 'push', 'publish', 'merge', 'eval')))
        result = subprocess.run([sys.executable, '-m', 'tools.evolution.pipeline', '--plan'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsInstance(json.loads(result.stdout), list)

    def test_failure_or_missing_tool_stops_candidate_without_marking_release_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'checks.json'
            failed = subprocess.CompletedProcess(['fixture'], 1, stdout='failure', stderr='')
            with patch('tools.evolution.pipeline.subprocess.run', return_value=failed) as runner:
                report = run_checks(directory, output=path)
                self.assertEqual(runner.call_count, 1)
                self.assertFalse(report['all_requested_checks_passed'])
                self.assertFalse(report['release_eligible'])
            with patch('tools.evolution.pipeline.subprocess.run', side_effect=FileNotFoundError('missing tool')):
                self.assertIsNone(run_checks(directory)['checks'][0]['exit_code'])
            self.assertFalse(json.loads(path.read_text())['signing_verified'])

    def test_success_is_not_signing_or_release_authorization(self):
        passed = subprocess.CompletedProcess(['fixture'], 0, stdout='ok', stderr='')
        with patch('tools.evolution.pipeline.subprocess.run', return_value=passed):
            report = run_checks()
        self.assertTrue(report['all_requested_checks_passed'])
        self.assertFalse(report['android_requested'])
        self.assertFalse(report['signing_verified'])
        self.assertFalse(report['release_eligible'])

    def test_apk_replacement_during_verification_cannot_receive_the_previous_certificate_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            apk.write_bytes(b'FAKE TEST APK version one')
            certificate = 'a' * 64
            def replace_original(argv, **kwargs):
                snapshot = Path(argv[-1])
                self.assertNotEqual(snapshot, apk)
                self.assertEqual(snapshot.read_bytes(), b'FAKE TEST APK version one')
                apk.write_bytes(b'replaced output after verification began')
                return subprocess.CompletedProcess(argv, 0,
                    stdout=f'Signer #1 certificate SHA-256 digest: {certificate}\n', stderr='')
            with patch('tools.evolution.pipeline.subprocess.run', side_effect=replace_original):
                with self.assertRaisesRegex(ValueError, 'changed during'):
                    verify_apk_signer(apk, certificate)

    def test_apk_signer_is_verified_and_independently_pinned(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / 'fixture.apk'
            apk.write_bytes(b'FAKE TEST APK; not installable')
            cert = 'a' * 64
            success = subprocess.CompletedProcess([], 0, stdout=f'Signer #1 certificate SHA-256 digest: {cert}\n', stderr='')
            with patch('tools.evolution.pipeline.subprocess.run', return_value=success) as runner:
                report = verify_apk_signer(apk, cert)
                self.assertTrue(report['signing_verified'])
                self.assertFalse(report['release_eligible'])
                self.assertEqual(runner.call_args.args[0][1:4], ['verify', '--verbose', '--print-certs'])
                with self.assertRaises(ValueError):
                    verify_apk_signer(apk, 'b' * 64)
            for code, stdout in [(1, success.stdout), (0, success.stdout + success.stdout.replace('#1', '#2')),
                                 (0, 'no certificate')]:
                with patch('tools.evolution.pipeline.subprocess.run', return_value=
                           subprocess.CompletedProcess([], code, stdout=stdout, stderr='')):
                    with self.assertRaises(ValueError):
                        verify_apk_signer(apk, cert)
            with self.assertRaises(ValueError):
                verify_apk_signer(apk, 'untrusted or missing pin')


class ModuleContractTest(unittest.TestCase):
    def setUp(self):
        self.payload = json.dumps({'sources': [], 'nodes': [], 'edges': []}).encode()
        self.manifest = dict(id='research-module', api_version=1, kind='knowledge_bundle', permissions=[],
                             min_sdk=29, payload_sha256=hashlib.sha256(self.payload).hexdigest())
        self.measurements = dict(peak_ram_mb=8, wall_ms=50, security_tests=True, compatibility_tests=True,
                                removal_tests=True, dns_unchanged=True, privacy_review=True)

    def test_valid_data_contract_never_loads_code_or_promotes_protection(self):
        result = validate_module(self.manifest, self.payload, self.measurements)
        self.assertTrue(result['contract_valid'])
        self.assertFalse(result['executable_loading'])
        self.assertFalse(result['protection_eligible'])

    def test_permissions_code_interfaces_api_incompatibility_and_digest_changes_rejected(self):
        for key, value in [('permissions', ['android.permission.INTERNET']), ('kind', 'dex_plugin'),
                           ('api_version', True), ('api_version', 2), ('min_sdk', 37),
                           ('payload_sha256', 'a' * 64), ('entrypoint', 'remote executable')]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    validate_module(dict(self.manifest, **{key: value}), self.payload, self.measurements)
        with self.assertRaises(ValueError):
            validate_module(self.manifest, b'x' * (4 * 1024 * 1024 + 1), self.measurements)

    def test_performance_and_removal_gates_fail_closed(self):
        for key, value in [('peak_ram_mb', 100), ('wall_ms', 1001), ('wall_ms', float('nan')),
                           ('peak_ram_mb', True), ('privacy_review', False), ('dns_unchanged', 'true'),
                           ('removal_tests', None), ('security_tests', 1)]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    validate_module(self.manifest, self.payload, dict(self.measurements, **{key: value}))
        with self.assertRaises(ValueError):
            validate_module(self.manifest, self.payload, {})

    def test_duplicate_json_fields_and_untrusted_payload_rejected(self):
        for payload in (b'{"sources":[],"nodes":[],"edges":[],"edges":[]}',
                        b'{"sources":[],"nodes":[],"edges":[],"reviews":[]}',
                        b'not JSON', b'\x00DEX executable'):
            manifest = dict(self.manifest, payload_sha256=hashlib.sha256(payload).hexdigest())
            with self.assertRaises(ValueError):
                validate_module(manifest, payload, self.measurements)


if __name__ == '__main__':
    unittest.main()
