"""Controlled engineering checks and data-only module validation; never publishes/installs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys

from .artifacts import sha_file
from .core import digest
from .knowledge import KnowledgeGraph, identifier

ROOT = Path(__file__).resolve().parents[2]


def commands(android=False):
    result = [
        ['git', 'diff', '--check'],
        [sys.executable, '-m', 'unittest', 'discover', '-s', 'tools/tests', '-v'],
        [sys.executable, '-m', 'tools.evolution.fixtures', '--check'],
        [sys.executable, '-m', 'tools.evolution.boundaries'],
        [sys.executable, 'tools/train_aether_tasks.py', '--check'],
        [sys.executable, 'tools/check_ui_performance.py'],
        ['npm', 'run', 'ci'],
        ['npm', '--prefix', 'cloud', 'test'],
    ]
    if android:
        result += [['./gradlew', ':app:testDebugUnitTest', ':app:lintDebug', ':app:assembleDebug',
                    '--no-daemon', '--console=plain'],
                   [sys.executable, '-m', 'tools.evolution.artifacts', 'validate', '.ci/evolution/current.json'],
                   [sys.executable, 'tools/check_universal_release.py',
                    'app/build/outputs/apk/debug/app-debug.apk', '--variant', 'debug']]
    return result


def run_checks(root=ROOT, android=False, output=None):
    """Fixed argv only. A failed or unavailable tool rejects this candidate, never retries blindly."""
    root = Path(root)
    results = []
    for argv in commands(android):
        try:
            result = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=1200)
            record = dict(command=argv, exit_code=result.returncode,
                          stdout_tail=result.stdout[-4000:], stderr_tail=result.stderr[-4000:])
        except (OSError, subprocess.TimeoutExpired) as error:
            record = dict(command=argv, exit_code=None, error=str(error))
        results.append(record)
        if record['exit_code'] != 0:
            break
    report = dict(schema=1, created_at=datetime.now(timezone.utc).isoformat(), checks=results,
                  all_requested_checks_passed=len(results) == len(commands(android)) and
                    all(row['exit_code'] == 0 for row in results),
                  android_requested=android, signing_verified=False, release_eligible=False,
                  protection_changed=False)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + '\n')
    return report


def verify_apk_signer(apk, expected_sha256, apksigner='apksigner'):
    """Verify with Android's existing apksigner, then pin the actual certificate digest.

    An expected digest must come from independently approved key custody, never from the APK.
    Does not sign, install, upload or assert release readiness.
    """
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or any(c not in '0123456789abcdefABCDEF' for c in expected_sha256)):
        raise ValueError('independently pinned certificate SHA-256 required')
    apk = Path(apk)
    if not apk.is_file() or apk.suffix != '.apk':
        raise ValueError('existing APK file required')
    result = subprocess.run([apksigner, 'verify', '--verbose', '--print-certs', str(apk.resolve())],
                            capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise ValueError('APK signature verification failed')
    import re
    certificates = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]{64})\s*$',
                              result.stdout, re.MULTILINE)
    if len(certificates) != 1 or certificates[0].lower() != expected_sha256.lower():
        raise ValueError('unexpected APK signer or multiple signers')
    return dict(apk_sha256=sha_file(apk),
                certificate_sha256=certificates[0].lower(), signing_verified=True, release_eligible=False)


def validate_module(manifest, payload, measurements):
    """Isolated DATA interfaces only. No dynamic code loading or permission escalation."""
    required = {'id', 'api_version', 'kind', 'permissions', 'min_sdk', 'payload_sha256'}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ValueError('invalid module manifest fields')
    identifier(manifest['id'])
    if (type(manifest['api_version']) is not int or manifest['api_version'] != 1
            or type(manifest['min_sdk']) is not int or not 29 <= manifest['min_sdk'] <= 36
            or manifest['kind'] != 'knowledge_bundle' or manifest['permissions'] != []):
        raise ValueError('incompatible module or non-isolated/executable interface')
    if not isinstance(payload, bytes) or len(payload) > 4 * 1024 * 1024:
        raise ValueError('bounded JSON byte payload required')
    if hashlib.sha256(payload).hexdigest() != manifest['payload_sha256']:
        raise ValueError('module payload digest mismatch')
    # Parse using the same strict duplicate-key/nonfinite rejecting loader semantics.
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate module JSON field')
            result[key] = value
        return result
    bundle = json.loads(payload, object_pairs_hook=unique,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    graph = KnowledgeGraph(':memory:')
    try:
        graph.import_bundle(bundle)  # enforce unverified, bounded, source-complete data contract
    finally:
        graph.close()
    # These are supplied benchmark evidence, not measurements performed by this parser.
    if not isinstance(measurements, dict):
        raise ValueError('module measurements and review evidence required')
    for key, maximum in [('peak_ram_mb', 32), ('wall_ms', 1000)]:
        value = measurements.get(key)
        if type(value) not in (int, float) or not 0 <= value <= maximum or not math.isfinite(value):
            raise ValueError('module performance budget failed or not measured')
    for key in ('security_tests', 'compatibility_tests', 'removal_tests', 'dns_unchanged', 'privacy_review'):
        if measurements.get(key) is not True:
            raise ValueError(f'{key} not verified')
    return dict(module_sha256=digest(manifest), payload_sha256=manifest['payload_sha256'],
                contract_valid=True, executable_loading=False, protection_eligible=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--android', action='store_true')
    parser.add_argument('--plan', action='store_true', help='Print fixed commands without running them')
    parser.add_argument('--output', type=Path, default=ROOT / '.cache/evolution/checks.json')
    args = parser.parse_args()
    if args.plan:
        print(json.dumps(commands(args.android), indent=2))
        return 0
    report = run_checks(android=args.android, output=args.output)
    print(json.dumps(report, indent=2))
    return 0 if report['all_requested_checks_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
