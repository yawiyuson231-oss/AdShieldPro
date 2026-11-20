import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import urlsplit

from tools.evolution.artifacts import (
    ADAPTER, SCOPE, EXTRA_SOURCES, compare, load_json, sha_file, source_paths, validate,
)
from tools.evolution.core import CATEGORIES, gate
from tools.evolution.fixtures import DATASET, generate


class SyntheticFixtureTest(unittest.TestCase):
    def test_checked_in_fixture_is_reproducible(self):
        self.assertEqual(load_json(DATASET), generate())
        result = subprocess.run([sys.executable, '-m', 'tools.evolution.fixtures', '--check'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_scope_coverage_and_safe_inputs(self):
        rows = generate()
        self.assertEqual(len(rows), 26)
        self.assertEqual(len({s['id'] for s in rows}), len(rows))
        for category in CATEGORIES:
            self.assertEqual({s['malicious'] for s in rows if s['category'] == category}, {False, True})
        for row in rows:
            self.assertEqual(row['label_scope'], 'synthetic-risk-or-policy-only')
            self.assertTrue(row['rationale'])
            self.assertTrue(row['observed_at'].endswith('Z'))
            self.assertEqual(row['license'], 'CC0-1.0')
            if 'target' in row['input']:
                target = row['input']['target']
                host = urlsplit(target).hostname if '://' in target else target
                self.assertTrue(host.lower().rstrip('.').endswith('.test'), host)
            if row['category'] == 'apk_metadata':
                self.assertNotIn('apk', row['input'])  # no executable payload


class DetectorArtifactTest(unittest.TestCase):
    """Contract tests use fake artifacts; these are not detector execution results."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        paths = list(EXTRA_SOURCES) + ['app/src/main/java/test/Detector.kt', DATASET]
        for name in paths:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('test fixture bytes\n')
        (self.root / DATASET).write_text(json.dumps(generate()))
        self.artifact = dict(
            schema=1, adapter=ADAPTER, scope=SCOPE, created_at='2026-11-20T00:00:00Z',
            dataset_file_sha256=sha_file(self.root / DATASET),
            source_manifest={p: sha_file(self.root / p) for p in source_paths(self.root)},
            predictions={s['id']: s['malicious'] for s in generate()},
        )

    def test_current_and_unchanged_baseline(self):
        self.assertEqual(len(validate(self.artifact, self.root, current=True)), 26)
        report = compare(self.artifact, self.artifact, self.root)
        self.assertFalse(report['eligible'])
        self.assertFalse(report['independent_holdout'])
        self.assertFalse(report['release_eligible'])
        self.assertIn('candidate_artifact_sha256', report)

    def test_source_mutation_and_inventory_change_rejected(self):
        path = self.root / 'app/src/main/java/test/Detector.kt'
        path.write_text('mutated')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            validate(self.artifact, self.root, current=True)
        validate(self.artifact, self.root)  # baseline sources need not match working tree
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
            validate(self.artifact, self.root, current=True)

    def test_dataset_tampering_rejected(self):
        with (self.root / DATASET).open('a') as stream:
            stream.write(' ')
        with self.assertRaisesRegex(ValueError, 'dataset bytes'):
            validate(self.artifact, self.root)

    def test_changed_adapter_requires_rebaseline(self):
        old = copy.deepcopy(self.artifact)
        old['source_manifest'][EXTRA_SOURCES[0]] = 'a' * 64
        with self.assertRaisesRegex(ValueError, 'adapter bytes changed'):
            compare(old, self.artifact, self.root)

    def test_invalid_contracts_rejected(self):
        for key, value in [('schema', True), ('adapter', 'unknown'), ('scope', 'live'),
                           ('created_at', '2026-11-20T00:00:00'), ('source_manifest', {}),
                           ('predictions', {}), ('predictions', dict(self.artifact['predictions'], extra=True))]:
            with self.subTest(key=key, value=value):
                bad = dict(self.artifact, **{key: value})
                with self.assertRaises((ValueError, TypeError)):
                    validate(bad, self.root, current=True)
        for path in ('../secret', '/etc/passwd', 'a/../b', 'a\\b', 'a//b'):
            bad = dict(self.artifact, source_manifest={path: 'a' * 64})
            with self.assertRaises(ValueError):
                validate(bad, self.root)

    def test_synthetic_improvement_never_overrides_holdout_requirement(self):
        old = copy.deepcopy(self.artifact)
        old['predictions']['domain:lookalike'] = False
        report = compare(old, self.artifact, self.root)
        self.assertTrue(report['eligible'])  # only the comparison, never release authorization
        self.assertFalse(report['release_eligible'])
        checks = dict.fromkeys(('regression_tests', 'dns_unchanged', 'ui_unchanged',
            'privacy_review', 'performance_budget', 'dependency_integrity',
            'signing_verified', 'rollback_tested', 'independent_holdout'), True)
        self.assertFalse(gate(report, checks)['eligible'])

    def test_duplicate_json_keys_and_nonfinite_values_rejected(self):
        path = self.root / 'invalid.json'
        for text in ('{"predictions":{},"predictions":{}}', '{"number":NaN}'):
            path.write_text(text)
            with self.assertRaises(ValueError):
                load_json(path)

    def test_artifact_cli(self):
        path = self.root / 'run.json'
        path.write_text(json.dumps(self.artifact))
        command = [sys.executable, '-m', 'tools.evolution.artifacts', '--root', str(self.root)]
        result = subprocess.run(command + ['validate', str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['release_eligible'])
        result = subprocess.run(command + ['compare', str(path), str(path)], capture_output=True)
        self.assertEqual(result.returncode, 1)
        path.write_text('{}')
        result = subprocess.run(command + ['validate', str(path)], capture_output=True)
        self.assertEqual(result.returncode, 2)


if __name__ == '__main__':
    unittest.main()
