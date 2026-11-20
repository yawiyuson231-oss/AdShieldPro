import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from tools.evolution.core import CATEGORIES, digest, evaluate
from tools.evolution.release_gate import authorize
from tools.tests.test_evolution_learning import CHECKS


class ReleaseApprovalTest(unittest.TestCase):
    def setUp(self):
        # Synthetic aggregate-contract test. Not production approval or independent real-world evidence.
        samples = [dict(id=f'{category}:{label}:{index}', category=category, malicious=label,
                        source='test fixture', verification='verified')
                   for category in sorted(CATEGORIES) for label in (False, True) for index in range(20)]
        candidate = {s['id']: s['malicious'] for s in samples}
        baseline = dict(candidate)
        baseline[next(s['id'] for s in samples if s['malicious'])] = False
        report = evaluate(samples, baseline, candidate)
        report['independent_holdout'] = True
        self.commit = 'c' * 40
        self.evidence = dict(schema=1, source_commit=self.commit, report=report, checks=CHECKS.copy())
        self.bind()

    def bind(self):
        body = {key: self.evidence[key] for key in ('source_commit', 'report', 'checks')}
        self.evidence['approval'] = dict(reviewer='synthetic-test-reviewer', evidence_sha256=digest(body))

    def test_source_bound_evidence_is_not_publication_or_signature_proof(self):
        result = authorize(self.evidence, self.commit)
        self.assertTrue(result['approval_record_valid'])
        self.assertFalse(result['publication_performed'])
        self.assertFalse(result['apk_signature_verified_by_this_gate'])
        with self.assertRaises(ValueError):
            authorize(self.evidence, 'd' * 40)
        bad = copy.deepcopy(self.evidence)
        bad['report']['candidate']['tp'] = 999
        with self.assertRaises(ValueError):
            authorize(bad, self.commit)

    def test_missing_approval_or_checks_and_public_synthetic_holdouts_rejected(self):
        for key, value in [('independent_holdout', False), ('eligible', False), ('dataset_sha256', 'bad')]:
            bad = copy.deepcopy(self.evidence)
            bad['report'][key] = value
            with self.assertRaises(ValueError):
                authorize(bad, self.commit)
        bad = copy.deepcopy(self.evidence)
        bad['checks'] = {}
        with self.assertRaises(ValueError):
            authorize(bad, self.commit)
        bad = copy.deepcopy(self.evidence)
        bad['approval']['evidence_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            authorize(bad, self.commit)

    def test_hidden_regression_inconsistent_coverage_or_boolean_counts_rejected(self):
        category = next(iter(CATEGORIES))
        for key, value in [('fp', 1), ('fn', 1), ('tp', True), ('tn', 19)]:
            bad = copy.deepcopy(self.evidence)
            bad['report']['slices'][category]['candidate'][key] = value
            with self.assertRaises(ValueError):
                authorize(bad, self.commit)
        bad = copy.deepcopy(self.evidence)
        del bad['report']['slices'][category]
        with self.assertRaises(ValueError):
            authorize(bad, self.commit)
        bad = copy.deepcopy(self.evidence)
        bad['report']['candidate_sha256'] = bad['report']['baseline_sha256']
        with self.assertRaises(ValueError):
            authorize(bad, self.commit)

    def test_cli_missing_evidence_blocks_without_echoing_private_input(self):
        env = dict(os.environ, ADSHIELD_EVOLUTION_APPROVAL_JSON='', GITHUB_SHA=self.commit)
        command = [sys.executable, '-m', 'tools.evolution.release_gate']
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        env['ADSHIELD_EVOLUTION_APPROVAL_JSON'] = json.dumps(self.evidence)
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('synthetic-test-reviewer', result.stdout)
        env['ADSHIELD_EVOLUTION_APPROVAL_JSON'] = '{"schema":1,"schema":1}'
        self.assertNotEqual(subprocess.run(command, env=env, capture_output=True).returncode, 0)

    def test_production_gate_precedes_signing_and_cannot_be_silently_skipped(self):
        workflow = Path('.github/workflows/release.yml').read_text()
        gate = workflow.index('run: python3 -m tools.evolution.release_gate')
        self.assertLess(gate, workflow.index('- name: Build with the approved Secure key'))
        self.assertIn('${{ vars.ADSHIELD_EVOLUTION_APPROVAL_JSON }}', workflow)


if __name__ == '__main__':
    unittest.main()
