import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from tools.evolution.core import CATEGORIES, Journal, digest, evaluate, gate, priorities


class EvolutionTest(unittest.TestCase):
    def setUp(self):
        self.samples = [dict(id=f'{c}-{v}', category=c, malicious=v,
                             source='synthetic fixture v1', verification='verified')
                        for c in sorted(CATEGORIES) for v in (False, True)]
        self.good = {s['id']: s['malicious'] for s in self.samples}
        self.old = dict(self.good)
        self.old['domain-True'] = False
        self.checks = dict.fromkeys(('regression_tests', 'dns_unchanged', 'ui_unchanged',
            'privacy_review', 'performance_budget', 'dependency_integrity',
            'signing_verified', 'rollback_tested', 'independent_holdout'), True)

    def report(self):
        return evaluate(self.samples, self.old, self.good)

    def test_measured_improvement(self):
        report = self.report()
        self.assertTrue(report['eligible'])
        self.assertEqual(report['baseline']['fn'], 1)
        self.assertEqual(report['candidate']['fn'], 0)
        self.assertEqual(report['incorrect_classifications']['baseline'], [
            {'id': 'domain-True', 'category': 'domain', 'expected': True, 'predicted': False}
        ])
        self.assertEqual(report['incorrect_classifications']['candidate'], [])
        self.assertTrue(gate(report, self.checks)['eligible'])

    def test_equal_model_is_not_improvement(self):
        self.assertFalse(evaluate(self.samples, self.good, self.good)['eligible'])

    def test_aggregate_gain_cannot_hide_slice_regression(self):
        self.old['phishing-True'] = False
        candidate = dict(self.good, **{'apk_metadata-True': False})
        self.assertFalse(evaluate(self.samples, self.old, candidate)['eligible'])

    def test_false_positive_is_regression(self):
        self.good['configuration-False'] = True
        self.assertFalse(self.report()['eligible'])

    def test_missing_category_or_class_rejected(self):
        rows = [s for s in self.samples if s['id'] != 'domain-False']
        old = {s['id']: self.old[s['id']] for s in rows}
        new = {s['id']: self.good[s['id']] for s in rows}
        self.assertFalse(evaluate(rows, old, new)['eligible'])

    def test_invalid_data(self):
        for field, value in [('verification', 'unverified'), ('malicious', 1),
                             ('source', ''), ('category', 'unknown')]:
            with self.subTest(field=field):
                rows = copy.deepcopy(self.samples)
                rows[0][field] = value
                with self.assertRaises(ValueError):
                    evaluate(rows, self.old, self.good)
        for predictions in ({}, dict(self.good, extra=True), dict(self.good, **{'domain-True': 1})):
            with self.assertRaises(ValueError):
                evaluate(self.samples, self.old, predictions)
        with self.assertRaises(ValueError):
            evaluate(self.samples + self.samples, self.old, self.good)
        with self.assertRaises(ValueError):
            evaluate([], {}, {})

    def test_fail_closed_checks(self):
        for value in (False, None, 'true', 1):
            self.assertFalse(gate(self.report(), dict(self.checks, privacy_review=value))['eligible'])
        self.assertFalse(gate(self.report(), {})['eligible'])

    def test_priorities_record_failure(self):
        report = evaluate(self.samples, self.good, self.good)
        self.assertEqual(priorities([report, report])[0]['cycles'], 2)

    def test_cli_exit_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ('samples.json', 'old.json', 'new.json')]
            for path, value in zip(paths, (self.samples, self.old, self.good)):
                path.write_text(json.dumps(value))
            command = [sys.executable, '-m', 'tools.evolution', *map(str, paths)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)['eligible'])
            paths[1].write_text(json.dumps(self.good))
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            paths[2].write_text('{}')
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)

    def test_journal_persists_across_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cycles.db'
            journal = Journal(path)
            tip = journal.append('c1', 'DISCOVER', {'issue': 'coverage'})
            journal.close()
            journal = Journal(path)
            try:
                self.assertEqual(journal.verify(tip)[0][0]['cycle'], 'c1')
                with self.assertRaises(ValueError):
                    journal.append('c1', 'DISCOVER', {})
            finally:
                journal.close()

    def test_journal_governance_integrity_and_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = Journal(Path(directory) / 'cycles.db')
            evidence = {'report': self.report(), 'checks': self.checks}
            try:
                with self.assertRaises(ValueError):
                    journal.append('c1', 'DEPLOY', evidence)
                journal.append('c1', 'DISCOVER', {'opportunity': 'missed synthetic domain'})
                journal.append('c1', 'EXPERIMENT', evidence)
                with self.assertRaises(ValueError):
                    journal.append('c1', 'VERIFY', dict(evidence, checks={}))
                journal.append('c1', 'VERIFY', evidence)
                with self.assertRaises(ValueError):
                    journal.append('c1', 'DEPLOY', evidence)
                approval = {'reviewer': 'test-reviewer', 'evidence_sha256': digest(evidence)}
                with self.assertRaises(ValueError):
                    journal.append('c1', 'DEPLOY', {}, approval)
                tip = journal.append('c1', 'DEPLOY', evidence, approval)
                self.assertEqual(len(journal.verify(tip)[0]), 4)
                journal.db.execute('DELETE FROM events WHERE seq = 4')
                journal.db.commit()
                with self.assertRaises(ValueError):
                    journal.verify(tip)
                journal.db.execute("UPDATE events SET payload = '{}' WHERE seq = 2")
                journal.db.commit()
                with self.assertRaises(ValueError):
                    journal.verify()
            finally:
                journal.close()


if __name__ == '__main__':
    unittest.main()
