import copy
import sqlite3
import unittest

from tools.evolution.core import CATEGORIES, digest, evaluate
from tools.evolution.learning import LearningRegistry, drift

CHECKS = dict.fromkeys(('regression_tests', 'dns_unchanged', 'ui_unchanged', 'privacy_review',
    'performance_budget', 'dependency_integrity', 'signing_verified', 'rollback_tested',
    'independent_holdout'), True)


class LearningTest(unittest.TestCase):
    def setUp(self):
        self.store = LearningRegistry(':memory:')
        self.addCleanup(self.store.close)

    def test_unverified_rejected_and_conflicting_feedback_never_silently_learns(self):
        sample = self.store.add_sample('domain', {'host': 'sample.test'}, 'holdout')
        positive = self.store.submit_feedback(sample, True, 'fixture', 'Synthetic suspicious case')
        self.assertEqual(self.store.dataset('holdout'), [])
        self.store.review_feedback(positive, 'reviewer', 'Verified fixture intent', True)
        self.assertTrue(self.store.dataset('holdout')[0]['malicious'])
        negative = self.store.submit_feedback(sample, False, 'other fixture', 'Contradictory evidence')
        self.assertTrue(self.store.dataset('holdout')[0]['malicious'])  # pending cannot overwrite
        self.store.review_feedback(negative, 'reviewer', 'Conflicting accepted claim', True)
        self.assertEqual(self.store.dataset('holdout'), [])  # quarantine conflict from evaluation
        self.store.review_feedback(positive, 'reviewer', 'Obsolete claim rejected', False)
        self.assertFalse(self.store.dataset('holdout')[0]['malicious'])
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM decisions').fetchone()[0], 3)

    def test_exact_content_cannot_leak_across_splits(self):
        features = {'host': 'sample.test'}
        self.store.add_sample('domain', features, 'train')
        self.assertEqual(self.store.add_sample('domain', features, 'train'), digest(features))
        for category, split in [('domain', 'holdout'), ('phishing', 'train')]:
            with self.assertRaises(ValueError):
                self.store.add_sample(category, features, split)

    def test_invalid_inputs_and_unknown_ids(self):
        for category, features, split in [('unknown', {'x': 1}, 'train'),
            ('domain', {}, 'train'), ('domain', {'x': 'y' * 20000}, 'train'),
            ('domain', {'x': float('nan')}, 'train'), ('domain', {'x': 1}, 'test')]:
            with self.assertRaises(ValueError):
                self.store.add_sample(category, features, split)
        with self.assertRaises(ValueError):
            self.store.submit_feedback('missing', True, 'source', 'rationale')
        sample = self.store.add_sample('domain', {'x': 1}, 'train')
        with self.assertRaises(ValueError):
            self.store.submit_feedback(sample, 1, 'source', 'rationale')
        with self.assertRaises(ValueError):
            self.store.review_feedback('missing', 'reviewer', 'reason', True)
        with self.assertRaises(ValueError):
            self.store.dataset('unknown')

    def populate(self, count=20):
        for category in sorted(CATEGORIES):
            for label in (False, True):
                for number in range(count):
                    identity = self.store.add_sample(category, {'fixture': category, 'label_case': label,
                                                                 'number': number}, 'holdout')
                    feedback = self.store.submit_feedback(identity, label, 'synthetic test only', 'Fixture intent')
                    self.store.review_feedback(feedback, 'test reviewer', 'Test fixture reviewed', True)
        data = self.store.dataset('holdout')
        predictions = {s['id']: s['malicious'] for s in data}
        baseline = dict(predictions)
        missed = next(s['id'] for s in data if s['malicious'])
        baseline[missed] = False
        report = evaluate(data, baseline, predictions)
        report.update(independent_holdout=True, candidate_model_sha256='a' * 64,
                      baseline_predictions=baseline, candidate_predictions=predictions)
        return report

    def test_selection_and_rollback_are_evidence_bound_metadata_only(self):
        report = self.populate()
        self.store.register_version('model-v1', 'a' * 64, 'c' * 64)
        self.store.register_version('model-v2', 'b' * 64, 'd' * 64)
        with self.assertRaises(ValueError):
            self.store.rollback('reviewer', 'No history yet')
        selected = self.store.select('model-v1', report, CHECKS, 'reviewer', 'Synthetic contract test')
        self.assertFalse(selected['protection_changed'])
        with self.assertRaises(ValueError):
            self.store.select('model-v2', report, CHECKS, 'reviewer', 'Wrong model bytes')
        report['candidate_model_sha256'] = 'b' * 64
        self.store.select('model-v2', report, CHECKS, 'reviewer', 'Synthetic second version')
        rollback = self.store.rollback('reviewer', 'Rollback rehearsal')
        self.assertEqual(rollback['version'], 'model-v1')
        self.assertEqual(self.store.current()['action'], 'rollback')
        self.assertFalse(rollback['protection_changed'])
        self.store.verify()

    def test_small_public_unverified_and_fabricated_metrics_fail_closed(self):
        report = self.populate(count=1)
        self.store.register_version('model-v1', 'a' * 64, 'c' * 64)
        with self.assertRaises(ValueError):
            self.store.select('model-v1', report, CHECKS, 'r', 'Insufficient holdout')
        bad = dict(report, independent_holdout=False)
        with self.assertRaises(ValueError):
            self.store.select('model-v1', bad, CHECKS, 'r', 'Public regression only')
        bad = copy.deepcopy(report)
        bad['candidate']['fn'] = 999
        with self.assertRaisesRegex(ValueError, 'reported metrics'):
            self.store.select('model-v1', bad, CHECKS, 'r', 'Forged metrics')
        with self.assertRaises(ValueError):
            self.store.select('model-v1', report, {}, 'r', 'Missing verification')
        self.assertIsNone(self.store.current())

    def test_model_version_is_immutable(self):
        self.store.register_version('model-v1', 'a' * 64, 'c' * 64)
        self.store.register_version('model-v1', 'a' * 64, 'c' * 64)
        with self.assertRaises(ValueError):
            self.store.register_version('model-v1', 'b' * 64, 'c' * 64)
        with self.assertRaises(ValueError):
            self.store.register_version('bad', 'not-a-hash', 'c' * 64)


class DriftTest(unittest.TestCase):
    def test_shift_is_advisory_and_insufficient_evidence_is_unknown(self):
        self.assertEqual(drift([5, 5], [5, 5])['status'], 'insufficient_evidence')
        self.assertEqual(drift([50, 50], [100, 0])['status'], 'review_distribution_shift')
        self.assertFalse(drift([50, 50], [100, 0])['protection_changed'])
        self.assertEqual(drift([50, 50], [100, 100])['distance'], 0)

    def test_invalid_bins_rejected(self):
        for a, b in [([], []), ([1, 2], [1]), ([True, 100], [50, 50]),
                     ([-1, 101], [50, 50]), ([0.5, 100], [50, 50])]:
            with self.assertRaises(ValueError):
                drift(a, b)
        with self.assertRaises(ValueError):
            drift([50, 50], [50, 50], threshold=float('nan'))


if __name__ == '__main__':
    unittest.main()
