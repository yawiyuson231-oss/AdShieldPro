import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.evolution.core import Journal
from tools.evolution.knowledge import KnowledgeGraph, LIMITS, NODE_TYPES


class KnowledgeGraphTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'knowledge.db'
        self.now = datetime(2026, 11, 20, tzinfo=timezone.utc)
        self.graph = KnowledgeGraph(self.path, clock=lambda: self.now)
        self.addCleanup(self.graph.close)
        self.bundle = {
            'sources': [dict(id='source-v1', url='https://research.example.test/advisory',
                             license='unknown', observed_at='2026-11-19T00:00:00Z',
                             expires_at='2026-12-20T00:00:00Z')],
            'nodes': [dict(id=kind, type=kind, value=f'synthetic {kind}') for kind in sorted(NODE_TYPES)],
            'edges': [dict(id='edge-v1', subject='advisory', relation='affects', object='dependency',
                           source='source-v1', observed_at='2026-11-19T01:00:00Z',
                           expires_at='2026-12-01T00:00:00Z', confidence=0.9,
                           verification='unverified')],
        }

    def import_and_review(self):
        self.graph.import_bundle(self.bundle)
        self.graph.review('source', 'source-v1', 'reviewer', 'Synthetic license and source reviewed',
                          'verified', reliability=0.95, license_allowed=True)
        self.graph.review('edge', 'edge-v1', 'reviewer', 'Synthetic relationship reviewed', 'verified')

    def count(self, table):
        return self.graph.db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]

    def test_import_is_unverified_and_idempotent(self):
        self.graph.import_bundle(self.bundle)
        self.graph.import_bundle(self.bundle)
        self.assertEqual(self.count('sources'), 1)
        self.assertEqual(self.count('nodes'), 8)
        result = self.graph.relationship('edge-v1')
        self.assertEqual(result['verification'], 'unverified')
        self.assertFalse(result['proposal_eligible'])
        self.assertFalse(result['protection_eligible'])
        for key in ('source', 'observed_at', 'confidence', 'verification'):
            self.assertIn(key, result['edge'])
        with self.assertRaises(ValueError):
            self.graph.propose('edge-v1', 'Review dependency')

    def test_reviewed_proposal_never_deploys(self):
        self.import_and_review()
        result = self.graph.relationship('edge-v1')
        self.assertTrue(result['proposal_eligible'])
        proposal = self.graph.propose('edge-v1', 'Investigate synthetic dependency exposure')
        self.assertEqual(proposal['stage'], 'DISCOVER')
        self.assertFalse(proposal['protection_eligible'])
        self.assertEqual(self.graph.propose('edge-v1', proposal['title'])['id'], proposal['id'])
        self.assertEqual(self.count('proposals'), 1)
        self.assertTrue(self.graph.proposal(proposal['id'])['currently_eligible'])

    def test_source_retraction_invalidates_prior_proposal_without_rewriting_snapshot(self):
        self.import_and_review()
        proposal = self.graph.propose('edge-v1', 'Investigate')
        self.graph.review('source', 'source-v1', 'reviewer-2', 'Source withdrawn',
                          'retracted', reliability=0.1, license_allowed=False)
        current = self.graph.proposal(proposal['id'])
        self.assertEqual(current['snapshot']['evidence']['source_review']['status'], 'verified')
        self.assertFalse(current['currently_eligible'])
        self.assertEqual(self.count('reviews'), 3)
        with self.assertRaises(ValueError):
            self.graph.propose('edge-v1', 'Must not be accepted')

    def test_research_can_only_record_discovery_and_rechecks_current_evidence(self):
        self.import_and_review()
        proposal = self.graph.propose('edge-v1', 'Investigate')
        journal = Journal(Path(self.temp.name) / 'cycles.db')
        try:
            tip = self.graph.record_discovery(journal, 'research-cycle-1', proposal['id'])
            events, _ = journal.verify(tip)
            self.assertEqual([event['stage'] for event in events], ['DISCOVER'])
            self.assertEqual(events[0]['evidence']['research_proposal_id'], proposal['id'])
            self.now = datetime(2026, 12, 1, tzinfo=timezone.utc)
            with self.assertRaises(ValueError):
                self.graph.record_discovery(journal, 'research-cycle-2', proposal['id'])
            self.assertEqual(len(journal.verify(tip)[0]), 1)
        finally:
            journal.close()

    def test_edge_dispute_and_confidence_gate(self):
        self.bundle['edges'][0]['confidence'] = 0.79
        self.import_and_review()
        self.assertIn('relationship confidence below 0.8', self.graph.relationship('edge-v1')['reasons'])
        self.graph.review('edge', 'edge-v1', 'reviewer', 'Contradictory evidence', 'disputed')
        result = self.graph.relationship('edge-v1')
        self.assertEqual(result['verification'], 'disputed')
        self.assertFalse(result['proposal_eligible'])

    def test_expiry_and_clock_rollback(self):
        self.import_and_review()
        proposal = self.graph.propose('edge-v1', 'Review')
        self.now = datetime(2026, 12, 1, tzinfo=timezone.utc)
        self.assertIn('expired evidence', self.graph.relationship('edge-v1')['reasons'])
        self.assertFalse(self.graph.proposal(proposal['id'])['currently_eligible'])
        self.now = datetime(2026, 11, 18, tzinfo=timezone.utc)
        self.assertFalse(self.graph.relationship('edge-v1')['proposal_eligible'])
        self.now = datetime(2026, 11, 19, 12, tzinfo=timezone.utc)
        self.assertIn('review is in the future relative to current clock',
                      self.graph.relationship('edge-v1')['reasons'])

    def test_source_expiry_is_also_enforced(self):
        self.bundle['sources'][0]['expires_at'] = '2026-11-21T00:00:00Z'
        self.import_and_review()
        self.now += timedelta(days=1)
        self.assertFalse(self.graph.relationship('edge-v1')['proposal_eligible'])

    def test_immutable_conflict_rolls_back_entire_bundle(self):
        self.graph.import_bundle(self.bundle)
        bad = copy.deepcopy(self.bundle)
        bad['nodes'].insert(0, dict(id='new-node', type='domain', value='new.test'))
        bad['edges'][0]['confidence'] = 0.1
        with self.assertRaisesRegex(ValueError, 'immutable'):
            self.graph.import_bundle(bad)
        self.assertEqual(self.count('nodes'), 8)
        self.assertEqual(self.graph.relationship('edge-v1')['edge']['confidence'], 0.9)

    def test_missing_reference_rolls_back_sources_and_nodes(self):
        self.bundle['edges'][0]['object'] = 'missing'
        with self.assertRaises(ValueError):
            self.graph.import_bundle(self.bundle)
        for table in ('sources', 'nodes', 'edges'):
            self.assertEqual(self.count(table), 0)

    def test_import_cannot_smuggle_reviews_or_verification(self):
        bad = dict(self.bundle, reviews=[])
        with self.assertRaises(ValueError):
            self.graph.import_bundle(bad)
        self.bundle['edges'][0]['verification'] = 'verified'
        with self.assertRaises(ValueError):
            self.graph.import_bundle(self.bundle)
        self.assertEqual(self.count('edges'), 0)

    def test_invalid_confidence_values(self):
        for value in (True, -0.1, 1.1, 10 ** 500, float('nan'), float('inf'), '0.9'):
            with self.subTest(value=value):
                self.bundle['edges'][0]['confidence'] = value
                with self.assertRaises(ValueError):
                    self.graph.import_bundle(self.bundle)
                self.assertEqual(self.count('edges'), 0)

    def test_invalid_times_text_types_and_relations(self):
        for table, field, value in (
            ('sources', 'url', 'http://research.test'),
            ('sources', 'url', 'https://user:secret@research.test'),
            ('sources', 'url', 'file:///tmp/feed'),
            ('sources', 'license', ''),
            ('sources', 'observed_at', '2026-11-21T00:00:00Z'),
            ('edges', 'observed_at', '2026-11-19T00:00:00'),
            ('edges', 'expires_at', '2026-11-18T00:00:00Z'),
            ('edges', 'expires_at', '2100-01-01T00:00:00Z'),
            ('edges', 'relation', 'execute'),
            ('edges', 'id', '../outside'),
            ('nodes', 'type', 'executable'),
            ('nodes', 'value', 'secret\nnewline'),
            ('nodes', 'value', 'x' * 2049),
        ):
            bad = copy.deepcopy(self.bundle)
            bad[table][0][field] = value
            with self.subTest(table=table, field=field, value=value):
                with self.assertRaises(ValueError):
                    self.graph.import_bundle(bad)
                self.assertEqual(self.count('sources'), 0)

    def test_invalid_reviews_and_low_reliability_license_decision(self):
        self.graph.import_bundle(self.bundle)
        for arguments in (
            ('edge', 'missing', 'r', 'why', 'verified'),
            ('edge', 'edge-v1', '', 'why', 'verified'),
            ('edge', 'edge-v1', 'r', 'why', 'trusted'),
            ('code', 'edge-v1', 'r', 'why', 'verified'),
        ):
            with self.assertRaises(ValueError):
                self.graph.review(*arguments)
        with self.assertRaises(ValueError):
            self.graph.review('source', 'source-v1', 'r', 'why', 'verified', reliability=0.9)
        self.graph.review('edge', 'edge-v1', 'r', 'why', 'verified')
        self.graph.review('source', 'source-v1', 'r', 'why', 'verified', reliability=0.79, license_allowed=True)
        self.assertFalse(self.graph.relationship('edge-v1')['proposal_eligible'])
        self.graph.review('source', 'source-v1', 'r', 'why', 'verified', reliability=0.99, license_allowed=False)
        self.assertFalse(self.graph.relationship('edge-v1')['proposal_eligible'])

    def test_capacity_and_bundle_bounds_fail_closed(self):
        with patch.dict(LIMITS, nodes=1):
            with self.assertRaisesRegex(ValueError, 'capacity'):
                self.graph.import_bundle(self.bundle)
        self.assertEqual(self.count('sources'), 0)
        with self.assertRaises(ValueError):
            self.graph.import_bundle(dict(self.bundle, sources=[{}] * 1001))
        self.import_and_review()
        with patch.dict(LIMITS, reviews=2, proposals=0):
            with self.assertRaises(ValueError):
                self.graph.review('edge', 'edge-v1', 'r', 'why', 'retracted')
            with self.assertRaises(ValueError):
                self.graph.propose('edge-v1', 'Review')
        self.assertEqual(self.count('reviews'), 2)

    def test_persistence_and_integrity(self):
        self.import_and_review()
        another = KnowledgeGraph(self.path, clock=lambda: self.now)
        try:
            another.verify()
            self.assertTrue(another.relationship('edge-v1')['proposal_eligible'])
        finally:
            another.close()
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.db.execute("INSERT INTO edges VALUES ('bad','missing','missing','missing','{}')")
        self.graph.db.rollback()

    def test_unknown_or_incomplete_schema_rejected(self):
        for version in (1, 99):
            path = Path(self.temp.name) / f'bad-{version}.db'
            with sqlite3.connect(path) as db:
                db.execute(f'PRAGMA user_version = {version}')
            with self.assertRaises(ValueError):
                KnowledgeGraph(path)
        path = Path(self.temp.name) / 'unversioned.db'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE unrelated (id TEXT)')
        with self.assertRaises(ValueError):
            KnowledgeGraph(path)

    def test_cli_import_inspect_and_failure_exit(self):
        bundle = copy.deepcopy(self.bundle)
        actual_now = datetime.now(timezone.utc)
        for row in bundle['sources'] + bundle['edges']:
            row['observed_at'] = (actual_now - timedelta(days=1)).isoformat()
            row['expires_at'] = (actual_now + timedelta(days=30)).isoformat()
        path = Path(self.temp.name) / 'bundle.json'
        path.write_text(json.dumps(bundle))
        command = [sys.executable, '-m', 'tools.evolution.knowledge', str(self.path)]
        result = subprocess.run(command + ['import', str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(command + ['inspect', 'edge-v1'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)['proposal_eligible'])
        result = subprocess.run(command + ['inspect', 'missing'], capture_output=True)
        self.assertEqual(result.returncode, 2)
        path.write_text('{"sources":[],"sources":[]}')
        self.assertEqual(subprocess.run(command + ['import', str(path)], capture_output=True).returncode, 2)


if __name__ == '__main__':
    unittest.main()
