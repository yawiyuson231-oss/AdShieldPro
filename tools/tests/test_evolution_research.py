import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.evolution.knowledge import KnowledgeGraph
from tools.evolution.research import ENDPOINT, collect_bundle, dependency_coordinates, fetch_github


class ResearchIntakeTest(unittest.TestCase):
    def setUp(self):
        # Synthetic metadata only; not an assertion that any real package has this advisory.
        self.advisory = dict(ghsa_id='GHSA-2345-6789-cfgh', cve_id='CVE-2099-00001', updated_at='synthetic',
            html_url='https://github.com/advisories/GHSA-2345-6789-cfgh', withdrawn_at=None,
            vulnerabilities=[{'package': {'ecosystem': 'maven', 'name': 'fixture.group:artifact'}}])
        self.now = datetime(2026, 11, 20, 12, tzinfo=timezone.utc)

    def test_relevant_metadata_is_unverified_and_never_asserts_affected_versions(self):
        bundle, report = collect_bundle([self.advisory], {'fixture.group:artifact'}, self.now)
        self.assertEqual(len(bundle['sources']), 1)
        self.assertEqual(bundle['sources'][0]['license'], 'NOASSERTION')
        self.assertEqual({row['verification'] for row in bundle['edges']}, {'unverified'})
        self.assertIn('related_to', {row['relation'] for row in bundle['edges']})
        self.assertNotIn('affects', {row['relation'] for row in bundle['edges']})
        self.assertFalse(report['exact_coordinate_matches'][0]['affected_version_verified'])
        self.assertFalse(report['exhaustive'])
        graph = KnowledgeGraph(':memory:', clock=lambda: self.now)
        try:
            graph.import_bundle(bundle)
            graph.import_bundle(bundle)
            self.assertFalse(graph.relationship(bundle['edges'][0]['id'])['proposal_eligible'])
        finally:
            graph.close()

    def test_explicit_review_can_assess_research_without_rewriting_imported_confidence(self):
        bundle, _ = collect_bundle([self.advisory], {'fixture.group:artifact'}, self.now)
        graph = KnowledgeGraph(':memory:', clock=lambda: self.now)
        try:
            graph.import_bundle(bundle)
            source, edge = bundle['sources'][0]['id'], bundle['edges'][0]['id']
            graph.review('source', source, 'test reviewer', 'Synthetic source/license review',
                         'verified', reliability=0.9, license_allowed=True)
            graph.review('edge', edge, 'test reviewer', 'Intent checked, confidence not assessed', 'verified')
            self.assertFalse(graph.relationship(edge)['proposal_eligible'])
            graph.review('edge', edge, 'test reviewer', 'Synthetic independent assessment',
                         'verified', assessed_confidence=0.95)
            result = graph.relationship(edge)
            self.assertEqual(result['edge']['confidence'], 0.5)
            self.assertEqual(result['confidence'], 0.95)
            self.assertEqual(graph.propose(edge, 'Investigate synthetic applicability')['stage'], 'DISCOVER')
            self.assertFalse(result['protection_eligible'])
            graph.review('edge', edge, 'test reviewer', 'New uncertainty', 'disputed', assessed_confidence=0.1)
            self.assertFalse(graph.relationship(edge)['proposal_eligible'])
            for value in (True, float('nan'), -0.1, 1.1):
                with self.assertRaises(ValueError):
                    graph.review('edge', edge, 'test reviewer', 'Invalid assessment',
                                 'verified', assessed_confidence=value)
        finally:
            graph.close()

    def test_irrelevant_and_withdrawn_entries_do_not_become_research_proposals(self):
        bundle, report = collect_bundle([self.advisory], {'other:module'}, self.now)
        self.assertEqual(bundle, dict(sources=[], nodes=[], edges=[]))
        self.assertEqual(report['examined'], 1)
        withdrawn = dict(self.advisory, withdrawn_at='2026-11-20T00:00:00Z')
        bundle, report = collect_bundle([withdrawn], {'fixture.group:artifact'}, self.now)
        self.assertEqual(bundle['edges'], [])
        self.assertEqual(report['withdrawn_advisories'], [self.advisory['ghsa_id']])

    def test_source_refreshes_preserve_history_and_reruns_are_idempotent(self):
        old, _ = collect_bundle([self.advisory], {'fixture.group:artifact'}, self.now)
        repeated, _ = collect_bundle([self.advisory], {'fixture.group:artifact'}, self.now)
        self.assertEqual(old, repeated)
        changed = dict(self.advisory, updated_at='changed-content')
        new, _ = collect_bundle([changed], {'fixture.group:artifact'}, self.now)
        self.assertNotEqual(old['sources'][0]['id'], new['sources'][0]['id'])

    def test_malformed_or_redirected_metadata_is_rejected(self):
        for key, value in [('ghsa_id', '../code'), ('html_url', 'https://malicious.test/payload'),
                           ('vulnerabilities', [{}] * 101), ('cve_id', 'not-a-cve')]:
            with self.assertRaises((ValueError, KeyError)):
                collect_bundle([dict(self.advisory, **{key: value})], {'fixture.group:artifact'}, self.now)
        bad = copy.deepcopy(self.advisory)
        bad['vulnerabilities'][0]['package']['ecosystem'] = 'npm'
        bundle, _ = collect_bundle([bad], {'fixture.group:artifact'}, self.now)
        self.assertEqual(bundle['sources'], [])
        bad['vulnerabilities'][0]['package'] = {'ecosystem': 'maven', 'name': '../invalid'}
        with self.assertRaises(ValueError):
            collect_bundle([bad], set(), self.now)
        with self.assertRaises(ValueError):
            collect_bundle([self.advisory] * 101, set(), self.now)

    def test_catalog_coordinates_use_existing_project_inventory(self):
        coordinates = dependency_coordinates('gradle/libs.versions.toml')
        self.assertIn('com.squareup.okhttp3:okhttp', coordinates)
        self.assertIn('androidx.room:room-runtime', coordinates)
        self.assertNotIn('unknown:invented', coordinates)

    def test_fetch_has_fixed_readonly_endpoint_and_cli_offline_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'response.json'
            def fake_fetch(argv, stdout, **kwargs):
                self.assertEqual(argv, ['gh', 'api', ENDPOINT])
                self.assertNotIn('shell', kwargs)
                stdout.write(b'[]')
                return subprocess.CompletedProcess(argv, 0)
            with patch('tools.evolution.research.subprocess.run', side_effect=fake_fetch):
                self.assertEqual(fetch_github(path), [])
            with patch('tools.evolution.research.subprocess.run', return_value=subprocess.CompletedProcess([], 1)):
                with self.assertRaises(ValueError):
                    fetch_github(path)
            path.write_text('[]')
            result = subprocess.run([sys.executable, '-m', 'tools.evolution.research',
                str(Path(directory) / 'graph.sqlite'), '--input', str(path),
                '--report', str(Path(directory) / 'report.json')], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['exhaustive'])


if __name__ == '__main__':
    unittest.main()
